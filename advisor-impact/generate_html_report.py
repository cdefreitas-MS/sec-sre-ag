#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
advisor-impact / generate_html_report.py  (collector ↔ renderer)

Planejador de remediação que une Azure Advisor + Microsoft Defender for Cloud:
  recomendações (Advisor: Cost/Reliability/Perf/OpEx · MDC: Microsoft.Security assessments)
  → cruza com o inventário do RG → classifica o RISCO DE APLICAR (safe/low/medium/high)
  → cadeia de cascata (recurso muda → workloads dependentes podem reiniciar)
  → PLANO DE EXECUÇÃO FASEADO (quick wins → janela → aprovação+rollback).
  → CUSTO DE IMPLEMENTAÇÃO estimado via Azure Retail Prices API (oficial, sem auth).

100% READ-ONLY — só GET ARM; RECOMENDA, nunca aplica.

Dois modos:
  --from-json inventory.json        → render determinístico/offline (primário)
  --workspace/--sub --rg            → auto-coleta via `az rest` (ARM)

Saída: --format both (default) → HTML (dark, email) + Markdown (repo).
"""
from __future__ import annotations
import argparse, datetime as dt, html, json, os, shutil, subprocess, sys, tempfile
import urllib.request, urllib.parse

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import yaml
except ImportError:
    print("ERRO: PyYAML ausente — `pip install pyyaml`.", file=sys.stderr)
    raise

AZ = shutil.which("az") or "az"

# =============================================================================
# CUSTO DE IMPLEMENTAÇÃO — Azure Retail Prices API (oficial, sem auth)
# Fonte: https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices
# Mapa de padrões de título que implicam aumento de custo → query de preço
# =============================================================================
# Valores fixos mensais estimados (USD) quando a API não retorna dados específicos
COST_INCREASE_PATTERNS = {
    # Padrão no título (case-insensitive) → { serviceName para API, fallback USD/mês, nota }
    "geo-replication": {"service": "Azure Cosmos DB", "meter": "Multi-master", "fallback_usd": 150, "note": "réplica adicional"},
    "enable backup": {"service": "Backup", "meter": "LRS", "fallback_usd": 20, "note": "backup habilitado"},
    "private endpoint": {"service": None, "meter": None, "fallback_usd": 10, "note": "~$0.01/h por endpoint"},
    "private link": {"service": None, "meter": None, "fallback_usd": 10, "note": "~$0.01/h por endpoint"},
    "nat gateway": {"service": "NAT Gateway", "meter": "Standard", "fallback_usd": 45, "note": "~$0.045/h + dados"},
    "availability zone": {"service": None, "meter": None, "fallback_usd": 0, "note": "premium incluso em alguns SKUs"},
    "zone redundant": {"service": "Storage", "meter": "ZRS", "fallback_usd": 5, "note": "storage ZRS vs LRS"},
    "premium tier": {"service": "Storage", "meter": "Premium", "fallback_usd": 30, "note": "tier Premium"},
    "enable soft delete": {"service": None, "meter": None, "fallback_usd": 5, "note": "retenção adicional"},
    "application gateway": {"service": "Application Gateway", "meter": "Basic", "fallback_usd": 20, "note": "por instância/mês"},
    "firewall": {"service": "Azure Firewall", "meter": "Firewall", "fallback_usd": 900, "note": "~$1.25/h mínimo"},
    "ddos protection": {"service": "Azure DDoS Protection", "meter": "DDoS", "fallback_usd": 2944, "note": "plano DDoS Standard"},
    "key vault": {"service": "Key Vault", "meter": "Operations", "fallback_usd": 5, "note": "estimativa operações"},
    "log analytics": {"service": "Log Analytics", "meter": "Data Ingestion", "fallback_usd": 100, "note": "por GB ingerido"},
    "waf": {"service": "Application Gateway", "meter": "WAF", "fallback_usd": 350, "note": "WAF v2"},
}

_RETAIL_PRICES_CACHE = {}  # cache in-memory para evitar chamadas repetidas

def fetch_implementation_cost(title: str, region: str = "eastus2") -> dict | None:
    """
    Busca preço estimado na Azure Retail Prices API.
    Retorna { "cost_month": float, "note": str, "confidence": str } ou None.
    """
    global _RETAIL_PRICES_CACHE
    t = (title or "").lower()
    matched = None
    for pat, spec in COST_INCREASE_PATTERNS.items():
        if pat in t:
            matched = spec
            break
    if not matched:
        return None
    
    # Se não temos serviço para consultar, usa fallback
    if not matched.get("service"):
        return {"cost_month": matched["fallback_usd"], "note": matched["note"], "confidence": "estimado"}
    
    cache_key = f"{matched['service']}|{region}"
    if cache_key in _RETAIL_PRICES_CACHE:
        cached = _RETAIL_PRICES_CACHE[cache_key]
        if cached is not None:
            return {"cost_month": cached, "note": matched["note"], "confidence": "API"}
        # Cache negativo - usa fallback
        return {"cost_month": matched["fallback_usd"], "note": matched["note"], "confidence": "estimado"}
    
    # Query Azure Retail Prices API (unauthenticated)
    try:
        base_url = "https://prices.azure.com/api/retail/prices"
        svc = matched["service"]
        query = f"serviceName eq '{svc}' and armRegionName eq '{region}' and priceType eq 'Consumption'"
        if matched.get("meter"):
            query += f" and contains(meterName, '{matched['meter']}')"
        url = f"{base_url}?$filter={urllib.parse.quote(query)}&$top=10"
        
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        
        items = data.get("Items", [])
        if not items:
            _RETAIL_PRICES_CACHE[cache_key] = None
            # Usa fallback quando API não retorna dados
            return {"cost_month": matched["fallback_usd"], "note": matched["note"], "confidence": "estimado"}
        
        # Pega o preço (unitPrice em USD/hora ou USD/unidade)
        # Assumimos 730 horas/mês para recursos por hora
        price = items[0].get("retailPrice") or items[0].get("unitPrice") or 0
        unit = items[0].get("unitOfMeasure", "").lower()
        
        # Converte para custo mensal
        if "hour" in unit:
            cost_month = price * 730  # ~30.4 dias * 24h
        elif "month" in unit:
            cost_month = price
        elif "gb" in unit or "tb" in unit:
            cost_month = price * 100  # estimativa 100 GB/mês
        else:
            cost_month = price * 730  # assume por hora como fallback
        
        _RETAIL_PRICES_CACHE[cache_key] = cost_month
        return {"cost_month": cost_month, "note": matched["note"], "confidence": "API"}
    except Exception as e:
        print(f"  [pricing] lookup falhou para '{svc}': {e}", file=sys.stderr)
        _RETAIL_PRICES_CACHE[cache_key] = None
        return {"cost_month": matched["fallback_usd"], "note": matched["note"], "confidence": "estimado"}

# =============================================================================
# helpers
# =============================================================================
def as_list(x):
    if x is None:
        return []
    if isinstance(x, dict):
        v = x.get("value")
        return v if isinstance(v, list) else []   # resposta ARM de erro ({} ou {error:...}) → vazio
    if isinstance(x, list):
        return x
    return [x]

def prop(obj, path, default=None):
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur if cur is not None else default

def esc(s):
    return html.escape("" if s is None else str(s))

def load_config():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(8):
        cand = os.path.join(d, "config.json")
        if os.path.isfile(cand):
            try:
                with open(cand, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return {}

# =============================================================================
# Collector (Modo A) — ARM REST via `az rest`
# =============================================================================
def run_arm(base, path, api, extra_query=None):
    url = f"{base}{path}?api-version={api}"
    if extra_query:
        url += f"&{extra_query}"
    try:
        out = subprocess.run(
            [AZ, "rest", "--method", "get", "--url", url, "-o", "json"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        if out.returncode != 0:
            print(f"  [arm] {path}: {out.stderr.strip()[:180]}", file=sys.stderr)
            return {}
        return json.loads(out.stdout or "{}")
    except (subprocess.SubprocessError, json.JSONDecodeError) as e:
        print(f"  [arm] {path}: exceção {e}", file=sys.stderr)
        return {}

def collect_live(q, sub, rg):
    eps = q["collector"]["arm"]["endpoints"]
    base = q["collector"]["arm"]["base"]
    def fetch(key):
        ep = eps[key]
        path = ep["path"].replace("{sub}", sub).replace("{rg}", rg)
        return run_arm(base, path, ep["api"], ep.get("query"))
    raw = {
        "advisor_recommendations": fetch("advisor_recommendations"),
        "resource_inventory": fetch("resource_inventory"),
        "mdc_assessments": fetch("mdc_assessments"),
        "mdc_secure_score": fetch("mdc_secure_score"),
        "mdc_secure_score_controls": fetch("mdc_secure_score_controls"),
        "mcsb_compliance_standards": fetch("mcsb_compliance_standards"),
    }
    # Controles do MCSB: descobre o nome do standard (atual/legado) e busca seus controles.
    std_name = _pick_mcsb_standard(raw.get("mcsb_compliance_standards"), q.get("mcsb_standard_names", []))
    if std_name:
        ep = eps["mcsb_compliance_controls"]
        path = ep["path"].replace("{sub}", sub).replace("{standard}", std_name)
        raw["mcsb_compliance_controls"] = run_arm(base, path, ep["api"])
        raw["_mcsb_standard_name"] = std_name
    else:
        raw["mcsb_compliance_controls"] = {}
    return raw

# =============================================================================
# Collector (Modo C) — Azure Resource Graph (tenant-wide). 1 query/dataset
# cobrindo TODAS as subscriptions que a identidade lê (ou um conjunto/MG).
# Mesma base do ESA (securityresources/advisorresources). 100% read-only.
# =============================================================================
ARG_URL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"

# Projeções SLIM: reconstroem `properties` SÓ com os campos que os parsers usam (via pack()),
# preservando a forma aninhada (parsers inalterados) e dropando o bloat (ex.: additionalData
# gigante dos assessments de CVE de container). Mantém o payload bem abaixo do limite de 2 MB.
ARG_QUERIES = {
    "subscriptions":
        'resourcecontainers | where type == "microsoft.resources/subscriptions" '
        '| project subscriptionId, name = tostring(properties.displayName)',
    "advisor_recommendations":
        'advisorresources | where type == "microsoft.advisor/recommendations" '
        '| project id, subscriptionId, properties = pack('
        '"category", properties.category, '
        '"impact", properties.impact, '
        '"shortDescription", pack("problem", properties.shortDescription.problem, "solution", properties.shortDescription.solution), '
        '"extendedProperties", pack("savingsAmount", properties.extendedProperties.savingsAmount, "annualSavingsAmount", properties.extendedProperties.annualSavingsAmount), '
        '"resourceMetadata", pack("resourceId", properties.resourceMetadata.resourceId))',
    "mdc_assessments":
        'securityresources | where type == "microsoft.security/assessments" '
        '| project id, name, subscriptionId, properties = pack('
        '"displayName", properties.displayName, '
        '"owner", properties.owner, '
        '"status", pack("code", properties.status.code, "cause", properties.status.cause), '
        '"resourceDetails", pack("Id", properties.resourceDetails.Id, "ResourceId", properties.resourceDetails.ResourceId), '
        '"links", pack("azurePortal", properties.links.azurePortal), '
        '"metadata", pack("severity", properties.metadata.severity, "categories", properties.metadata.categories, '
        '"remediationDescription", properties.metadata.remediationDescription, '
        '"tactics", properties.metadata.tactics, "techniques", properties.metadata.techniques))',
    "mdc_secure_score_controls":
        'securityresources | where type == "microsoft.security/securescores/securescorecontrols" '
        '| where id matches regex "/secureScores/ascScore/" '
        '| project id, name, subscriptionId, properties = pack('
        '"displayName", properties.displayName, '
        '"score", pack("current", properties.score.current, "max", properties.score.max), '
        '"healthyResourceCount", properties.healthyResourceCount, '
        '"unhealthyResourceCount", properties.unhealthyResourceCount, '
        '"notApplicableResourceCount", properties.notApplicableResourceCount, '
        '"definition", pack("properties", pack("assessmentDefinitions", properties.definition.properties.assessmentDefinitions)))',
    "mdc_secure_score":
        'securityresources | where type == "microsoft.security/securescores" '
        '| where name == "ascScore" | project id, name, subscriptionId, '
        'properties = pack("score", pack("current", properties.score.current, "max", properties.score.max, "percentage", properties.score.percentage))',
    "mcsb_compliance_standards":
        'securityresources | where type == "microsoft.security/regulatorycompliancestandards" '
        '| project id, name, subscriptionId, properties = pack('
        '"state", properties.state, "passedControls", properties.passedControls, '
        '"failedControls", properties.failedControls, "skippedControls", properties.skippedControls, '
        '"unsupportedControls", properties.unsupportedControls)',
    "mcsb_compliance_controls":
        'securityresources '
        '| where type == "microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols" '
        '| where id has "Microsoft-cloud-security-benchmark" or id has "Azure-Security-Benchmark" '
        '| project id, name, subscriptionId, properties = pack('
        '"state", properties.state, "description", properties.description, '
        '"passedAssessments", properties.passedAssessments, "failedAssessments", properties.failedAssessments, '
        '"skippedAssessments", properties.skippedAssessments, '
        '"links", pack("azurePortal", properties.links.azurePortal))',
    "devops_findings":
        'securityresources '
        '| where type =~ "microsoft.security/assessments/subassessments" '
        '| where id has "githubowners" or id has "/devops/" or id has "/securityconnectors/" '
        '| project id, name, subscriptionId, properties = pack('
        '"displayName", properties.displayName, '
        '"category", properties.category, '
        '"severity", properties.status.severity, '
        '"code", properties.status.code, '
        '"remediation", properties.remediation, '
        '"links", pack("azurePortal", properties.links.azurePortal))',
}

def run_arg(query, subscriptions=None):
    """Executa 1 query no Azure Resource Graph via `az rest` POST, paginando por $skipToken."""
    rows = []
    skip_token = None
    page = 0
    while True:
        body = {"query": query, "options": {"resultFormat": "objectArray", "$top": 1000}}
        if subscriptions:
            body["subscriptions"] = subscriptions
        if skip_token:
            body["options"]["$skipToken"] = skip_token
        tmp = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                json.dump(body, f)
                tmp = f.name
            out = subprocess.run(
                [AZ, "rest", "--method", "post", "--url", ARG_URL, "--body", f"@{tmp}", "-o", "json"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
            if out.returncode != 0:
                print(f"  [arg] {query[:48]}…: {out.stderr.strip()[:180]}", file=sys.stderr)
                break
            data = json.loads(out.stdout or "{}")
        except (subprocess.SubprocessError, json.JSONDecodeError) as e:
            print(f"  [arg] {query[:48]}…: exceção {e}", file=sys.stderr)
            break
        finally:
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        rows.extend(data.get("data", []) or [])
        skip_token = data.get("$skipToken")
        page += 1
        if not skip_token or page >= 30:   # teto de segurança: 30k linhas/dataset
            break
    return {"value": rows}

def collect_tenant(q, subscriptions=None):
    """Coleta tenant-wide (ou subscriptions específicas) via Azure Resource Graph."""
    raw = {}
    for key, kql in ARG_QUERIES.items():
        raw[key] = run_arg(kql, subscriptions)
    raw["_mcsb_standard_name"] = _pick_mcsb_standard(
        raw.get("mcsb_compliance_standards"), q.get("mcsb_standard_names", []))
    return raw

def _pick_mcsb_standard(standards_data, preferred_names):
    """Acha o nome do standard MCSB na lista de regulatoryComplianceStandards."""
    rows = as_list(standards_data)
    names = {str(r.get("name", "")): r for r in rows}
    # 1) match exato pelos nomes conhecidos (atual + legado)
    for pref in (preferred_names or []):
        if pref in names:
            return pref
    # 2) match por substring (case-insensitive) — cobre variações de versão
    for nm in names:
        low = nm.lower().replace("-", " ")
        if "cloud security benchmark" in low or "azure security benchmark" in low:
            return nm
    return ""

# =============================================================================
# Risk engine
# =============================================================================
_ORDER = {"safe": 0, "low": 1, "medium": 2, "high": 3}

def classify_risk(text, risk_baseline):
    t = (text or "").lower()
    for level in ("high", "medium", "low", "safe"):   # mais severo primeiro p/ desempate
        for pat in risk_baseline.get(level, []) or []:
            if pat.lower() in t:
                return level
    return "low"  # default: mudanças de config são baixo-disrupção

def _rg_of(resource_id):
    rid = (resource_id or "").lower()
    marker = "/resourcegroups/"
    if marker in rid:
        tail = rid.split(marker, 1)[1]
        return tail.split("/", 1)[0]
    return ""

def _sub_of(resource_id):
    rid = (resource_id or "").lower()
    marker = "/subscriptions/"
    if marker in rid:
        tail = rid.split(marker, 1)[1]
        return tail.split("/", 1)[0]
    return ""

def _devops_info(resource_id):
    """
    Detecta recurso de DevOps security (GitHub/Azure DevOps/GitLab) a partir do resourceId
    do connector e devolve (provider, repo). Caso contrário (None, "").
    Ex.: .../securityConnectors/<c>/devops/default/gitHubOwners/<org>/repos/<repo>
    """
    rid = (resource_id or "")
    low = rid.lower()
    if "/securityconnectors/" not in low and "/devops/" not in low:
        return (None, "")
    if "githubowners" in low:
        provider = "GitHub"
    elif "azuredevopsorgs" in low or "azuredevops" in low:
        provider = "Azure DevOps"
    elif "gitlab" in low:
        provider = "GitLab"
    else:
        provider = "DevOps"
    repo = ""
    parts = rid.split("/")
    for marker in ("repos", "repositories", "projects"):
        if marker in [p.lower() for p in parts]:
            idx = [p.lower() for p in parts].index(marker)
            if idx + 1 < len(parts):
                repo = parts[idx + 1]
                break
    return (provider, repo)

# =============================================================================
# Parsers — Advisor + Defender for Cloud → itens unificados
# =============================================================================
def _portal_resource_link(resource_id):
    """Deep link determinístico para o recurso no Azure Portal (a partir do resourceId)."""
    rid = (resource_id or "").strip()
    if not rid or not rid.lower().startswith("/subscriptions/"):
        return ""
    return f"https://portal.azure.com/#@/resource{rid}/overview"

def build_resource_map(inventory):
    rmap = {}
    for r in as_list(inventory):
        rid = str(r.get("id", "")).lower()
        if rid:
            rmap[rid] = {"name": r.get("name"), "type": r.get("type"), "location": r.get("location")}
    return rmap

def _enrich(item, resource_id, risk, rmap, q, region="eastus2", sub_names=None):
    res = rmap.get(str(resource_id or "").lower(), {})
    item["resource_id"] = resource_id or ""
    item["resource_name"] = res.get("name") or (resource_id.split("/")[-1] if resource_id else "—")
    item["resource_type"] = res.get("type") or "—"
    # Escopo (p/ filtros tenant-wide): subscription + resource group do resourceId
    sub_id = _sub_of(resource_id)
    item["subscription_id"] = sub_id
    item["subscription_name"] = (sub_names or {}).get(sub_id, sub_id[:8] if sub_id else "—")
    item["resource_group"] = _rg_of(resource_id) or "—"
    # DevOps security (GitHub/ADO/GitLab) — recomendações que NÃO afetam o secure score
    dp_provider, dp_repo = _devops_info(resource_id)
    if dp_provider:
        item["devops_provider"] = dp_provider
        item["devops_repo"] = dp_repo or "(org)"
    # Link oficial da recomendação (MDC fornece em links.azurePortal) tem prioridade;
    # senão cai p/ deep link determinístico do recurso.
    item["portal_link"] = item.get("rec_link") or _portal_resource_link(resource_id)
    loc = res.get("location") or region
    amps = []
    if resource_id and not res:
        amps.append("Recurso não encontrado no inventário — verificar manualmente")
    item["amplifiers"] = amps
    # Cascata/validação só fazem sentido p/ recursos de infra (não p/ repos DevOps).
    if not dp_provider and resource_id and risk in ("low", "medium", "high"):
        item["cascade"] = q.get("cascade_template", "").replace("{resource}", item["resource_name"])
    if not dp_provider and resource_id and risk in ("medium", "high"):
        item["validation"] = [s.replace("{resource}", item["resource_name"]) for s in (q.get("validation_steps") or [])]
    
    # Estimar custo de implementação (se aplicável)
    impl_cost = fetch_implementation_cost(item.get("title", ""), loc)
    if impl_cost and impl_cost["cost_month"] > 0:
        item["cost_increase"] = f"+US$ {impl_cost['cost_month']:,.2f}/mês ({impl_cost['note']}, {impl_cost['confidence']})"
        item["cost_increase_raw"] = impl_cost["cost_month"]
    return item

def analyze_advisor(data, rmap, q, category, sub_names=None):
    rb = q.get("risk_baseline", {})
    out = []
    for r in as_list(data):
        props = r.get("properties", {}) or {}
        cat = props.get("category", "")
        if category != "all" and cat.lower() != category.lower():
            continue
        title = prop(props, "shortDescription.problem", "—")
        risk = classify_risk(title, rb)
        ext = props.get("extendedProperties", {}) or {}
        savings = ext.get("savingsAmount") or ext.get("annualSavingsAmount")
        item = {
            "source": "Advisor",
            "title": title,
            "remediation": prop(props, "shortDescription.solution", ""),
            "category": cat,
            "priority": props.get("impact", "Medium"),
            "risk": risk,
            "cost_delta": (f"−US$ {savings}/ano" if savings else None),
        }
        # resourceId pode vir de resourceMetadata.resourceId (ARM) ou do id da row (ARG)
        rid = prop(props, "resourceMetadata.resourceId", "") or str(r.get("id", "") or "")
        out.append(_enrich(item, rid, risk, rmap, q, sub_names=sub_names))
    return out

def analyze_mdc(data, rmap, q, rg, include_healthy, sub_names=None):
    rb = q.get("risk_baseline", {})
    rg = (rg or "").lower()
    out = []
    for a in as_list(data):
        props = a.get("properties", {}) or {}
        code = prop(props, "status.code", "Unknown")
        if not include_healthy and code.lower() != "unhealthy":
            continue
        rid = prop(props, "resourceDetails.Id") or prop(props, "resourceDetails.ResourceId") or ""
        item_rg = _rg_of(rid)
        # Se um RG-alvo foi informado, mantém só ele OU assessments de nível subscription.
        # Tenant-wide (rg vazio) → mantém tudo.
        if rg and item_rg and item_rg != rg:
            continue
        name = props.get("displayName", "—")
        risk = classify_risk(name, rb)
        meta = props.get("metadata", {}) or {}
        # Link OFICIAL da recomendação (Defender for Cloud fornece em links.azurePortal)
        portal = prop(props, "links.azurePortal", "") or ""
        if portal and not portal.lower().startswith("http"):
            portal = "https://" + portal
        # MITRE ATT&CK — assessment já carrega tactics/techniques na metadata
        tactics = meta.get("tactics") if isinstance(meta.get("tactics"), list) else ([meta["tactics"]] if meta.get("tactics") else [])
        techniques = meta.get("techniques") if isinstance(meta.get("techniques"), list) else ([meta["techniques"]] if meta.get("techniques") else [])
        item = {
            "source": "Defender for Cloud",
            "title": name,
            "remediation": meta.get("remediationDescription", "") or "",
            "category": ", ".join(meta.get("categories", []) or []) if isinstance(meta.get("categories"), list) else (meta.get("categories") or ""),
            "priority": meta.get("severity", "Unknown"),
            "risk": risk,
            "cost_delta": None,
            "scope": "subscription" if not item_rg else "resource",
            "assessment_key": str(a.get("name", "")).lower(),
            "rec_link": portal,
            "tactics": [t for t in tactics if t],
            "techniques": [t for t in techniques if t],
            "owner": prop(props, "owner", "") or "",
        }
        out.append(_enrich(item, rid, risk, rmap, q, sub_names=sub_names))
    return out

def parse_secure_score(data):
    rows = as_list(data)
    if not rows:
        return None
    chosen = next((r for r in rows if str(r.get("name", "")).lower() == "ascscore"), rows[0])
    p = chosen.get("properties", {}) or {}
    score = p.get("score", {}) or {}
    pct = score.get("percentage")
    if pct is not None:
        return round(float(pct) * 100, 1) if pct <= 1 else round(float(pct), 1)
    cur, mx = score.get("current"), score.get("max")
    if cur is not None and mx:
        return round(100.0 * float(cur) / float(mx), 1)
    return None

def parse_secure_score_controls(data):
    """
    Processa secureScoreControls (com $expand=definition), AGRUPANDO POR SUBSCRIPTION
    (tenant-wide). Para cada sub: current/max/potential points + mapa assessment_guid→controle.
    Fórmula MCSB: score_por_recurso = max / (saudáveis + não-saudáveis);
                  potencial do controle = score_por_recurso × não-saudáveis.
    Retorna None se Defender for Cloud não estiver habilitado (degrada para n/a).
    """
    controls = as_list(data)
    if not controls:
        return None
    by_sub = {}
    for c in controls:
        p = c.get("properties", {}) or {}
        sub_id = str(c.get("subscriptionId") or _sub_of(c.get("id", "")) or "").lower()
        bucket = by_sub.setdefault(sub_id, {"a2c": {}, "current_total": 0.0, "max_total": 0.0, "potential_total": 0.0})
        score = p.get("score", {}) or {}
        cur = float(score.get("current", 0) or 0)
        mx = float(score.get("max", 0) or 0)
        healthy = int(p.get("healthyResourceCount", 0) or 0)
        unhealthy = int(p.get("unhealthyResourceCount", 0) or 0)
        total_res = healthy + unhealthy
        per_resource = (mx / total_res) if total_res > 0 else 0.0
        potential = per_resource * unhealthy
        ctrl = {
            "name": p.get("displayName", "—"),
            "max": mx, "current": cur, "potential": potential,
            "unhealthy": unhealthy, "healthy": healthy, "per_resource": per_resource,
        }
        bucket["current_total"] += cur
        bucket["max_total"] += mx
        bucket["potential_total"] += potential
        defn = (p.get("definition", {}) or {}).get("properties", {}) or {}
        for ad in defn.get("assessmentDefinitions", []) or []:
            guid = str(ad.get("id", "")).rstrip("/").split("/")[-1].lower()
            if guid:
                bucket["a2c"][guid] = ctrl

    # Agregado tenant-wide (soma de pontos entre subs)
    cur_all = sum(b["current_total"] for b in by_sub.values())
    max_all = sum(b["max_total"] for b in by_sub.values())
    pot_all = sum(b["potential_total"] for b in by_sub.values())
    if max_all <= 0:
        return None
    current_pct = round(100.0 * cur_all / max_all, 1)
    potential_pct = round(100.0 * min(cur_all + pot_all, max_all) / max_all, 1)
    return {
        "by_sub": by_sub,
        "current_pct": current_pct,
        "potential_pct": potential_pct,
        "delta_pct": round(potential_pct - current_pct, 1),
        "max_total": max_all,
        "current_total": cur_all,
        "potential_points": pot_all,
    }

def parse_mcsb_compliance(standards_data, controls_data, std_name, preferred_names):
    """
    Pilar MCSB (ESA): postura de compliance contra o Microsoft Cloud Security Benchmark,
    AGRUPANDO POR SUBSCRIPTION (tenant-wide). Headline por sub = passed/failed/skipped/
    unsupported. Detalhe = controles FAILED (com subscriptionId p/ filtro).
    Retorna None se o standard MCSB não estiver atribuído (degrada).
    """
    standards = as_list(standards_data)
    if not standards:
        return None
    wanted = set([std_name] if std_name else []) | set(preferred_names or [])

    def _is_mcsb(nm):
        if nm in wanted:
            return True
        low = str(nm).lower().replace("-", " ")
        return "cloud security benchmark" in low or "azure security benchmark" in low

    by_sub = {}
    for s in standards:
        nm = str(s.get("name", ""))
        if not _is_mcsb(nm):
            continue
        sub_id = str(s.get("subscriptionId") or _sub_of(s.get("id", "")) or "").lower()
        p = s.get("properties", {}) or {}
        by_sub[sub_id] = {
            "standard_name": nm,
            "state": str(p.get("state", "")),
            "passed": int(p.get("passedControls", 0) or 0),
            "failed": int(p.get("failedControls", 0) or 0),
            "skipped": int(p.get("skippedControls", 0) or 0),
            "unsupported": int(p.get("unsupportedControls", 0) or 0),
        }
    if not by_sub:
        return None

    # Controles em falha (detalhe) — agrega por controle, guarda subscriptionId p/ filtro
    failing = []
    for c in as_list(controls_data):
        cp = c.get("properties", {}) or {}
        if str(cp.get("state", "")).lower() != "failed":
            continue
        sub_id = str(c.get("subscriptionId") or _sub_of(c.get("id", "")) or "").lower()
        failing.append({
            "id": str(c.get("name", "")),
            "name": cp.get("description", "") or str(c.get("name", "")),
            "failed": int(cp.get("failedAssessments", 0) or 0),
            "passed": int(cp.get("passedAssessments", 0) or 0),
            "skipped": int(cp.get("skippedAssessments", 0) or 0),
            "link": prop(cp, "links.azurePortal", "") or "",
            "subscription_id": sub_id,
        })
    failing.sort(key=lambda x: x["failed"], reverse=True)

    passed = sum(b["passed"] for b in by_sub.values())
    failed = sum(b["failed"] for b in by_sub.values())
    skipped = sum(b["skipped"] for b in by_sub.values())
    unsupported = sum(b["unsupported"] for b in by_sub.values())
    assessable = passed + failed
    compliance_pct = round(100.0 * passed / assessable, 1) if assessable > 0 else None
    # nome representativo do standard (o mais comum)
    std = next(iter(by_sub.values()))["standard_name"]
    state = "Failed" if failed > 0 else (next(iter(by_sub.values()))["state"] or "Passed")
    return {
        "by_sub": by_sub,
        "standard_name": std,
        "state": state,
        "passed": passed, "failed": failed, "skipped": skipped, "unsupported": unsupported,
        "compliance_pct": compliance_pct,
        "failing_controls": failing,
    }

def analyze_devops_findings(data, sub_names=None):
    """
    Pilar DevOps Remediation: ingere os FINDINGS granulares (subassessments) do Defender
    DevOps (GitHub/ADO/GitLab) — CVE de dependência, code scanning, IaC, secrets — agregados
    por repositório × severidade × categoria. Distinto das recs de POSTURA ("should have X").
    Retorna None se não houver findings (degrada).
    """
    rows = as_list(data)
    if not rows:
        return None
    _SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    findings = []
    for r in rows:
        p = r.get("properties", {}) or {}
        # severity/code podem vir flat (query ARG slim) OU aninhados em status.* (prefetch cru)
        code = p.get("code") or prop(p, "status.code", "")
        if str(code).lower() == "healthy":
            continue  # só os não-resolvidos
        rid = str(r.get("id", "") or "")
        provider, repo = _devops_info(rid)
        if not provider:
            continue
        sev_raw = p.get("severity") or prop(p, "status.severity", "") or "—"
        sev = str(sev_raw).capitalize()
        cat = str(p.get("category", "") or "—")
        findings.append({
            "repo": repo or "(org)",
            "provider": provider,
            "severity": sev,
            "category": cat,
            "finding": p.get("displayName", "—"),
            "remediation": p.get("remediation", "") or "",
            "link": prop(p, "links.azurePortal", "") or "",
            "subscription_id": str(r.get("subscriptionId") or _sub_of(rid) or "").lower(),
        })
    if not findings:
        return None
    by_sev, by_cat, by_repo, by_repo_sev = {}, {}, {}, {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
        by_repo[f["repo"]] = by_repo.get(f["repo"], 0) + 1
        rs = by_repo_sev.setdefault(f["repo"], {})
        rs[f["severity"]] = rs.get(f["severity"], 0) + 1
    # ordena severidades canônico
    sev_order = sorted(by_sev.items(), key=lambda kv: _SEV.get(kv[0].lower(), -1), reverse=True)
    sevs = [s for s, _ in sev_order]
    # ordena repos por RISCO: Critical+High primeiro, total como desempate
    def _repo_risk(repo):
        rs = by_repo_sev.get(repo, {})
        return (rs.get("Critical", 0) + rs.get("High", 0), by_repo.get(repo, 0))
    repos_ranked = sorted(by_repo.keys(), key=_repo_risk, reverse=True)
    # matriz repo × severidade (top 20 repos por risco)
    matrix = []
    for repo in repos_ranked[:20]:
        rs = by_repo_sev.get(repo, {})
        matrix.append({"repo": repo, "total": by_repo.get(repo, 0),
                       "by_sev": {s: rs.get(s, 0) for s in sevs}})
    # findings ordenados por severidade (Critical→) p/ tabela de remediação por finding
    top_findings = sorted(findings, key=lambda f: _SEV.get(f["severity"].lower(), -1), reverse=True)
    return {
        "total": len(findings),
        "by_severity": dict(sev_order),
        "by_category": by_cat,
        "by_repo": {r: by_repo[r] for r in repos_ranked},
        "sev_order": sevs,
        "matrix": matrix,
        "findings": findings,
        "top_findings": top_findings,
    }

# =============================================================================
# Build context
# =============================================================================
def build_sub_names(raw):
    """Mapa subscriptionId(lower) → nome amigável. ARG popula raw['subscriptions']."""
    names = {}
    for s in as_list(raw.get("subscriptions")):
        sid = str(s.get("subscriptionId") or s.get("id", "")).lower()
        sid = _sub_of(sid) or sid
        nm = s.get("displayName") or s.get("name") or s.get("subscriptionName")
        if sid and nm:
            names[sid] = nm
    return names

def build_context(q, raw, params):
    sub_names = build_sub_names(raw)
    rmap = build_resource_map(raw.get("resource_inventory"))
    advisor = analyze_advisor(raw.get("advisor_recommendations"), rmap, q, params.get("category", "all"), sub_names)
    mdc = analyze_mdc(raw.get("mdc_assessments"), rmap, q, params.get("_rg", ""), params.get("include_healthy", False), sub_names)
    items = advisor + mdc

    # Secure score por controle (POR SUBSCRIPTION) → elevação + impacto por recomendação
    ss_controls = parse_secure_score_controls(raw.get("mdc_secure_score_controls"))
    if ss_controls:
        for it in mdc:
            bucket = ss_controls["by_sub"].get(it.get("subscription_id", ""))
            if not bucket:
                continue
            ctrl = bucket["a2c"].get(it.get("assessment_key", ""))
            mx = bucket["max_total"]
            if ctrl and mx > 0:
                # impacto de remediar ESTE recurso = score_por_recurso / max-da-sub × 100
                impact_pct = round(100.0 * ctrl["per_resource"] / mx, 2)
                it["score_impact_pct"] = impact_pct
                it["score_control"] = ctrl["name"]
                it["score_impact_label"] = f"+{impact_pct:.2f}% SS" if impact_pct >= 0.01 else "<0.01% SS"

    phases = {"safe": [], "low": [], "medium": [], "high": []}
    for it in items:
        phases[it["risk"]].append(it)
    # savings total (economia por ano)
    savings_total = 0.0
    for it in advisor:
        cd = it.get("cost_delta")
        if cd:
            digits = "".join(ch for ch in cd if ch.isdigit() or ch == ".")
            try:
                savings_total += float(digits)
            except ValueError:
                pass
    # custo de implementação total (aumento por mês)
    cost_increase_total = 0.0
    for it in items:
        ci = it.get("cost_increase_raw")
        if ci:
            cost_increase_total += ci

    # secure score: atual + potencial (agregado tenant-wide via controles).
    secure_score = ss_controls["current_pct"] if ss_controls else parse_secure_score(raw.get("mdc_secure_score"))
    secure_score_potential = ss_controls["potential_pct"] if ss_controls else None
    secure_score_delta = None
    if secure_score is not None and secure_score_potential is not None:
        secure_score_delta = round(max(secure_score_potential - secure_score, 0.0), 1)

    # Pilar MCSB (compliance regulatório) — ESA, por subscription
    mcsb = parse_mcsb_compliance(
        raw.get("mcsb_compliance_standards"),
        raw.get("mcsb_compliance_controls"),
        raw.get("_mcsb_standard_name", ""),
        q.get("mcsb_standard_names", []),
    )

    # Pilar DevOps Remediation — findings granulares (subassessments) do Defender DevOps
    devops = analyze_devops_findings(raw.get("devops_findings"), sub_names)

    # Mapa POR SUBSCRIPTION (p/ recalcular SS + MCSB sob filtro de subscription no JS)
    subs = {}
    sub_ids = set(it.get("subscription_id") for it in items if it.get("subscription_id"))
    if ss_controls:
        sub_ids |= set(ss_controls["by_sub"].keys())
    if mcsb:
        sub_ids |= set(mcsb["by_sub"].keys())
    for sid in sub_ids:
        entry = {"name": sub_names.get(sid, sid[:8] if sid else "—")}
        b = ss_controls["by_sub"].get(sid) if ss_controls else None
        if b:
            entry["ss_current_points"] = round(b["current_total"], 3)
            entry["ss_max_points"] = round(b["max_total"], 3)
            entry["ss_potential_points"] = round(min(b["current_total"] + b["potential_total"], b["max_total"]), 3)
        m = mcsb["by_sub"].get(sid) if mcsb else None
        if m:
            entry["mcsb"] = {"passed": m["passed"], "failed": m["failed"],
                             "skipped": m["skipped"], "unsupported": m["unsupported"]}
        subs[sid] = entry

    return {
        "items": items, "advisor": advisor, "mdc": mdc, "phases": phases,
        "secure_score": secure_score,
        "secure_score_potential": secure_score_potential,
        "secure_score_delta": secure_score_delta,
        "mcsb": mcsb,
        "subs": subs,
        "devops": devops,
        "scope_label": params.get("_scope_label", ""),
        "resources_in_scope": len(rmap) or len({it.get("resource_id") for it in items if it.get("resource_id")}),
        "savings_total": savings_total,
        "cost_increase_total": cost_increase_total,
        "generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
    }

# =============================================================================
# RENDER
# =============================================================================
def _src_badge(src):
    c = "#7cd0ff" if src == "Advisor" else "#c9a7ff"
    return f"<span style='color:{c};font-weight:700'>{esc(src)}</span>"

def _savings_raw(cd):
    if not cd:
        return 0.0
    digits = "".join(ch for ch in cd if ch.isdigit() or ch == ".")
    try:
        return float(digits)
    except ValueError:
        return 0.0

_SEV_COLOR = {"Critical": "#ff4d4d", "High": "#ff6b6b", "Medium": "#ffd96b", "Low": "#7cd0ff", "Informational": "#9fb0c8"}

def _render_devops_section(devops):
    """Seção estática 🐙 DevOps Remediation: severidade + matriz repo×severidade + categorias."""
    if not devops:
        return ""
    sevs = devops["sev_order"]
    # KPIs de severidade
    kpis = ""
    for s in sevs:
        c = _SEV_COLOR.get(s, "#9fb0c8")
        kpis += (f"<div class='kpi'><div class='n' style='color:{c}'>{devops['by_severity'].get(s,0)}</div>"
                 f"<div class='l'>{esc(s)}</div></div>")
    kpis = (f"<div class='kpi'><div class='n' style='color:#7ee2a8'>{devops['total']}</div>"
            f"<div class='l'>🐙 findings</div></div>") + kpis
    # categorias
    cats = " · ".join(f"{esc(k)}: <b>{v}</b>" for k, v in sorted(devops["by_category"].items(), key=lambda kv: kv[1], reverse=True))
    # matriz repo × severidade
    head_cells = "".join(f"<th>{esc(s)}</th>" for s in sevs)
    rows_html = ""
    for m in devops["matrix"]:
        cells = ""
        for s in sevs:
            v = m["by_sev"].get(s, 0)
            col = _SEV_COLOR.get(s, "#9fb0c8") if v else "#3a4a63"
            cells += f"<td style='color:{col};font-weight:{700 if v else 400}'>{v or '·'}</td>"
        rows_html += (f"<tr><td class='mono'>🐙 {esc(m['repo'])}</td>"
                      f"<td style='font-weight:700'>{m['total']}</td>{cells}</tr>")
    table = (f"<table style='margin-top:10px'><tr><th>Repositório</th><th>Total</th>{head_cells}</tr>"
             f"{rows_html}</table>")
    # tabela de findings com remediação + link oficial por finding (top por severidade)
    det = ""
    tf = devops.get("top_findings") or []
    LIMIT = 25
    for f in tf[:LIMIT]:
        s = f.get("severity", "—")
        c = _SEV_COLOR.get(s, "#9fb0c8")
        rem = esc(f.get("remediation", "") or "—")
        link = f.get("link", "") or ""
        link_html = (f"<a href='{esc(link)}' target='_blank' style='color:#7cd0ff'>Portal ↗</a>"
                     if link else "<span class='meta'>—</span>")
        det += (f"<tr><td style='color:{c};font-weight:700;white-space:nowrap'>{esc(s)}</td>"
                f"<td class='mono'>🐙 {esc(f.get('repo','—'))}</td>"
                f"<td>{esc(f.get('finding','—'))}</td>"
                f"<td class='meta'>{esc(f.get('category','—'))}</td>"
                f"<td class='meta'>{rem}</td>"
                f"<td style='white-space:nowrap'>{link_html}</td></tr>")
    more = ""
    if len(tf) > LIMIT:
        more = f"<div class='meta' style='margin-top:6px'>… +{len(tf) - LIMIT} findings (priorize Critical→High; veja o relatório completo).</div>"
    det_table = (
        "<h3 style='margin-top:16px'>🔧 Findings a corrigir <span class='meta'>· por severidade · remediação + link oficial</span></h3>"
        "<table><tr><th>Sev</th><th>Repositório</th><th>Finding</th><th>Categoria</th>"
        f"<th>Remediação</th><th>Link</th></tr>{det}</table>{more}") if det else ""
    return (
        "<div class='phase'><h3>🐙 DevOps Remediation — findings do GitHub/Defender DevOps "
        "<span class='meta'>· vulnerabilidades a corrigir (CVE/code/IaC/secret), não postura</span></h3>"
        "<div class='card'>"
        f"<div class='kpis' style='margin-bottom:10px'>{kpis}</div>"
        f"<div class='meta'>Por categoria: {cats}</div>"
        f"{table}"
        "<div class='meta' style='margin-top:8px'>Matriz ordenada por <b>Critical+High</b> (maior risco no topo) · "
        "dependency CVEs normalmente têm PR do Dependabot pronto p/ merge.</div>"
        f"{det_table}"
        "</div></div>")

# CSS + JS do relatório interativo (string normal, SEM f-string → não precisa escapar {}).
_REPORT_CSS = """
  body{margin:0;background:#0b0f17;color:#e7edf5;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:1180px;margin:0 auto;padding:24px}
  .hero{background:linear-gradient(135deg,#121a2b,#0d1422);border:1px solid #1e2a3f;border-radius:16px;padding:22px 24px;margin-bottom:14px}
  .hero h1{margin:0 0 10px;font-size:20px}
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px;margin-top:6px}
  .kpi{background:#0d1422;border:1px solid #1e2a3f;border-radius:10px;padding:10px;text-align:center}
  .kpi .n{font-size:20px;font-weight:800} .kpi .l{font-size:11px;color:#9fb0c8;margin-top:2px}
  h3{font-size:14px;margin:18px 0 8px}
  table{width:100%;border-collapse:collapse;font-size:13px;background:#0d1422;border:1px solid #1e2a3f;border-radius:10px;overflow:hidden}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #182337;vertical-align:top}
  th{background:#111a2b;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#9fb0c8}
  .mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
  .casc{color:#ffd96b;font-size:12px;margin-top:4px}
  .amp{color:#ff9f6b;font-size:12px;margin-top:3px}
  .mtags{margin-top:5px;font-size:11px;color:#9fb0c8}
  .mitre{display:inline-block;background:#2a1a3a;border:1px solid #4a2d6b;color:#c9a7ff;border-radius:5px;padding:1px 6px;margin:0 4px 2px 0;font-family:ui-monospace,Consolas,monospace;font-size:11px}
  .owner{color:#7cd0ff;font-size:11px;margin-top:4px}
  .devops{display:inline-block;background:#10261b;border:1px solid #1f5135;color:#7ee2a8;border-radius:5px;padding:1px 7px;margin-top:4px;font-size:11px}
  .phase{margin-bottom:14px} .meta{color:#9fb0c8;font-size:12px}
  .card{background:#0d1422;border:1px solid #1e2a3f;border-radius:12px;padding:14px}
  .filters{background:#0d1422;border:1px solid #1e2a3f;border-radius:12px;padding:12px 14px;margin-bottom:16px}
  .filters .frow{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
  .fbox{min-width:0}
  .flabel{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#9fb0c8;margin-bottom:5px;display:flex;justify-content:space-between}
  .fopts{max-height:120px;overflow:auto;background:#0b0f17;border:1px solid #1e2a3f;border-radius:8px;padding:6px 8px}
  .fopts label{display:flex;align-items:center;gap:6px;font-size:12px;padding:2px 0;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .fopts input{accent-color:#7cd0ff}
  .ftop{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:10px;flex-wrap:wrap}
  .btn{background:#16223a;border:1px solid #2a3c5a;color:#cfe0f5;border-radius:8px;padding:6px 12px;font-size:12px;cursor:pointer}
  .btn:hover{background:#1d2c49}
  @media(max-width:680px){.kpis{grid-template-columns:repeat(3,1fr)}}
"""

_REPORT_JS = """
const PHASES=["safe","low","medium","high"];
const PHMETA=DATA.phases_meta;
const DIMS=[["sub","Subscription"],["rg","Resource Group"],["source","Fonte"],["category","Categoria"],["risk","Risco / Fase"],["severity","Severidade"],["repo","Repositório DevOps"]];
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function val(it,dim){if(dim==="sub")return it.subscription_id;if(dim==="rg")return it.resource_group;if(dim==="source")return it.source;if(dim==="category")return it.category;if(dim==="risk")return it.risk;if(dim==="severity")return it.priority;if(dim==="repo")return it.devops_repo||"";return "";}
function label(dim,v){if(dim==="sub"){const s=DATA.subs[v];return (s&&s.name)?s.name:(v?v.slice(0,8):"—");}if(dim==="risk"){return (PHMETA[v]?PHMETA[v].emoji+" "+PHMETA[v].label:v);}return v;}
function uniq(dim){const set=new Set();DATA.items.forEach(it=>{const v=val(it,dim);if(v&&v!=="—")set.add(v);});if(dim==="sub"){Object.keys(DATA.subs||{}).forEach(s=>set.add(s));}return [...set].sort((a,b)=>label(dim,a).localeCompare(label(dim,b)));}
function buildFilters(){const root=document.getElementById("frow");DIMS.forEach(([dim,name])=>{const vals=uniq(dim);if(!vals.length)return;const box=document.createElement("div");box.className="fbox";let opts="";vals.forEach(v=>{opts+=`<label title="${esc(label(dim,v))}"><input type="checkbox" data-dim="${dim}" value="${esc(v)}">${esc(label(dim,v))}</label>`;});box.innerHTML=`<div class="flabel"><span>${esc(name)}</span><span class="meta">${vals.length}</span></div><div class="fopts">${opts}</div>`;root.appendChild(box);});root.querySelectorAll("input[type=checkbox]").forEach(cb=>cb.addEventListener("change",apply));}
function sel(dim){return new Set([...document.querySelectorAll(`input[data-dim="${dim}"]:checked`)].map(c=>c.value));}
function fmtUSD(n,suf){if(!n)return "—";return "US$ "+Math.round(n).toLocaleString("pt-BR")+suf;}
function selectedSubs(){const s=sel("sub");if(s.size)return s;return new Set(Object.keys(DATA.subs||{}));}
function aggSecure(subs){let cur=0,max=0,pot=0,has=false;subs.forEach(sid=>{const s=DATA.subs[sid];if(s&&s.ss_max_points){has=true;cur+=s.ss_current_points;max+=s.ss_max_points;pot+=s.ss_potential_points;}});if(!has||max<=0)return null;return {cur:Math.round(1000*cur/max)/10,pot:Math.round(1000*pot/max)/10};}
function aggMcsb(subs){let p=0,f=0,sk=0,un=0,has=false;subs.forEach(sid=>{const s=DATA.subs[sid];if(s&&s.mcsb){has=true;p+=s.mcsb.passed;f+=s.mcsb.failed;sk+=s.mcsb.skipped;un+=s.mcsb.unsupported;}});if(!has)return null;const a=p+f;return {passed:p,failed:f,skipped:sk,unsupported:un,pct:a>0?Math.round(1000*p/a)/10:null};}
function rowHtml(it){let cs=it.cost_delta?`<span style="color:#5ed16a">${esc(it.cost_delta)}</span>`:"";let ci=it.cost_increase?`<span style="color:#ff6b6b">${esc(it.cost_increase)}</span>`:"";let cost=(cs&&ci)?cs+"<br/>"+ci:(cs||ci||"—");let ss=it.score_impact_label?`<span style="color:#9ae6b4;font-weight:700">${esc(it.score_impact_label)}</span><div class="meta" style="font-size:11px">${esc(it.score_control)}</div>`:"—";let title=esc(it.title);if(it.portal_link){title=`<a href="${esc(it.portal_link)}" style="color:#e7edf5;text-decoration:none;border-bottom:1px dotted #4a5a72">${title}</a> <a href="${esc(it.portal_link)}" title="Abrir no portal" style="color:#7cd0ff;text-decoration:none">🔗</a>`;}const tags=(it.tactics||[]).concat(it.techniques||[]);let mitre=tags.length?`<div class="mtags">🎯 ${tags.slice(0,4).map(m=>`<span class="mitre">${esc(m)}</span>`).join("")}</div>`:"";let owner=it.owner?`<div class="owner">👤 ${esc(it.owner)}</div>`:"";let casc=it.cascade?`<div class="casc">↳ ${esc(it.cascade)}</div>`:"";let dvo=it.devops_repo?`<div class="devops">🐙 ${esc(it.devops_provider||"DevOps")} · ${esc(it.devops_repo)}</div>`:"";let src=`<span style="color:${it.source==="Advisor"?"#7cd0ff":"#c9a7ff"};font-weight:700">${esc(it.source)}</span>`;let subn=it.subscription_name&&it.subscription_name!=="—"?`<div class="meta" style="font-size:11px">${esc(it.subscription_name)} / ${esc(it.resource_group)}</div>`:"";return `<tr><td>${src}</td><td>${title}${dvo}${mitre}${owner}${casc}</td><td>${esc(it.category)}</td><td>${esc(it.priority)}</td><td>${ss}</td><td class="mono">${esc(it.resource_name)}${subn}</td><td>${cost}</td></tr>`;}
function renderPlan(items){const by={safe:[],low:[],medium:[],high:[]};items.forEach(it=>{(by[it.risk]||by.low).push(it);});let html="";PHASES.forEach(lvl=>{const rows=by[lvl];if(!rows.length)return;const m=PHMETA[lvl]||{};html+=`<div class="phase"><h3>${esc(m.emoji||"")} ${esc(m.label||lvl)} <span class="meta">· ${esc(m.action||"")} · ${rows.length} item(ns)</span></h3><table><tr><th>Fonte</th><th>Recomendação</th><th>Categoria</th><th>Prioridade</th><th>Impacto SS</th><th>Recurso</th><th>Custo</th></tr>${rows.map(rowHtml).join("")}</table></div>`;});document.getElementById("plan").innerHTML=html||`<div class="card meta">Nenhuma recomendação para os filtros selecionados.</div>`;}
function renderKpis(items,subs){const c={safe:0,low:0,medium:0,high:0};let sav=0,impl=0,devops=0;items.forEach(it=>{c[it.risk]=(c[it.risk]||0)+1;sav+=it.savings_raw||0;impl+=it.cost_increase_raw||0;if(it.devops_repo)devops++;});const ssA=aggSecure(subs);const mc=aggMcsb(subs);const k=document.getElementById("kpis");let cards=[["#7cd0ff",items.length,"recomendações"],["#5ed16a",c.safe,"🟢 quick wins"],["#ffd96b",c.low+c.medium,"🟡🟠 janela"],["#ff6b6b",c.high,"🔴 aprovação"],["#9fb0c8",ssA?ssA.cur+"%":"n/a","🛡️ SS atual"],["#9ae6b4",ssA?ssA.pot+"%":"n/a","🎯 SS potencial"],["#ff6b6b",impl?"+"+fmtUSD(impl,"/mês"):"—","💰 custo impl."]];if(mc&&mc.pct!=null){const cc=mc.pct>=80?"#5ed16a":(mc.pct>=50?"#ffd96b":"#ff6b6b");cards.push([cc,mc.pct+"%","🛡️ MCSB compliance"]);}if(devops)cards.push(["#7ee2a8",devops,"🐙 DevOps findings"]);k.innerHTML=cards.map(([col,n,l])=>`<div class="kpi"><div class="n" style="color:${col};font-size:${String(n).length>7?"14px":"20px"}">${esc(n)}</div><div class="l">${esc(l)}</div></div>`).join("");document.getElementById("subline").innerHTML=`economia potencial: <b style="color:#5ed16a">${sav?"−"+fmtUSD(sav,"/ano"):"—"}</b> · custo de implementação: <b style="color:#ff6b6b">${impl?"+"+fmtUSD(impl,"/mês"):"—"}</b> · 100% read-only`;const bar=document.getElementById("ssbar");if(ssA){bar.style.display="block";bar.innerHTML=`<div class="meta" style="margin-bottom:4px">🛡️ Secure Score: <b style="color:#9fb0c8">${ssA.cur}%</b> agora → <b style="color:#9ae6b4">${ssA.pot}%</b> se remediar tudo (<b style="color:#9ae6b4">+${Math.round(10*(ssA.pot-ssA.cur))/10} pp</b>)</div><div style="background:#0b0f17;border:1px solid #1e2a3f;border-radius:8px;height:14px;overflow:hidden;position:relative"><div style="position:absolute;left:0;top:0;height:100%;width:${ssA.pot}%;background:linear-gradient(90deg,#2d6a4f,#52b788);opacity:.45"></div><div style="position:absolute;left:0;top:0;height:100%;width:${ssA.cur}%;background:linear-gradient(90deg,#7cd0ff,#5ed16a)"></div></div>`;}else{bar.style.display="none";}}
function renderMcsb(subs){const el=document.getElementById("mcsb");const mc=aggMcsb(subs);if(!mc){el.innerHTML="";return;}const cc=(mc.pct||0)>=80?"#5ed16a":((mc.pct||0)>=50?"#ffd96b":"#ff6b6b");const fc=(DATA.mcsb&&DATA.mcsb.failing_controls||[]).filter(x=>!sel("sub").size||subs.has(x.subscription_id)).slice(0,15);let ft="";if(fc.length){ft=`<table style="margin-top:10px"><tr><th>Controle</th><th>Nome</th><th>Falhando</th><th>OK</th></tr>${fc.map(x=>{let nm=esc(x.name);if(x.link)nm=`<a href="${esc(x.link)}" style="color:#e7edf5;text-decoration:none;border-bottom:1px dotted #4a5a72">${nm}</a>`;return `<tr><td class="mono">${esc(x.id)}</td><td>${nm}</td><td style="color:#ff6b6b;font-weight:700">${x.failed}</td><td style="color:#5ed16a">${x.passed}</td></tr>`;}).join("")}</table>`;}el.innerHTML=`<div class="phase"><h3>🛡️ Postura de Compliance — Microsoft Cloud Security Benchmark <span class="meta">· standard: ${esc(DATA.mcsb?DATA.mcsb.standard_name:"")}</span></h3><div class="card"><div style="display:flex;gap:18px;flex-wrap:wrap;align-items:center"><div><span style="font-size:28px;font-weight:800;color:${cc}">${mc.pct!=null?mc.pct+"%":"n/a"}</span><div class="meta">controles em conformidade</div></div><div class="meta">✅ ${mc.passed} passed · ❌ ${mc.failed} failed · ⏭️ ${mc.skipped} skipped · ⚪ ${mc.unsupported} unsupported</div></div><div style="background:#0b0f17;border:1px solid #1e2a3f;border-radius:8px;height:12px;overflow:hidden;margin-top:10px"><div style="height:100%;width:${mc.pct||0}%;background:linear-gradient(90deg,${cc},#52b788)"></div></div>${ft}</div></div>`;}
function apply(){let items=DATA.items;DIMS.forEach(([dim])=>{const s=sel(dim);if(s.size)items=items.filter(it=>s.has(val(it,dim)));});const subs=selectedSubs();renderKpis(items,subs);renderPlan(items);renderMcsb(subs);}
function clearAll(){document.querySelectorAll("#frow input[type=checkbox]").forEach(c=>c.checked=false);apply();}
buildFilters();apply();
"""

def render_html(ctx, q):
    ph = q.get("phases", {})
    phases_meta = {lvl: {"emoji": ph.get(lvl, {}).get("emoji", ""),
                         "label": ph.get(lvl, {}).get("label", lvl),
                         "action": ph.get(lvl, {}).get("action", "")}
                   for lvl in ("safe", "low", "medium", "high")}

    def slim(it):
        return {
            "source": it.get("source"), "title": it.get("title"),
            "category": it.get("category") or "—", "priority": it.get("priority") or "—",
            "risk": it.get("risk"),
            "resource_name": it.get("resource_name") or "—",
            "resource_group": it.get("resource_group") or "—",
            "subscription_id": it.get("subscription_id") or "",
            "subscription_name": it.get("subscription_name") or "—",
            "cost_delta": it.get("cost_delta") or "",
            "cost_increase": it.get("cost_increase") or "",
            "cost_increase_raw": round(float(it.get("cost_increase_raw") or 0), 2),
            "savings_raw": _savings_raw(it.get("cost_delta")),
            "score_impact_label": it.get("score_impact_label") or "",
            "score_control": it.get("score_control") or "",
            "tactics": it.get("tactics") or [], "techniques": it.get("techniques") or [],
            "owner": it.get("owner") or "", "portal_link": it.get("portal_link") or "",
            "cascade": it.get("cascade") or "",
            "devops_repo": it.get("devops_repo") or "",
            "devops_provider": it.get("devops_provider") or "",
        }

    mcsb = ctx.get("mcsb")
    mcsb_js = None
    if mcsb:
        mcsb_js = {
            "standard_name": mcsb.get("standard_name", ""),
            "failing_controls": [
                {"id": fc["id"], "name": fc["name"], "failed": fc["failed"],
                 "passed": fc["passed"], "link": fc.get("link", ""),
                 "subscription_id": fc.get("subscription_id", "")}
                for fc in (mcsb.get("failing_controls") or [])
            ],
        }

    data = {
        "items": [slim(it) for it in ctx["items"]],
        "subs": ctx.get("subs", {}),
        "phases_meta": phases_meta,
        "mcsb": mcsb_js,
        "scope_label": ctx.get("scope_label", ""),
        "generated": ctx.get("generated", ""),
    }
    data_json = json.dumps(data, ensure_ascii=False)
    scope = esc(ctx.get("scope_label", "") or "escopo")
    n = len(ctx["items"])
    nsubs = len(ctx.get("subs", {}) or {})

    head = ('<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Advisor + Defender for Cloud — Remediation Plan</title>'
            '<style>' + _REPORT_CSS + '</style></head><body><div class="wrap">')
    hero = (
        '<div class="hero"><h1>🧭 Plano de Remediação — Advisor + Defender for Cloud</h1>'
        '<div class="meta" style="margin-bottom:8px">escopo: <b>' + scope + '</b> · '
        + str(n) + ' recomendação(ões) · ' + str(nsubs) + ' subscription(s) · gerado '
        + esc(ctx.get("generated", "")) + '</div>'
        '<div class="kpis" id="kpis"></div>'
        '<div id="ssbar" style="margin-top:12px;display:none"></div>'
        '<div class="meta" id="subline" style="margin-top:12px"></div></div>')
    filters = (
        '<div class="filters"><div class="ftop"><div class="meta">🔎 Filtros — marque para refinar; '
        'vazio = tudo. Secure Score e MCSB recalculam pelo filtro de Subscription.</div>'
        '<button class="btn" onclick="clearAll()">Limpar filtros</button></div>'
        '<div class="frow" id="frow"></div></div>')
    devops_html = _render_devops_section(ctx.get("devops"))
    body = ('<div id="plan"></div><div id="mcsb"></div>' + devops_html +
            '<div class="meta" style="margin-top:20px;border-top:1px solid #1e2a3f;padding-top:12px">'
            'advisor-impact · Azure Advisor + Microsoft Defender for Cloud · risco = disrupção de aplicar '
            '(não criticidade). Custos via Azure Retail Prices API · Compliance via MCSB '
            '(inspirado no <a href="https://github.com/microsoft/ESA" style="color:#7cd0ff">microsoft/ESA</a>).</div></div>')
    script = '<script>const DATA=' + data_json + ';\n' + _REPORT_JS + '</script>'
    return head + hero + filters + body + script + '</body></html>'

def render_md(ctx, q):
    ph = q.get("phases", {})
    ss = ctx["secure_score"]
    ss_pot = ctx.get("secure_score_potential")
    ss_delta = ctx.get("secure_score_delta")
    savings = f"−US$ {ctx['savings_total']:,.0f}/ano" if ctx["savings_total"] else "—"
    cost_impl = f"+US$ {ctx.get('cost_increase_total', 0):,.0f}/mês" if ctx.get("cost_increase_total") else "—"
    if ss is not None and ss_pot is not None:
        ss_line = f"**Secure score:** {ss}% → **{ss_pot}%** potencial (+{ss_delta} pp se remediar tudo)"
    elif ss is not None:
        ss_line = f"**Secure score:** {ss}%"
    else:
        ss_line = "**Secure score:** n/a"
    lines = ["# 🧭 Plano de Remediação — Advisor + Defender for Cloud",
             f"**Recomendações:** {len(ctx['items'])} · {ss_line}",
             f"**Recursos no escopo:** {ctx['resources_in_scope']} · **Economia potencial:** {savings} · **Custo de implementação:** {cost_impl}",
             "\n_Risco = disrupção de APLICAR (não criticidade). Read-only — recomenda, não aplica._",
             "_Impacto SS = elevação do secure score ao remediar o recurso. Custos via [Azure Retail Prices API](https://prices.azure.com)._\n"]
    for lvl in ("safe", "low", "medium", "high"):
        rows = ctx["phases"][lvl]
        if not rows:
            continue
        meta = ph.get(lvl, {})
        lines.append(f"## {meta.get('emoji','')} {meta.get('label', lvl)} — {meta.get('action','')} ({len(rows)})")
        lines.append("| Fonte | Recomendação | Categoria | Prioridade | Impacto SS | MITRE | Recurso | Economia | Custo Impl. |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for it in rows:
            sav = it.get('cost_delta') or '—'
            impl = it.get('cost_increase') or '—'
            ss_imp = it.get('score_impact_label') or '—'
            mtags = (it.get("tactics") or []) + (it.get("techniques") or [])
            mitre = ", ".join(str(m) for m in mtags[:3]) if mtags else "—"
            title = it['title']
            if it.get("devops_repo"):
                title = f"{title} · 🐙 {it.get('devops_provider','DevOps')}/{it['devops_repo']}"
            if it.get("owner"):
                title = f"{title} · 👤 {it['owner']}"
            link = it.get('portal_link')
            if link:
                title = f"[{title}]({link})"
            lines.append(f"| {it['source']} | {title} | {it.get('category') or '—'} | {it.get('priority')} | {ss_imp} | {mitre} | {it.get('resource_name')} | {sav} | {impl} |")
        casc = [it for it in rows if it.get("cascade")]
        if casc:
            for it in casc:
                lines.append(f"  - ↳ {it['cascade']}")
        lines.append("")
    # Pilar MCSB — compliance regulatório
    mcsb = ctx.get("mcsb")
    if mcsb:
        cpct = mcsb.get("compliance_pct")
        cpct_txt = f"{cpct}%" if cpct is not None else "n/a"
        lines.append(f"## 🛡️ Postura de Compliance — Microsoft Cloud Security Benchmark")
        lines.append(f"**Conformidade:** {cpct_txt} · **Estado:** {mcsb.get('state','')} · "
                     f"✅ {mcsb.get('passed',0)} passed · ❌ {mcsb.get('failed',0)} failed · "
                     f"⏭️ {mcsb.get('skipped',0)} skipped · ⚪ {mcsb.get('unsupported',0)} unsupported")
        failing = mcsb.get("failing_controls") or []
        if failing:
            lines.append("")
            lines.append("| Controle | Nome | Falhando | OK |")
            lines.append("|---|---|---|---|")
            for fc in failing[:12]:
                name = fc["name"]
                if fc.get("link"):
                    name = f"[{name}]({fc['link']})"
                lines.append(f"| {fc['id']} | {name} | {fc['failed']} | {fc['passed']} |")
        lines.append("")
    # Pilar DevOps Remediation — findings granulares
    devops = ctx.get("devops")
    if devops:
        lines.append("## 🐙 DevOps Remediation — findings do GitHub/Defender DevOps")
        sev_txt = " · ".join(f"{s}: {devops['by_severity'].get(s,0)}" for s in devops["sev_order"])
        cat_txt = " · ".join(f"{k}: {v}" for k, v in sorted(devops["by_category"].items(), key=lambda kv: kv[1], reverse=True))
        lines.append(f"**Total:** {devops['total']} · **Severidade:** {sev_txt} · **Categoria:** {cat_txt}")
        lines.append("")
        sevs = devops["sev_order"]
        lines.append("| Repositório | Total | " + " | ".join(sevs) + " |")
        lines.append("|---|---|" + "|".join(["---"] * len(sevs)) + "|")
        for m in devops["matrix"]:
            cells = " | ".join(str(m["by_sev"].get(s, 0)) for s in sevs)
            lines.append(f"| 🐙 {m['repo']} | {m['total']} | {cells} |")
        lines.append("")
        lines.append("_Matriz ordenada por Critical+High (maior risco no topo) · dependency CVEs normalmente têm PR do Dependabot pronto p/ merge._")
        lines.append("")
        # tabela de findings com remediação + link oficial por finding
        tf = devops.get("top_findings") or []
        if tf:
            LIMIT = 25
            lines.append("### 🔧 Findings a corrigir (por severidade · remediação + link oficial)")
            lines.append("| Sev | Repositório | Finding | Categoria | Remediação | Link |")
            lines.append("|---|---|---|---|---|---|")
            for f in tf[:LIMIT]:
                rem = (f.get("remediation", "") or "—").replace("|", "\\|").replace("\n", " ")
                fnd = (f.get("finding", "—") or "—").replace("|", "\\|").replace("\n", " ")
                link = f.get("link", "") or ""
                link_md = f"[Portal]({link})" if link else "—"
                lines.append(f"| {f.get('severity','—')} | 🐙 {f.get('repo','—')} | {fnd} | {f.get('category','—')} | {rem} | {link_md} |")
            if len(tf) > LIMIT:
                lines.append("")
                lines.append(f"_… +{len(tf) - LIMIT} findings (priorize Critical→High; veja o relatório completo)._")
            lines.append("")
    lines.append(f"_advisor-impact · gerado {ctx['generated']} · read-only · MCSB inspirado no microsoft/ESA (MIT)._")
    return "\n".join(lines)

# =============================================================================
# main
# =============================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(description="advisor-impact — Advisor + Defender for Cloud remediation planner.")
    ap.add_argument("--from-json", dest="from_json")
    ap.add_argument("--workspace", dest="ws_guid", help="(compat — não usado; o escopo é sub/rg)")
    ap.add_argument("--sub", dest="sub"); ap.add_argument("--rg", dest="rg")
    ap.add_argument("--tenant", action="store_true", help="Coleta tenant-wide via Azure Resource Graph (todas as subs que a identidade lê)")
    ap.add_argument("--subs", dest="subs", default=None, help="Lista de subscription IDs separados por vírgula (escopo ARG); sem isso = tenant inteiro")
    ap.add_argument("--category", default=None, help="Cost|Security|Reliability|OperationalExcellence|Performance|all")
    ap.add_argument("--queries", default=None)
    ap.add_argument("--output", default=".")
    ap.add_argument("--format", choices=["html", "md", "both"], default="both")
    ap.add_argument("--save-raw", action="store_true")
    args = ap.parse_args(argv)

    qpath = args.queries or os.path.join(os.path.dirname(os.path.abspath(__file__)), "queries.yaml")
    with open(qpath, "r", encoding="utf-8") as f:
        q = yaml.safe_load(f)
    params = dict(q.get("parameters", {}) or {})
    if args.category:
        params["category"] = args.category
    params["_rg"] = (args.rg or "").lower()
    sub_list = [s.strip() for s in (args.subs or "").split(",") if s.strip()]

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as f:
            raw = json.load(f)
        # tenant-wide se houver múltiplas subs nos dados; senão infere RG p/ filtrar MDC
        sub_ids_in_data = {_sub_of(str(r.get("id", ""))) for r in as_list(raw.get("mdc_assessments"))}
        sub_ids_in_data |= {str(s.get("subscriptionId", "")).lower() for s in as_list(raw.get("subscriptions"))}
        sub_ids_in_data.discard("")
        if not params["_rg"] and len(sub_ids_in_data) <= 1:
            inv = as_list(raw.get("resource_inventory"))
            if inv:
                params["_rg"] = _rg_of(inv[0].get("id", ""))
        params["_scope_label"] = "tenant" if len(sub_ids_in_data) > 1 else (f"RG {args.rg}" if args.rg else "subscription")
    elif args.tenant or sub_list:
        raw = collect_tenant(q, sub_list or None)
        params["_rg"] = ""   # tenant-wide: sem filtro de RG
        params["_scope_label"] = f"{len(sub_list)} subscription(s)" if sub_list else "tenant inteiro"
        if not as_list(raw.get("advisor_recommendations")) and not as_list(raw.get("mdc_assessments")):
            print("Modo C (ARG) não retornou dados (sem Reader nas subs, az sem auth, ou extensão ARG indisponível). "
                  "Use Modo B (--from-json).", file=sys.stderr)
            return 2
    elif args.sub and args.rg:
        raw = collect_live(q, args.sub, args.rg)
        params["_scope_label"] = f"RG {args.rg}"
        if not as_list(raw.get("advisor_recommendations")) and not as_list(raw.get("mdc_assessments")) and not as_list(raw.get("resource_inventory")):
            print("Modo A não retornou dados (sem Reader na subscription/RG, az sem auth, ou escopo vazio). "
                  "Use Modo B (--from-json).", file=sys.stderr)
            return 2
    else:
        print("Informe --from-json <arquivo> · OU --tenant [/--subs id,id] (tenant-wide ARG) · OU --sub <id> --rg <nome>.", file=sys.stderr)
        return 2

    os.makedirs(args.output, exist_ok=True)
    if args.save_raw:
        with open(os.path.join(args.output, "_raw.json"), "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False, indent=2)

    ctx = build_context(q, raw, params)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    base = f"advisor-impact-{stamp}"
    if args.format in ("html", "both"):
        p = os.path.join(args.output, base + ".html")
        with open(p, "w", encoding="utf-8") as f:
            f.write(render_html(ctx, q))
        c = {k: len(v) for k, v in ctx["phases"].items()}
        print(f"✅ {len(ctx['items'])} recomendações · 🟢{c['safe']} 🟡{c['low']} 🟠{c['medium']} 🔴{c['high']} · "
              f"secure score {ctx['secure_score']}")
        print(f"   → {p}")
    if args.format in ("md", "both"):
        p = os.path.join(args.output, base + ".md")
        with open(p, "w", encoding="utf-8") as f:
            f.write(render_md(ctx, q))
        print(f"   → {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

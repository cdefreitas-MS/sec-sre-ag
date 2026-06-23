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
import argparse, datetime as dt, html, json, math, os, re, shutil, subprocess, sys, tempfile
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

def _devops_owner(resource_id):
    """Extrai o owner/org do connector DevOps a partir do resourceId."""
    parts = (resource_id or "").split("/")
    low = [p.lower() for p in parts]
    for marker in ("githubowners", "azuredevopsorgs", "gitlabgroups", "owners", "orgs"):
        if marker in low:
            i = low.index(marker)
            if i + 1 < len(parts):
                return parts[i + 1]
    return ""

_GH_SEC_TAB = {
    "dependency": "dependabot", "dependencies": "dependabot",
    "code": "code-scanning", "infrastructure as code": "code-scanning", "iac": "code-scanning",
    "secret": "secret-scanning", "secrets": "secret-scanning",
}

def _devops_ref_link(provider, owner, repo, category, portal_link=""):
    """Referência acionável: link oficial do portal se houver, senão a aba Security do repo (GitHub)."""
    if portal_link:
        return portal_link
    if provider == "GitHub" and owner and repo:
        tab = _GH_SEC_TAB.get((category or "").strip().lower(), "")
        base = "https://github.com/%s/%s/security" % (owner, repo)
        return "%s/%s" % (base, tab) if tab else base
    return ""

def _short_finding(name, limit=140):
    """Resumo curto do finding: 'pacote/ecossistema — 1a frase'. Corta o corpo gigante do advisory GHAS."""
    raw = (name or "").strip()
    if not raw:
        return "\u2014"
    head = raw.split(":", 1)[0].strip() if ":" in raw else ""
    body = raw.split(":", 1)[1].strip() if ":" in raw else raw
    first = re.split(r"(?:\.\s|[\n\r])", body, 1)[0]    # 1a frase: para em ". " ou quebra (não em 3.16.0)
    first = re.sub(r"[#>*`\[\]]+", " ", first)          # remove marcas markdown
    first = re.sub(r"\s+", " ", first).strip()
    title = head if (head and len(head) <= 60 and "\n" not in head) else ""
    if title and first:
        out = "%s \u2014 %s" % (title, first)
    elif title:
        out = title
    else:
        out = first or re.sub(r"\s+", " ", raw)
    out = out.strip()
    if len(out) > limit:
        out = out[:limit].rstrip() + "\u2026"
    return out

# =============================================================================
# Parsers — Advisor + Defender for Cloud → itens unificados
# =============================================================================
def _portal_resource_link(resource_id):
    """Deep link determinístico para o recurso no Azure Portal (a partir do resourceId)."""
    rid = (resource_id or "").strip()
    if not rid or not rid.lower().startswith("/subscriptions/"):
        return ""
    return f"https://portal.azure.com/#@/resource{rid}/overview"

# Links de acesso rápido GARANTIDOS (oficiais) por origem — usados como fallback quando
# não há deep link específico da recomendação nem resourceId. Garantem que TODA recomendação
# tenha um link clicável.
_ADVISOR_PORTAL = "https://aka.ms/azureadvisordashboard"
_MDC_RECS_PORTAL = "https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/5"
_M365_SECURESCORE_PORTAL = "https://security.microsoft.com/securescore"

def _fallback_portal_link(source):
    """Fallback oficial por origem (Advisor → Advisor dashboard; demais → Defender recommendations)."""
    if "advisor" in (source or "").lower():
        return _ADVISOR_PORTAL
    return _MDC_RECS_PORTAL


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
    # senão cai p/ deep link determinístico do recurso; senão fallback oficial por origem
    # (garante que TODA recomendação tenha link de acesso rápido).
    item["portal_link"] = (item.get("rec_link") or _portal_resource_link(resource_id)
                           or _fallback_portal_link(item.get("source")))
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
            "link": prop(cp, "links.azurePortal", "") or _MDC_RECS_PORTAL,
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
        portal = prop(p, "links.azurePortal", "") or ""
        owner = _devops_owner(rid)
        findings.append({
            "repo": repo or "(org)",
            "provider": provider,
            "severity": sev,
            "category": cat,
            "finding": _short_finding(p.get("displayName", "—")),
            "remediation": p.get("remediation", "") or "",
            "link": _devops_ref_link(provider, owner, repo, cat, portal),
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

    # Pilar XDR — UNIFICADO na aba Microsoft Secure Score (mesma fonte: secureScoreControlProfiles).
    # Mantido None para não duplicar card/aba; o dashboard m365 abaixo consome o mesmo dataset.
    xdr = None

    # Microsoft Secure Score (M365/Entra) — dataset opcional (prefetch via Graph). Inclui os
    # Recommended Actions que antes ficavam na aba "Defender XDR" (mesma origem secureScoreControlProfiles).
    m365 = analyze_m365_dashboard(raw.get("m365_secure_score") or raw.get("secure_score_m365"), raw.get("xdr_recommendations"))

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
        "xdr": xdr,
        "m365": m365,
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
_SEV_CLASS = {"Critical": "sv-critical", "High": "sv-high", "Medium": "sv-medium", "Low": "sv-low", "Informational": "sv-informational"}

# Logo Microsoft Security (PNG horizontal, base64 embutido — self-contained). Texto branco:
# no tema claro renderiza sobre um chip escuro (ver CSS .mslogo-wrap).
_LOGO_DATA_URI = "data:image/png;base64,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"

# Logos de produto (base64 embutido — self-contained). Coloridos -> ok nos 2 temas.
_DFC_LOGO_URI = "data:image/png;base64,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"  # Microsoft Defender for Cloud (escudo verde)
_XDR_LOGO_URI = "data:image/svg+xml;base64,PHN2ZyBpZD0iZTUwZGMzNDEtYjg4My00ZTU1LTg2NTEtOTdjYzBiZTEzMGFkIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxOCAxOCI+PGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJhMmVlZGVkNS1iZDc0LTQxMzYtYWRlNi1hMDRkODM3ODk5Y2EiIHgxPSI5IiB5MT0iMTYuNzk1IiB4Mj0iOSIgeTI9IjEuMjA1IiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHN0b3Agb2Zmc2V0PSIwIiBzdG9wLWNvbG9yPSIjMDA3OGQ0Ii8+PHN0b3Agb2Zmc2V0PSIwLjA2NCIgc3RvcC1jb2xvcj0iIzBhN2NkNyIvPjxzdG9wIG9mZnNldD0iMC4zMzgiIHN0b3AtY29sb3I9IiMyZThjZTEiLz48c3RvcCBvZmZzZXQ9IjAuNTk0IiBzdG9wLWNvbG9yPSIjNDg5N2U5Ii8+PHN0b3Agb2Zmc2V0PSIwLjgyMiIgc3RvcC1jb2xvcj0iIzU4OWVlZCIvPjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzVlYTBlZiIvPjwvbGluZWFyR3JhZGllbnQ+PC9kZWZzPjxwYXRoIGQ9Ik0xNS41LDguNDg1YzAsNC4xOTEtNS4xNiw3LjU2Ni02LjI4Miw4LjI1YS40MTIuNDEyLDAsMCwxLS40MjgsMEM3LjY2NCwxNi4wNTEsMi41LDEyLjY3NiwyLjUsOC40ODVWMy40NDFhLjQuNCwwLDAsMSwuNC0uNEM2LjkxNiwyLjkzNSw1Ljk5MiwxLjIwNSw5LDEuMjA1czIuMDg0LDEuNzMsNi4xLDEuODM3YS40LjQsMCwwLDEsLjQuNFoiIGZpbGw9InVybCgjYTJlZWRlZDUtYmQ3NC00MTM2LWFkZTYtYTA0ZDgzNzg5OWNhKSIvPjwvc3ZnPg=="  # Microsoft Security / XDR (escudo azul)

def _svg_donut(segments, size=160, stroke=28):
    """Donut SVG (sem libs) p/ proporção de severidade. segments = [(label, value, color)]."""
    total = sum(v for _, v, _ in segments) or 1
    r = (size - stroke) / 2.0
    cx = cy = size / 2.0
    circ = 2 * math.pi * r
    off = 0.0
    arcs = (f"<circle cx='{cx}' cy='{cy}' r='{r:.1f}' fill='none' stroke='var(--inset)' "
            f"stroke-width='{stroke}'/>")
    for _label, v, color in segments:
        if v <= 0:
            continue
        dash = (v / total) * circ
        arcs += (f"<circle cx='{cx}' cy='{cy}' r='{r:.1f}' fill='none' stroke='{color}' "
                 f"stroke-width='{stroke}' stroke-dasharray='{dash:.2f} {circ - dash:.2f}' "
                 f"stroke-dashoffset='{-off:.2f}' transform='rotate(-90 {cx} {cy})'/>")
        off += dash
    center = (f"<text x='{cx}' y='{cy - 2}' text-anchor='middle' class='donut-num'>{total}</text>"
              f"<text x='{cx}' y='{cy + 17}' text-anchor='middle' class='donut-lbl'>findings</text>")
    return (f"<svg viewBox='0 0 {size} {size}' width='{size}' height='{size}' class='donut' "
            f"role='img' aria-label='Severidade'>{arcs}{center}</svg>")

def _svg_pie(segments, size=88):
    """Gráfico de pizza (pie) cheio, sem libs. segments = [(label, value, color)]."""
    nz = [(l, v, c) for l, v, c in segments if v and v > 0]
    if not nz:
        return ""
    total = sum(v for _, v, _ in nz) or 1
    cx = cy = size / 2.0
    r = size / 2.0 - 1
    if len(nz) == 1:
        return (f"<svg viewBox='0 0 {size} {size}' width='{size}' height='{size}' class='pie' role='img'>"
                f"<circle cx='{cx}' cy='{cy}' r='{r:.1f}' fill='{nz[0][2]}'/></svg>")
    ang = -90.0
    paths = ""
    for _l, v, c in nz:
        frac = v / total
        a0 = math.radians(ang)
        ang += frac * 360.0
        a1 = math.radians(ang)
        x0 = cx + r * math.cos(a0); y0 = cy + r * math.sin(a0)
        x1 = cx + r * math.cos(a1); y1 = cy + r * math.sin(a1)
        large = 1 if frac > 0.5 else 0
        paths += (f"<path d='M{cx:.2f},{cy:.2f} L{x0:.2f},{y0:.2f} "
                  f"A{r:.2f},{r:.2f} 0 {large} 1 {x1:.2f},{y1:.2f} Z' fill='{c}'/>")
    return (f"<svg viewBox='0 0 {size} {size}' width='{size}' height='{size}' class='pie' role='img'>{paths}</svg>")

def _stacked_bars(matrix, sevs):
    """Barras horizontais empilhadas por repo (escala pelo maior total). Estilo Power BI."""
    maxt = max((m["total"] for m in matrix), default=1) or 1
    rows = ""
    for m in matrix:
        segs = ""
        for s in sevs:
            v = m["by_sev"].get(s, 0)
            if not v:
                continue
            w = 100.0 * v / maxt
            segs += (f"<span class='seg' style='width:{w:.2f}%;background:{_SEV_COLOR.get(s, '#9fb0c8')}' "
                     f"title='{esc(s)}: {v}'></span>")
        rows += (f"<div class='barrow'><div class='barlbl mono' title='{esc(m['repo'])}'>\U0001f419 {esc(m['repo'])}</div>"
                 f"<div class='bartrack'>{segs}</div>"
                 f"<div class='barval'>{m['total']}</div></div>")
    return f"<div class='bars'>{rows}</div>"

def _render_devops_section(devops):
    """Página 🐙 DevOps Remediation (dashboard interativo via JS: KPIs + pizzas + barras por
    repositório + findings). O shell traz filtros (por repositório e criticidade) + placeholders;
    o JS (renderDevops) calcula tudo sob filtro."""
    if not devops:
        return ""
    filters = (
        '<div class="filters"><div class="ftop">'
        '<div class="meta">🔎 Filtros — selecione repositório e/ou criticidade; vazio = tudo. Tudo recalcula conforme a seleção.</div>'
        '<button class="btn" onclick="clearDevops()">Limpar filtros</button></div>'
        '<div class="frow" id="devopsfrow"></div></div>')
    return (
        "<div class='phase'><h3>🐙 DevOps Remediation "
        "<span class='meta'>· findings do GitHub/Defender DevOps — CVE/code/IaC/secret a corrigir (não postura)</span></h3>"
        + filters +
        "<div class='card'>"
        "<div class='kpis' id='devopskpis'></div>"
        "<div class='pgrid' id='devopspies' style='margin-top:14px'></div>"
        "<h3 style='margin-top:16px'>📊 Por repositório <span class='meta'>· empilhado por criticidade · ordenado por Critical+High</span></h3>"
        "<div id='devopsbars'></div>"
        "<h3 style='margin-top:16px'>🔧 Findings a corrigir <span class='meta'>· por criticidade · clique na referência p/ a recomendação</span></h3>"
        "<div id='devopstable'></div>"
        "</div></div>")

# =============================================================================
# Pilar XDR — recomendações do Microsoft Defender XDR / Microsoft Secure Score
# Dataset OPCIONAL (prefetch Mode B): chave "xdr_recommendations".
# Aceita DOIS shapes:
#   (A) Microsoft Graph `GET /security/secureScoreControlProfiles` = Recommended Actions
#       (security.microsoft.com/securescore): title, controlCategory (Identity/Device/Apps/Data),
#       service, maxScore, actionUrl, controlStateUpdates(state), threats, remediation…
#   (B) MDE TVM `api.securitycenter.microsoft.com/api/recommendations`: recommendationName,
#       recommendationCategory, severityScore, exposedMachinesCount, publicExploit…
# =============================================================================
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
_CAT_COLOR = {"Identity": "#7cd0ff", "Device": "#7ee2a8", "Apps": "#c9a7ff", "Data": "#ffd96b",
              "Account": "#7cd0ff", "Infrastructure": "#ff9f6b", "Network": "#5ed16a", "—": "#9fb0c8"}

def analyze_xdr_recommendations(data, sub_names=None):
    """Sumariza Recommended Actions (Graph secureScoreControlProfiles) OU recs TVM (MDE). Unifica em groups/top."""
    rows = [r for r in as_list(data) if isinstance(r, dict)]
    if not rows:
        return None

    def field(r, *keys):
        p = r.get("properties") if isinstance(r.get("properties"), dict) else {}
        for k in keys:
            if r.get(k) not in (None, ""):
                return r.get(k)
            if p.get(k) not in (None, ""):
                return p.get(k)
        return None

    # Detecta shape Recommended Actions (Secure Score control profiles)
    is_actions = any(
        (r.get("controlCategory") or r.get("actionType") or r.get("controlStateUpdates")
         or ("maxScore" in r and "severityScore" not in r)) for r in rows)

    if is_actions:
        recs = []
        for r in rows:
            name = str(field(r, "title", "controlName", "displayName", "name", "id") or "—")
            if len(name) > 130:
                name = _short_finding(name, 130)
            status = ""
            csu = field(r, "controlStateUpdates")
            if isinstance(csu, list) and csu:
                last = csu[-1] if isinstance(csu[-1], dict) else {}
                status = str(last.get("state") or last.get("assignedTo") or "")
            status = (status or str(field(r, "implementationStatus", "state") or "To address")).strip() or "To address"
            try:
                pts = round(float(field(r, "maxScore", "score") or 0), 1)
            except (TypeError, ValueError):
                pts = 0.0
            threats = field(r, "threats") or []
            recs.append({
                "name": name,
                "category": str(field(r, "controlCategory", "category") or "—"),
                "service": str(field(r, "service", "actionType") or "—"),
                "status": status,
                "points": pts,
                "link": str(field(r, "actionUrl", "remediationUrl", "link") or ""),
                "threats": ", ".join(str(t) for t in threats) if isinstance(threats, list) else str(threats),
                "severity": "", "exposed": 0, "exploit": False,
            })
        by_cat, by_status = {}, {}
        for r in recs:
            by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        groups = [(c, n, _CAT_COLOR.get(c, "#9fb0c8")) for c, n in sorted(by_cat.items(), key=lambda kv: kv[1], reverse=True)]
        top = sorted(recs, key=lambda r: r["points"], reverse=True)
        return {
            "total": len(recs), "mode": "actions", "groups": groups, "group_label": "Categoria",
            "by_category": by_cat, "by_status": by_status,
            "points_total": round(sum(r["points"] for r in recs), 1),
            "top": top,
        }

    # ---- Shape TVM (severidade) ----
    def sev_of(r):
        s = field(r, "severity", "severityLevel")
        if s:
            return str(s).capitalize()
        try:
            sc = float(field(r, "severityScore", "cvssScore") or 0)
        except (TypeError, ValueError):
            sc = 0.0
        return "Critical" if sc >= 9 else "High" if sc >= 7 else "Medium" if sc >= 4 else "Low" if sc > 0 else "—"

    recs = []
    for r in rows:
        name = str(field(r, "recommendationName", "displayName", "title", "name") or "—")
        if len(name) > 130:
            name = _short_finding(name, 130)
        recs.append({
            "name": name,
            "category": str(field(r, "recommendationCategory", "category", "subCategory") or "—"),
            "severity": sev_of(r),
            "exposed": int(field(r, "exposedMachinesCount", "exposedDevicesCount", "exposedAssetsCount") or 0),
            "exploit": bool(field(r, "publicExploit", "hasExploit")),
            "weaknesses": int(field(r, "weaknesses", "cveCount") or 0),
            "link": str(field(r, "recommendationLink", "portalLink", "link") or ""),
            "service": "", "status": "", "points": 0,
        })
    if not recs:
        return None
    by_sev, by_cat = {}, {}
    for r in recs:
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
    sev_order = sorted(by_sev.items(), key=lambda kv: _SEV_ORDER.get(kv[0].lower(), -1), reverse=True)
    sevs = [s for s, _ in sev_order]
    groups = [(s, by_sev.get(s, 0), _SEV_COLOR.get(s, "#9fb0c8")) for s in sevs]
    top = sorted(recs, key=lambda r: (_SEV_ORDER.get(r["severity"].lower(), -1), r["exposed"], r["weaknesses"]), reverse=True)
    return {
        "total": len(recs), "mode": "severity", "groups": groups, "group_label": "Severidade",
        "by_severity": dict(sev_order), "by_category": by_cat, "sev_order": sevs,
        "exposed_total": sum(r["exposed"] for r in recs),
        "exploit_total": sum(1 for r in recs if r["exploit"]),
        "top": top,
    }

def _count_bars(pairs, color="var(--accent)"):
    """Barras horizontais simples (1 cor) escaladas pelo maior valor. pairs = [(label, count)]."""
    maxv = max((v for _, v in pairs), default=1) or 1
    rows = ""
    for label, v in pairs:
        w = 100.0 * v / maxv
        rows += (f"<div class='barrow'><div class='barlbl' title='{esc(str(label))}'>{esc(str(label))}</div>"
                 f"<div class='bartrack'><span class='seg' style='width:{w:.2f}%;background:{color}'></span></div>"
                 f"<div class='barval'>{v}</div></div>")
    return f"<div class='bars'>{rows}</div>"

def _render_xdr_section(xdr):
    """Página 🛡️ Defender XDR / Recommended Actions estilo Power BI: pizza/donut + KPIs + barras + tabela."""
    if not xdr:
        return ""
    groups = xdr.get("groups", [])
    donut = _svg_donut([(g, v, c) for g, v, c in groups])
    donut_legend = "<div class='legend'>" + "".join(
        f"<span><i class='dot' style='background:{c}'></i>{esc(g)} · {v}</span>" for g, v, c in groups) + "</div>"
    bars = _count_bars(sorted(xdr["by_category"].items(), key=lambda kv: kv[1], reverse=True))

    if xdr.get("mode") == "actions":
        kcards = (f"<div class='kpi'><div class='n' style='color:#1fab89'>{xdr['total']}</div>"
                  f"<div class='l'>🛡️ recommended actions</div></div>")
        for g, v, c in groups[:5]:
            kcards += f"<div class='kpi'><div class='n' style='color:{c}'>{v}</div><div class='l'>{esc(g)}</div></div>"
        kcards += (f"<div class='kpi'><div class='n' style='color:#9ae6b4'>{xdr.get('points_total',0)}</div>"
                   f"<div class='l'>🎯 pontos de melhoria</div></div>")
        det = ""
        for r in xdr["top"][:25]:
            link = r.get("link", "") or ""
            link_html = (f"<a href='{esc(link)}' target='_blank' style='color:var(--accent);white-space:nowrap'>Portal ↗</a>"
                         if link else "<span class='meta'>—</span>")
            det += (f"<tr><td>{esc(r['name'])}</td>"
                    f"<td class='meta' style='white-space:nowrap'>{esc(r.get('service','—'))}</td>"
                    f"<td class='meta' style='white-space:nowrap'>{esc(r['category'])}</td>"
                    f"<td class='meta' style='white-space:nowrap'>{esc(r.get('status','—'))}</td>"
                    f"<td style='text-align:right;font-weight:700'>{r.get('points',0)}</td><td>{link_html}</td></tr>")
        table = ("<h3 style='margin-top:16px'>🔧 Recommended Actions <span class='meta'>· ordenadas por pontos de melhoria</span></h3>"
                 "<table><tr><th>Ação recomendada</th><th>Serviço</th><th>Categoria</th><th>Status</th><th>Pontos</th><th>Referência</th></tr>"
                 f"{det}</table>")
        subtitle = "· Microsoft Secure Score — Recommended Actions (security.microsoft.com/securescore)"
        bars_title = "📊 Por categoria (Identity / Device / Apps / Data)"
    else:
        kcards = (f"<div class='kpi'><div class='n' style='color:#1fab89'>{xdr['total']}</div>"
                  f"<div class='l'>🛡️ recomendações</div></div>")
        for g, v, c in groups:
            kcards += f"<div class='kpi'><div class='n' style='color:{c}'>{v}</div><div class='l'>{esc(g)}</div></div>"
        kcards += (f"<div class='kpi'><div class='n' style='color:#ff6b6b'>{xdr.get('exploit_total',0)}</div>"
                   f"<div class='l'>💥 exploit público</div></div>"
                   f"<div class='kpi'><div class='n' style='color:#ffd96b'>{xdr.get('exposed_total',0)}</div>"
                   f"<div class='l'>🖥️ máquinas expostas</div></div>")
        det = ""
        for r in xdr["top"][:25]:
            cls = _SEV_CLASS.get(r["severity"], "sv-informational")
            ex = "💥 sim" if r["exploit"] else "<span class='meta'>—</span>"
            link = r.get("link", "") or ""
            link_html = (f"<a href='{esc(link)}' target='_blank' style='color:var(--accent);white-space:nowrap'>Defender ↗</a>"
                         if link else "<span class='meta'>—</span>")
            det += (f"<tr><td class='{cls}' style='font-weight:700;white-space:nowrap'>{esc(r['severity'])}</td>"
                    f"<td>{esc(r['name'])}</td>"
                    f"<td class='meta' style='white-space:nowrap'>{esc(r['category'])}</td>"
                    f"<td style='text-align:right;font-weight:700'>{r['exposed']}</td>"
                    f"<td style='white-space:nowrap'>{ex}</td><td>{link_html}</td></tr>")
        table = ("<h3 style='margin-top:16px'>🔧 Recomendações <span class='meta'>· por severidade e máquinas expostas</span></h3>"
                 "<table><tr><th>Sev</th><th>Recomendação</th><th>Categoria</th><th>Máquinas</th><th>Exploit</th><th>Referência</th></tr>"
                 f"{det}</table>")
        subtitle = "· Vulnerability Management / Exposure — priorize por exposição e exploit"
        bars_title = "📊 Por categoria"

    return (
        "<div class='phase'><h3><img class='plogo-h' src='" + _XDR_LOGO_URI + "' alt=''>Recomendações do Defender XDR "
        f"<span class='meta'>{subtitle}</span></h3>"
        "<div class='card'>"
        "<div class='dvgrid'>"
        f"<div style='text-align:center'>{donut}{donut_legend}</div>"
        f"<div><div class='kpis'>{kcards}</div></div>"
        "</div>"
        f"<h3 style='margin-top:16px'>{bars_title}</h3>"
        f"{bars}"
        f"{table}"
        "</div></div>")

# =============================================================================
# Microsoft Secure Score (M365/Entra) — dataset OPCIONAL (Graph /security/secureScores)
# + cards de score (estilo Power BI) e Resumo Executivo
# =============================================================================
def _find_shared(name):
    """Locate shared/<name> by walking up the tree (repo convention)."""
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(8):
        cand = os.path.join(d, "shared", name)
        if os.path.isfile(cand):
            return cand
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return None


def _shared_secure_score(resp):
    """Delegate to the canonical shared/secure_score.py reader when resolvable (single source of truth)."""
    path = _find_shared("secure_score.py")
    if not path:
        return False, None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("secure_score", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return True, mod.latest_secure_score(resp)
    except Exception:
        return False, None


def analyze_m365_secure_score(data):
    """Microsoft Secure Score (Entra ID + Microsoft 365) via Graph /security/secureScores. Opcional.
    Single source of truth = shared/secure_score.py (the SAME reader as org-posture's Identity pillar,
    so the headline number can't drift between the two reports). Falls back to an inline read
    aligned to the canonical method (latest entry by createdDateTime)."""
    ok, ss = _shared_secure_score(data)
    if ok:
        return ss
    rows = as_list(data)
    if not rows:
        return None
    props = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        p = r.get("properties") if isinstance(r.get("properties"), dict) else r
        if isinstance(p, dict) and p:
            props.append(p)
    if not props:
        return None
    props.sort(key=lambda p: str(p.get("createdDateTime", "")), reverse=True)
    p = props[0]
    try:
        cur = float(p.get("currentScore"))
        mx = float(p.get("maxScore"))
    except (TypeError, ValueError):
        return None
    if mx <= 0:
        return None
    return {"pct": round(100.0 * cur / mx, 1), "current": round(cur, 1),
            "max": round(mx, 1), "controls": len(p.get("controlScores") or [])}

# ----- Dashboard Microsoft Secure Score (estilo ESA, página dedicada) ---------
# Junta secureScores.controlScores (score ATUAL por controle) com
# secureScoreControlProfiles (título/categoria/produto/maxScore/estado).
_M365_STATE_MAP = {
    "default": "A endereçar", "toaddress": "A endereçar", "reviewed": "Em revisão",
    "planned": "Planejado", "ignored": "Risco aceito", "riskaccepted": "Risco aceito",
    "thirdparty": "Mitigação alternativa", "resolved": "Concluído", "completed": "Concluído",
}
_M365_STATUS_COLOR = {
    "Concluído": "#5ed16a", "A endereçar": "#ffb020", "Planejado": "#7cd0ff",
    "Em revisão": "#9aa7ff", "Risco aceito": "#c9a7ff", "Mitigação alternativa": "#f48fb1",
}
_M365_CAT_COLOR = {"Identity": "#7cd0ff", "Device": "#7ee2a8", "Apps": "#c9a7ff", "Data": "#ffd96b",
                   "Account": "#7cd0ff", "Infrastructure": "#ff9f6b", "—": "#9fb0c8"}
_M365_BUCKET_COLOR = {"Alcançado": "#5ed16a", "Parcial": "#ffd96b", "Oportunidade": "#ff6b6b"}


def analyze_m365_dashboard(m365_raw, profiles_raw):
    """Dashboard Microsoft Secure Score (estilo ESA): por-recomendação com status/categoria/
    produto/pontuação/impacto/licença. Usa secureScores p/ o score atual; também renderiza
    só com secureScoreControlProfiles (degrada: score atual = 0 onde não houver join)."""
    base = analyze_m365_secure_score(m365_raw)
    rows = as_list(m365_raw)
    head = rows[0] if rows and isinstance(rows[0], dict) else {}
    hp = head.get("properties") if isinstance(head.get("properties"), dict) else head
    cscores = {}
    for cs in (hp.get("controlScores") or []):
        if not isinstance(cs, dict):
            continue
        key = str(cs.get("controlName") or cs.get("name") or "").strip().lower()
        if not key:
            continue
        try:
            sc = float(cs.get("score") or 0)
        except (TypeError, ValueError):
            sc = 0.0
        cscores[key] = {"score": sc, "category": cs.get("controlCategory") or "",
                        "applicable": cs.get("IsApplicable", cs.get("isApplicable", None))}
    profs = [r for r in as_list(profiles_raw) if isinstance(r, dict)]
    if not profs:
        return base  # só o card simples (sem página de dashboard)

    def field(r, *keys):
        p = r.get("properties") if isinstance(r.get("properties"), dict) else {}
        for k in keys:
            if r.get(k) not in (None, ""):
                return r.get(k)
            if p.get(k) not in (None, ""):
                return p.get(k)
        return None

    recs = []
    for r in profs:
        if bool(field(r, "deprecated")):
            continue
        cid = str(field(r, "id", "controlName", "name") or "").strip()
        title = str(field(r, "title", "displayName", "controlName", "id") or "—")
        cat = str(field(r, "controlCategory", "category") or "")
        product = str(field(r, "service", "actionType") or "—")
        try:
            maxs = float(field(r, "maxScore", "max") or 0)
        except (TypeError, ValueError):
            maxs = 0.0
        csu = field(r, "controlStateUpdates")
        state_raw = ""
        if isinstance(csu, list) and csu and isinstance(csu[-1], dict):
            state_raw = str(csu[-1].get("state") or "")
        cs = cscores.get(cid.lower(), {})
        cur = cs.get("score", 0.0)
        if not cat or cat == "—":
            cat = cs.get("category") or "—"
        if maxs > 0 and cur >= maxs - 1e-9:
            status = "Concluído"
        else:
            status = _M365_STATE_MAP.get(re.sub(r"\s+", "", state_raw).lower(), "A endereçar")
        if maxs <= 0 or cur <= 0:
            bucket = "Oportunidade"
        elif cur >= maxs - 1e-9:
            bucket = "Alcançado"
        else:
            bucket = "Parcial"
        appl = cs.get("applicable", None)
        recs.append({
            "name": title, "category": cat or "—", "product": product or "—",
            "score": round(cur, 1), "max": round(maxs, 1), "missing": round(max(maxs - cur, 0.0), 1),
            "status": status, "bucket": bucket, "licensed": (appl is not False),
            "link": str(field(r, "actionUrl", "remediationUrl", "link") or "") or _M365_SECURESCORE_PORTAL,
        })
    if not recs:
        return base

    def tally(key):
        d = {}
        for x in recs:
            d[x[key]] = d.get(x[key], 0) + 1
        return d

    prod = {}
    for x in recs:
        pp = prod.setdefault(x["product"], {"completed": 0, "to_address": 0, "cur": 0.0, "max": 0.0})
        pp["completed" if x["status"] == "Concluído" else "to_address"] += 1
        pp["cur"] += x["score"]
        pp["max"] += x["max"]
    by_product = sorted(
        [{"product": k, "completed": v["completed"], "to_address": v["to_address"],
          "pct": round(100.0 * v["cur"] / v["max"]) if v["max"] else 0,
          "gain": round(v["max"] - v["cur"], 1)} for k, v in prod.items()],
        key=lambda r: (r["to_address"], r["gain"]), reverse=True)
    no_license = sum(1 for x in recs if not x["licensed"])
    completed = sum(1 for x in recs if x["status"] == "Concluído")
    if base:
        out = dict(base)
    else:
        cur = round(sum(x["score"] for x in recs), 1)
        mx = round(sum(x["max"] for x in recs), 1)
        out = {"pct": round(100.0 * cur / mx, 1) if mx else 0.0,
               "current": cur, "max": mx, "controls": len(cscores)}
    out.update({
        "dashboard": True, "total": len(recs), "completed": completed,
        "to_address": len(recs) - completed, "no_license": no_license,
        "missing_total": round(sum(x["missing"] for x in recs)),
        "by_status": tally("status"), "by_category": tally("category"), "by_bucket": tally("bucket"),
        "by_product": by_product,
        "license_segs": ([("Licenciado", len(recs) - no_license, "#5ed16a"),
                          ("Sem licença", no_license, "#ff6b6b")] if no_license else None),
        "top": sorted(recs, key=lambda x: (x["missing"], x["max"]), reverse=True),
    })
    return out


def _render_m365_section(ctx):
    """Página 🏆 Microsoft Secure Score (dashboard estilo ESA, interativo via JS).
    O shell traz filtros + placeholders; o JS (renderM365) calcula KPIs/pizzas/tabelas sob filtro."""
    m = ctx.get("m365")
    if not m or not m.get("dashboard"):
        return ""
    filters = (
        '<div class="filters"><div class="ftop">'
        '<div class="meta">🔎 Filtros — marque para refinar; vazio = tudo. Tudo recalcula conforme a seleção.</div>'
        '<button class="btn" onclick="clearM365()">Limpar filtros</button></div>'
        '<div class="frow" id="m365frow"></div></div>')
    return (
        "<div class='phase'><h3>🏆 Microsoft Secure Score "
        "<span class='meta'>· Entra ID + Microsoft 365 · Recommended Actions (security.microsoft.com/securescore)</span></h3>"
        + filters +
        "<div class='card'>"
        "<div class='kpis' id='m365kpis'></div>"
        "<div class='pgrid' id='m365pies' style='margin-top:14px'></div>"
        "<h3 style='margin-top:16px'>📦 Recomendações por produto</h3><div id='m365prod'></div>"
        "<h3 style='margin-top:16px'>🎯 Onde concentrar esforço <span class='meta'>· top 12 ações por pontos a recuperar (maior → menor)</span></h3>"
        "<div id='m365bars'></div>"
        "<h3 style='margin-top:16px'>🔧 Ações recomendadas <span class='meta'>· ordenadas por pontos a ganhar</span></h3>"
        "<div id='m365table'></div>"
        "</div></div>")

def _score_card(icon, title, big, big_sub, rows, onclick="", pie=""):
    """Card de score estilo Power BI: ícone + título + número grande + pizza + sub-métricas. rows=[(label,value,color)]."""
    click = (" onclick=\"" + onclick + "\" style=\"cursor:pointer\"") if onclick else ""
    rh = "".join(f"<div class='scrow'><span>{esc(l)}</span><b style='color:{c}'>{esc(str(v))}</b></div>"
                 for l, v, c in rows)
    big_lbl = (f"<div class='scbiglbl'>{esc(big_sub)}</div>" if big_sub else "")
    pie_html = (f"<div class='scpie'>{pie}</div>" if pie else "")
    return (f"<div class='scorecard'{click}><div class='schead'><span class='scic'>{icon}</span>"
            f"<span class='sctitle'>{esc(title)}</span></div>"
            f"<div class='sctop'><div class='scnum'><div class='scbig'>{esc(str(big))}</div>{big_lbl}</div>{pie_html}</div>"
            f"<div class='scrows'>{rh}</div></div>")

def _exec_summary_html(ctx):
    """Resumo executivo consolidado (narrativa server-side a partir do ctx)."""
    n = len(ctx["items"])
    ph = ctx.get("phases", {})
    safe, low, med, high = (len(ph.get(k, [])) for k in ("safe", "low", "medium", "high"))
    ss, ss_pot, ss_delta = ctx.get("secure_score"), ctx.get("secure_score_potential"), ctx.get("secure_score_delta")
    mcsb, xdr, devops, m365 = ctx.get("mcsb"), ctx.get("xdr"), ctx.get("devops"), ctx.get("m365")
    savings = ctx.get("savings_total") or 0
    # pizza de VOLUME de recomendações/ações por origem
    ov = []
    if len(ctx.get("advisor", [])):
        ov.append(("Advisor", len(ctx["advisor"]), "#7cd0ff"))
    if len(ctx.get("mdc", [])):
        ov.append(("Defender for Cloud", len(ctx["mdc"]), "#c9a7ff"))
    if m365 and m365.get("total"):
        ov.append(("Microsoft Secure Score", m365["total"], "#ffd96b"))
    if xdr:
        ov.append(("Defender XDR", xdr["total"], "#9aa7ff"))
    if devops:
        ov.append(("DevOps", devops["total"], "#7ee2a8"))
    pie_block = ""
    if ov:
        pie = _svg_pie(ov, 150)
        legend = "".join(f"<span><i class='dot' style='background:{c}'></i>{esc(l)} · <b>{v}</b></span>" for l, v, c in ov)
        total_actions = sum(v for _, v, _ in ov)
        pie_block = ("<div class='card' style='margin-bottom:14px'><h3 style='margin-top:0'>Volume de recomendações / ações por origem "
                     f"<span class='meta'>· total {total_actions}</span></h3>"
                     "<div style='display:flex;gap:20px;align-items:center;flex-wrap:wrap'>"
                     f"<div>{pie}</div><div class='legend' style='justify-content:flex-start'>{legend}</div></div></div>")
    b = []
    sav_txt = (f" Economia potencial <b style='color:#5ed16a'>−US$ {savings:,.0f}/ano</b>." if savings else "")
    b.append(f"<li><b>Plano de remediação:</b> {n} recomendações — 🟢 {safe} quick wins · 🟡🟠 {low+med} em janela · 🔴 {high} exigem aprovação.{sav_txt}</li>")
    if m365:
        b.append(f"<li><b>Microsoft Secure Score:</b> <b>{m365['pct']}%</b> (Entra ID + Microsoft 365).</li>")
    if ss is not None:
        ptxt = (f" → potencial <b style='color:#9ae6b4'>{ss_pot}%</b> (+{ss_delta} pp se remediar tudo)" if ss_pot is not None else "")
        b.append(f"<li><b>Defender for Cloud — Secure Score:</b> atual <b>{ss}%</b>{ptxt}.</li>")
    if mcsb:
        b.append(f"<li><b>MCSB Compliance:</b> <b>{mcsb.get('compliance_pct')}%</b> de conformidade — {mcsb.get('passed',0)} passed / <b style='color:#ff6b6b'>{mcsb.get('failed',0)} failed</b>.</li>")
    if xdr:
        if xdr.get("mode") == "actions":
            b.append(f"<li><b>Defender XDR — Recommended Actions:</b> {xdr['total']} ações de melhoria do Microsoft Secure Score (<b style='color:#5ed16a'>{xdr.get('points_total',0)}</b> pontos de oportunidade).</li>")
        else:
            b.append(f"<li><b>Defender XDR:</b> {xdr['total']} recomendações — <b style='color:#ff6b6b'>{xdr.get('exploit_total',0)}</b> com exploit público · {xdr.get('exposed_total',0)} máquinas expostas.</li>")
    if devops:
        c = devops['by_severity'].get('Critical', 0)
        h = devops['by_severity'].get('High', 0)
        b.append(f"<li><b>DevOps Remediation:</b> {devops['total']} findings — <b style='color:#ff4d4d'>{c} Critical</b> / <b style='color:#ff6b6b'>{h} High</b>.</li>")
    prio = ("Prioridade sugerida: 🔴 aprovações + Critical/High (XDR/DevOps) → 🟢 quick wins do Secure Score → "
            "controles MCSB em falha.")
    return (pie_block + "<div class='card'><h3 style='margin-top:0'>Visão consolidada</h3>"
            "<ul style='margin:6px 0 0;padding-left:18px;line-height:1.9'>" + "".join(b) + "</ul>"
            f"<div class='meta' style='margin-top:10px'>{prio}</div></div>")

_MDC_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

def _exec_critical_tables(ctx):
    """Tabelas de 'recomendações/controles mais críticos' por pilar (estilo Executive Summary do dashboard).
    Cada linha traz link de acesso rápido (Portal/Referência) à recomendação citada."""
    def _lnk(url, label="Portal ↗"):
        url = (url or "").strip()
        if not url:
            return "<span class='meta'>—</span>"
        return (f"<a href='{esc(url)}' target='_blank' "
                f"style='color:var(--accent);white-space:nowrap;text-decoration:none'>{esc(label)}</a>")
    blocks = []
    mdc = ctx.get("mdc", [])
    if mdc:
        top = sorted(mdc, key=lambda it: _MDC_ORDER.get(str(it.get("priority", "")).lower(), -1), reverse=True)[:6]
        rows = "".join(
            f"<tr><td class='{_SEV_CLASS.get(str(it.get('priority','—')).capitalize(),'sv-informational')}' "
            f"style='font-weight:700;white-space:nowrap'>{esc(str(it.get('priority','—')).capitalize())}</td>"
            f"<td>{esc(it.get('title','—'))}</td>"
            f"<td style='text-align:right'>{_lnk(it.get('portal_link') or it.get('rec_link'))}</td></tr>" for it in top)
        blocks.append(("🛡️ Defender for Cloud — críticas", "<table><tr><th>Sev</th><th>Recomendação</th><th>&nbsp;</th></tr>" + rows + "</table>"))
    m365 = ctx.get("m365")
    if m365 and m365.get("top"):
        m_top = sorted([x for x in m365["top"] if x.get("missing", 0) > 0],
                       key=lambda x: x.get("missing", 0), reverse=True)[:6]
        rows = "".join(
            f"<tr><td>{esc(r['name'])}</td><td class='meta' style='white-space:nowrap'>{esc(r.get('category','—'))}</td>"
            f"<td style='text-align:right;color:#9ae6b4;font-weight:700;white-space:nowrap'>+{round(r.get('missing',0))}</td>"
            f"<td style='text-align:right'>{_lnk(r.get('link'))}</td></tr>" for r in m_top)
        if rows:
            blocks.append(("🏆 Microsoft Secure Score — maior ganho", "<table><tr><th>Ação recomendada</th><th>Categoria</th><th>Pts</th><th>&nbsp;</th></tr>" + rows + "</table>"))
    mcsb = ctx.get("mcsb")
    if mcsb and mcsb.get("failing_controls"):
        fc = mcsb["failing_controls"][:6]
        rows = "".join(
            f"<tr><td class='mono'>{esc(x.get('id',''))}</td><td>{esc(x.get('name',''))}</td>"
            f"<td style='color:#ff6b6b;font-weight:700;text-align:right'>{x.get('failed',0)}</td>"
            f"<td style='text-align:right'>{_lnk(x.get('link'), 'Portal ↗') if x.get('link') else '<span class=meta>—</span>'}</td></tr>" for x in fc)
        blocks.append(("📋 MCSB — controles mais falhando", "<table><tr><th>Controle</th><th>Nome</th><th>Falhas</th><th>&nbsp;</th></tr>" + rows + "</table>"))
    xdr = ctx.get("xdr")
    if xdr and xdr.get("top"):
        if xdr.get("mode") == "actions":
            rows = "".join(
                f"<tr><td>{esc(r['name'])}</td><td class='meta' style='white-space:nowrap'>{esc(r.get('category','—'))}</td>"
                f"<td style='text-align:right;font-weight:700'>{r.get('points',0)}</td></tr>" for r in xdr["top"][:6])
            blocks.append(("🛡️ Defender XDR — recommended actions", "<table><tr><th>Ação</th><th>Categoria</th><th>Pontos</th></tr>" + rows + "</table>"))
        else:
            rows = "".join(
                f"<tr><td class='{_SEV_CLASS.get(r['severity'],'sv-informational')}' style='font-weight:700;white-space:nowrap'>{esc(r['severity'])}</td>"
                f"<td>{esc(r['name'])}</td><td style='text-align:right;font-weight:700'>{r['exposed']}</td></tr>" for r in xdr["top"][:6])
            blocks.append(("🛡️ Defender XDR — críticas", "<table><tr><th>Sev</th><th>Recomendação</th><th>Máq.</th></tr>" + rows + "</table>"))
    devops = ctx.get("devops")
    if devops and devops.get("top_findings"):
        rows = "".join(
            f"<tr><td class='{_SEV_CLASS.get(f.get('severity','—'),'sv-informational')}' style='font-weight:700;white-space:nowrap'>{esc(f.get('severity','—'))}</td>"
            f"<td>{esc(f.get('finding','—'))}</td>"
            f"<td style='text-align:right'>{_lnk(f.get('link'), 'GitHub ↗' if 'github.com' in (f.get('link') or '') else 'Portal ↗')}</td></tr>" for f in devops["top_findings"][:6])
        blocks.append(("🐙 DevOps — findings críticos", "<table><tr><th>Sev</th><th>Finding</th><th>&nbsp;</th></tr>" + rows + "</table>"))
    if not blocks:
        return ""
    cards = "".join(f"<div class='card'><h3 style='margin-top:0;font-size:13px'>{t}</h3>{tbl}</div>" for t, tbl in blocks)
    return ("<h3 style='margin-top:18px'>Recomendações / controles mais críticos "
            "<span class='meta'>· clique em Portal ↗ para abrir a recomendação</span></h3>"
            "<div class='critgrid'>" + cards + "</div>")

def _render_mdc_section(ctx):
    """Página Defender for Cloud (dashboard interativo via JS: KPIs + pizzas + tabela + dropdowns)."""
    if not ctx.get("mdc"):
        return ""
    filters = (
        '<div class="filters"><div class="ftop">'
        '<div class="meta">🔎 Filtros — selecione para refinar; vazio = tudo. Tudo recalcula conforme a seleção.</div>'
        '<button class="btn" onclick="clearMdc()">Limpar filtros</button></div>'
        '<div class="frow" id="mdcfrow"></div></div>')
    return (
        "<div class='phase'><h3><img class='plogo-h' src='" + _DFC_LOGO_URI + "' alt=''>Defender for Cloud — Secure Score "
        "<span class='meta'>· security assessments (postura de nuvem)</span></h3>"
        + filters +
        "<div class='card'>"
        "<div class='kpis' id='mdckpis'></div>"
        "<div class='pgrid' id='mdcpies' style='margin-top:14px'></div>"
        "<h3 style='margin-top:16px'>🔧 Recomendações <span class='meta'>· ordenadas por potencial de elevação do Secure Score (maior → menor)</span></h3>"
        "<div id='mdctable'></div>"
        "</div></div>")


def _render_mcsb_section(ctx):
    """Página Microsoft Cloud Security Benchmark (dashboard interativo via JS, filtro por Subscription)."""
    mcsb = ctx.get("mcsb")
    if not mcsb:
        return ""
    std = esc(mcsb.get("standard_name", ""))
    filters = (
        '<div class="filters"><div class="ftop">'
        '<div class="meta">🔎 Filtro — escolha a(s) subscription(s); vazio = todas. Recalcula a conformidade.</div>'
        '<button class="btn" onclick="clearMcsb()">Limpar filtros</button></div>'
        '<div class="frow" id="mcsbfrow"></div></div>')
    return (
        "<div class='phase'><h3>📋 Microsoft Cloud Security Benchmark "
        "<span class='meta'>· standard: " + std + " (postura de compliance)</span></h3>"
        + filters +
        "<div class='card'>"
        "<div class='kpis' id='mcsbkpis'></div>"
        "<div class='pgrid' id='mcsbpies' style='margin-top:14px'></div>"
        "<h3 style='margin-top:16px'>🔧 Controles em falha <span class='meta'>· por nº de avaliações falhando</span></h3>"
        "<div id='mcsbtable'></div>"
        "</div></div>")


# CSS + JS do relatório interativo (string normal, SEM f-string → não precisa escapar {}).
_REPORT_CSS = """
  :root{
    --bg:#0b0f17;--fg:#e7edf5;--muted:#9fb0c8;--card:#0d1422;--border:#1e2a3f;
    --inset:#0b0f17;--th:#111a2b;--hero1:#121a2b;--hero2:#0d1422;--accent:#7cd0ff;
    --btn:#16223a;--btn-bd:#2a3c5a;--btn-fg:#cfe0f5;--shadow:rgba(0,0,0,.25);
    --sev-critical:#ff4d4d;--sev-high:#ff6b6b;--sev-medium:#ffd96b;--sev-low:#7cd0ff;--sev-info:#9fb0c8;
  }
  :root[data-theme="light"]{
    --bg:#eef1f6;--fg:#1b2733;--muted:#5b6b80;--card:#ffffff;--border:#dce3ec;
    --inset:#eef2f7;--th:#f4f7fb;--hero1:#ffffff;--hero2:#e7f0fb;--accent:#0a66c2;
    --btn:#eef2f7;--btn-bd:#cbd6e4;--btn-fg:#1b2733;--shadow:rgba(20,40,80,.10);
    --sev-critical:#d62828;--sev-high:#e85d04;--sev-medium:#b8860b;--sev-low:#0a66c2;--sev-info:#5b6b80;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;transition:background .2s,color .2s}
  .wrap{max-width:1180px;margin:0 auto;padding:24px}
  .hero{background:linear-gradient(135deg,var(--hero1),var(--hero2));border:1px solid var(--border);border-radius:16px;padding:22px 24px;margin-bottom:14px;box-shadow:0 2px 8px var(--shadow)}
  .hero h1{margin:0;font-size:20px}
  .herotop{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:10px}
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px;margin-top:6px}
  .kpi{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px 10px;text-align:center;box-shadow:0 1px 3px var(--shadow)}
  .kpi .n{font-size:22px;font-weight:800;line-height:1.1} .kpi .l{font-size:11px;color:var(--muted);margin-top:3px}
  h3{font-size:14px;margin:18px 0 8px}
  table{width:100%;border-collapse:collapse;font-size:13px;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
  th{background:var(--th);font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
  .plan-table{table-layout:fixed}
  .plan-table td{overflow-wrap:anywhere;word-break:break-word}
  .mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
  .casc{color:#e0a800;font-size:12px;margin-top:4px}
  .amp{color:#ff9f6b;font-size:12px;margin-top:3px}
  .mtags{margin-top:5px;font-size:11px;color:var(--muted)}
  .mitre{display:inline-block;background:#2a1a3a;border:1px solid #4a2d6b;color:#c9a7ff;border-radius:5px;padding:1px 6px;margin:0 4px 2px 0;font-family:ui-monospace,Consolas,monospace;font-size:11px}
  .owner{color:var(--accent);font-size:11px;margin-top:4px}
  .devops{display:inline-block;background:#10261b;border:1px solid #1f5135;color:#7ee2a8;border-radius:5px;padding:1px 7px;margin-top:4px;font-size:11px}
  .phase{margin-bottom:14px} .meta{color:var(--muted);font-size:12px}
  .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px;box-shadow:0 1px 3px var(--shadow)}
  .filters{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px 14px;margin-bottom:16px;box-shadow:0 1px 3px var(--shadow)}
  .filters .frow{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
  .fbox{min-width:0}
  .flabel{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-bottom:5px;display:flex;justify-content:space-between}
  .fopts{max-height:120px;overflow:auto;background:var(--inset);border:1px solid var(--border);border-radius:8px;padding:6px 8px}
  .fopts label{display:flex;align-items:center;gap:6px;font-size:12px;padding:2px 0;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .fopts input{accent-color:var(--accent)}
  .ftop{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:10px;flex-wrap:wrap}
  .btn{background:var(--btn);border:1px solid var(--btn-bd);color:var(--btn-fg);border-radius:8px;padding:6px 12px;font-size:12px;cursor:pointer}
  .btn:hover{filter:brightness(1.08)}
  .sv-critical{color:var(--sev-critical)} .sv-high{color:var(--sev-high)} .sv-medium{color:var(--sev-medium)} .sv-low{color:var(--sev-low)} .sv-informational{color:var(--sev-info)}
  .dvgrid{display:grid;grid-template-columns:190px 1fr;gap:20px;align-items:center}
  @media(max-width:620px){.dvgrid{grid-template-columns:1fr}}
  .donut .donut-num{font-size:30px;font-weight:800;fill:var(--fg)} .donut .donut-lbl{font-size:11px;fill:var(--muted)}
  .legend{display:flex;flex-wrap:wrap;gap:10px;margin-top:8px;justify-content:center}
  .legend span{font-size:11px;color:var(--muted);display:flex;align-items:center;gap:5px}
  .dot{width:10px;height:10px;border-radius:3px;display:inline-block}
  .bars{margin-top:8px} .barrow{display:grid;grid-template-columns:170px 1fr 42px;gap:10px;align-items:center;margin:6px 0}
  .barlbl{font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .bartrack{display:flex;height:16px;border-radius:6px;overflow:hidden;background:var(--inset);border:1px solid var(--border)}
  .seg{height:100%} .barval{font-size:12px;font-weight:700;text-align:right}
  .topbar{position:sticky;top:0;z-index:10;display:flex;justify-content:space-between;align-items:center;gap:12px;background:var(--card);border:1px solid var(--border);border-radius:14px;padding:9px 14px;margin-bottom:16px;box-shadow:0 2px 8px var(--shadow);flex-wrap:wrap}
  .brand{display:flex;align-items:center;gap:9px;cursor:pointer}
  .mslogo{display:block} .mslogo-sm{height:22px} .mslogo-lg{height:44px}
  .mslogo-wrap{display:inline-flex;align-items:center;border-radius:8px;transition:background .2s}
  :root[data-theme="light"] .mslogo-wrap{background:#0b1220;padding:5px 12px}
  .plogo{height:22px;width:auto;display:inline-block;vertical-align:middle}
  .plogo-h{height:26px;width:auto;vertical-align:middle;margin-right:9px}
  .home-logo{margin-bottom:14px}
  .navlinks{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
  .navbtn{background:transparent;border:1px solid transparent;color:var(--muted);border-radius:8px;padding:6px 10px;font-size:12px;cursor:pointer}
  .navbtn:hover{background:var(--inset);color:var(--fg)}
  .navbtn.active{background:var(--inset);color:var(--fg);border-color:var(--border);font-weight:700}
  .page{animation:fade .18s ease}
  @keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
  .home-hero{text-align:center;padding:24px 16px 4px}
  .home-hero h1{font-size:24px;margin:0 0 6px}
  .navgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-top:10px}
  .navcard{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;cursor:pointer;box-shadow:0 1px 3px var(--shadow);transition:transform .12s,box-shadow .12s,border-color .12s;display:flex;flex-direction:column;gap:3px}
  .navcard:hover{transform:translateY(-3px);box-shadow:0 8px 20px var(--shadow);border-color:var(--accent)}
  .navcard .ic{font-size:26px} .navcard b{font-size:15px} .navcard .big{font-size:26px;font-weight:800;margin-top:2px} .navcard span{color:var(--muted);font-size:12px}
  .back{margin-bottom:12px} h2{font-size:18px;margin:4px 0 12px}
  .scoregrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px;margin-top:8px}
  .scorecard{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:18px 20px;box-shadow:0 1px 3px var(--shadow);transition:transform .12s,box-shadow .12s,border-color .12s}
  .scorecard[onclick]:hover{transform:translateY(-3px);box-shadow:0 8px 20px var(--shadow);border-color:var(--accent)}
  .schead{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px;font-weight:600;min-height:38px}
  .scic{font-size:20px}
  .sctop{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:4px}
  .scnum{min-width:0}
  .scbig{font-size:38px;font-weight:800;text-align:left;margin:0;letter-spacing:-1px;line-height:1.05}
  .scbiglbl{text-align:left;color:var(--muted);font-size:12px;margin-top:2px}
  .scpie{flex-shrink:0} .pie{display:block}
  .scrows{margin-top:10px;border-top:1px solid var(--border);padding-top:8px}
  .scrow{display:flex;justify-content:space-between;align-items:center;font-size:13px;padding:3px 0}
  .scrow span{color:var(--muted)}
  .critgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-top:8px}
  .pgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}
  .piecard{background:var(--inset);border:1px solid var(--border);border-radius:12px;padding:14px 12px;text-align:center}
  .pctitle{font-size:12px;font-weight:700;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:.03em}
  .m365slicers,.slicers{display:flex;flex-wrap:wrap;gap:10px}
  .slicer{position:relative}
  .slicer-btn{display:inline-flex;align-items:center;gap:7px;background:var(--inset);border:1px solid var(--border);color:var(--fg);border-radius:9px;padding:8px 12px;font-size:12px;cursor:pointer;min-width:160px}
  .slicer-btn:hover,.slicer-btn.on{border-color:var(--accent)}
  .slicer-btn .cap{color:var(--muted);font-weight:700}
  .slicer-btn .valtxt{flex:1;text-align:left;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:130px}
  .slicer-btn .car{color:var(--muted);font-size:10px}
  .slicer-pop{position:absolute;z-index:30;top:calc(100% + 4px);left:0;min-width:210px;max-height:250px;overflow:auto;background:var(--card);border:1px solid var(--border);border-radius:10px;box-shadow:0 8px 24px var(--shadow);padding:6px;display:none}
  .slicer-pop.open{display:block}
  .slicer-pop label{display:flex;align-items:center;gap:8px;font-size:12px;padding:5px 8px;border-radius:6px;cursor:pointer;white-space:nowrap}
  .slicer-pop label:hover{background:var(--inset)}
  .slicer-pop input{accent-color:var(--accent)}
  .slicer-clear{display:block;width:100%;text-align:left;background:transparent;border:none;border-bottom:1px solid var(--border);color:var(--accent);font-size:11px;padding:4px 8px;margin-bottom:4px;cursor:pointer}
  @media(max-width:680px){.kpis{grid-template-columns:repeat(3,1fr)}.barrow{grid-template-columns:110px 1fr 34px}}
"""

_REPORT_JS = """
const PHASES=["safe","low","medium","high"];
const PHMETA=DATA.phases_meta;
const DIMS=[["sub","Subscription"],["rg","Resource Group"],["source","Fonte"],["category","Categoria"],["risk","Risco / Fase"],["severity","Severidade"],["repo","Repositório DevOps"]];
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function val(it,dim){if(dim==="sub")return it.subscription_id;if(dim==="rg")return it.resource_group;if(dim==="source")return it.source;if(dim==="category")return it.category;if(dim==="risk")return it.risk;if(dim==="severity")return it.priority;if(dim==="repo")return it.devops_repo||"";return "";}
function label(dim,v){if(dim==="sub"){const s=DATA.subs[v];return (s&&s.name)?s.name:(v?v.slice(0,8):"—");}if(dim==="risk"){return (PHMETA[v]?PHMETA[v].emoji+" "+PHMETA[v].label:v);}return v;}
function uniq(dim){const set=new Set();DATA.items.forEach(it=>{const v=val(it,dim);if(v&&v!=="—")set.add(v);});if(dim==="sub"){Object.keys(DATA.subs||{}).forEach(s=>set.add(s));}return [...set].sort((a,b)=>label(dim,a).localeCompare(label(dim,b)));}
function buildFilters(){const root=document.getElementById("frow");root.className="slicers";DIMS.forEach(([dim,name])=>{const vals=uniq(dim);if(!vals.length)return;const wrap=document.createElement("div");wrap.className="slicer";let opts="";vals.forEach(v=>{opts+=`<label><input type="checkbox" data-dim="${dim}" value="${esc(v)}">${esc(label(dim,v))}</label>`;});wrap.innerHTML=`<button type="button" class="slicer-btn" data-dim="${dim}"><span class="cap">${esc(name)}</span><span class="valtxt">Todos</span><span class="car">▾</span></button><div class="slicer-pop"><button type="button" class="slicer-clear" data-dim="${dim}">Limpar</button>${opts}</div>`;root.appendChild(wrap);});root.querySelectorAll(".slicer-btn").forEach(b=>b.addEventListener("click",function(e){e.stopPropagation();var pop=this.nextElementSibling;var op=pop.classList.contains("open");closeAllSlicers();if(!op)pop.classList.add("open");}));root.querySelectorAll(".slicer-pop").forEach(p=>p.addEventListener("click",e=>e.stopPropagation()));root.querySelectorAll('.slicer-pop input[data-dim]').forEach(cb=>cb.addEventListener("change",function(){planUpdateBtn(this.getAttribute("data-dim"));apply();}));root.querySelectorAll(".slicer-clear").forEach(b=>b.addEventListener("click",function(){var dim=this.getAttribute("data-dim");this.parentNode.querySelectorAll('input[data-dim="'+dim+'"]').forEach(x=>x.checked=false);planUpdateBtn(dim);apply();}));document.addEventListener("click",closeAllSlicers);}
function planUpdateBtn(dim){var btn=document.querySelector('#frow .slicer-btn[data-dim="'+dim+'"]');if(!btn)return;var s=sel(dim);btn.querySelector(".valtxt").textContent=!s.size?"Todos":(s.size===1?label(dim,[...s][0]):s.size+" selecionados");btn.classList.toggle("on",s.size>0);}
function sel(dim){return new Set([...document.querySelectorAll(`input[data-dim="${dim}"]:checked`)].map(c=>c.value));}
function fmtUSD(n,suf){if(!n)return "—";return "US$ "+Math.round(n).toLocaleString("pt-BR")+suf;}
function selectedSubs(){const s=sel("sub");if(s.size)return s;return new Set(Object.keys(DATA.subs||{}));}
function aggSecure(subs){let cur=0,max=0,pot=0,has=false;subs.forEach(sid=>{const s=DATA.subs[sid];if(s&&s.ss_max_points){has=true;cur+=s.ss_current_points;max+=s.ss_max_points;pot+=s.ss_potential_points;}});if(!has||max<=0)return null;return {cur:Math.round(1000*cur/max)/10,pot:Math.round(1000*pot/max)/10};}
function aggMcsb(subs){let p=0,f=0,sk=0,un=0,has=false;subs.forEach(sid=>{const s=DATA.subs[sid];if(s&&s.mcsb){has=true;p+=s.mcsb.passed;f+=s.mcsb.failed;sk+=s.mcsb.skipped;un+=s.mcsb.unsupported;}});if(!has)return null;const a=p+f;return {passed:p,failed:f,skipped:sk,unsupported:un,pct:a>0?Math.round(1000*p/a)/10:null};}
function rowHtml(it){let cs=it.cost_delta?`<span style="color:#5ed16a">${esc(it.cost_delta)}</span>`:"";let ci=it.cost_increase?`<span style="color:#ff6b6b">${esc(it.cost_increase)}</span>`:"";let cost=(cs&&ci)?cs+"<br/>"+ci:(cs||ci||"—");let ss=it.score_impact_label?`<span style="color:#9ae6b4;font-weight:700">${esc(it.score_impact_label)}</span><div class="meta" style="font-size:11px">${esc(it.score_control)}</div>`:"—";let title=esc(it.title);if(it.portal_link){title=`<a href="${esc(it.portal_link)}" style="color:#e7edf5;text-decoration:none;border-bottom:1px dotted #4a5a72">${title}</a> <a href="${esc(it.portal_link)}" title="Abrir no portal" style="color:#7cd0ff;text-decoration:none">🔗</a>`;}const tags=(it.tactics||[]).concat(it.techniques||[]);let mitre=tags.length?`<div class="mtags">🎯 ${tags.slice(0,4).map(m=>`<span class="mitre">${esc(m)}</span>`).join("")}</div>`:"";let owner=it.owner?`<div class="owner">👤 ${esc(it.owner)}</div>`:"";let casc=it.cascade?`<div class="casc">↳ ${esc(it.cascade)}</div>`:"";let dvo=it.devops_repo?`<div class="devops">🐙 ${esc(it.devops_provider||"DevOps")} · ${esc(it.devops_repo)}</div>`:"";let src=`<span style="color:${it.source==="Advisor"?"#7cd0ff":"#c9a7ff"};font-weight:700">${esc(it.source)}</span>`;let subn=it.subscription_name&&it.subscription_name!=="—"?`<div class="meta" style="font-size:11px">${esc(it.subscription_name)} / ${esc(it.resource_group)}</div>`:"";return `<tr><td>${src}</td><td>${title}${dvo}${mitre}${owner}${casc}</td><td>${esc(it.category)}</td><td>${esc(it.priority)}</td><td>${ss}</td><td class="mono">${esc(it.resource_name)}${subn}</td><td>${cost}</td></tr>`;}
function renderPlan(items){const by={safe:[],low:[],medium:[],high:[]};items.forEach(it=>{(by[it.risk]||by.low).push(it);});let html="";const cg='<colgroup><col style="width:8%"><col style="width:33%"><col style="width:11%"><col style="width:9%"><col style="width:12%"><col style="width:17%"><col style="width:10%"></colgroup>';PHASES.forEach(lvl=>{const rows=by[lvl];if(!rows.length)return;const m=PHMETA[lvl]||{};html+=`<div class="phase"><h3>${esc(m.emoji||"")} ${esc(m.label||lvl)} <span class="meta">· ${esc(m.action||"")} · ${rows.length} item(ns)</span></h3><table class="plan-table">${cg}<tr><th>Fonte</th><th>Recomendação</th><th>Categoria</th><th>Prioridade</th><th>Impacto SS</th><th>Recurso</th><th>Custo</th></tr>${rows.map(rowHtml).join("")}</table></div>`;});document.getElementById("plan").innerHTML=html||`<div class="card meta">Nenhuma recomendação para os filtros selecionados.</div>`;}
function renderKpis(items,subs){const c={safe:0,low:0,medium:0,high:0};let sav=0,impl=0,devops=0;items.forEach(it=>{c[it.risk]=(c[it.risk]||0)+1;sav+=it.savings_raw||0;impl+=it.cost_increase_raw||0;if(it.devops_repo)devops++;});const ssA=aggSecure(subs);const mc=aggMcsb(subs);const k=document.getElementById("kpis");let cards=[["#7cd0ff",items.length,"recomendações"],["#5ed16a",c.safe,"🟢 quick wins"],["#ffd96b",c.low+c.medium,"🟡🟠 janela"],["#ff6b6b",c.high,"🔴 aprovação"],["#9fb0c8",ssA?ssA.cur+"%":"n/a","🛡️ SS atual"],["#9ae6b4",ssA?ssA.pot+"%":"n/a","🎯 SS potencial"],["#ff6b6b",impl?"+"+fmtUSD(impl,"/mês"):"—","💰 custo impl."]];if(mc&&mc.pct!=null){const cc=mc.pct>=80?"#5ed16a":(mc.pct>=50?"#ffd96b":"#ff6b6b");cards.push([cc,mc.pct+"%","🛡️ MCSB compliance"]);}if(devops)cards.push(["#7ee2a8",devops,"🐙 DevOps findings"]);k.innerHTML=cards.map(([col,n,l])=>`<div class="kpi"><div class="n" style="color:${col};font-size:${String(n).length>7?"14px":"20px"}">${esc(n)}</div><div class="l">${esc(l)}</div></div>`).join("");document.getElementById("subline").innerHTML=`economia potencial: <b style="color:#5ed16a">${sav?"−"+fmtUSD(sav,"/ano"):"—"}</b> · custo de implementação: <b style="color:#ff6b6b">${impl?"+"+fmtUSD(impl,"/mês"):"—"}</b> · 100% read-only`;const bar=document.getElementById("ssbar");if(ssA){bar.style.display="block";bar.innerHTML=`<div class="meta" style="margin-bottom:4px">🛡️ Secure Score: <b style="color:#9fb0c8">${ssA.cur}%</b> agora → <b style="color:#9ae6b4">${ssA.pot}%</b> se remediar tudo (<b style="color:#9ae6b4">+${Math.round(10*(ssA.pot-ssA.cur))/10} pp</b>)</div><div style="background:var(--inset);border:1px solid var(--border);border-radius:8px;height:14px;overflow:hidden;position:relative"><div style="position:absolute;left:0;top:0;height:100%;width:${ssA.pot}%;background:linear-gradient(90deg,#2d6a4f,#52b788);opacity:.45"></div><div style="position:absolute;left:0;top:0;height:100%;width:${ssA.cur}%;background:linear-gradient(90deg,#7cd0ff,#5ed16a)"></div></div>`;}else{bar.style.display="none";}}
const MDC_SEV_COLOR={"Critical":"#ff4d4d","High":"#ff6b6b","Medium":"#ffd96b","Low":"#7cd0ff","Informational":"#9fb0c8","Unknown":"#9fb0c8"};
const MDCDIMS=[["severity","Severidade"],["category","Categoria"],["sub","Subscription"],["rg","Resource Group"]];
function mdcRaw(it,dim){return dim==="sub"?(it.sub||""):(it[dim]||"—");}
function mdcLabel(dim,v){if(dim==="sub"){var s=DATA.subs[v];return (s&&s.name)?s.name:(v?v.slice(0,8):"—");}return v;}
function mdcUniq(dim){var set=new Set();DATA.mdc.recs.forEach(it=>{var v=mdcRaw(it,dim);if(v&&v!=="—")set.add(v);});return [...set].sort((a,b)=>String(mdcLabel(dim,a)).localeCompare(String(mdcLabel(dim,b))));}
function buildMdcFilters(){var root=document.getElementById("mdcfrow");if(!root)return;root.className="slicers";MDCDIMS.forEach(([dim,name])=>{var vals=mdcUniq(dim);if(vals.length<2)return;var wrap=document.createElement("div");wrap.className="slicer";var opts=vals.map(v=>'<label><input type="checkbox" data-mdcdim="'+dim+'" value="'+esc(v)+'">'+esc(mdcLabel(dim,v))+'</label>').join("");wrap.innerHTML='<button type="button" class="slicer-btn" data-dim="'+dim+'"><span class="cap">'+esc(name)+'</span><span class="valtxt">Todos</span><span class="car">▾</span></button><div class="slicer-pop"><button type="button" class="slicer-clear" data-dim="'+dim+'">Limpar</button>'+opts+'</div>';root.appendChild(wrap);});root.querySelectorAll(".slicer-btn").forEach(b=>b.addEventListener("click",function(e){e.stopPropagation();var pop=this.nextElementSibling;var op=pop.classList.contains("open");closeAllSlicers();if(!op)pop.classList.add("open");}));root.querySelectorAll(".slicer-pop").forEach(p=>p.addEventListener("click",e=>e.stopPropagation()));root.querySelectorAll('.slicer-pop input[data-mdcdim]').forEach(cb=>cb.addEventListener("change",function(){mdcUpdateBtn(this.getAttribute("data-mdcdim"));applyMdc();}));root.querySelectorAll(".slicer-clear").forEach(b=>b.addEventListener("click",function(){var dim=this.getAttribute("data-dim");this.parentNode.querySelectorAll('input[data-mdcdim="'+dim+'"]').forEach(x=>x.checked=false);mdcUpdateBtn(dim);applyMdc();}));document.addEventListener("click",closeAllSlicers);}
function mdcSelDim(dim){return new Set([...document.querySelectorAll('input[data-mdcdim="'+dim+'"]:checked')].map(c=>c.value));}
function mdcUpdateBtn(dim){var btn=document.querySelector('#mdcfrow .slicer-btn[data-dim="'+dim+'"]');if(!btn)return;var s=mdcSelDim(dim);btn.querySelector(".valtxt").textContent=!s.size?"Todos":(s.size===1?mdcLabel(dim,[...s][0]):s.size+" selecionados");btn.classList.toggle("on",s.size>0);}
function clearMdc(){document.querySelectorAll("#mdcfrow input[type=checkbox]").forEach(c=>c.checked=false);MDCDIMS.forEach(d=>mdcUpdateBtn(d[0]));applyMdc();}
function applyMdc(){if(!DATA.mdc)return;var recs=DATA.mdc.recs;MDCDIMS.forEach(([dim])=>{var s=mdcSelDim(dim);if(s.size)recs=recs.filter(it=>s.has(mdcRaw(it,dim)));});renderMdc(recs);}
function renderMdc(recs){var SEVO=["Critical","High","Medium","Low","Informational","Unknown"];var sev={};recs.forEach(x=>{sev[x.severity]=(sev[x.severity]||0)+1;});var hi=(sev["Critical"]||0)+(sev["High"]||0);var kp=[["#1fab89",recs.length,"recomendações"],["#ff6b6b",hi,"🔴 Critical+High"]];SEVO.forEach(s=>{if(sev[s])kp.push([MDC_SEV_COLOR[s],sev[s],s]);});if(DATA.mdc.ss!=null){kp.push(["#9fb0c8",DATA.mdc.ss+"%","🛡️ Secure Score"]);if(DATA.mdc.ss_pot!=null)kp.push(["#9ae6b4",DATA.mdc.ss_pot+"%","🎯 potencial"]);}document.getElementById("mdckpis").innerHTML=kp.map(a=>'<div class="kpi"><div class="n" style="color:'+a[0]+'">'+esc(a[1])+'</div><div class="l">'+esc(a[2])+'</div></div>').join("");var sevSegs=SEVO.filter(s=>sev[s]).map(s=>[s,sev[s],MDC_SEV_COLOR[s]]);var cat={};recs.forEach(x=>{var c=x.category||"—";cat[c]=(cat[c]||0)+1;});var pal=["#7cd0ff","#7ee2a8","#c9a7ff","#ffd96b","#ff9f6b","#9fb0c8"];var catSegs=Object.keys(cat).filter(c=>c!=="—").sort((a,b)=>cat[b]-cat[a]).slice(0,6).map((c,i)=>[c,cat[c],pal[i]||"#9fb0c8"]);var pies=m365PieCard("Severidade",sevSegs);if(catSegs.length>1)pies+=m365PieCard("Categoria",catSegs);document.getElementById("mdcpies").innerHTML=pies;var ord={Critical:5,High:4,Medium:3,Low:2,Informational:1,Unknown:0};var top=recs.slice().sort((a,b)=>{var ai=(a.ss_impact!=null?a.ss_impact:-1),bi=(b.ss_impact!=null?b.ss_impact:-1);if(bi!==ai)return bi-ai;return (ord[b.severity]||0)-(ord[a.severity]||0);}).slice(0,30);document.getElementById("mdctable").innerHTML='<table><tr><th>Sev</th><th>Recomendação</th><th>Impacto SS</th><th>Recurso</th><th>Referência</th></tr>'+top.map(x=>{var rf=x.link?'<a href="'+esc(x.link)+'" target="_blank" style="color:var(--accent);white-space:nowrap">Portal ↗</a>':'<span class="meta">—</span>';var ss=x.ss_label?'<span style="color:#9ae6b4;font-weight:700;white-space:nowrap">'+esc(x.ss_label)+'</span>'+(x.ss_control?'<div class="meta" style="font-size:11px">'+esc(x.ss_control)+'</div>':''):'<span class="meta">—</span>';return '<tr><td style="font-weight:700;white-space:nowrap;color:'+(MDC_SEV_COLOR[x.severity]||"#9fb0c8")+'">'+esc(x.severity)+'</td><td>'+esc(x.title)+'</td><td>'+ss+'</td><td class="mono">'+esc(x.resource)+'</td><td>'+rf+'</td></tr>';}).join("")+'</table>';}
function mcsbSubsAll(){return Object.keys(DATA.subs||{}).filter(s=>DATA.subs[s]&&DATA.subs[s].mcsb);}
function buildMcsbFilters(){var root=document.getElementById("mcsbfrow");if(!root)return;root.className="slicers";var subs=mcsbSubsAll();if(subs.length<2)return;var wrap=document.createElement("div");wrap.className="slicer";var opts=subs.map(s=>'<label><input type="checkbox" data-mcsbdim="sub" value="'+esc(s)+'">'+esc(DATA.subs[s].name||s.slice(0,8))+'</label>').join("");wrap.innerHTML='<button type="button" class="slicer-btn" data-dim="sub"><span class="cap">Subscription</span><span class="valtxt">Todos</span><span class="car">▾</span></button><div class="slicer-pop"><button type="button" class="slicer-clear" data-dim="sub">Limpar</button>'+opts+'</div>';root.appendChild(wrap);root.querySelectorAll(".slicer-btn").forEach(b=>b.addEventListener("click",function(e){e.stopPropagation();var pop=this.nextElementSibling;var op=pop.classList.contains("open");closeAllSlicers();if(!op)pop.classList.add("open");}));root.querySelectorAll(".slicer-pop").forEach(p=>p.addEventListener("click",e=>e.stopPropagation()));root.querySelectorAll('.slicer-pop input[data-mcsbdim]').forEach(cb=>cb.addEventListener("change",function(){mcsbUpdateBtn();applyMcsb();}));root.querySelectorAll(".slicer-clear").forEach(b=>b.addEventListener("click",function(){this.parentNode.querySelectorAll('input[data-mcsbdim]').forEach(x=>x.checked=false);mcsbUpdateBtn();applyMcsb();}));document.addEventListener("click",closeAllSlicers);}
function mcsbSel(){return new Set([...document.querySelectorAll('input[data-mcsbdim="sub"]:checked')].map(c=>c.value));}
function mcsbUpdateBtn(){var btn=document.querySelector('#mcsbfrow .slicer-btn[data-dim="sub"]');if(!btn)return;var s=mcsbSel();btn.querySelector(".valtxt").textContent=!s.size?"Todos":(s.size===1?(DATA.subs[[...s][0]]&&DATA.subs[[...s][0]].name||"1"):s.size+" selecionados");btn.classList.toggle("on",s.size>0);}
function clearMcsb(){document.querySelectorAll("#mcsbfrow input[type=checkbox]").forEach(c=>c.checked=false);mcsbUpdateBtn();applyMcsb();}
function applyMcsb(){if(!DATA.mcsb)return;var s=mcsbSel();var subs=s.size?s:new Set(mcsbSubsAll());renderMcsbDash(subs);}
function renderMcsbDash(subs){var p=0,f=0,sk=0,un=0;subs.forEach(sid=>{var m=DATA.subs[sid]&&DATA.subs[sid].mcsb;if(m){p+=m.passed;f+=m.failed;sk+=m.skipped;un+=m.unsupported;}});var pct=(p+f)>0?Math.round(1000*p/(p+f))/10:null;var cc=(pct||0)>=80?"#5ed16a":((pct||0)>=50?"#ffd96b":"#ff6b6b");var kp=[[cc,(pct!=null?pct+"%":"n/a"),"📋 conformidade"],["#5ed16a",p,"✅ passed"],["#ff6b6b",f,"❌ failed"],["#ffd96b",sk,"⏭️ skipped"],["#aeb8c7",un,"⚪ unsupported"]];document.getElementById("mcsbkpis").innerHTML=kp.map(a=>'<div class="kpi"><div class="n" style="color:'+a[0]+'">'+esc(a[1])+'</div><div class="l">'+esc(a[2])+'</div></div>').join("");var segs=[["Passed",p,"#5ed16a"],["Failed",f,"#ff6b6b"],["Skipped",sk,"#ffd96b"],["Unsupported",un,"#aeb8c7"]];document.getElementById("mcsbpies").innerHTML=m365PieCard("Conformidade",segs);var hasSel=mcsbSel().size>0;var fc=(DATA.mcsb.failing_controls||[]).filter(x=>!hasSel||subs.has(x.subscription_id)).slice(0,20);document.getElementById("mcsbtable").innerHTML='<table><tr><th>Controle</th><th>Nome</th><th style="text-align:right">Falhando</th><th style="text-align:right">OK</th></tr>'+fc.map(x=>{var nm=esc(x.name);if(x.link)nm='<a href="'+esc(x.link)+'" target="_blank" style="color:var(--fg);text-decoration:none;border-bottom:1px dotted #4a5a72">'+nm+'</a>';return '<tr><td class="mono">'+esc(x.id)+'</td><td>'+nm+'</td><td style="text-align:right;color:#ff6b6b;font-weight:700">'+x.failed+'</td><td style="text-align:right;color:#5ed16a">'+x.passed+'</td></tr>';}).join("")+'</table>';}
function apply(){let items=DATA.items;DIMS.forEach(([dim])=>{const s=sel(dim);if(s.size)items=items.filter(it=>s.has(val(it,dim)));});const subs=selectedSubs();renderKpis(items,subs);renderPlan(items);}
function clearAll(){document.querySelectorAll("#frow input[type=checkbox]").forEach(c=>c.checked=false);DIMS.forEach(d=>planUpdateBtn(d[0]));apply();}
function setTheme(t){document.documentElement.setAttribute("data-theme",t);try{localStorage.setItem("ai_theme",t);}catch(e){}var b=document.getElementById("themebtn");if(b)b.textContent=(t==="light"?"🌙 Tema escuro":"☀️ Tema claro");}
function toggleTheme(){var c=document.documentElement.getAttribute("data-theme")||"dark";setTheme(c==="light"?"dark":"light");}
function showPage(id){document.querySelectorAll(".page").forEach(function(p){p.style.display="none";});var el=document.getElementById(id);if(el)el.style.display="block";document.querySelectorAll(".navbtn").forEach(function(b){b.classList.toggle("active",b.getAttribute("data-page")===id);});try{location.hash=id;}catch(e){}window.scrollTo(0,0);}
function goHome(){showPage("home");}
function gotoSource(src){document.querySelectorAll("#frow input[type=checkbox]").forEach(function(c){c.checked=false;});if(src){var box=document.querySelector('#frow input[data-dim="source"][value="'+src.replace(/"/g,'\\\\"')+'"]');if(box)box.checked=true;}DIMS.forEach(d=>planUpdateBtn(d[0]));apply();showPage("page-plan");}
const M365_STATUS_COLOR={"Concluído":"#5ed16a","A endereçar":"#ffb020","Planejado":"#7cd0ff","Em revisão":"#9aa7ff","Risco aceito":"#c9a7ff","Mitigação alternativa":"#f48fb1"};
const M365_CAT_COLOR={"Identity":"#7cd0ff","Device":"#7ee2a8","Apps":"#c9a7ff","Data":"#ffd96b","Account":"#7cd0ff","Infrastructure":"#ff9f6b","—":"#9fb0c8"};
const M365_BUCKET_COLOR={"Alcançado":"#5ed16a","Parcial":"#ffd96b","Oportunidade":"#ff6b6b"};
const M365DIMS=[["status","Status"],["category","Categoria"],["product","Produto"],["bucket","Pontuação"],["license","Licença"]];
function m365Val(it,dim){return dim==="license"?(it.licensed?"Licenciado":"Sem licença"):it[dim];}
function m365Pie(segs,size){size=size||150;var nz=segs.filter(s=>s[1]>0);if(!nz.length)return "";var total=nz.reduce((a,s)=>a+s[1],0)||1;var cx=size/2,cy=size/2,r=size/2-1;if(nz.length===1)return '<svg viewBox="0 0 '+size+' '+size+'" width="'+size+'" height="'+size+'" class="pie"><circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="'+nz[0][2]+'"/></svg>';var ang=-90,p="";nz.forEach(s=>{var f=s[1]/total,a0=ang*Math.PI/180;ang+=f*360;var a1=ang*Math.PI/180,x0=cx+r*Math.cos(a0),y0=cy+r*Math.sin(a0),x1=cx+r*Math.cos(a1),y1=cy+r*Math.sin(a1),lg=f>0.5?1:0;p+='<path d="M'+cx+','+cy+' L'+x0.toFixed(2)+','+y0.toFixed(2)+' A'+r+','+r+' 0 '+lg+' 1 '+x1.toFixed(2)+','+y1.toFixed(2)+' Z" fill="'+s[2]+'"/>';});return '<svg viewBox="0 0 '+size+' '+size+'" width="'+size+'" height="'+size+'" class="pie">'+p+'</svg>';}
function m365PieCard(title,segs){var nz=segs.filter(s=>s[1]);var lg=nz.map(s=>'<span><i class="dot" style="background:'+s[2]+'"></i>'+esc(s[0])+' · '+s[1]+'</span>').join("");return '<div class="piecard"><div class="pctitle">'+esc(title)+'</div>'+m365Pie(nz)+'<div class="legend">'+lg+'</div></div>';}
function m365Uniq(dim){var set=new Set();DATA.m365.recs.forEach(it=>{var v=m365Val(it,dim);if(v&&v!=="—")set.add(v);});return [...set].sort();}
function buildM365Filters(){var root=document.getElementById("m365frow");if(!root)return;root.className="m365slicers";M365DIMS.forEach(([dim,name])=>{var vals=m365Uniq(dim);if(!vals.length)return;var wrap=document.createElement("div");wrap.className="slicer";var opts=vals.map(v=>'<label><input type="checkbox" data-m365dim="'+dim+'" value="'+esc(v)+'">'+esc(v)+'</label>').join("");wrap.innerHTML='<button type="button" class="slicer-btn" data-dim="'+dim+'"><span class="cap">'+esc(name)+'</span><span class="valtxt">Todos</span><span class="car">▾</span></button><div class="slicer-pop"><button type="button" class="slicer-clear" data-dim="'+dim+'">Limpar</button>'+opts+'</div>';root.appendChild(wrap);});root.querySelectorAll(".slicer-btn").forEach(b=>b.addEventListener("click",function(e){e.stopPropagation();var pop=this.nextElementSibling;var op=pop.classList.contains("open");closeAllSlicers();if(!op)pop.classList.add("open");}));root.querySelectorAll(".slicer-pop").forEach(p=>p.addEventListener("click",e=>e.stopPropagation()));root.querySelectorAll('.slicer-pop input[data-m365dim]').forEach(cb=>cb.addEventListener("change",function(){m365UpdateBtn(this.getAttribute("data-m365dim"));applyM365();}));root.querySelectorAll(".slicer-clear").forEach(b=>b.addEventListener("click",function(){var dim=this.getAttribute("data-dim");this.parentNode.querySelectorAll('input[data-m365dim="'+dim+'"]').forEach(x=>x.checked=false);m365UpdateBtn(dim);applyM365();}));document.addEventListener("click",closeAllSlicers);}
function closeAllSlicers(){document.querySelectorAll(".slicer-pop.open").forEach(p=>p.classList.remove("open"));}
function m365UpdateBtn(dim){var btn=document.querySelector('#m365frow .slicer-btn[data-dim="'+dim+'"]');if(!btn)return;var s=m365SelDim(dim);btn.querySelector(".valtxt").textContent=!s.size?"Todos":(s.size===1?[...s][0]:s.size+" selecionados");btn.classList.toggle("on",s.size>0);}
function m365SelDim(dim){return new Set([...document.querySelectorAll('input[data-m365dim="'+dim+'"]:checked')].map(c=>c.value));}
function clearM365(){document.querySelectorAll("#m365frow input[type=checkbox]").forEach(c=>c.checked=false);M365DIMS.forEach(d=>m365UpdateBtn(d[0]));applyM365();}
function applyM365(){if(!DATA.m365)return;var recs=DATA.m365.recs;M365DIMS.forEach(([dim])=>{var s=m365SelDim(dim);if(s.size)recs=recs.filter(it=>s.has(m365Val(it,dim)));});renderM365(recs);}
function renderM365(recs){var d=DATA.m365;var done=recs.filter(x=>x.status==="Concluído").length;var miss=recs.reduce((a,x)=>a+x.missing,0);var nol=recs.filter(x=>!x.licensed).length;var kp=[["#9fb0c8",d.pct+"%","🏆 Secure Score"],["#7cd0ff",recs.length,"recomendações"],["#5ed16a",done,"✅ concluídas"],["#ffb020",recs.length-done,"🟠 a endereçar"],["#9ae6b4","+"+Math.round(miss),"🎯 pontos a ganhar"]];if(nol)kp.push(["#ff6b6b",nol,"⚠️ sem licença"]);document.getElementById("m365kpis").innerHTML=kp.map(a=>'<div class="kpi"><div class="n" style="color:'+a[0]+'">'+esc(a[1])+'</div><div class="l">'+esc(a[2])+'</div></div>').join("");var tal=function(fn){var m={};recs.forEach(x=>{var k=fn(x);m[k]=(m[k]||0)+1;});return m;};var st=tal(x=>x.status),ct=tal(x=>x.category),bk=tal(x=>x.bucket);var sS=Object.keys(st).sort((a,b)=>st[b]-st[a]).map(s=>[s,st[s],M365_STATUS_COLOR[s]||"#9fb0c8"]);var cS=Object.keys(ct).sort((a,b)=>ct[b]-ct[a]).map(c=>[c,ct[c],M365_CAT_COLOR[c]||"#9fb0c8"]);var bS=["Alcançado","Parcial","Oportunidade"].filter(b=>bk[b]).map(b=>[b,bk[b],M365_BUCKET_COLOR[b]]);var pies=m365PieCard("Status",sS)+m365PieCard("Categoria",cS)+m365PieCard("Pontuação",bS);if(recs.some(x=>!x.licensed))pies+=m365PieCard("Licença",[["Licenciado",recs.length-nol,"#5ed16a"],["Sem licença",nol,"#ff6b6b"]]);document.getElementById("m365pies").innerHTML=pies;var pr={};recs.forEach(x=>{var p=pr[x.product]||(pr[x.product]={c:0,t:0,cur:0,mx:0});if(x.status==="Concluído")p.c++;else p.t++;p.cur+=x.score;p.mx+=x.max;});var prows=Object.keys(pr).map(k=>({p:k,c:pr[k].c,t:pr[k].t,g:Math.round((pr[k].mx-pr[k].cur)*10)/10,pct:pr[k].mx?Math.round(100*pr[k].cur/pr[k].mx):0})).sort((a,b)=>b.g-a.g||b.t-a.t).slice(0,15);document.getElementById("m365prod").innerHTML='<table><tr><th>Produto</th><th style="text-align:right">Concluídas</th><th style="text-align:right">A endereçar</th><th style="text-align:right">A ganhar</th><th style="text-align:right">% atingido</th><th>&nbsp;</th></tr>'+prows.map(p=>'<tr><td>'+esc(p.p)+'</td><td style="text-align:right;color:#5ed16a;font-weight:700">'+p.c+'</td><td style="text-align:right;color:#ffb020;font-weight:700">'+p.t+'</td><td style="text-align:right;color:#9ae6b4;font-weight:700">+'+p.g+'</td><td style="text-align:right">'+p.pct+'%</td><td><div class="bartrack" style="height:10px"><span class="seg" style="width:'+p.pct+'%;background:#52b788"></span></div></td></tr>').join("")+'</table>';var srt=recs.slice().filter(x=>x.missing>0).sort((a,b)=>b.missing-a.missing);var tb=srt.slice(0,12);var mv=Math.max.apply(null,[1].concat(tb.map(x=>x.missing)));document.getElementById("m365bars").innerHTML=tb.length?('<div class="bars">'+tb.map(x=>{var w=100*x.missing/mv;return '<div class="barrow"><div class="barlbl" title="'+esc(x.name)+'">'+esc(x.name)+'</div><div class="bartrack"><span class="seg" style="width:'+w.toFixed(1)+'%;background:linear-gradient(90deg,#f59f00,#ffd96b)"></span></div><div class="barval" style="color:#9ae6b4;font-weight:700;white-space:nowrap">+'+(Math.round(x.missing*10)/10)+' pts</div></div>';}).join("")+'</div>'):'<div class="meta" style="padding:8px 0">Todas as ações pontuáveis já estão concluídas. 🎉</div>';document.getElementById("m365table").innerHTML='<table><tr><th>Ação recomendada</th><th>Categoria</th><th>Produto</th><th>Status</th><th style="text-align:right">Pontuação</th><th style="text-align:right">Máx</th><th style="text-align:right">A ganhar</th><th>Referência</th></tr>'+srt.slice(0,30).map(x=>{var sc=M365_STATUS_COLOR[x.status]||"#9fb0c8";var rf=x.link?'<a href="'+esc(x.link)+'" target="_blank" style="color:var(--accent);white-space:nowrap">Portal ↗</a>':'<span class="meta">—</span>';return '<tr><td>'+esc(x.name)+'</td><td class="meta" style="white-space:nowrap">'+esc(x.category)+'</td><td class="meta" style="white-space:nowrap">'+esc(x.product)+'</td><td style="white-space:nowrap;color:'+sc+';font-weight:700">'+esc(x.status)+'</td><td style="text-align:right">'+(+x.score)+'</td><td style="text-align:right" class="meta">'+(+x.max)+'</td><td style="text-align:right;color:#9ae6b4;font-weight:700">+'+(+x.missing)+'</td><td>'+rf+'</td></tr>';}).join("")+'</table>';}
const DEVOPSDIMS=[["repo","Repositório"],["severity","Criticidade"],["category","Categoria"]];
const DEVOPS_SEVO=["Critical","High","Medium","Low","Informational","Unknown"];
function devopsRaw(it,dim){return it[dim]||"—";}
function devopsUniq(dim){var set=new Set();DATA.devops.findings.forEach(it=>{var v=devopsRaw(it,dim);if(v&&v!=="—")set.add(v);});var a=[...set];if(dim==="severity")a.sort((x,y)=>DEVOPS_SEVO.indexOf(x)-DEVOPS_SEVO.indexOf(y));else a.sort((x,y)=>String(x).localeCompare(String(y)));return a;}
function buildDevopsFilters(){var root=document.getElementById("devopsfrow");if(!root)return;root.className="slicers";DEVOPSDIMS.forEach(([dim,name])=>{var vals=devopsUniq(dim);if(vals.length<2)return;var wrap=document.createElement("div");wrap.className="slicer";var opts=vals.map(v=>'<label><input type="checkbox" data-devopsdim="'+dim+'" value="'+esc(v)+'">'+esc(v)+'</label>').join("");wrap.innerHTML='<button type="button" class="slicer-btn" data-dim="'+dim+'"><span class="cap">'+esc(name)+'</span><span class="valtxt">Todos</span><span class="car">▾</span></button><div class="slicer-pop"><button type="button" class="slicer-clear" data-dim="'+dim+'">Limpar</button>'+opts+'</div>';root.appendChild(wrap);});root.querySelectorAll(".slicer-btn").forEach(b=>b.addEventListener("click",function(e){e.stopPropagation();var pop=this.nextElementSibling;var op=pop.classList.contains("open");closeAllSlicers();if(!op)pop.classList.add("open");}));root.querySelectorAll(".slicer-pop").forEach(p=>p.addEventListener("click",e=>e.stopPropagation()));root.querySelectorAll('.slicer-pop input[data-devopsdim]').forEach(cb=>cb.addEventListener("change",function(){devopsUpdateBtn(this.getAttribute("data-devopsdim"));applyDevops();}));root.querySelectorAll(".slicer-clear").forEach(b=>b.addEventListener("click",function(){var dim=this.getAttribute("data-dim");this.parentNode.querySelectorAll('input[data-devopsdim="'+dim+'"]').forEach(x=>x.checked=false);devopsUpdateBtn(dim);applyDevops();}));document.addEventListener("click",closeAllSlicers);}
function devopsSelDim(dim){return new Set([...document.querySelectorAll('input[data-devopsdim="'+dim+'"]:checked')].map(c=>c.value));}
function devopsUpdateBtn(dim){var btn=document.querySelector('#devopsfrow .slicer-btn[data-dim="'+dim+'"]');if(!btn)return;var s=devopsSelDim(dim);btn.querySelector(".valtxt").textContent=!s.size?"Todos":(s.size===1?[...s][0]:s.size+" selecionados");btn.classList.toggle("on",s.size>0);}
function clearDevops(){document.querySelectorAll("#devopsfrow input[type=checkbox]").forEach(c=>c.checked=false);DEVOPSDIMS.forEach(d=>devopsUpdateBtn(d[0]));applyDevops();}
function applyDevops(){if(!DATA.devops)return;var f=DATA.devops.findings;DEVOPSDIMS.forEach(([dim])=>{var s=devopsSelDim(dim);if(s.size)f=f.filter(it=>s.has(devopsRaw(it,dim)));});renderDevops(f);}
function renderDevops(f){var sev={};f.forEach(x=>{sev[x.severity]=(sev[x.severity]||0)+1;});var hi=(sev["Critical"]||0)+(sev["High"]||0);var repos={};f.forEach(x=>{repos[x.repo]=(repos[x.repo]||0)+1;});var kp=[["#1fab89",f.length,"🐙 findings"],["#ff6b6b",hi,"🔴 Critical+High"],["#7cd0ff",Object.keys(repos).length,"repositórios"]];DEVOPS_SEVO.forEach(s=>{if(sev[s])kp.push([MDC_SEV_COLOR[s]||"#9fb0c8",sev[s],s]);});document.getElementById("devopskpis").innerHTML=kp.map(a=>'<div class="kpi"><div class="n" style="color:'+a[0]+'">'+esc(a[1])+'</div><div class="l">'+esc(a[2])+'</div></div>').join("");var sevSegs=DEVOPS_SEVO.filter(s=>sev[s]).map(s=>[s,sev[s],MDC_SEV_COLOR[s]||"#9fb0c8"]);var cat={};f.forEach(x=>{var c=x.category||"—";cat[c]=(cat[c]||0)+1;});var pal=["#7cd0ff","#7ee2a8","#c9a7ff","#ffd96b","#ff9f6b","#9fb0c8"];var catSegs=Object.keys(cat).filter(c=>c!=="—").sort((a,b)=>cat[b]-cat[a]).slice(0,6).map((c,i)=>[c,cat[c],pal[i]||"#9fb0c8"]);var pies=m365PieCard("Criticidade",sevSegs);if(catSegs.length>1)pies+=m365PieCard("Categoria",catSegs);document.getElementById("devopspies").innerHTML=pies;var bysev={};f.forEach(x=>{var r=bysev[x.repo]||(bysev[x.repo]={});r[x.severity]=(r[x.severity]||0)+1;});var sevs=DEVOPS_SEVO.filter(s=>sev[s]);var repoRank=Object.keys(bysev).map(r=>({r:r,t:repos[r],hi:(bysev[r]["Critical"]||0)+(bysev[r]["High"]||0)})).sort((a,b)=>b.hi-a.hi||b.t-a.t).slice(0,20);var mvr=Math.max.apply(null,[1].concat(repoRank.map(o=>o.t)));document.getElementById("devopsbars").innerHTML=repoRank.length?('<div class="bars">'+repoRank.map(o=>{var segs=sevs.map(s=>{var c=bysev[o.r][s]||0;return c?'<span class="seg" style="width:'+(100*c/mvr).toFixed(1)+'%;background:'+(MDC_SEV_COLOR[s]||"#9fb0c8")+'" title="'+esc(s)+': '+c+'"></span>':'';}).join("");return '<div class="barrow"><div class="barlbl" title="'+esc(o.r)+'">🐙 '+esc(o.r)+'</div><div class="bartrack">'+segs+'</div><div class="barval">'+o.t+'</div></div>';}).join("")+'</div><div class="legend" style="margin-top:8px">'+sevs.map(s=>'<span><i class="dot" style="background:'+(MDC_SEV_COLOR[s]||"#9fb0c8")+'"></i>'+esc(s)+'</span>').join("")+'</div>'):'<div class="meta">Nenhum finding para os filtros.</div>';var ord={Critical:5,High:4,Medium:3,Low:2,Informational:1,Unknown:0};var top=f.slice().sort((a,b)=>(ord[b.severity]||0)-(ord[a.severity]||0)).slice(0,40);document.getElementById("devopstable").innerHTML='<table><tr><th>Criticidade</th><th>Repositório</th><th>Finding</th><th>Categoria</th><th>Referência</th></tr>'+top.map(x=>{var rf=x.link?'<a href="'+esc(x.link)+'" target="_blank" style="color:var(--accent);white-space:nowrap">'+(x.link.indexOf("github.com")>=0?"GitHub ↗":"Portal ↗")+'</a>':'<span class="meta">—</span>';return '<tr><td style="font-weight:700;white-space:nowrap;color:'+(MDC_SEV_COLOR[x.severity]||"#9fb0c8")+'">'+esc(x.severity)+'</td><td class="mono">🐙 '+esc(x.repo)+'</td><td>'+esc(x.finding)+'</td><td class="meta" style="white-space:nowrap">'+esc(x.category)+'</td><td>'+rf+'</td></tr>';}).join("")+'</table>'+(f.length>40?'<div class="meta" style="margin-top:6px">… +'+(f.length-40)+' findings (priorize Critical→High).</div>':'');}
(function(){var t="dark";try{t=localStorage.getItem("ai_theme")||"dark";}catch(e){}setTheme(t);})();
buildFilters();apply();
if(DATA.m365){buildM365Filters();applyM365();}
if(DATA.mdc){buildMdcFilters();applyMdc();}
if(DATA.mcsb){buildMcsbFilters();applyMcsb();}
if(DATA.devops){buildDevopsFilters();applyDevops();}
(function(){var h=(location.hash||"").replace("#","");showPage(h&&document.getElementById(h)?h:"home");})();
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

    m365_ctx = ctx.get("m365")
    m365_js = None
    if m365_ctx and m365_ctx.get("dashboard"):
        m365_js = {
            "pct": m365_ctx["pct"],
            "recs": [
                {"name": x["name"], "category": x["category"], "product": x["product"],
                 "status": x["status"], "bucket": x["bucket"], "score": x["score"],
                 "max": x["max"], "missing": x["missing"], "licensed": bool(x["licensed"]),
                 "link": x.get("link", "")}
                for x in (m365_ctx.get("top") or [])
            ],
        }

    mdc_ctx = ctx.get("mdc") or []
    mdc_js = None
    if mdc_ctx:
        mdc_js = {
            "ss": ctx.get("secure_score"), "ss_pot": ctx.get("secure_score_potential"),
            "recs": [
                {"title": it.get("title") or "—",
                 "severity": str(it.get("priority", "—")).capitalize(),
                 "category": it.get("category") or "—",
                 "resource": it.get("resource_name") or "—",
                 "link": it.get("portal_link") or it.get("rec_link") or "",
                 "sub": it.get("subscription_id") or "",
                 "rg": it.get("resource_group") or "—",
                 "ss_impact": it.get("score_impact_pct"),
                 "ss_label": it.get("score_impact_label") or "",
                 "ss_control": it.get("score_control") or ""}
                for it in mdc_ctx
            ],
        }

    devops_ctx = ctx.get("devops")
    devops_js = None
    if devops_ctx and devops_ctx.get("findings"):
        devops_js = {
            "sev_order": devops_ctx.get("sev_order", []),
            "findings": [
                {"repo": f.get("repo", "—"), "severity": f.get("severity", "—"),
                 "category": f.get("category", "—"), "finding": f.get("finding", "—"),
                 "provider": f.get("provider", ""), "link": f.get("link", "") or ""}
                for f in devops_ctx["findings"]
            ],
        }

    data = {
        "items": [slim(it) for it in ctx["items"]],
        "subs": ctx.get("subs", {}),
        "phases_meta": phases_meta,
        "mcsb": mcsb_js,
        "m365": m365_js,
        "mdc": mdc_js,
        "devops": devops_js,
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

    generated = esc(ctx.get("generated", ""))
    mcsb_pct = ctx["mcsb"].get("compliance_pct") if ctx.get("mcsb") else None
    devops_total = ctx["devops"]["total"] if ctx.get("devops") else 0
    xdr = ctx.get("xdr")
    xdr_total = xdr["total"] if xdr else 0
    mcsb = ctx.get("mcsb")
    m365 = ctx.get("m365")
    ss, ss_pot, ss_delta = ctx.get("secure_score"), ctx.get("secure_score_potential"), ctx.get("secure_score_delta")
    n_adv = len(ctx.get("advisor", []))
    n_mdc = len(ctx.get("mdc", []))
    n_high_mdc = sum(1 for it in ctx.get("mdc", []) if str(it.get("priority", "")).lower() in ("high", "critical"))

    logo_svg = ('<img class="mslogo mslogo-lg" src="' + _LOGO_DATA_URI + '" alt="Microsoft Security">')
    logo_sm = ('<img class="mslogo mslogo-sm" src="' + _LOGO_DATA_URI + '" alt="Microsoft Security">')

    # ---- barra superior (sempre visível) ----
    nav_extra = "<button class=\"navbtn\" data-page=\"page-exec\" onclick=\"showPage('page-exec')\">📊 Resumo Executivo</button>"
    if m365 and m365.get("dashboard"):
        nav_extra += "<button class=\"navbtn\" data-page=\"page-m365\" onclick=\"showPage('page-m365')\">🏆 Microsoft Secure Score</button>"
    if n_adv:
        nav_extra += "<button class=\"navbtn\" data-page=\"page-plan\" onclick=\"gotoSource('Advisor')\">📘 Advisor</button>"
    if n_mdc:
        nav_extra += "<button class=\"navbtn\" data-page=\"page-mdc\" onclick=\"showPage('page-mdc')\">🛡️ Defender for Cloud</button>"
    if mcsb_pct is not None:
        nav_extra += "<button class=\"navbtn\" data-page=\"page-mcsb\" onclick=\"showPage('page-mcsb')\">📋 MCSB</button>"
    if devops_total:
        nav_extra += "<button class=\"navbtn\" data-page=\"page-devops\" onclick=\"showPage('page-devops')\">🐙 DevOps</button>"
    topbar = (
        '<div class="topbar"><div class="brand" onclick="goHome()"><span class="mslogo-wrap">' + logo_sm + '</span></div>'
        '<div class="navlinks">'
        '<button class="navbtn" data-page="home" onclick="showPage(\'home\')">🏠 Início</button>'
        + nav_extra +
        '<button id="themebtn" class="btn" onclick="toggleTheme()">☀️ Tema claro</button></div></div>')

    # ---- cards de SCORE na home (estilo Power BI: só os scores, bem clean) ----
    mdc_by_sev = {}
    for it in ctx.get("mdc", []):
        s = str(it.get("priority", "—")).capitalize()
        mdc_by_sev[s] = mdc_by_sev.get(s, 0) + 1
    _SEVS = ["Critical", "High", "Medium", "Low", "Informational"]
    score_cards = ""
    if m365:
        m_pie = _svg_pie([("Obtidos", m365['current'], "#5ed16a"),
                          ("Restantes", max(m365['max'] - m365['current'], 0), "#aeb8c7")])
        m_click = "showPage('page-m365')" if m365.get('dashboard') else "showPage('page-exec')"
        score_cards += _score_card("🏆", "Microsoft Secure Score", f"{m365['pct']}%", "Entra ID + Microsoft 365",
            [("Pontos atuais", m365['current'], "var(--accent)"),
             ("Pontos máximos", m365['max'], "var(--muted)"),
             ("Controles avaliados", m365['controls'], "var(--muted)")],
            m_click, m_pie)
    if ss is not None:
        d_pie = _svg_pie([(s, mdc_by_sev.get(s, 0), _SEV_COLOR.get(s, '#9fb0c8')) for s in _SEVS])
        score_cards += _score_card("<img class='plogo' src='" + _DFC_LOGO_URI + "' alt=''>", "Defender for Cloud — Secure Score", f"{ss}%", "postura de nuvem",
            [("Potencial", f"{ss_pot}%" if ss_pot is not None else "—", "#5ed16a"),
             ("Elevação possível", f"+{ss_delta} pp" if ss_delta is not None else "—", "#5ed16a"),
             ("Recomendações", n_mdc, "var(--fg)"),
             ("Severidade alta", n_high_mdc, "#ff6b6b")],
            "showPage('page-mdc')", d_pie)
    if mcsb:
        c_pie = _svg_pie([("Passed", mcsb.get('passed', 0), "#5ed16a"),
                          ("Failed", mcsb.get('failed', 0), "#ff6b6b"),
                          ("Skipped", mcsb.get('skipped', 0), "#ffd96b"),
                          ("Unsupported", mcsb.get('unsupported', 0), "#aeb8c7")])
        score_cards += _score_card("📋", "MCSB Compliance", f"{mcsb_pct}%" if mcsb_pct is not None else "n/a",
            "Microsoft Cloud Security Benchmark",
            [("Passed", mcsb.get('passed', 0), "#5ed16a"),
             ("Failed", mcsb.get('failed', 0), "#ff6b6b"),
             ("Skipped", mcsb.get('skipped', 0), "var(--muted)"),
             ("Unsupported", mcsb.get('unsupported', 0), "var(--muted)")],
            "showPage('page-mcsb')", c_pie)
    if not score_cards:
        score_cards = ("<div class=\"navcard\" onclick=\"showPage('page-plan')\"><div class=\"ic\">🧭</div>"
                       "<b>Plano de Remediação</b><div class=\"big\">" + str(n) + "</div>"
                       "<span>recomendações priorizadas por risco</span></div>")

    home = (
        '<div id="home" class="page"><div class="home-hero"><span class="mslogo-wrap home-logo">' + logo_svg + '</span>'
        '<h1>Plano de Remediação</h1>'
        '<div class="meta">Advisor + Microsoft Defender for Cloud · escopo <b>' + scope + '</b> · '
        + str(n) + ' recomendação(ões) · ' + str(nsubs) + ' subscription(s) · gerado ' + generated + '</div></div>'
        '<div class="scoregrid">' + score_cards + '</div></div>')

    # ---- Resumo Executivo (estilo dashboard: score cards + tabelas críticas + visão consolidada) ----
    page_exec = (
        '<div id="page-exec" class="page" style="display:none">'
        '<button class="btn back" onclick="goHome()">← Início</button>'
        '<h2>📊 Resumo Executivo</h2>'
        '<div class="scoregrid">' + score_cards + '</div>'
        + _exec_critical_tables(ctx)
        + '<div style="margin-top:14px"></div>'
        + _exec_summary_html(ctx)
        + '<div class="kpis" id="kpis" style="display:none"></div>'
        '<div id="ssbar" style="display:none"></div>'
        '<div class="meta" id="subline" style="display:none"></div></div>')

    page_mdc = (
        '<div id="page-mdc" class="page" style="display:none">'
        '<button class="btn back" onclick="goHome()">← Início</button>'
        + _render_mdc_section(ctx) + '</div>') if ctx.get("mdc") else ''

    page_m365 = (
        '<div id="page-m365" class="page" style="display:none">'
        '<button class="btn back" onclick="goHome()">← Início</button>'
        + _render_m365_section(ctx) + '</div>') if (m365 and m365.get("dashboard")) else ''

    filters = (
        '<div class="filters"><div class="ftop"><div class="meta">🔎 Filtros — marque para refinar; '
        'vazio = tudo. O Secure Score recalcula pelo filtro de Subscription.</div>'
        '<button class="btn" onclick="clearAll()">Limpar filtros</button></div>'
        '<div class="frow" id="frow"></div></div>')
    devops_html = _render_devops_section(ctx.get("devops"))

    page_plan = (
        '<div id="page-plan" class="page" style="display:none">'
        '<button class="btn back" onclick="goHome()">← Início</button>'
        '<h2>🧭 Plano de Remediação <span class="meta">· Advisor + Defender for Cloud · por fase de risco de aplicar</span></h2>'
        + filters + '<div id="plan"></div></div>')
    page_mcsb = (
        '<div id="page-mcsb" class="page" style="display:none">'
        '<button class="btn back" onclick="goHome()">← Início</button>'
        + _render_mcsb_section(ctx) + '</div>') if ctx.get("mcsb") else ''
    page_devops = (
        '<div id="page-devops" class="page" style="display:none">'
        '<button class="btn back" onclick="goHome()">← Início</button>'
        + devops_html + '</div>')

    footer = ('<div class="meta" style="margin-top:20px;border-top:1px solid var(--border);padding-top:12px">'
              'advisor-impact · Azure Advisor + Microsoft Defender for Cloud · risco = disrupção de aplicar '
              '(não criticidade). Custos via Azure Retail Prices API · Compliance via MCSB '
              '(inspirado no <a href="https://github.com/microsoft/ESA" style="color:var(--accent)">microsoft/ESA</a>).</div>')

    body = topbar + home + page_exec + page_mdc + page_m365 + page_plan + page_mcsb + page_devops + footer + '</div>'
    script = '<script>const DATA=' + data_json + ';\n' + _REPORT_JS + '</script>'
    return head + body + script + '</body></html>'

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
        # tabela de findings com referência clicável por finding
        tf = devops.get("top_findings") or []
        if tf:
            LIMIT = 25
            lines.append("### 🔧 Findings a corrigir (por severidade · clique na referência p/ a recomendação)")
            lines.append("| Sev | Repositório | Finding | Categoria | Referência |")
            lines.append("|---|---|---|---|---|")
            for f in tf[:LIMIT]:
                fnd = (f.get("finding", "—") or "—").replace("|", "\\|").replace("\n", " ")
                link = f.get("link", "") or ""
                if link:
                    label = "GitHub" if "github.com" in link else "Portal"
                    link_md = f"[{label}]({link})"
                else:
                    link_md = "—"
                lines.append(f"| {f.get('severity','—')} | 🐙 {f.get('repo','—')} | {fnd} | {f.get('category','—')} | {link_md} |")
            if len(tf) > LIMIT:
                lines.append("")
                lines.append(f"_… +{len(tf) - LIMIT} findings (priorize Critical→High; abra a referência p/ a lista completa)._")
            lines.append("")
    lines.append(f"_advisor-impact · gerado {ctx['generated']} · read-only · MCSB inspirado no microsoft/ESA (MIT)._")
    return "\n".join(lines)

# =============================================================================
# main
# =============================================================================
def _validate_links(ctx):
    """Valida cobertura de links: TODA recomendação deve ter link clicável e, de preferência,
    o deep link DIRETO da recomendação. Classifica direct/resource/generic/missing e imprime no stderr."""
    generic = {_ADVISOR_PORTAL, _MDC_RECS_PORTAL, _M365_SECURESCORE_PORTAL}

    def classify(link):
        if not link:
            return "missing"
        if link in generic:
            return "generic"
        if "/#@/resource/" in link and link.endswith("/overview"):
            return "resource"
        return "direct"

    def tally(links):
        c = {"direct": 0, "resource": 0, "generic": 0, "missing": 0}
        for l in links:
            c[classify(l)] += 1
        return c

    sections = {
        "Plano (Advisor+Defender)": [it.get("portal_link", "") for it in ctx.get("items", [])],
        "Microsoft Secure Score": [x.get("link", "") for x in ((ctx.get("m365") or {}).get("top") or [])],
        "MCSB": [fc.get("link", "") for fc in ((ctx.get("mcsb") or {}).get("failing_controls") or [])],
    }
    total = 0
    missing = 0
    sys.stderr.write("🔗 Validação de links (acesso rápido à recomendação):\n")
    for name, links in sections.items():
        if not links:
            continue
        c = tally(links)
        n = len(links)
        total += n
        missing += c["missing"]
        sys.stderr.write(f"   · {name}: {n} recs — {c['direct']} diretos · {c['resource']} recurso · "
                         f"{c['generic']} genérico · {c['missing']} SEM LINK\n")
    devops = (ctx.get("devops") or {}).get("total")
    if devops:
        sys.stderr.write(f"   · DevOps: {devops} findings — link sempre presente (portal ou aba Security do repo)\n")
    status = "✅ todas as recomendações têm link" if missing == 0 else f"⚠️ {missing} recomendação(ões) SEM link"
    sys.stderr.write(f"   {status} (total {total})\n")
    return missing


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
    _validate_links(ctx)
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

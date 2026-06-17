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
import argparse, datetime as dt, html, json, os, shutil, subprocess, sys
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

def _enrich(item, resource_id, risk, rmap, q, region="eastus2"):
    res = rmap.get(str(resource_id or "").lower(), {})
    item["resource_id"] = resource_id or ""
    item["resource_name"] = res.get("name") or (resource_id.split("/")[-1] if resource_id else "—")
    item["resource_type"] = res.get("type") or "—"
    # Link oficial da recomendação (MDC fornece em links.azurePortal) tem prioridade;
    # senão cai p/ deep link determinístico do recurso.
    item["portal_link"] = item.get("rec_link") or _portal_resource_link(resource_id)
    loc = res.get("location") or region
    amps = []
    if resource_id and not res:
        amps.append("Recurso não encontrado no inventário — verificar manualmente")
    item["amplifiers"] = amps
    if resource_id and risk in ("low", "medium", "high"):
        item["cascade"] = q.get("cascade_template", "").replace("{resource}", item["resource_name"])
    if resource_id and risk in ("medium", "high"):
        item["validation"] = [s.replace("{resource}", item["resource_name"]) for s in (q.get("validation_steps") or [])]
    
    # Estimar custo de implementação (se aplicável)
    impl_cost = fetch_implementation_cost(item.get("title", ""), loc)
    if impl_cost and impl_cost["cost_month"] > 0:
        item["cost_increase"] = f"+US$ {impl_cost['cost_month']:,.2f}/mês ({impl_cost['note']}, {impl_cost['confidence']})"
        item["cost_increase_raw"] = impl_cost["cost_month"]
    return item

def analyze_advisor(data, rmap, q, category):
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
        out.append(_enrich(item, prop(props, "resourceMetadata.resourceId", ""), risk, rmap, q))
    return out

def analyze_mdc(data, rmap, q, rg, include_healthy):
    rb = q.get("risk_baseline", {})
    out = []
    for a in as_list(data):
        props = a.get("properties", {}) or {}
        code = prop(props, "status.code", "Unknown")
        if not include_healthy and code.lower() != "unhealthy":
            continue
        rid = prop(props, "resourceDetails.Id") or prop(props, "resourceDetails.ResourceId") or ""
        item_rg = _rg_of(rid)
        # mantém: recurso no RG-alvo OU assessment de nível subscription (sem RG)
        if item_rg and item_rg != rg.lower():
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
        out.append(_enrich(item, rid, risk, rmap, q))
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
    Processa secureScoreControls (com $expand=definition) p/ calcular:
      - elevação potencial do secure score (se TODAS as recomendações forem remediadas)
      - mapa assessment_guid → controle (p/ impacto por recomendação)
    Fórmula MCSB: score_por_recurso = max / (saudáveis + não-saudáveis);
                  potencial do controle = score_por_recurso × não-saudáveis.
    Retorna None se Defender for Cloud não estiver habilitado (degrada para n/a).
    """
    controls = as_list(data)
    if not controls:
        return None
    a2c = {}
    current_total = 0.0
    max_total = 0.0
    potential_total = 0.0
    for c in controls:
        p = c.get("properties", {}) or {}
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
        current_total += cur
        max_total += mx
        potential_total += potential
        defn = (p.get("definition", {}) or {}).get("properties", {}) or {}
        for ad in defn.get("assessmentDefinitions", []) or []:
            guid = str(ad.get("id", "")).rstrip("/").split("/")[-1].lower()
            if guid:
                a2c[guid] = ctrl
    if max_total <= 0:
        return None
    current_pct = round(100.0 * current_total / max_total, 1)
    potential_pct = round(100.0 * min(current_total + potential_total, max_total) / max_total, 1)
    return {
        "assessment_to_control": a2c,
        "current_pct": current_pct,
        "potential_pct": potential_pct,
        "delta_pct": round(potential_pct - current_pct, 1),
        "max_total": max_total,
        "current_total": current_total,
        "potential_points": potential_total,
    }

def parse_mcsb_compliance(standards_data, controls_data, std_name, preferred_names):
    """
    Pilar MCSB (ESA): postura de compliance contra o Microsoft Cloud Security Benchmark.
    Headline = passed/failed/skipped/unsupported controls do standard.
    Detalhe = controles que estão FAILED (com nº de assessments falhando).
    Retorna None se o standard MCSB não estiver atribuído (degrada).
    """
    standards = as_list(standards_data)
    if not standards:
        return None
    # Acha o standard MCSB (pelo nome descoberto, ou pelos nomes conhecidos, ou substring)
    target = None
    wanted = set([std_name] if std_name else []) | set(preferred_names or [])
    for s in standards:
        nm = str(s.get("name", ""))
        if nm in wanted:
            target = s
            break
    if not target:
        for s in standards:
            low = str(s.get("name", "")).lower().replace("-", " ")
            if "cloud security benchmark" in low or "azure security benchmark" in low:
                target = s
                break
    if not target:
        return None
    p = target.get("properties", {}) or {}
    passed = int(p.get("passedControls", 0) or 0)
    failed = int(p.get("failedControls", 0) or 0)
    skipped = int(p.get("skippedControls", 0) or 0)
    unsupported = int(p.get("unsupportedControls", 0) or 0)
    assessable = passed + failed
    compliance_pct = round(100.0 * passed / assessable, 1) if assessable > 0 else None

    # Controles em falha (detalhe)
    failing = []
    for c in as_list(controls_data):
        cp = c.get("properties", {}) or {}
        state = str(cp.get("state", "")).lower()
        if state != "failed":
            continue
        failing.append({
            "id": str(c.get("name", "")),
            "name": cp.get("description", "") or str(c.get("name", "")),
            "failed": int(cp.get("failedAssessments", 0) or 0),
            "passed": int(cp.get("passedAssessments", 0) or 0),
            "skipped": int(cp.get("skippedAssessments", 0) or 0),
            "link": prop(cp, "links.azurePortal", "") or "",
        })
    failing.sort(key=lambda x: x["failed"], reverse=True)
    return {
        "standard_name": str(target.get("name", "")),
        "state": str(p.get("state", "")),
        "passed": passed, "failed": failed, "skipped": skipped, "unsupported": unsupported,
        "compliance_pct": compliance_pct,
        "failing_controls": failing,
    }

# =============================================================================
# Build context
# =============================================================================
def build_context(q, raw, params):
    rmap = build_resource_map(raw.get("resource_inventory"))
    advisor = analyze_advisor(raw.get("advisor_recommendations"), rmap, q, params.get("category", "all"))
    mdc = analyze_mdc(raw.get("mdc_assessments"), rmap, q, params.get("_rg", ""), params.get("include_healthy", False))
    items = advisor + mdc

    # Secure score por controle → elevação potencial + impacto por recomendação
    ss_controls = parse_secure_score_controls(raw.get("mdc_secure_score_controls"))
    if ss_controls:
        a2c = ss_controls["assessment_to_control"]
        max_total = ss_controls["max_total"]
        for it in mdc:
            ctrl = a2c.get(it.get("assessment_key", ""))
            if ctrl and max_total > 0:
                # impacto de remediar ESTE recurso = score_por_recurso / total × 100
                impact_pct = round(100.0 * ctrl["per_resource"] / max_total, 2)
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

    # secure score: atual + potencial. Prioriza o cálculo por controle; cai p/ headline.
    secure_score = parse_secure_score(raw.get("mdc_secure_score"))
    if secure_score is None and ss_controls:
        secure_score = ss_controls["current_pct"]
    secure_score_potential = ss_controls["potential_pct"] if ss_controls else None
    # delta relativo ao score EXIBIDO (mantém atual + delta = potencial, mesmo se
    # headline e soma-dos-controles divergirem por arredondamento/escopo).
    secure_score_delta = None
    if secure_score is not None and secure_score_potential is not None:
        secure_score_delta = round(max(secure_score_potential - secure_score, 0.0), 1)

    # Pilar MCSB (compliance regulatório) — ESA
    mcsb = parse_mcsb_compliance(
        raw.get("mcsb_compliance_standards"),
        raw.get("mcsb_compliance_controls"),
        raw.get("_mcsb_standard_name", ""),
        q.get("mcsb_standard_names", []),
    )

    return {
        "items": items, "advisor": advisor, "mdc": mdc, "phases": phases,
        "secure_score": secure_score,
        "secure_score_potential": secure_score_potential,
        "secure_score_delta": secure_score_delta,
        "mcsb": mcsb,
        "resources_in_scope": len(rmap),
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

def render_html(ctx, q):
    rb_emoji = q.get("risk_emoji", {})
    ph = q.get("phases", {})
    ss = ctx["secure_score"]
    ss_txt = f"{ss}%" if ss is not None else "n/a"
    ss_pot = ctx.get("secure_score_potential")
    ss_delta = ctx.get("secure_score_delta")
    ss_pot_txt = f"{ss_pot}%" if ss_pot is not None else "n/a"
    ss_delta_txt = f"+{ss_delta} pp" if ss_delta else ("—" if ss_delta is None else "0 pp")
    n = len(ctx["items"])
    counts = {k: len(v) for k, v in ctx["phases"].items()}

    # phased plan
    plan_html = ""
    for lvl in ("safe", "low", "medium", "high"):
        rows = ctx["phases"][lvl]
        if not rows:
            continue
        meta = ph.get(lvl, {})
        head = f"{meta.get('emoji','')} {esc(meta.get('label', lvl))} <span class='meta'>· {esc(meta.get('action',''))} · {len(rows)} item(ns)</span>"
        body = ""
        for it in rows:
            # Economia (verde) - do Advisor
            cost_save = f"<span style='color:#5ed16a'>{esc(it['cost_delta'])}</span>" if it.get("cost_delta") else ""
            # Custo de implementação (vermelho) - estimado via Retail Prices API
            cost_impl = f"<span style='color:#ff6b6b'>{esc(it['cost_increase'])}</span>" if it.get("cost_increase") else ""
            cost_cell = cost_save or cost_impl or "—"
            if cost_save and cost_impl:
                cost_cell = f"{cost_save}<br/>{cost_impl}"
            # Impacto no secure score (Defender for Cloud)
            if it.get("score_impact_label"):
                ctrl = esc(it.get("score_control") or "")
                ss_cell = (f"<span style='color:#9ae6b4;font-weight:700'>{esc(it['score_impact_label'])}</span>"
                           f"<div class='meta' style='font-size:11px'>{ctrl}</div>")
            else:
                ss_cell = "—"
            # Link direto para o recurso/recomendação no portal
            link = it.get("portal_link")
            title_html = esc(it['title'])
            if link:
                title_html = f"<a href='{esc(link)}' style='color:#e7edf5;text-decoration:none;border-bottom:1px dotted #4a5a72'>{title_html}</a> <a href='{esc(link)}' title='Abrir no portal' style='color:#7cd0ff;text-decoration:none'>🔗</a>"
            # MITRE ATT&CK (táticas/técnicas vindas da metadata do assessment)
            mitre = ""
            mtags = (it.get("tactics") or []) + (it.get("techniques") or [])
            if mtags:
                badges = "".join(f"<span class='mitre'>{esc(str(m))}</span>" for m in mtags[:4])
                mitre = f"<div class='mtags'>🎯 {badges}</div>"
            # Owner (governança — quem responde pela remediação)
            owner = f"<div class='owner'>👤 {esc(it.get('owner'))}</div>" if it.get("owner") else ""
            casc = f"<div class='casc'>↳ {esc(it.get('cascade'))}</div>" if it.get("cascade") else ""
            amps = "".join(f"<div class='amp'>⚠ {esc(a)}</div>" for a in it.get("amplifiers", []))
            body += (f"<tr><td>{_src_badge(it['source'])}</td><td>{title_html}{mitre}{owner}{casc}{amps}</td>"
                     f"<td>{esc(it.get('category') or '—')}</td><td>{esc(it.get('priority'))}</td>"
                     f"<td>{ss_cell}</td>"
                     f"<td class='mono'>{esc(it.get('resource_name'))}</td><td>{cost_cell}</td></tr>")
        plan_html += (f"<div class='phase'><h3>{head}</h3><table>"
                      f"<tr><th>Fonte</th><th>Recomendação</th><th>Categoria</th><th>Prioridade</th><th>Impacto SS</th><th>Recurso</th><th>Custo</th></tr>"
                      f"{body}</table></div>")
    if not plan_html:
        plan_html = "<div class='card meta'>Nenhuma recomendação aberta encontrada no escopo (ou sem Reader na subscription/RG).</div>"

    # Pilar MCSB — postura de compliance regulatório (Microsoft Cloud Security Benchmark)
    mcsb = ctx.get("mcsb")
    mcsb_html = ""
    mcsb_kpi = ""
    if mcsb:
        cpct = mcsb.get("compliance_pct")
        cpct_txt = f"{cpct}%" if cpct is not None else "n/a"
        ccolor = "#5ed16a" if (cpct or 0) >= 80 else ("#ffd96b" if (cpct or 0) >= 50 else "#ff6b6b")
        mcsb_kpi = (f"<div class='kpi'><div class='n' style='color:{ccolor}'>{cpct_txt}</div>"
                    f"<div class='l'>🛡️ MCSB compliance</div></div>")
        rows_html = ""
        for fc in (mcsb.get("failing_controls") or [])[:12]:
            cname = esc(fc["name"])
            if fc.get("link"):
                cname = f"<a href='{esc(fc['link'])}' style='color:#e7edf5;text-decoration:none;border-bottom:1px dotted #4a5a72'>{cname}</a>"
            rows_html += (f"<tr><td class='mono'>{esc(fc['id'])}</td><td>{cname}</td>"
                          f"<td style='color:#ff6b6b;font-weight:700'>{fc['failed']}</td>"
                          f"<td style='color:#5ed16a'>{fc['passed']}</td></tr>")
        fail_table = ""
        if rows_html:
            fail_table = (f"<table style='margin-top:10px'>"
                          f"<tr><th>Controle</th><th>Nome</th><th>Falhando</th><th>OK</th></tr>{rows_html}</table>")
        bar_w = cpct if cpct is not None else 0
        mcsb_html = (
            f"<div class='phase'><h3>🛡️ Postura de Compliance — Microsoft Cloud Security Benchmark "
            f"<span class='meta'>· standard: {esc(mcsb.get('standard_name',''))} · estado: {esc(mcsb.get('state',''))}</span></h3>"
            f"<div class='card'>"
            f"<div style='display:flex;gap:18px;flex-wrap:wrap;align-items:center'>"
            f"<div><span style='font-size:28px;font-weight:800;color:{ccolor}'>{cpct_txt}</span>"
            f"<div class='meta'>controles em conformidade</div></div>"
            f"<div class='meta'>✅ {mcsb.get('passed',0)} passed · ❌ {mcsb.get('failed',0)} failed · "
            f"⏭️ {mcsb.get('skipped',0)} skipped · ⚪ {mcsb.get('unsupported',0)} unsupported</div>"
            f"</div>"
            f"<div style='background:#0b0f17;border:1px solid #1e2a3f;border-radius:8px;height:12px;overflow:hidden;margin-top:10px'>"
            f"<div style='height:100%;width:{bar_w}%;background:linear-gradient(90deg,{ccolor},#52b788)'></div></div>"
            f"{fail_table}</div></div>")

    savings = f"−US$ {ctx['savings_total']:,.0f}/ano".replace(",", ".") if ctx["savings_total"] else "—"
    cost_impl_total = f"+US$ {ctx['cost_increase_total']:,.0f}/mês".replace(",", ".") if ctx.get("cost_increase_total") else "—"

    # Barra de progresso do secure score (atual → potencial)
    ss_bar = ""
    if ss is not None and ss_pot is not None:
        ss_bar = (f"<div style='margin-top:12px'>"
                  f"<div class='meta' style='margin-bottom:4px'>🛡️ Secure Score: <b style='color:#9fb0c8'>{ss}%</b> agora "
                  f"→ <b style='color:#9ae6b4'>{ss_pot}%</b> se remediar tudo "
                  f"(<b style='color:#9ae6b4'>+{ss_delta} pontos percentuais</b>)</div>"
                  f"<div style='background:#0b0f17;border:1px solid #1e2a3f;border-radius:8px;height:14px;overflow:hidden;position:relative'>"
                  f"<div style='position:absolute;left:0;top:0;height:100%;width:{ss_pot}%;background:linear-gradient(90deg,#2d6a4f,#52b788);opacity:.45'></div>"
                  f"<div style='position:absolute;left:0;top:0;height:100%;width:{ss}%;background:linear-gradient(90deg,#7cd0ff,#5ed16a)'></div>"
                  f"</div></div>")

    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Advisor + Defender for Cloud — Remediation Plan</title>
<style>
  body{{margin:0;background:#0b0f17;color:#e7edf5;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
  .wrap{{max-width:1040px;margin:0 auto;padding:24px}}
  .hero{{background:linear-gradient(135deg,#121a2b,#0d1422);border:1px solid #1e2a3f;border-radius:16px;padding:22px 24px;margin-bottom:18px}}
  .hero h1{{margin:0 0 10px;font-size:20px}}
  .kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px;margin-top:6px}}
  .kpi{{background:#0d1422;border:1px solid #1e2a3f;border-radius:10px;padding:10px;text-align:center}}
  .kpi .n{{font-size:20px;font-weight:800}} .kpi .l{{font-size:11px;color:#9fb0c8;margin-top:2px}}
  h3{{font-size:14px;margin:18px 0 8px}}
  table{{width:100%;border-collapse:collapse;font-size:13px;background:#0d1422;border:1px solid #1e2a3f;border-radius:10px;overflow:hidden}}
  th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #182337;vertical-align:top}}
  th{{background:#111a2b;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#9fb0c8}}
  .mono{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}
  .casc{{color:#ffd96b;font-size:12px;margin-top:4px}}
  .amp{{color:#ff9f6b;font-size:12px;margin-top:3px}}
  .mtags{{margin-top:5px;font-size:11px;color:#9fb0c8}}
  .mitre{{display:inline-block;background:#2a1a3a;border:1px solid #4a2d6b;color:#c9a7ff;border-radius:5px;padding:1px 6px;margin:0 4px 2px 0;font-family:ui-monospace,Consolas,monospace;font-size:11px}}
  .owner{{color:#7cd0ff;font-size:11px;margin-top:4px}}
  .phase{{margin-bottom:14px}} .meta{{color:#9fb0c8;font-size:12px}}
  .card{{background:#0d1422;border:1px solid #1e2a3f;border-radius:12px;padding:14px}}
  @media(max-width:680px){{.kpis{{grid-template-columns:repeat(3,1fr)}}}}
</style></head><body><div class="wrap">

  <div class="hero">
    <h1>🧭 Plano de Remediação — Advisor + Defender for Cloud</h1>
    <div class="kpis">
      <div class="kpi"><div class="n" style="color:#7cd0ff">{n}</div><div class="l">recomendações</div></div>
      <div class="kpi"><div class="n" style="color:#5ed16a">{counts['safe']}</div><div class="l">🟢 quick wins</div></div>
      <div class="kpi"><div class="n" style="color:#ffd96b">{counts['low']+counts['medium']}</div><div class="l">🟡🟠 janela</div></div>
      <div class="kpi"><div class="n" style="color:#ff6b6b">{counts['high']}</div><div class="l">🔴 aprovação</div></div>
      <div class="kpi"><div class="n" style="color:#9fb0c8">{ss_txt}</div><div class="l">🛡️ SS atual</div></div>
      <div class="kpi"><div class="n" style="color:#9ae6b4">{ss_pot_txt}</div><div class="l">🎯 SS potencial</div></div>
      <div class="kpi"><div class="n" style="color:#ff6b6b;font-size:14px">{cost_impl_total}</div><div class="l">💰 custo impl.</div></div>
      {mcsb_kpi}
    </div>
    {ss_bar}
    <div class="meta" style="margin-top:12px">{ctx['resources_in_scope']} recurso(s) no escopo · economia potencial: <b style="color:#5ed16a">{savings}</b> · custo de implementação estimado: <b style="color:#ff6b6b">{cost_impl_total}</b> (<a href="https://prices.azure.com" style="color:#7cd0ff">Retail Prices</a>) · 100% read-only.</div>
  </div>

  {plan_html}

  {mcsb_html}

  <div class="meta" style="margin-top:20px;border-top:1px solid #1e2a3f;padding-top:12px">
    advisor-impact · gerado {esc(ctx['generated'])} · Azure Advisor + Microsoft Defender for Cloud · risco = disrupção de aplicar (não criticidade). Custos via Azure Retail Prices API · Compliance via MCSB (inspirado no <a href="https://github.com/microsoft/ESA" style="color:#7cd0ff">microsoft/ESA</a>).
  </div>
</div></body></html>"""

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

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as f:
            raw = json.load(f)
        # se o RG não veio por arg, tenta inferir do inventário p/ filtrar MDC
        if not params["_rg"]:
            inv = as_list(raw.get("resource_inventory"))
            if inv:
                params["_rg"] = _rg_of(inv[0].get("id", ""))
    elif args.sub and args.rg:
        raw = collect_live(q, args.sub, args.rg)
        if not as_list(raw.get("advisor_recommendations")) and not as_list(raw.get("mdc_assessments")) and not as_list(raw.get("resource_inventory")):
            print("Modo A não retornou dados (sem Reader na subscription/RG, az sem auth, ou escopo vazio). "
                  "Use Modo B (--from-json).", file=sys.stderr)
            return 2
    else:
        print("Informe --from-json <arquivo> OU --sub <id> --rg <nome>.", file=sys.stderr)
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

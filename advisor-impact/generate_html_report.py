#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
advisor-impact / generate_html_report.py  (collector ↔ renderer)

Planejador de remediação que une Azure Advisor + Microsoft Defender for Cloud:
  recomendações (Advisor: Cost/Reliability/Perf/OpEx · MDC: Microsoft.Security assessments)
  → cruza com o inventário do RG → classifica o RISCO DE APLICAR (safe/low/medium/high)
  → cadeia de cascata (recurso muda → workloads dependentes podem reiniciar)
  → PLANO DE EXECUÇÃO FASEADO (quick wins → janela → aprovação+rollback).

100% READ-ONLY — só GET ARM; RECOMENDA, nunca aplica.

Dois modos:
  --from-json inventory.json        → render determinístico/offline (primário)
  --workspace/--sub --rg            → auto-coleta via `az rest` (ARM)

Saída: --format both (default) → HTML (dark, email) + Markdown (repo).
"""
from __future__ import annotations
import argparse, datetime as dt, html, json, os, shutil, subprocess, sys

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
def run_arm(base, path, api):
    url = f"{base}{path}?api-version={api}"
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
        return run_arm(base, path, ep["api"])
    return {
        "advisor_recommendations": fetch("advisor_recommendations"),
        "resource_inventory": fetch("resource_inventory"),
        "mdc_assessments": fetch("mdc_assessments"),
        "mdc_secure_score": fetch("mdc_secure_score"),
    }

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
def build_resource_map(inventory):
    rmap = {}
    for r in as_list(inventory):
        rid = str(r.get("id", "")).lower()
        if rid:
            rmap[rid] = {"name": r.get("name"), "type": r.get("type"), "location": r.get("location")}
    return rmap

def _enrich(item, resource_id, risk, rmap, q):
    res = rmap.get(str(resource_id or "").lower(), {})
    item["resource_name"] = res.get("name") or (resource_id.split("/")[-1] if resource_id else "—")
    item["resource_type"] = res.get("type") or "—"
    amps = []
    if resource_id and not res:
        amps.append("Recurso não encontrado no inventário — verificar manualmente")
    item["amplifiers"] = amps
    if resource_id and risk in ("low", "medium", "high"):
        item["cascade"] = q.get("cascade_template", "").replace("{resource}", item["resource_name"])
    if resource_id and risk in ("medium", "high"):
        item["validation"] = [s.replace("{resource}", item["resource_name"]) for s in (q.get("validation_steps") or [])]
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
        item = {
            "source": "Defender for Cloud",
            "title": name,
            "remediation": meta.get("remediationDescription", "") or "",
            "category": ", ".join(meta.get("categories", []) or []) if isinstance(meta.get("categories"), list) else (meta.get("categories") or ""),
            "priority": meta.get("severity", "Unknown"),
            "risk": risk,
            "cost_delta": None,
            "scope": "subscription" if not item_rg else "resource",
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

# =============================================================================
# Build context
# =============================================================================
def build_context(q, raw, params):
    rmap = build_resource_map(raw.get("resource_inventory"))
    advisor = analyze_advisor(raw.get("advisor_recommendations"), rmap, q, params.get("category", "all"))
    mdc = analyze_mdc(raw.get("mdc_assessments"), rmap, q, params.get("_rg", ""), params.get("include_healthy", False))
    items = advisor + mdc
    phases = {"safe": [], "low": [], "medium": [], "high": []}
    for it in items:
        phases[it["risk"]].append(it)
    # savings total
    savings_total = 0.0
    for it in advisor:
        cd = it.get("cost_delta")
        if cd:
            digits = "".join(ch for ch in cd if ch.isdigit() or ch == ".")
            try:
                savings_total += float(digits)
            except ValueError:
                pass
    return {
        "items": items, "advisor": advisor, "mdc": mdc, "phases": phases,
        "secure_score": parse_secure_score(raw.get("mdc_secure_score")),
        "resources_in_scope": len(rmap),
        "savings_total": savings_total,
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
            cost = f"<span style='color:#5ed16a'>{esc(it['cost_delta'])}</span>" if it.get("cost_delta") else ""
            casc = f"<div class='casc'>↳ {esc(it.get('cascade'))}</div>" if it.get("cascade") else ""
            amps = "".join(f"<div class='amp'>⚠ {esc(a)}</div>" for a in it.get("amplifiers", []))
            body += (f"<tr><td>{_src_badge(it['source'])}</td><td>{esc(it['title'])}{casc}{amps}</td>"
                     f"<td>{esc(it.get('category') or '—')}</td><td>{esc(it.get('priority'))}</td>"
                     f"<td class='mono'>{esc(it.get('resource_name'))}</td><td>{cost}</td></tr>")
        plan_html += (f"<div class='phase'><h3>{head}</h3><table>"
                      f"<tr><th>Fonte</th><th>Recomendação</th><th>Categoria</th><th>Prioridade</th><th>Recurso</th><th>Custo</th></tr>"
                      f"{body}</table></div>")
    if not plan_html:
        plan_html = "<div class='card meta'>Nenhuma recomendação aberta encontrada no escopo (ou sem Reader na subscription/RG).</div>"

    savings = f"−US$ {ctx['savings_total']:,.0f}/ano".replace(",", ".") if ctx["savings_total"] else "—"

    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Advisor + Defender for Cloud — Remediation Plan</title>
<style>
  body{{margin:0;background:#0b0f17;color:#e7edf5;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
  .wrap{{max-width:960px;margin:0 auto;padding:24px}}
  .hero{{background:linear-gradient(135deg,#121a2b,#0d1422);border:1px solid #1e2a3f;border-radius:16px;padding:22px 24px;margin-bottom:18px}}
  .hero h1{{margin:0 0 10px;font-size:20px}}
  .kpis{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:6px}}
  .kpi{{background:#0d1422;border:1px solid #1e2a3f;border-radius:10px;padding:10px;text-align:center}}
  .kpi .n{{font-size:20px;font-weight:800}} .kpi .l{{font-size:11px;color:#9fb0c8;margin-top:2px}}
  h3{{font-size:14px;margin:18px 0 8px}}
  table{{width:100%;border-collapse:collapse;font-size:13px;background:#0d1422;border:1px solid #1e2a3f;border-radius:10px;overflow:hidden}}
  th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #182337;vertical-align:top}}
  th{{background:#111a2b;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#9fb0c8}}
  .mono{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}
  .casc{{color:#ffd96b;font-size:12px;margin-top:4px}}
  .amp{{color:#ff9f6b;font-size:12px;margin-top:3px}}
  .phase{{margin-bottom:14px}} .meta{{color:#9fb0c8;font-size:12px}}
  .card{{background:#0d1422;border:1px solid #1e2a3f;border-radius:12px;padding:14px}}
  @media(max-width:680px){{.kpis{{grid-template-columns:repeat(2,1fr)}}}}
</style></head><body><div class="wrap">

  <div class="hero">
    <h1>🧭 Plano de Remediação — Advisor + Defender for Cloud</h1>
    <div class="kpis">
      <div class="kpi"><div class="n" style="color:#7cd0ff">{n}</div><div class="l">recomendações</div></div>
      <div class="kpi"><div class="n" style="color:#5ed16a">{counts['safe']}</div><div class="l">🟢 quick wins</div></div>
      <div class="kpi"><div class="n" style="color:#ffd96b">{counts['low']+counts['medium']}</div><div class="l">🟡🟠 janela</div></div>
      <div class="kpi"><div class="n" style="color:#ff6b6b">{counts['high']}</div><div class="l">🔴 aprovação</div></div>
      <div class="kpi"><div class="n" style="color:#9fb0c8">{ss_txt}</div><div class="l">secure score</div></div>
    </div>
    <div class="meta" style="margin-top:12px">{ctx['resources_in_scope']} recurso(s) no escopo · economia potencial estimada: <b style="color:#5ed16a">{savings}</b> · 100% read-only (recomenda, não aplica).</div>
  </div>

  {plan_html}

  <div class="meta" style="margin-top:20px;border-top:1px solid #1e2a3f;padding-top:12px">
    advisor-impact · gerado {esc(ctx['generated'])} · Azure Advisor + Microsoft Defender for Cloud · risco = disrupção de aplicar (não criticidade).
  </div>
</div></body></html>"""

def render_md(ctx, q):
    ph = q.get("phases", {})
    ss = ctx["secure_score"]
    lines = ["# 🧭 Plano de Remediação — Advisor + Defender for Cloud",
             f"**Recomendações:** {len(ctx['items'])} · **Secure score:** {ss}%" if ss is not None else f"**Recomendações:** {len(ctx['items'])} · **Secure score:** n/a",
             f"**Recursos no escopo:** {ctx['resources_in_scope']} · **Economia potencial:** {('−US$ %.0f/ano' % ctx['savings_total']) if ctx['savings_total'] else '—'}",
             "\n_Risco = disrupção de APLICAR (não criticidade). Read-only — recomenda, não aplica._\n"]
    for lvl in ("safe", "low", "medium", "high"):
        rows = ctx["phases"][lvl]
        if not rows:
            continue
        meta = ph.get(lvl, {})
        lines.append(f"## {meta.get('emoji','')} {meta.get('label', lvl)} — {meta.get('action','')} ({len(rows)})")
        lines.append("| Fonte | Recomendação | Categoria | Prioridade | Recurso | Custo |")
        lines.append("|---|---|---|---|---|---|")
        for it in rows:
            lines.append(f"| {it['source']} | {it['title']} | {it.get('category') or '—'} | {it.get('priority')} | {it.get('resource_name')} | {it.get('cost_delta') or '—'} |")
        casc = [it for it in rows if it.get("cascade")]
        if casc:
            for it in casc:
                lines.append(f"  - ↳ {it['cascade']}")
        lines.append("")
    lines.append(f"_advisor-impact · gerado {ctx['generated']} · read-only._")
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

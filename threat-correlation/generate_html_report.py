#!/usr/bin/env python3
"""
threat-correlation — deterministic collector + renderer.

Correlates threat intelligence with the environment's real vulnerabilities and active
alerts to surface the CVEs that matter right now.

Pattern: collector↔renderer (queries.yaml = CAPTURE, this = RENDER).
Modes:
  1. Self-collect: acquires a Graph token via Azure CLI, runs the Tier-1 Advanced Hunting
     queries (DeviceTvm* + Alert*) via runHuntingQuery, then (Tier 2) enriches the top CVEs
     with MDTI if the premium API is licensed (degrades gracefully on 402/403).
  2. --from-json: renders from a pre-collected payload.

Usage:
  python generate_html_report.py [--output out.html]            # self-collect
  python generate_html_report.py --from-json results.json       # render from payload
  python generate_html_report.py --no-mdti                      # skip Tier 2 entirely

results.json shape (all keys optional; missing = empty):
  {
    "cve_kb":            [ {CveId, CvssScore, VulnerabilitySeverityLevel, IsExploitAvailable, PublishedDate, VulnerabilityDescription}, ... ],
    "cve_exposure":      [ {CveId, ExposedDevices, SampleDevices:[...]}, ... ],
    "cve_active_threat": [ {CveId, AlertedDevices, MaxAlertSeverity}, ... ],
    "alerts_summary":    [ {Severity, Alerts, Devices}, ... ],
    "crown_jewels":      [ {DeviceId, DeviceName}, ... ],
    "mdti": { "available": bool, "articles": [...], "intel_profiles": [...], "vulnerabilities": { "CVE-…": {...} } }
  }

Requires: PyYAML. Self-collect also requires Azure CLI logged in with ThreatHunting.Read.All
(Tier 1) and, for Tier 2, ThreatIntelligence.Read.All + an MDTI premium API add-on.
"""
import argparse
import datetime as dt
import html
import json
import pathlib
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

HERE = pathlib.Path(__file__).parent
SKILL = "threat-correlation"
AZ = shutil.which("az") or "az"


# --------------------------------------------------------------------------- io
def load_queries(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def subst(text, params):
    out = text
    for k, v in params.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def graph_token(resource="https://graph.microsoft.com"):
    cmd = [AZ, "account", "get-access-token", "--resource", resource,
           "--query", "accessToken", "-o", "tsv"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"token failed: {res.stderr.strip()}")
    return res.stdout.strip()


def run_hunt(url, token, body):
    # Defender XDR Advanced Hunting via Microsoft Graph (tabelas que não vivem no Sentinel).
    req = urllib.request.Request(
        url, data=body.encode("utf-8"), method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def mdti_get(url, token):
    """GET an MDTI endpoint. Returns (json, None) on success, (None, status) on HTTP error.

    status 402 = PaymentRequired (no MDTI premium add-on); 403 = scope missing.
    """
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        return None, e.code
    except Exception:
        return None, -1


# ---------------------------------------------------------------------- collect
def collect(args, q):
    params = dict(q.get("parameters", {}))
    data = {name: [] for name in q.get("graph_xdr", {})}
    token = graph_token()

    # --- Tier 1: Advanced Hunting via Graph runHuntingQuery ---
    for name, spec in q.get("graph_xdr", {}).items():
        body = subst(spec.get("body", ""), params)
        try:
            resp = run_hunt(spec["url"], token, body)
            data[name] = resp.get(spec.get("result_key", "results")) or resp.get("Results") or []
        except Exception as e:
            print(f"  ! graph_xdr '{name}' failed: {e}", file=sys.stderr)
            data[name] = []

    # --- Tier 2: MDTI flat context (articles + intel profiles). Per-CVE enrichment happens
    #     after ranking (mdti_enrich), so it only hits the top CVEs. ---
    data["mdti"] = {"available": None, "articles": [], "intel_profiles": [], "vulnerabilities": {}}
    if not getattr(args, "no_mdti", False):
        m = q.get("mdti", {})
        base = m.get("base", "")
        for key in ("articles", "intel_profiles"):
            path = m.get("endpoints", {}).get(key)
            if not path:
                continue
            url = base + path.replace(" ", "%20").replace("$", "%24")
            resp, err = mdti_get(url, token)
            if err in (402, 403):
                data["mdti"]["available"] = False
                print(f"  · MDTI '{key}' HTTP {err} → Tier 2 indisponível (sem add-on premium).", file=sys.stderr)
                break
            if resp is not None:
                data["mdti"]["available"] = True
                data["mdti"][key] = resp.get("value", [])
    return data


def mdti_enrich(top_cves, q, params, token):
    """Tier 2 per-CVE enrichment for the ranked top CVEs. Degrades to {} on 402/403."""
    m = q.get("mdti", {})
    base = m.get("base", "")
    tmpl = m.get("endpoints", {}).get("vulnerabilities", "")
    out = {"available": None, "vulnerabilities": {}}
    if not tmpl:
        return out
    limit = params.get("mdti_enrich_top", 8)
    for c in top_cves[:limit]:
        cve = c["cve"]
        url = base + tmpl.replace("{cve}", cve)
        resp, err = mdti_get(url, token)
        if err in (402, 403):
            out["available"] = False
            break
        if resp is not None:
            out["available"] = True
            out["vulnerabilities"][cve] = resp
    return out


# ---------------------------------------------------------------------- compute
def _num(x, d=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return d


def _i(x, d=0):
    try:
        return int(float(x))
    except (TypeError, ValueError):
        return d


def _truthy(x):
    return str(x).strip().lower() in ("1", "true", "yes")


def compute(data, params, scoring):
    sw = scoring.get("severity_weight", {})
    xw = scoring.get("exploit_weight", 3.0)
    ab = scoring.get("alert_bonus", 2.0)
    cb = scoring.get("crown_jewel_bonus", 1.5)

    kb = {}
    for v in data.get("cve_kb", []) or []:
        cid = v.get("CveId")
        if cid:
            kb[cid] = v

    exposure = {}
    for v in data.get("cve_exposure", []) or []:
        cid = v.get("CveId")
        if cid:
            exposure[cid] = v

    active = {}
    for v in data.get("cve_active_threat", []) or []:
        cid = v.get("CveId")
        if cid:
            active[cid] = v

    crown_names = set()
    for d in data.get("crown_jewels", []) or []:
        n = d.get("DeviceName")
        if n:
            crown_names.add(n)

    def _pick(ex, meta, key, default=None):
        # Prefer the enriched exposure row (KQL join); fall back to the KB catalog row.
        v = ex.get(key)
        if v in (None, ""):
            v = meta.get(key)
        return default if v in (None, "") else v

    ranked = []
    for cid, ex in exposure.items():
        meta = kb.get(cid, {})
        sev = _pick(ex, meta, "VulnerabilitySeverityLevel", "High")
        cvss = _num(_pick(ex, meta, "CvssScore"), 7.0)
        exploit = _truthy(_pick(ex, meta, "IsExploitAvailable"))
        exposed = _i(ex.get("ExposedDevices"))
        sample = ex.get("SampleDevices") or []
        if isinstance(sample, str):
            sample = [sample]
        act = active.get(cid, {})
        alerted = _i(act.get("AlertedDevices"))
        max_alert_sev = act.get("MaxAlertSeverity")
        crown_hit = bool(set(sample) & crown_names)

        score = exposed * cvss * sw.get(sev, 0.3)
        score *= (xw if exploit else 1.0)
        score *= (ab if alerted > 0 else 1.0)
        score *= (cb if crown_hit else 1.0)

        ranked.append({
            "cve": cid, "severity": sev, "cvss": cvss, "exploit": exploit,
            "exposed": exposed, "alerted": alerted, "max_alert_sev": max_alert_sev,
            "crown": crown_hit, "sample": sample,
            "published": _pick(ex, meta, "PublishedDate"),
            "desc": _pick(ex, meta, "VulnerabilityDescription") or "",
            "score": round(score, 1),
        })

    max_exposed = max((r["exposed"] for r in ranked), default=0)
    high_thr = max(1, round(0.4 * max_exposed))

    for r in ranked:
        if r["exploit"] and (r["alerted"] > 0 or r["exposed"] >= high_thr):
            r["verdict"] = "fix_now"
        elif r["exploit"] or r["exposed"] >= high_thr:
            r["verdict"] = "window"
        else:
            r["verdict"] = "monitor"

    ranked.sort(key=lambda r: (r["score"], r["cvss"], 1 if r["exploit"] else 0), reverse=True)
    top_cves = ranked[:params.get("top_cves", 15)]
    top_threats = [r for r in ranked if r["verdict"] != "monitor"][:params.get("top_threats", 5)]

    alerts_by_sev = {}
    for a in data.get("alerts_summary", []) or []:
        alerts_by_sev[a.get("Severity", "Unknown")] = {
            "alerts": _i(a.get("Alerts")), "devices": _i(a.get("Devices"))}

    n_env = len(ranked)
    n_exploit = sum(1 for r in ranked if r["exploit"])
    n_alerted = sum(1 for r in ranked if r["alerted"] > 0)
    n_crown = sum(1 for r in ranked if r["crown"])
    n_fix_now = sum(1 for r in ranked if r["verdict"] == "fix_now")

    if any(r["verdict"] == "fix_now" for r in ranked):
        posture, verdict = "CRÍTICA", "ELEVATED"
    elif any(r["verdict"] == "window" for r in ranked):
        posture, verdict = "ELEVADA", "MONITOR"
    else:
        posture, verdict = "CONTROLADA", "CLEAR"

    mdti = data.get("mdti") or {}
    return {
        "posture": posture, "verdict": verdict,
        "n_env": n_env, "n_exploit": n_exploit, "n_alerted": n_alerted,
        "n_crown": n_crown, "n_fix_now": n_fix_now, "max_exposed": max_exposed,
        "top_cves": top_cves, "top_threats": top_threats,
        "alerts_by_sev": alerts_by_sev,
        "mdti_available": mdti.get("available"),
        "mdti_articles": mdti.get("articles", []),
        "mdti_vulns": mdti.get("vulnerabilities", {}),
    }


# ----------------------------------------------------------------------- render
VERDICT_COLOR = {"ELEVATED": "#d13438", "MONITOR": "#ffb900", "CLEAR": "#107c10"}
SEV_COLOR = {"Critical": "#d13438", "High": "#ff8c00", "Medium": "#ffb900", "Low": "#888"}
VERDICT_LABEL = {"fix_now": "🔴 corrigir agora", "window": "🟠 janela", "monitor": "🟢 monitorar"}


def _mdti_badge(r):
    a = r["mdti_available"]
    if a is True:
        return '<span style="color:#9ec5ff">MDTI: ativo (Tier 2)</span>'
    if a is False:
        return '<span style="color:#6b7280">MDTI: não licenciado · Tier 1 (TVM)</span>'
    return '<span style="color:#6b7280">MDTI: não consultado · Tier 1 (TVM)</span>'


def render_html(r):
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    vc = VERDICT_COLOR.get(r["verdict"], "#107c10")

    threat_cards = ""
    for t in r["top_threats"]:
        tags = []
        if t["exploit"]:
            tags.append('<span class="tag tx">🔥 exploit</span>')
        if t["alerted"] > 0:
            tags.append(f'<span class="tag ta">⚠️ {t["alerted"]} alvo(s) c/ alerta ativo</span>')
        if t["crown"]:
            tags.append('<span class="tag tc">👑 crown jewel</span>')
        mdti = r["mdti_vulns"].get(t["cve"])
        mdti_line = ""
        if mdti:
            arts = mdti.get("articles@odata.count") or len(mdti.get("articles", []) or [])
            mdti_line = f'<div class="mdti">MDTI: {arts} artigo(s) relacionados</div>'
        threat_cards += (
            f'<div class="threat"><div class="th-h"><code>{html.escape(t["cve"])}</code>'
            f'<span class="vd">{VERDICT_LABEL[t["verdict"]]}</span></div>'
            f'<div class="th-m">CVSS <b>{t["cvss"]}</b> · {t["exposed"]:,} device(s) exposto(s) · '
            f'prioridade <b>{t["score"]:,}</b></div>'
            f'<div class="tags">{"".join(tags) or "—"}</div>'
            f'{mdti_line}'
            f'<div class="desc">{html.escape((t["desc"] or "")[:200])}</div></div>')
    threat_cards = threat_cards or '<div class="threat" style="color:#107c10">Nenhuma ameaça correlacionada com exploit/alerta ativo. 🎉</div>'

    cve_rows = ""
    for c in r["top_cves"]:
        fire = '🔥' if c["exploit"] else '<span style="color:#6b7280">—</span>'
        alert = (f'<span style="color:#ff8c00;font-weight:700">{c["alerted"]:,}</span>'
                 if c["alerted"] > 0 else '<span style="color:#6b7280">0</span>')
        crown = '👑' if c["crown"] else '<span style="color:#6b7280">—</span>'
        cve_rows += (
            f'<tr><td><code>{html.escape(c["cve"])}</code></td>'
            f'<td style="text-align:center;color:{SEV_COLOR.get(c["severity"],"#888")};font-weight:700">{c["severity"]}</td>'
            f'<td style="text-align:center">{c["cvss"]}</td>'
            f'<td style="text-align:center;font-weight:700">{c["exposed"]:,}</td>'
            f'<td style="text-align:center">{alert}</td>'
            f'<td style="text-align:center">{fire}</td>'
            f'<td style="text-align:center">{crown}</td>'
            f'<td style="text-align:center;font-weight:700;color:#38bdf8">{c["score"]:,}</td>'
            f'<td style="text-align:center">{VERDICT_LABEL[c["verdict"]]}</td></tr>')
    cve_rows = cve_rows or '<tr><td colspan="9" style="color:#107c10">Nenhuma CVE Critical/High exposta no ambiente. 🎉</td></tr>'

    alert_chips = ""
    for sev in ("High", "Medium", "Low", "Informational"):
        info = r["alerts_by_sev"].get(sev)
        if info:
            alert_chips += (f'<span class="chip"><b style="color:{SEV_COLOR.get(sev,"#888")}">{sev}</b> '
                            f'{info["alerts"]} alerta(s) · {info["devices"]} device(s)</span>')
    alert_chips = alert_chips or '<span class="chip">Sem alertas na janela.</span>'

    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Threat ↔ Vulnerability Correlation — {now}</title>
<style>
body{{margin:0;background:#0a0e1a;color:#e7eef9;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.5}}
.wrap{{max-width:960px;margin:0 auto;padding:24px}}
.hd{{background:linear-gradient(135deg,#5a189a,#7a1f5f,#d13438);border-radius:14px;padding:26px}}
.hd h1{{margin:0;font-size:24px}} .hd p{{margin:6px 0 0;opacity:.88;font-size:13px}}
.badge{{display:inline-block;margin-top:14px;padding:8px 18px;border-radius:999px;font-weight:800;font-size:18px;background:{vc}22;color:{vc};border:2px solid {vc}}}
.cards{{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}}
.card{{flex:1;min-width:140px;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;padding:18px;text-align:center}}
.card .n{{font-size:28px;font-weight:800}} .card .l{{font-size:12px;color:#93a1bd;margin-top:4px}}
h2{{font-size:17px;margin:28px 0 12px}}
.threat{{background:#111a2e;border:1px solid #2a1f47;border-left:4px solid #a855f7;border-radius:10px;padding:14px 16px;margin:10px 0}}
.th-h{{display:flex;justify-content:space-between;align-items:center}}
.th-h code{{background:#16203a;padding:3px 9px;border-radius:6px;color:#c9b3ff;font-size:14px}}
.vd{{font-weight:800;font-size:13px}} .th-m{{margin:8px 0;font-size:13px;color:#cdd7ea}}
.tags{{margin:6px 0}} .tag{{display:inline-block;font-size:11px;padding:2px 8px;border-radius:6px;margin-right:6px}}
.tx{{background:#3a1010;color:#ffb4b4}} .ta{{background:#3a2a10;color:#ffd9a0}} .tc{{background:#2a1040;color:#d9b4ff}}
.mdti{{font-size:12px;color:#9ec5ff;margin-top:4px}} .desc{{font-size:12px;color:#8a96ad;margin-top:6px}}
table{{width:100%;border-collapse:collapse;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;overflow:hidden;font-size:13px}}
th{{background:#16203a;text-align:center;padding:11px 10px;font-size:12px;color:#c9b3ff}}
th:first-child{{text-align:left}} td{{padding:9px 10px;border-top:1px solid #1f2c47}}
code{{background:#16203a;padding:2px 7px;border-radius:5px;color:#c9b3ff}}
.chip{{display:inline-block;background:#16203a;border:1px solid #1f2c47;border-radius:999px;padding:5px 12px;margin:4px 6px 0 0;font-size:12px}}
.note{{font-size:12px;color:#8a96ad;margin:8px 0}} .ft{{margin-top:24px;color:#647394;font-size:12px;text-align:center}}
</style></head><body><div class="wrap">
<div class="hd"><h1>🎯 Threat ↔ Vulnerability Correlation</h1>
<p>{now} · Defender TVM + Alertas ativos · {_mdti_badge(r)}</p>
<div class="badge">Postura: {r['posture']}</div></div>
<div class="cards">
<div class="card"><div class="n" style="color:#d13438">{r['n_fix_now']}</div><div class="l">Corrigir agora</div></div>
<div class="card"><div class="n">{r['n_env']:,}</div><div class="l">CVEs no ambiente</div></div>
<div class="card"><div class="n" style="color:#ff8c00">{r['n_exploit']}</div><div class="l">com exploit</div></div>
<div class="card"><div class="n" style="color:#ffb900">{r['n_alerted']}</div><div class="l">c/ alerta ativo</div></div>
<div class="card"><div class="n" style="color:#a855f7">{r['n_crown']}</div><div class="l">em crown jewels</div></div>
</div>
<h2>🚨 Top ameaças que importam pra você</h2>
{threat_cards}
<h2>📋 CVEs priorizadas (exposição × CVSS × exploit × alerta ativo × ativo crítico)</h2>
<table><tr><th>CVE</th><th>Sev</th><th>CVSS</th><th>Expostos</th><th>Alerta ativo</th><th>Exploit</th><th>Crown</th><th>Prioridade</th><th>Veredito</th></tr>{cve_rows}</table>
<h2>📡 Alertas ativos na janela</h2>
<div>{alert_chips}</div>
<p class="note">Ranking determinístico. "Alerta ativo" = device exposto à CVE que TAMBÉM tem alerta na janela (ameaça em andamento sobre ativo vulnerável). "Crown jewel" = ativo de alto valor (DeviceValue=High). Tier 2 (MDTI) enriquece as CVEs do topo quando o add-on premium está licenciado.</p>
<div class="ft">{SKILL} · collector↔renderer · gerado pelo SOC Autônomo</div>
</div></body></html>"""


def render_md(r):
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# 🎯 Threat ↔ Vulnerability Correlation — {now}", ""]
    mdti = {True: "MDTI ativo (Tier 2)", False: "MDTI não licenciado (Tier 1/TVM)"}.get(
        r["mdti_available"], "MDTI não consultado (Tier 1/TVM)")
    lines += [f"**Postura:** {r['posture']} · {mdti}", "",
              f"- Corrigir agora: **{r['n_fix_now']}**",
              f"- CVEs no ambiente: {r['n_env']:,}",
              f"- com exploit: {r['n_exploit']} · c/ alerta ativo: {r['n_alerted']} · em crown jewels: {r['n_crown']}",
              "", "## 🚨 Top ameaças que importam pra você", ""]
    if r["top_threats"]:
        for t in r["top_threats"]:
            flags = []
            if t["exploit"]:
                flags.append("🔥 exploit")
            if t["alerted"] > 0:
                flags.append(f"⚠️ {t['alerted']} alvo(s) c/ alerta ativo")
            if t["crown"]:
                flags.append("👑 crown jewel")
            lines.append(f"- **{t['cve']}** — {VERDICT_LABEL[t['verdict']]} · CVSS {t['cvss']} · "
                         f"{t['exposed']:,} exposto(s) · prioridade {t['score']:,}"
                         + (f" · {', '.join(flags)}" if flags else ""))
    else:
        lines.append("- Nenhuma ameaça correlacionada com exploit/alerta ativo. 🎉")
    lines += ["", "## 📋 CVEs priorizadas", "",
              "| CVE | Sev | CVSS | Expostos | Alerta ativo | Exploit | Crown | Prioridade | Veredito |",
              "|---|---|---|---|---|---|---|---|---|"]
    for c in r["top_cves"]:
        lines.append(f"| {c['cve']} | {c['severity']} | {c['cvss']} | {c['exposed']:,} | "
                     f"{c['alerted']:,} | {'sim' if c['exploit'] else '—'} | "
                     f"{'sim' if c['crown'] else '—'} | {c['score']:,} | {VERDICT_LABEL[c['verdict']]} |")
    lines += ["", f"_{SKILL} · collector↔renderer · gerado pelo SOC Autônomo_"]
    return "\n".join(lines)


# ------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="threat-correlation report generator")
    ap.add_argument("--from-json", dest="from_json", help="Render from a pre-collected payload")
    ap.add_argument("--queries", default=str(HERE / "queries.yaml"))
    ap.add_argument("--output", default=None, help="HTML output path (.md written alongside)")
    ap.add_argument("--no-mdti", action="store_true", help="Skip Tier 2 (MDTI) entirely")
    args = ap.parse_args()

    q = load_queries(args.queries)
    params = dict(q.get("parameters", {}))
    scoring = q.get("scoring", {})

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = collect(args, q)

    r = compute(data, params, scoring)

    # Tier 2 per-CVE enrichment (self-collect only; --from-json may already carry data['mdti']).
    if not args.from_json and not args.no_mdti and r["mdti_available"] is not False:
        try:
            enr = mdti_enrich(r["top_cves"], q, params, graph_token())
            if enr.get("available") is not None:
                r["mdti_available"] = enr["available"]
            r["mdti_vulns"] = enr.get("vulnerabilities", {})
        except Exception as e:
            print(f"  · MDTI enrich pulado: {e}", file=sys.stderr)

    htmlout = render_html(r)
    mdout = render_md(r)

    ts = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out = args.output or str(HERE / "reports" / f"{SKILL}_{ts}.html")
    out_path = pathlib.Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(htmlout, encoding="utf-8")
    out_path.with_suffix(".md").write_text(mdout, encoding="utf-8")

    print(f"✅ {SKILL}: postura {r['posture']} · {r['n_fix_now']} corrigir-agora · "
          f"{r['n_env']} CVEs · {r['n_exploit']} c/ exploit · {r['n_alerted']} c/ alerta ativo")
    print(f"📄 {out_path}")
    print(f"📄 {out_path.with_suffix('.md')}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
exposure-graph — deterministic collector + renderer.

Pattern: collector↔renderer (queries.yaml = CAPTURE, this = RENDER). API-NATIVE (MDE + Graph).
Synthesizes an attack-surface / blast-radius:
  entry points (risky users + exposed machines) → crown jewels (privileged identities),
  weighted by org exposure score and exploitable exposed recommendations.

Modes:
  1. Self-collect: acquires MDE + Graph tokens via Azure CLI and GETs the endpoints.
  2. --from-json:  renders from pre-collected responses.

Usage:
  python generate_html_report.py [--output out.html]            # self-collect
  python generate_html_report.py --from-json results.json

results.json shape (keys = endpoint names):
  {"exposure_score": <mde>, "machines": <mde>, "recommendations": <mde>,
   "directory_roles": <graph>, "risky_users": <graph>}
Requires: PyYAML. Self-collect needs Azure CLI logged in with MDE Score/SecurityRecommendation
+ Graph IdentityRiskyUser.Read.All + Directory.Read.All (RoleManagement.Read.Directory).
"""
import argparse
import datetime as dt
import html
import json
import pathlib
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

HERE = pathlib.Path(__file__).parent
SKILL = "exposure-graph"
AZ = shutil.which("az") or "az"  # resolve az.cmd no Windows; no Linux (SRE Agent) acha o binário


def load_queries(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_token(resource):
    cmd = [AZ, "account", "get-access-token", "--resource", resource,
           "--query", "accessToken", "-o", "tsv"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"token failed: {res.stderr.strip()}")
    return res.stdout.strip()


def api_get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)


def _enc(path):
    # encode só o que precisa, preservando ? & = $ / da query OData
    return path.replace(" ", "%20").replace("'", "%27")


def collect(q):
    out = {}
    # MDE
    m = q["mde"]
    try:
        mtok = get_token(m["token_resource"])
        for key, path in m["endpoints"].items():
            try:
                out[key] = api_get(m["base"] + _enc(path), mtok)
            except Exception as e:
                print(f"  ! MDE '{key}' failed: {e}", file=sys.stderr)
                out[key] = {}
    except Exception as e:
        print(f"  ! MDE token failed: {e}", file=sys.stderr)
    # Graph
    g = q["graph"]
    try:
        gtok = get_token(g["token_resource"])
        for key, path in g["endpoints"].items():
            try:
                out[key] = api_get(g["base"] + _enc(path), gtok)
            except Exception as e:
                print(f"  ! Graph '{key}' failed: {e}", file=sys.stderr)
                out[key] = {}
    except Exception as e:
        print(f"  ! Graph token failed: {e}", file=sys.stderr)
    return out


def _num(x, d=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return d


def _val(resp):
    if isinstance(resp, dict):
        return resp.get("value", []) or []
    if isinstance(resp, list):
        return resp
    return []


def compute(data, params, scoring):
    lw = scoring.get("level_weight", {"High": 3, "Medium": 2, "Low": 1, "None": 0, "Informational": 0})
    good = params.get("exposure_good", 30)
    moderate = params.get("exposure_moderate", 50)
    priv_roles = set(r.lower() for r in params.get("privileged_roles", []))

    # org exposure score
    es_resp = data.get("exposure_score") or {}
    exposure_score = round(_num(es_resp.get("score")), 1) if isinstance(es_resp, dict) else 0.0

    # exposed machines (entry points lado endpoint)
    machines = _val(data.get("machines"))
    exposed_machines = []
    for mac in machines:
        el = str(mac.get("exposureLevel", "None"))
        rs = str(mac.get("riskScore", "None"))
        w = lw.get(el, 0) + lw.get(rs, 0)
        if w >= 2 or el in ("High", "Medium"):
            exposed_machines.append({
                "Machine": mac.get("computerDnsName", ""),
                "OS": mac.get("osPlatform", ""),
                "ExposureLevel": el, "RiskScore": rs, "Weight": w,
                "Health": mac.get("healthStatus", ""),
            })
    exposed_machines.sort(key=lambda r: r["Weight"], reverse=True)

    # exploitable exposed recommendations
    recs = _val(data.get("recommendations"))
    exposed_recs = []
    for r in recs:
        exp = int(_num(r.get("exposedMachinesCount")))
        if exp <= 0:
            continue
        sev = _num(r.get("severityScore"))
        pub = bool(r.get("publicExploit"))
        exposed_recs.append({
            "Recommendation": r.get("recommendationName", ""),
            "Component": r.get("relatedComponent", ""),
            "ExposedMachines": exp, "Severity": round(sev, 1),
            "PublicExploit": "sim" if pub else "não",
            "Remediation": r.get("remediationType", ""),
            "_exploit": pub,
        })
    exposed_recs.sort(key=lambda r: (r["_exploit"], r["ExposedMachines"], r["Severity"]), reverse=True)
    exploitable_exposed = [r for r in exposed_recs if r["_exploit"] or r["Severity"] >= 8.0]

    # crown jewels — identidades privilegiadas
    roles = _val(data.get("directory_roles"))
    jewels = {}  # upn -> set(roles)
    for role in roles:
        rname = str(role.get("displayName", ""))
        if rname.lower() not in priv_roles:
            continue
        for mem in (role.get("members") or []):
            upn = mem.get("userPrincipalName") or mem.get("displayName") or mem.get("id", "")
            if upn:
                jewels.setdefault(upn, set()).add(rname)
    jewel_rows = [{"Identity": u, "Roles": ", ".join(sorted(rs))} for u, rs in sorted(jewels.items())]

    # entry points — risky users (lado identidade)
    rusers = _val(data.get("risky_users"))
    risky_rows = [{
        "User": u.get("userPrincipalName", ""),
        "RiskLevel": u.get("riskLevel", ""),
        "RiskState": u.get("riskState", ""),
        "Updated": (u.get("riskLastUpdatedDateTime") or "")[:19].replace("T", " "),
    } for u in rusers]

    entry_points = len(risky_rows) + len(exposed_machines)
    priv_targets = len(jewel_rows)
    blast_radius = entry_points * priv_targets

    # verdict
    if exposure_score > moderate or (entry_points > 0 and priv_targets > 0 and len(exploitable_exposed) > 0):
        verdict = "ALTA"
    elif exposure_score > good or entry_points > 0 or len(exploitable_exposed) > 0:
        verdict = "MODERADA"
    else:
        verdict = "BAIXA"

    return {
        "exposure_score": exposure_score, "verdict": verdict,
        "entry_points": entry_points, "priv_targets": priv_targets,
        "blast_radius": blast_radius,
        "exploitable_exposed": len(exploitable_exposed),
        "machines": exposed_machines, "recs": exposed_recs[:params.get("top_recommendations", 10)],
        "jewels": jewel_rows, "risky": risky_rows,
        "machines_top": exposed_machines[:params.get("top_machines", 25)],
    }


VERDICT_COLOR = {"ALTA": "#d13438", "MODERADA": "#ffb900", "BAIXA": "#107c10"}


def table(rows, cols):
    if not rows:
        return f'<tr><td colspan="{len(cols)}" style="color:#647394">Sem dados.</td></tr>'
    out = ""
    for r in rows:
        out += "<tr>" + "".join(f'<td>{html.escape(str(r.get(k, "")))}</td>' for _, k in cols) + "</tr>"
    return out


def th(cols):
    return "".join(f"<th>{h}</th>" for h, _ in cols)


def render_html(s):
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    vc = VERDICT_COLOR.get(s["verdict"], "#107c10")

    mac_cols = [("Máquina", "Machine"), ("OS", "OS"), ("Exposição", "ExposureLevel"),
                ("Risco", "RiskScore"), ("Saúde", "Health")]
    rec_cols = [("Recomendação", "Recommendation"), ("Componente", "Component"),
                ("Máquinas expostas", "ExposedMachines"), ("Severidade", "Severity"),
                ("Exploit público", "PublicExploit"), ("Remediação", "Remediation")]
    jewel_cols = [("Identidade privilegiada", "Identity"), ("Papéis", "Roles")]
    risky_cols = [("Usuário (entry point)", "User"), ("Risco", "RiskLevel"),
                  ("Estado", "RiskState"), ("Atualizado", "Updated")]

    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Exposure Graph</title>
<style>
body{{margin:0;background:#0a0e1a;color:#e7eef9;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.5}}
.wrap{{max-width:1000px;margin:0 auto;padding:24px}}
.hd{{background:linear-gradient(135deg,#3b0a64,#7b2ff7);border-radius:14px;padding:26px}}
.hd h1{{margin:0;font-size:23px}} .hd p{{margin:6px 0 0;opacity:.9;font-size:13px}}
.badge{{display:inline-block;margin-top:14px;padding:8px 18px;border-radius:999px;font-weight:800;font-size:18px;background:{vc}22;color:{vc};border:2px solid {vc}}}
.cards{{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}}
.card{{flex:1;min-width:120px;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;padding:16px;text-align:center}}
.card .n{{font-size:26px;font-weight:800}} .card .l{{font-size:11.5px;color:#93a1bd;margin-top:4px}}
.path{{background:#111a2e;border:1px solid #1f2c47;border-left:4px solid {vc};border-radius:10px;padding:14px 18px;margin:8px 0;font-size:13.5px}}
table{{width:100%;border-collapse:collapse;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;overflow:hidden;font-size:12.5px;margin-bottom:8px}}
th{{background:#16203a;text-align:left;padding:10px 12px;font-size:11.5px;color:#c9a7ff}}
td{{padding:8px 12px;border-top:1px solid #1f2c47}}
h2{{font-size:16px;margin:26px 0 10px}} .ft{{margin-top:24px;color:#647394;font-size:12px;text-align:center}}
</style></head><body><div class="wrap">
<div class="hd"><h1>🕸️ Exposure Graph &amp; Blast Radius</h1>
<p>Attack surface sintetizado · MDE + Identity Protection + papéis privilegiados · {now}</p>
<div class="badge">EXPOSIÇÃO {s['verdict']}</div></div>
<div class="cards">
<div class="card"><div class="n" style="color:{vc}">{s['exposure_score']}</div><div class="l">Exposure Score (org)</div></div>
<div class="card"><div class="n" style="color:#ff8c00">{s['entry_points']}</div><div class="l">Entry points</div></div>
<div class="card"><div class="n" style="color:#d13438">{s['priv_targets']}</div><div class="l">Crown jewels</div></div>
<div class="card"><div class="n" style="color:#ffb900">{s['exploitable_exposed']}</div><div class="l">Exploráveis expostas</div></div>
<div class="card"><div class="n">{s['blast_radius']}</div><div class="l">Caminhos (blast radius)</div></div>
</div>
<div class="path">🧭 <b>Caminhos de ataque sintetizados:</b> {s['entry_points']} pontos de entrada
(risky users + máquinas expostas) × {s['priv_targets']} identidades privilegiadas =
<b>{s['blast_radius']}</b> caminhos potenciais. {s['exploitable_exposed']} recomendações
expostas com peso de exploração amplificam o risco.</div>
<h2>🚪 Entry points — usuários de alto risco</h2>
<table><tr>{th(risky_cols)}</tr>{table(s['risky'], risky_cols)}</table>
<h2>💻 Entry points — máquinas mais expostas</h2>
<table><tr>{th(mac_cols)}</tr>{table(s['machines_top'], mac_cols)}</table>
<h2>👑 Crown jewels — identidades privilegiadas</h2>
<table><tr>{th(jewel_cols)}</tr>{table(s['jewels'], jewel_cols)}</table>
<h2>🎯 Fraquezas exploráveis expostas</h2>
<table><tr>{th(rec_cols)}</tr>{table(s['recs'], rec_cols)}</table>
<div class="ft">exposure-graph · collector↔renderer · gerado pelo SOC Autônomo</div>
</div></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="exposure-graph report generator")
    ap.add_argument("--from-json", dest="from_json", help="Render from pre-collected responses JSON")
    ap.add_argument("--queries", default=str(HERE / "queries.yaml"))
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    q = load_queries(args.queries)
    params = q.get("parameters", {})
    scoring = q.get("scoring", {})

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = collect(q)

    s = compute(data, params, scoring)
    htmlout = render_html(s)

    out = args.output or str(HERE / "reports" / f"exposure_{dt.datetime.utcnow():%Y%m%d_%H%M%S}.html")
    pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(htmlout)
    print(f"✅ {SKILL}: EXPOSIÇÃO {s['verdict']} · score {s['exposure_score']} · "
          f"entry {s['entry_points']} · jewels {s['priv_targets']} · "
          f"exploráveis {s['exploitable_exposed']} · blast {s['blast_radius']}")
    print(f"📄 {out}")


if __name__ == "__main__":
    main()

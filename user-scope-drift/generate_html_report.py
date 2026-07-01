#!/usr/bin/env python3
"""
user-scope-drift — deterministic collector + renderer.

Pattern: collector↔renderer (queries.yaml = CAPTURE, this = RENDER).
Two modes:
  1. Self-collect: runs the KQL from queries.yaml via `az monitor log-analytics query`.
  2. --from-json:  renders from pre-collected results (e.g. captured by the SRE Agent's
                   own QueryLogAnalyticsByWorkspaceId tool). Keeps rendering deterministic.

Usage:
  python generate_html_report.py --workspace <LA_GUID> [--target user@x.com] [--output out.html]
  python generate_html_report.py --from-json results.json [--output out.html]

results.json shape (keys map to queries.yaml query names):
  {"drift": [ {row}, ... ], "email_surge": [ ... ], "mfa_reregistration": [ ... ]}

Requires: PyYAML (pip install pyyaml). Self-collect mode also requires Azure CLI logged in.
"""
import argparse
import datetime as dt
import html
import json
import pathlib
import subprocess
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

HERE = pathlib.Path(__file__).parent
SKILL = "user-scope-drift"


def load_queries(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def subst(kql, params):
    out = kql
    for k, v in params.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def run_kql(workspace, kql):
    """Run a KQL query via Azure CLI; returns a list of row dicts."""
    cmd = ["az", "monitor", "log-analytics", "query",
           "--workspace", workspace, "--analytics-query", kql, "-o", "json"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"KQL failed:\n{res.stderr.strip()}")
    return json.loads(res.stdout or "[]")


def collect(args, q):
    params = dict(q.get("parameters", {}))
    params["floor"] = params.get("low_volume_floor", 10)
    params["target"] = args.target or ""
    data = {}
    for name in ("drift", "email_surge", "mfa_reregistration"):
        kql = subst(q["queries"][name], params)
        try:
            data[name] = run_kql(args.workspace, kql)
        except Exception as e:  # one query failing must not abort the report
            print(f"  ! query '{name}' failed: {e}", file=sys.stderr)
            data[name] = []
    return data


def classify(data, params):
    flag_th = params.get("flag_threshold", 150)
    crit_th = params.get("critical_threshold", 250)
    surge_upns = {r.get("SenderFromAddress", "").lower() for r in data.get("email_surge", [])}
    mfa_upns = {r.get("UPN", "").lower() for r in data.get("mfa_reregistration", [])}

    users = []
    for r in data.get("drift", []):
        upn = (r.get("UserPrincipalName") or "").lower()
        score = float(r.get("DriftScore") or 0)
        verdict = r.get("Verdict") or "Stable"
        signals = []
        if upn in surge_upns:
            signals.append("exfil-email-surge")
        if upn in mfa_upns:
            signals.append("aitm-mfa-rereg")
        # independent signals upgrade a Stable/Monitor user to FLAG
        if signals and verdict in ("Stable", "Contracting", "Monitor"):
            verdict = "FLAG"
        r["_verdict"] = verdict
        r["_signals"] = signals
        users.append(r)

    # surface email-surge users not present in the drift top-N
    seen = {(u.get("UserPrincipalName") or "").lower() for u in users}
    for r in data.get("email_surge", []):
        upn = (r.get("SenderFromAddress") or "").lower()
        if upn and upn not in seen:
            users.append({"UserPrincipalName": r.get("SenderFromAddress"), "DriftScore": "",
                          "_verdict": "FLAG", "_signals": ["exfil-email-surge"],
                          "rDaily": "", "blDaily": ""})

    flagged = [u for u in users if u["_verdict"] in ("FLAG", "Critical")]
    exfil = sum(1 for u in users if u["_signals"])
    scores = [float(u["DriftScore"]) for u in users if str(u.get("DriftScore")).replace(".", "", 1).isdigit()]
    avg = round(sum(scores) / len(scores), 1) if scores else 0
    worst = "CLEAR"
    if any(u["_verdict"] == "Critical" for u in users) or any(u["_verdict"] == "FLAG" for u in users):
        worst = "ELEVATED"
    elif any(u["_verdict"] == "Monitor" for u in users):
        worst = "MONITOR"
    return users, {"analyzed": len(data.get("drift", [])), "flagged": len(flagged),
                   "exfil": exfil, "avg": avg, "overall": worst}


VERDICT_COLOR = {"ELEVATED": "#d13438", "MONITOR": "#ffb900", "CLEAR": "#107c10"}
ROW_COLOR = {"Critical": "#d13438", "FLAG": "#ff8c00", "Monitor": "#ffb900",
             "Stable": "#107c10", "Contracting": "#6b7280"}


def render_html(users, summary, params, window):
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    vc = VERDICT_COLOR.get(summary["overall"], "#107c10")
    rows = ""
    for u in users[:30]:
        v = u["_verdict"]
        sig = " ".join(f'<span style="background:#1f2c47;color:#9ec5ff;padding:2px 7px;border-radius:6px;font-size:11px">{html.escape(s)}</span>' for s in u["_signals"]) or "<span style='color:#6b7280'>—</span>"
        rows += (f'<tr><td>{html.escape(str(u.get("UserPrincipalName","")))}</td>'
                 f'<td style="text-align:center;font-weight:700">{u.get("DriftScore","")}</td>'
                 f'<td style="text-align:center;color:{ROW_COLOR.get(v,"#888")};font-weight:700">{v}</td>'
                 f'<td style="text-align:center">{u.get("blDaily","")} → {u.get("rDaily","")}</td>'
                 f'<td>{sig}</td></tr>')
    recs = ""
    for u in users:
        if u["_verdict"] in ("FLAG", "Critical"):
            upn = html.escape(str(u.get("UserPrincipalName", "")))
            why = ", ".join(u["_signals"]) or f"drift score {u.get('DriftScore','')}"
            recs += f'<li><b>{upn}</b> — {why}. Recomendado: <code>contain user {upn}</code></li>'
    recs = recs or "<li style='color:#107c10'>Nenhum usuário em FLAG/Critical. Nenhuma ação necessária.</li>"

    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>User Scope Drift — {now}</title>
<style>
body{{margin:0;background:#0a0e1a;color:#e7eef9;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.5}}
.wrap{{max-width:900px;margin:0 auto;padding:24px}}
.hd{{background:linear-gradient(135deg,#1a3a8c,#0078d4);border-radius:14px;padding:26px}}
.hd h1{{margin:0;font-size:24px}} .hd p{{margin:6px 0 0;opacity:.85;font-size:13px}}
.badge{{display:inline-block;margin-top:14px;padding:8px 18px;border-radius:999px;font-weight:800;font-size:18px;background:{vc}22;color:{vc};border:2px solid {vc}}}
.cards{{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}}
.card{{flex:1;min-width:150px;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;padding:18px;text-align:center}}
.card .n{{font-size:30px;font-weight:800}} .card .l{{font-size:12px;color:#93a1bd;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;overflow:hidden;font-size:13px}}
th{{background:#16203a;text-align:left;padding:11px 13px;font-size:12px;color:#9ec5ff}}
td{{padding:10px 13px;border-top:1px solid #1f2c47}}
h2{{font-size:17px;margin:28px 0 12px}} code{{background:#16203a;padding:2px 7px;border-radius:5px;color:#9ec5ff}}
ul{{line-height:1.9}} .ft{{margin-top:24px;color:#647394;font-size:12px;text-align:center}}
</style></head><body><div class="wrap">
<div class="hd"><h1>📊 User Scope Drift</h1>
<p>{now} · baseline {window[0]}d vs recente {window[1]}d</p>
<div class="badge">{summary['overall']}</div></div>
<div class="cards">
<div class="card"><div class="n">{summary['analyzed']}</div><div class="l">Usuários analisados</div></div>
<div class="card"><div class="n" style="color:#ff8c00">{summary['flagged']}</div><div class="l">FLAG / Critical</div></div>
<div class="card"><div class="n" style="color:#d13438">{summary['exfil']}</div><div class="l">Sinais de exfiltração</div></div>
<div class="card"><div class="n">{summary['avg']}</div><div class="l">Drift score médio</div></div>
</div>
<h2>Top drifters</h2>
<table><tr><th>Usuário</th><th>Score</th><th>Verdict</th><th>Sign-ins/dia (BL→rec)</th><th>Sinais</th></tr>{rows}</table>
<h2>Recomendações</h2><ul>{recs}</ul>
<div class="ft">user-scope-drift · collector↔renderer · gerado pelo SOC Autônomo</div>
</div></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="user-scope-drift report generator")
    ap.add_argument("--workspace", help="Log Analytics workspace GUID (self-collect mode)")
    ap.add_argument("--target", default="", help="UPN to scope to (empty = all users)")
    ap.add_argument("--from-json", dest="from_json", help="Render from pre-collected results JSON")
    ap.add_argument("--queries", default=str(HERE / "queries.yaml"))
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    q = load_queries(args.queries)
    params = dict(q.get("parameters", {}))

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif args.workspace:
        data = collect(args, q)
    else:
        ap.error("provide --workspace (self-collect) or --from-json (render)")

    users, summary = classify(data, params)
    window = (params.get("baseline_days", 90), params.get("recent_days", 7))
    htmlout = render_html(users, summary, params, window)

    out = args.output or str(HERE / "reports" /
                             f"user-scope-drift_{dt.datetime.utcnow():%Y%m%d_%H%M%S}.html")
    pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(htmlout)
    print(f"✅ {SKILL}: {summary['overall']} · {summary['flagged']} flagged / {summary['analyzed']} analyzed")
    print(f"📄 {out}")


if __name__ == "__main__":
    main()

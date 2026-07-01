#!/usr/bin/env python3
"""
secure-score-leadership — deterministic collector + renderer.

Pattern: collector↔renderer (queries.yaml = CAPTURE, this = RENDER).
Modes:
  1. Self-collect: acquires a Graph token via Azure CLI and GETs the two Secure Score endpoints.
  2. --from-json:  renders from pre-collected Graph responses.

Usage:
  python generate_html_report.py [--output out.html]            # self-collect
  python generate_html_report.py --from-json results.json

results.json shape: {"secure_scores": <graph response>, "control_profiles": <graph response>}
Requires: PyYAML. Self-collect mode also requires Azure CLI logged in with SecurityEvents.Read.All.
"""
import argparse
import datetime as dt
import html
import json
import pathlib
import subprocess
import sys
import urllib.request

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

HERE = pathlib.Path(__file__).parent
SKILL = "secure-score-leadership"


def load_queries(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_token(resource):
    cmd = ["az", "account", "get-access-token", "--resource", resource,
           "--query", "accessToken", "-o", "tsv"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"token failed: {res.stderr.strip()}")
    return res.stdout.strip()


def graph_get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def collect(q):
    g = q["graph"]
    params = q.get("parameters", {})
    token = get_token(g["token_resource"])
    ss_url = g["base"] + g["endpoints"]["secure_scores"].replace(
        "{trend_snapshots}", str(params.get("trend_snapshots", 90)))
    cp_url = g["base"] + g["endpoints"]["control_profiles"]
    return {"secure_scores": graph_get(ss_url, token),
            "control_profiles": graph_get(cp_url, token)}


def _num(x, d=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return d


def compute(data, params, scoring):
    scores = (data.get("secure_scores") or {}).get("value", [])
    profiles = (data.get("control_profiles") or {}).get("value", [])
    if not scores:
        raise RuntimeError("no secureScores returned (need SecurityEvents.Read.All + score history)")
    scores.sort(key=lambda s: s.get("createdDateTime", ""), reverse=True)
    latest = scores[0]
    cur, mx = _num(latest.get("currentScore")), _num(latest.get("maxScore"), 1)
    pct = round(cur / mx * 100, 1) if mx else 0

    def score_at(days):
        # snapshots are daily and sorted newest-first, so index ≈ N days ago
        idx = min(days, len(scores) - 1)
        return _num(scores[idx].get("currentScore"))
    delta7 = round(cur - score_at(7), 1)
    delta30 = round(cur - score_at(30), 1)

    comps = {c.get("basis"): round(_num(c.get("averageScore")), 1)
             for c in latest.get("averageComparativeScores", [])}

    prof = {p.get("id"): p for p in profiles}
    # category breakdown
    cats = {}
    for cs in latest.get("controlScores", []):
        cat = cs.get("controlCategory") or "Other"
        p = prof.get(cs.get("controlName"), {})
        cats.setdefault(cat, [0.0, 0.0])
        cats[cat][0] += _num(cs.get("score"))
        cats[cat][1] += _num(p.get("maxScore"))

    # quick wins by ROI
    cw, iw = scoring["cost_weight"], scoring["impact_weight"]
    wins = []
    for cs in latest.get("controlScores", []):
        p = prof.get(cs.get("controlName"))
        if not p or p.get("deprecated"):
            continue
        sc, m = _num(cs.get("score")), _num(p.get("maxScore"))
        gain = m - sc
        if gain <= 0:
            continue
        roi = gain * cw.get(p.get("implementationCost", "Moderate"), 0.6) \
                   * iw.get(p.get("userImpact", "Moderate"), 0.7)
        wins.append({"title": p.get("title") or cs.get("controlName"), "gain": round(gain, 1),
                     "cost": p.get("implementationCost", "—"), "impact": p.get("userImpact", "—"),
                     "service": p.get("service", "—"), "roi": roi})
    wins.sort(key=lambda w: w["roi"], reverse=True)
    wins = wins[:params.get("quick_wins", 8)]

    strong, moderate = params.get("strong_pct", 70), params.get("moderate_pct", 50)
    if pct >= strong:
        posture, verdict = "FORTE", "CLEAR"
    elif pct >= moderate:
        posture, verdict = "MODERADA", "MONITOR"
    else:
        posture, verdict = "FRACA", "ELEVATED"

    return {"current": round(cur, 1), "max": round(mx, 1), "pct": pct, "delta7": delta7,
            "delta30": delta30, "comps": comps, "cats": cats, "wins": wins,
            "posture": posture, "verdict": verdict,
            "active_users": latest.get("activeUserCount"), "as_of": latest.get("createdDateTime", "")[:10]}


VERDICT_COLOR = {"ELEVATED": "#d13438", "MONITOR": "#ffb900", "CLEAR": "#107c10"}


def render_html(r):
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    vc = VERDICT_COLOR.get(r["verdict"], "#107c10")

    def arrow(d):
        return f'<span style="color:#107c10">▲ +{d}</span>' if d > 0 else (
               f'<span style="color:#d13438">▼ {d}</span>' if d < 0 else '<span style="color:#93a1bd">▬ 0</span>')

    comp_rows = ""
    labels = {"AllTenants": "Todos os tenants", "TotalSeats": "Mesmo porte",
              "IndustryTypes": "Mesma indústria", "CurrentRank": "Rank atual"}
    for basis, avg in r["comps"].items():
        if basis == "CurrentRank":
            continue
        diff = round(r["current"] - avg, 1)
        cmp = (f'<span style="color:#107c10">+{diff} à frente</span>' if diff >= 0
               else f'<span style="color:#d13438">{diff} atrás</span>')
        comp_rows += (f'<tr><td>{labels.get(basis, html.escape(str(basis)))}</td>'
                      f'<td style="text-align:center">{avg}</td><td style="text-align:center">{cmp}</td></tr>')
    comp_rows = comp_rows or '<tr><td colspan="3" style="color:#93a1bd">Comparativo indisponível.</td></tr>'

    cat_bars = ""
    for cat, (sc, mx) in sorted(r["cats"].items(), key=lambda x: -(x[1][0] / x[1][1] if x[1][1] else 0)):
        p = round(sc / mx * 100) if mx else 0
        cat_bars += (f'<div style="margin:8px 0"><div style="display:flex;justify-content:space-between;'
                     f'font-size:13px"><span>{html.escape(cat)}</span><span style="color:#93a1bd">{round(sc)}/{round(mx)} ({p}%)</span></div>'
                     f'<div style="height:8px;background:#0c1626;border-radius:6px;overflow:hidden;margin-top:3px">'
                     f'<div style="height:100%;width:{p}%;background:linear-gradient(90deg,#3b82f6,#38bdf8)"></div></div></div>')

    win_rows = ""
    for w in r["wins"]:
        win_rows += (f'<tr><td>{html.escape(str(w["title"]))}</td>'
                     f'<td style="text-align:center;color:#38bdf8;font-weight:700">+{w["gain"]}</td>'
                     f'<td style="text-align:center">{html.escape(str(w["cost"]))}</td>'
                     f'<td style="text-align:center">{html.escape(str(w["impact"]))}</td>'
                     f'<td>{html.escape(str(w["service"]))}</td></tr>')
    win_rows = win_rows or '<tr><td colspan="5" style="color:#107c10">Todos os controles implementados. 🎉</td></tr>'

    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Secure Score — Liderança — {now}</title>
<style>
body{{margin:0;background:#0a0e1a;color:#e7eef9;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.5}}
.wrap{{max-width:900px;margin:0 auto;padding:24px}}
.hd{{background:linear-gradient(135deg,#0b3d2e,#107c10);border-radius:14px;padding:26px}}
.hd h1{{margin:0;font-size:24px}} .hd p{{margin:6px 0 0;opacity:.85;font-size:13px}}
.badge{{display:inline-block;margin-top:14px;padding:8px 18px;border-radius:999px;font-weight:800;font-size:18px;background:{vc}22;color:{vc};border:2px solid {vc}}}
.score{{font-size:48px;font-weight:800;margin:18px 0 0}} .score small{{font-size:20px;color:#93a1bd}}
.cards{{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}}
.card{{flex:1;min-width:150px;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;padding:18px;text-align:center}}
.card .n{{font-size:26px;font-weight:800}} .card .l{{font-size:12px;color:#93a1bd;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;overflow:hidden;font-size:13px}}
th{{background:#16203a;text-align:left;padding:11px 13px;font-size:12px;color:#9ae6b4}}
td{{padding:10px 13px;border-top:1px solid #1f2c47}}
h2{{font-size:17px;margin:28px 0 12px}} .ft{{margin-top:24px;color:#647394;font-size:12px;text-align:center}}
</style></head><body><div class="wrap">
<div class="hd"><h1>📈 Secure Score — Liderança</h1>
<p>{now} · dados de {r['as_of']} · {r['active_users']} usuários ativos</p>
<div class="badge">Postura: {r['posture']}</div>
<div class="score">{r['current']}<small> / {r['max']} ({r['pct']}%)</small></div></div>
<div class="cards">
<div class="card"><div class="n">{r['pct']}%</div><div class="l">Score atual</div></div>
<div class="card"><div class="n">{arrow(r['delta30'])}</div><div class="l">Tendência 30d</div></div>
<div class="card"><div class="n">{arrow(r['delta7'])}</div><div class="l">Tendência 7d</div></div>
<div class="card"><div class="n">{len(r['wins'])}</div><div class="l">Quick wins</div></div>
</div>
<h2>Comparativo com peers</h2>
<table><tr><th>Base</th><th>Média</th><th>Nós</th></tr>{comp_rows}</table>
<h2>Por categoria</h2><div style="background:#111a2e;border:1px solid #1f2c47;border-radius:12px;padding:18px">{cat_bars}</div>
<h2>🎯 Quick wins (maior ROI: ganho × baixo custo × baixo impacto)</h2>
<table><tr><th>Controle</th><th>+Pts</th><th>Custo</th><th>Impacto</th><th>Serviço</th></tr>{win_rows}</table>
<div class="ft">secure-score-leadership · collector↔renderer · gerado pelo SOC Autônomo</div>
</div></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="secure-score-leadership report generator")
    ap.add_argument("--from-json", dest="from_json", help="Render from pre-collected Graph JSON")
    ap.add_argument("--queries", default=str(HERE / "queries.yaml"))
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    q = load_queries(args.queries)
    params = dict(q.get("parameters", {}))
    scoring = q.get("scoring", {})

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = collect(q)

    r = compute(data, params, scoring)
    htmlout = render_html(r)

    out = args.output or str(HERE / "reports" /
                             f"secure-score_{dt.datetime.utcnow():%Y%m%d_%H%M%S}.html")
    pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(htmlout)
    print(f"✅ {SKILL}: postura {r['posture']} · {r['current']}/{r['max']} ({r['pct']}%) · Δ30d {r['delta30']}")
    print(f"📄 {out}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
org-posture — deterministic collector + renderer (executive consolidator).

Pattern: collector↔renderer (queries.yaml = CAPTURE, this = RENDER). API-NATIVE (Graph + MDE).
Consolidates 4 pillars into one Org Posture Index (0-100, grade A-F):
  Identity (Secure Score %) · Endpoint (100 - exposureScore) ·
  Threat pressure (active incidents, inverse) · Identity risk (high-risk users, inverse).

Modes:
  1. Self-collect: acquires Graph + MDE tokens via Azure CLI and GETs the endpoints.
  2. --from-json:  renders from pre-collected responses.

Usage:
  python generate_html_report.py [--output out.html]            # self-collect
  python generate_html_report.py --from-json results.json

results.json shape (keys = endpoint names):
  {"secure_scores": <graph>, "incidents": <graph>, "risky_users": <graph>, "exposure_score": <mde>}
Requires: PyYAML. Self-collect needs Azure CLI with SecurityEvents/SecurityIncident.Read.All,
IdentityRiskyUser.Read.All (Graph) + MDE Score.Read.All.
"""
import argparse
import datetime as dt
import html
import json
import pathlib
import shutil
import subprocess
import sys
import urllib.request

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

HERE = pathlib.Path(__file__).parent
SKILL = "org-posture"
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
    return path.replace(" ", "%20").replace("'", "%27")


def collect(q):
    out = {}
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


def _clamp(v, lo=0.0, hi=100.0):
    return max(lo, min(hi, v))


def compute(data, params, scoring):
    w = scoring["weights"]
    pen = scoring.get("incident_penalty", {})
    rup = scoring.get("risky_user_penalty", 12)

    # --- Identity (Secure Score %) ---
    scores = _val(data.get("secure_scores"))
    scores.sort(key=lambda s: s.get("createdDateTime", ""), reverse=True)
    latest = scores[0] if scores else {}
    cur, mx = _num(latest.get("currentScore")), _num(latest.get("maxScore"), 1)
    ss_pct = round(cur / mx * 100, 1) if mx else 0.0
    identity = _clamp(ss_pct)

    # --- Endpoint (100 - exposureScore) ---
    es = data.get("exposure_score") or {}
    exposure = round(_num(es.get("score")), 1) if isinstance(es, dict) else 0.0
    endpoint = _clamp(100 - exposure)

    # --- Threat pressure (active incidents) ---
    incidents = _val(data.get("incidents"))
    sev_counts = {}
    penalty = 0.0
    for inc in incidents:
        sev = str(inc.get("severity", "medium")).lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        penalty += pen.get(sev, pen.get("medium", 6))
    threat = _clamp(100 - penalty)

    # --- Identity risk (high-risk users) ---
    risky = _val(data.get("risky_users"))
    n_risky = len(risky)
    identity_risk = _clamp(100 - n_risky * rup)

    index = round(w["identity"] * identity + w["endpoint"] * endpoint +
                  w["threat"] * threat + w["identity_risk"] * identity_risk, 1)

    grade = "F"
    for thr, g in scoring.get("grades", [[90, "A"], [80, "B"], [70, "C"], [60, "D"], [0, "F"]]):
        if index >= thr:
            grade = g
            break

    if index >= params.get("grade_strong", 80):
        posture = "FORTE"
    elif index >= params.get("grade_moderate", 60):
        posture = "MODERADA"
    else:
        posture = "FRACA"

    pillars = [
        {"name": "Identidade & Config (Secure Score)", "score": round(identity, 1),
         "weight": w["identity"], "contrib": round(w["identity"] * identity, 1),
         "driver": f"{int(cur)}/{int(mx)} pts ({ss_pct}%)"},
        {"name": "Endpoint (Exposure Score)", "score": round(endpoint, 1),
         "weight": w["endpoint"], "contrib": round(w["endpoint"] * endpoint, 1),
         "driver": f"exposure {exposure} (menor é melhor)"},
        {"name": "Pressão de ameaças (incidentes ativos)", "score": round(threat, 1),
         "weight": w["threat"], "contrib": round(w["threat"] * threat, 1),
         "driver": f"{len(incidents)} ativos · " + (", ".join(f"{k}:{v}" for k, v in sorted(sev_counts.items())) or "nenhum")},
        {"name": "Risco de identidade (risky users)", "score": round(identity_risk, 1),
         "weight": w["identity_risk"], "contrib": round(w["identity_risk"] * identity_risk, 1),
         "driver": f"{n_risky} usuários de alto risco"},
    ]
    return {"index": index, "grade": grade, "posture": posture, "pillars": pillars,
            "secure_pct": ss_pct, "exposure": exposure,
            "incidents": len(incidents), "risky": n_risky, "sev_counts": sev_counts}


POSTURE_COLOR = {"FORTE": "#107c10", "MODERADA": "#ffb900", "FRACA": "#d13438"}


def bar(score, color):
    return (f'<div style="background:#1f2c47;border-radius:6px;height:10px;overflow:hidden">'
            f'<div style="width:{_clamp(score)}%;height:100%;background:{color}"></div></div>')


def render_html(s):
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    pc = POSTURE_COLOR.get(s["posture"], "#ffb900")

    rows = ""
    for p in s["pillars"]:
        sc = p["score"]
        col = "#107c10" if sc >= 80 else ("#ffb900" if sc >= 60 else "#d13438")
        rows += (f"<tr><td>{html.escape(p['name'])}</td>"
                 f"<td style='min-width:160px'>{bar(sc, col)}</td>"
                 f"<td style='text-align:right;color:{col};font-weight:700'>{sc}</td>"
                 f"<td style='text-align:right'>{int(p['weight']*100)}%</td>"
                 f"<td style='text-align:right'>{p['contrib']}</td>"
                 f"<td style='color:#93a1bd'>{html.escape(p['driver'])}</td></tr>")

    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Org Posture</title>
<style>
body{{margin:0;background:#0a0e1a;color:#e7eef9;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.5}}
.wrap{{max-width:980px;margin:0 auto;padding:24px}}
.hd{{background:linear-gradient(135deg,#0b3d2e,#0078d4);border-radius:14px;padding:26px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px}}
.hd h1{{margin:0;font-size:23px}} .hd p{{margin:6px 0 0;opacity:.9;font-size:13px}}
.gradebox{{text-align:center}}
.grade{{font-size:64px;font-weight:900;line-height:1;color:{pc}}}
.index{{font-size:13px;color:#dbe6f5;margin-top:4px}}
.badge{{display:inline-block;margin-top:8px;padding:6px 16px;border-radius:999px;font-weight:800;font-size:15px;background:{pc}22;color:{pc};border:2px solid {pc}}}
.cards{{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}}
.card{{flex:1;min-width:130px;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;padding:16px;text-align:center}}
.card .n{{font-size:24px;font-weight:800}} .card .l{{font-size:11.5px;color:#93a1bd;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;overflow:hidden;font-size:12.5px;margin-bottom:8px}}
th{{background:#16203a;text-align:left;padding:10px 12px;font-size:11.5px;color:#9ec5ff}}
td{{padding:10px 12px;border-top:1px solid #1f2c47;vertical-align:middle}}
h2{{font-size:16px;margin:26px 0 10px}} .ft{{margin-top:24px;color:#647394;font-size:12px;text-align:center}}
</style></head><body><div class="wrap">
<div class="hd"><div><h1>🛡️ Org Security Posture</h1>
<p>Índice executivo consolidado · Secure Score + Endpoint + Ameaças + Identidade · {now}</p>
<div class="badge">POSTURA {s['posture']}</div></div>
<div class="gradebox"><div class="grade">{s['grade']}</div><div class="index">Índice {s['index']}/100</div></div></div>
<div class="cards">
<div class="card"><div class="n">{s['secure_pct']}%</div><div class="l">Secure Score</div></div>
<div class="card"><div class="n" style="color:#ff8c00">{s['exposure']}</div><div class="l">Exposure (MDE)</div></div>
<div class="card"><div class="n" style="color:#d13438">{s['incidents']}</div><div class="l">Incidentes ativos</div></div>
<div class="card"><div class="n" style="color:#ffb900">{s['risky']}</div><div class="l">Risky users (high)</div></div>
</div>
<h2>📊 Pilares da postura (índice ponderado)</h2>
<table><tr><th>Pilar</th><th>Sub-score</th><th style="text-align:right">Valor</th><th style="text-align:right">Peso</th><th style="text-align:right">Contrib.</th><th>Driver</th></tr>
{rows}</table>
<div class="ft">org-posture · collector↔renderer · consolida os domínios das skills das Fases A/B · gerado pelo SOC Autônomo</div>
</div></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="org-posture executive consolidator")
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

    out = args.output or str(HERE / "reports" / f"orgposture_{dt.datetime.utcnow():%Y%m%d_%H%M%S}.html")
    pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(htmlout)
    print(f"✅ {SKILL}: POSTURA {s['posture']} · nota {s['grade']} · índice {s['index']}/100 · "
          f"SS {s['secure_pct']}% · exp {s['exposure']} · inc {s['incidents']} · risky {s['risky']}")
    print(f"📄 {out}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
aitm-dashboard — deterministic collector + renderer.

Pattern: collector↔renderer (queries.yaml = CAPTURE, this = RENDER). TENANT-WIDE.
Modes:
  1. Self-collect: runs the KQL from queries.yaml via `az monitor log-analytics query`.
  2. --from-json:  renders from pre-collected results (captured by the SRE Agent).

Usage:
  python generate_html_report.py --workspace <LA_GUID> [--output out.html]
  python generate_html_report.py --from-json results.json

results.json shape (keys = queries.yaml query names):
  {"overview":[...], "risky_success":[...], "anomalous_token":[...], "session_anomaly":[...],
   "mfa_changes":[...], "inbox_rules":[...], "top_targets":[...]}
Requires: PyYAML.
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
SKILL = "aitm-dashboard"
AZ = shutil.which("az") or "az"  # resolve az.cmd no Windows; no Linux (SRE Agent) acha o binário

# pesos do score AiTM por indicador (BEC inbox rule e anomalous token são os mais fortes)
W = {"anomalous_token": 25, "inbox_rules": 30, "session_anomaly": 15, "risky_success": 5, "mfa_changes": 10}


def load_queries(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def subst(kql, params):
    out = kql
    for k, v in params.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def _flatten_kql(kql):
    # args de CLI com newlines são truncados pelo az.cmd no Windows → achatar p/ 1 linha.
    # remove comentários // de linha inteira e junta com espaço (KQL fica equivalente). Sem efeito no Linux.
    parts = []
    for ln in kql.splitlines():
        if ln.lstrip().startswith("//"):
            continue
        s = ln.strip()
        if s:
            parts.append(s)
    return " ".join(parts)


def run_kql(workspace, kql):
    cmd = [AZ, "monitor", "log-analytics", "query",
           "--workspace", workspace, "--analytics-query", _flatten_kql(kql), "-o", "json"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"KQL failed:\n{res.stderr.strip()}")
    return json.loads(res.stdout or "[]")


def graph_token():
    cmd = [AZ, "account", "get-access-token", "--resource", "https://graph.microsoft.com",
           "--query", "accessToken", "-o", "tsv"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip())
    return res.stdout.strip()


def run_hunt(url, token, body):
    # Defender XDR Advanced Hunting via Microsoft Graph (tabelas que não vivem no Sentinel)
    req = urllib.request.Request(
        url, data=body.encode("utf-8"), method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)


def collect(args, q):
    p = q.get("parameters", {})
    params = {"lookback_days": p.get("lookback_days", 7),
              "session_window_hours": p.get("session_window_hours", 1),
              "session_country_min": p.get("session_country_min", 2)}
    data = {}
    # --- Sentinel KQL: tabelas AAD que vivem no Log Analytics ---
    for name in q["queries"]:
        kql = subst(q["queries"][name], params)
        try:
            data[name] = run_kql(args.workspace, kql)
        except Exception as e:
            print(f"  ! KQL '{name}' failed: {e}", file=sys.stderr)
            data[name] = []
    # --- XDR-native via Graph runHuntingQuery: tabelas que NÃO estão no Sentinel (inbox rules) ---
    gx = q.get("graph_xdr", {})
    for name in gx:
        data.setdefault(name, [])
    if gx and not getattr(args, "no_graph", False):
        try:
            token = graph_token()
            for name, spec in gx.items():
                body = subst(spec.get("body", ""), params)
                try:
                    resp = run_hunt(spec["url"], token, body)
                    data[name] = resp.get(spec.get("result_key", "results")) or resp.get("Results") or []
                except Exception as e:
                    print(f"  ! graph_xdr '{name}' failed: {e}", file=sys.stderr)
        except Exception as e:
            print(f"  ! graph token failed (XDR ignorado): {e}", file=sys.stderr)
    return data


def _i(x):
    try:
        return int(float(x))
    except (TypeError, ValueError):
        return 0


def classify(data):
    ov = (data.get("overview") or [{}])[0] if data.get("overview") else {}
    counts = {
        "anomalous_token": len(data.get("anomalous_token", [])),
        "inbox_rules": len(data.get("inbox_rules", [])),
        "session_anomaly": len(data.get("session_anomaly", [])),
        "risky_success": _i(ov.get("RiskySuccess")) or len(data.get("risky_success", [])),
        "mfa_changes": len(data.get("mfa_changes", [])),
    }
    score = sum(W[k] * counts[k] for k in counts)

    # verdict: token/inbox = sinais fortes de AiTM/BEC
    if counts["anomalous_token"] > 0 or counts["inbox_rules"] > 0 or counts["session_anomaly"] >= 3:
        verdict = "ELEVATED"
    elif counts["risky_success"] > 0 or counts["mfa_changes"] > 0 or counts["session_anomaly"] > 0:
        verdict = "MONITOR"
    else:
        verdict = "CLEAR"

    affected = _i(ov.get("AffectedUsers")) or len({r.get("UserPrincipalName") for r in data.get("risky_success", [])})
    return ov, {"verdict": verdict, "score": score, "counts": counts, "affected": affected}


VERDICT_COLOR = {"ELEVATED": "#d13438", "MONITOR": "#ffb900", "CLEAR": "#107c10"}


def _trunc_times(rows, keys=("TimeGenerated", "Window", "Timestamp", "FirstSeen", "LastSeen")):
    for r in rows:
        for k in keys:
            if k in r and isinstance(r[k], str) and len(r[k]) > 19:
                r[k] = r[k][:19].replace("T", " ")
    return rows


def table(rows, cols):
    if not rows:
        return f'<tr><td colspan="{len(cols)}" style="color:#647394">Sem dados no período.</td></tr>'
    out = ""
    for r in rows:
        out += "<tr>" + "".join(f'<td>{html.escape(str(r.get(k, "")))}</td>' for _, k in cols) + "</tr>"
    return out


def th(cols):
    return "".join(f"<th>{h}</th>" for h, _ in cols)


def render_html(ov, summary, data):
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    vc = VERDICT_COLOR.get(summary["verdict"], "#107c10")
    lookback = data.get("_lookback", 7)
    c = summary["counts"]

    risky_cols = [("Quando", "TimeGenerated"), ("Usuário", "UserPrincipalName"), ("IP", "IPAddress"),
                  ("País", "Country"), ("App", "AppDisplayName"), ("Risco", "RiskLevelDuringSignIn"), ("Estado", "RiskState")]
    token_cols = [("Quando", "TimeGenerated"), ("Usuário", "UserPrincipalName"), ("IP", "IPAddress"),
                  ("País", "Country"), ("Eventos de risco", "RiskEvents")]
    sess_cols = [("Janela", "Window"), ("Usuário", "UserPrincipalName"), ("Países", "Countries"),
                 ("IPs", "IPs"), ("Lista países", "CountryList")]
    mfa_cols = [("Quando", "TimeGenerated"), ("Operação", "OperationName"), ("Alvo", "Target"),
                ("Iniciador", "Initiator"), ("Resultado", "Result")]
    inbox_cols = [("Quando", "Timestamp"), ("Usuário", "AccountDisplayName"), ("Ação", "ActionType"),
                  ("IP", "IPAddress"), ("Regra", "Rule")]
    target_cols = [("Usuário", "UserPrincipalName"), ("Indicadores", "Indicators"), ("Sucesso de risco", "RiskySuccess"),
                   ("Países", "Countries"), ("IPs", "IPs"), ("Último", "LastSeen")]

    risky = _trunc_times(data.get("risky_success", []))
    token = _trunc_times(data.get("anomalous_token", []))
    sess = _trunc_times(data.get("session_anomaly", []))
    mfa = _trunc_times(data.get("mfa_changes", []))
    inbox = _trunc_times(data.get("inbox_rules", []))
    targets = _trunc_times(data.get("top_targets", []))

    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>AiTM Dashboard</title>
<style>
body{{margin:0;background:#0a0e1a;color:#e7eef9;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.5}}
.wrap{{max-width:1000px;margin:0 auto;padding:24px}}
.hd{{background:linear-gradient(135deg,#6e1423,#d13438);border-radius:14px;padding:26px}}
.hd h1{{margin:0;font-size:23px}} .hd p{{margin:6px 0 0;opacity:.9;font-size:13px}}
.badge{{display:inline-block;margin-top:14px;padding:8px 18px;border-radius:999px;font-weight:800;font-size:18px;background:{vc}22;color:{vc};border:2px solid {vc}}}
.cards{{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}}
.card{{flex:1;min-width:120px;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;padding:16px;text-align:center}}
.card .n{{font-size:26px;font-weight:800}} .card .l{{font-size:11.5px;color:#93a1bd;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;overflow:hidden;font-size:12.5px;margin-bottom:8px}}
th{{background:#16203a;text-align:left;padding:10px 12px;font-size:11.5px;color:#ff9ea3}}
td{{padding:8px 12px;border-top:1px solid #1f2c47}}
h2{{font-size:16px;margin:26px 0 10px}} .ft{{margin-top:24px;color:#647394;font-size:12px;text-align:center}}
.score{{font-size:13px;color:#93a1bd;margin-top:8px}}
</style></head><body><div class="wrap">
<div class="hd"><h1>🎣 AiTM &amp; Token Theft Dashboard</h1>
<p>Adversary-in-the-Middle · token replay · MFA bypass · BEC persistence · janela {lookback}d · {now}</p>
<div class="badge">{summary['verdict']}</div>
<div class="score">AiTM risk score: <b>{summary['score']}</b> · usuários afetados: <b>{summary['affected']}</b></div></div>
<div class="cards">
<div class="card"><div class="n" style="color:#d13438">{c['anomalous_token']}</div><div class="l">Anomalous token</div></div>
<div class="card"><div class="n" style="color:#ff8c00">{c['risky_success']}</div><div class="l">Sucesso de risco</div></div>
<div class="card"><div class="n" style="color:#ffb900">{c['session_anomaly']}</div><div class="l">Anomalias de sessão</div></div>
<div class="card"><div class="n" style="color:#d13438">{c['inbox_rules']}</div><div class="l">Inbox rules (BEC)</div></div>
<div class="card"><div class="n">{c['mfa_changes']}</div><div class="l">Trocas de MFA</div></div>
</div>
<h2>🔑 Anomalous token / token issuer anomaly</h2>
<table><tr>{th(token_cols)}</tr>{table(token, token_cols)}</table>
<h2>⚠️ Sign-ins de sucesso com risco (MFA satisfeito via token)</h2>
<table><tr>{th(risky_cols)}</tr>{table(risky, risky_cols)}</table>
<h2>🌐 Anomalias de sessão (multi-país numa janela curta)</h2>
<table><tr>{th(sess_cols)}</tr>{table(sess, sess_cols)}</table>
<h2>📨 Inbox rules suspeitas (persistência BEC)</h2>
<table><tr>{th(inbox_cols)}</tr>{table(inbox, inbox_cols)}</table>
<h2>🔐 Alterações de método MFA</h2>
<table><tr>{th(mfa_cols)}</tr>{table(mfa, mfa_cols)}</table>
<h2>🎯 Top alvos</h2>
<table><tr>{th(target_cols)}</tr>{table(targets, target_cols)}</table>
<div class="ft">aitm-dashboard · collector↔renderer · gerado pelo SOC Autônomo</div>
</div></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="aitm-dashboard report generator")
    ap.add_argument("--workspace", help="Log Analytics workspace GUID (self-collect mode)")
    ap.add_argument("--from-json", dest="from_json", help="Render from pre-collected results JSON")
    ap.add_argument("--no-graph", dest="no_graph", action="store_true",
                    help="Pula o runHuntingQuery XDR (inbox rules) no modo self-collect")
    ap.add_argument("--queries", default=str(HERE / "queries.yaml"))
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    q = load_queries(args.queries)
    lookback = q.get("parameters", {}).get("lookback_days", 7)

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif args.workspace:
        data = collect(args, q)
    else:
        ap.error("provide --workspace (self-collect) or --from-json (render)")

    data["_lookback"] = lookback
    ov, summary = classify(data)
    htmlout = render_html(ov, summary, data)

    out = args.output or str(HERE / "reports" / f"aitm_{dt.datetime.utcnow():%Y%m%d_%H%M%S}.html")
    pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(htmlout)
    c = summary["counts"]
    print(f"✅ {SKILL}: {summary['verdict']} · score {summary['score']} · "
          f"token {c['anomalous_token']} · inbox {c['inbox_rules']} · sessão {c['session_anomaly']} · "
          f"risky {c['risky_success']} · afetados {summary['affected']}")
    print(f"📄 {out}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
forensic-user-investigation — deterministic collector + renderer.

Pattern: collector↔renderer (queries.yaml = CAPTURE, this = RENDER). SINGLE-USER.
Modes:
  1. Self-collect: runs the KQL from queries.yaml via `az monitor log-analytics query`.
  2. --from-json:  renders from pre-collected results (captured by the SRE Agent).

Usage:
  python generate_html_report.py --workspace <LA_GUID> --target user@x.com [--output out.html]
  python generate_html_report.py --from-json results.json --target user@x.com

results.json shape (keys = queries.yaml query names):
  {"overview":[...], "geo":[...], "auth_ca":[...], "risky":[...], "alerts":[...], "audit":[...], "devices":[...]}
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
SKILL = "forensic-user-investigation"
AZ = shutil.which("az") or "az"  # resolve az.cmd no Windows; no Linux (SRE Agent) acha o binário


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
    params = {"target": args.target, "lookback_days": q.get("parameters", {}).get("lookback_days", 30)}
    data = {}
    # --- Sentinel KQL: tabelas AAD que vivem no Log Analytics ---
    for name in q["queries"]:
        kql = subst(q["queries"][name], params)
        try:
            data[name] = run_kql(args.workspace, kql)
        except Exception as e:
            print(f"  ! KQL '{name}' failed: {e}", file=sys.stderr)
            data[name] = []
    # --- XDR-native via Graph runHuntingQuery: DeviceLogonEvents (não existe no Sentinel) ---
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
    risky = data.get("risky", [])
    alerts = data.get("alerts", [])
    high_alert = any(str(a.get("AlertSeverity", "")).lower() in ("high", "critical") for a in alerts)
    confirmed = any(str(r.get("RiskState", "")).lower() in ("atrisk", "confirmedcompromised") for r in risky)
    ca_fail = any(_i(r.get("Fails")) > 0 for r in data.get("auth_ca", []))

    if _i(ov.get("RiskHigh")) > 0 or confirmed or high_alert:
        verdict = "ELEVATED"
    elif _i(ov.get("RiskMedium")) > 0 or alerts or ca_fail:
        verdict = "MONITOR"
    else:
        verdict = "CLEAR"

    risk_count = _i(ov.get("RiskHigh")) + _i(ov.get("RiskMedium"))
    if not risk_count:
        risk_count = len(risky)
    return ov, {"verdict": verdict, "alerts": len(alerts), "risk_count": risk_count,
                "high_alert": high_alert, "confirmed": confirmed}


VERDICT_COLOR = {"ELEVATED": "#d13438", "MONITOR": "#ffb900", "CLEAR": "#107c10"}


def _trunc_times(rows, keys=("TimeGenerated", "FirstSeen", "LastSeen", "First", "Last")):
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


def render_html(target, ov, summary, data):
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    vc = VERDICT_COLOR.get(summary["verdict"], "#107c10")
    lookback = data.get("_lookback", 30)

    geo_cols = [("País", "Country"), ("Cidade", "City"), ("IP", "IPAddress"), ("Sign-ins", "Count"), ("Falhas", "Fails")]
    ca_cols = [("CA Status", "ConditionalAccessStatus"), ("Auth Requirement", "AuthenticationRequirement"), ("Sign-ins", "Count"), ("Falhas", "Fails")]
    risky_cols = [("Quando", "TimeGenerated"), ("IP", "IPAddress"), ("País", "Country"), ("App", "AppDisplayName"), ("Risco", "RiskLevelDuringSignIn"), ("Estado", "RiskState")]
    alert_cols = [("Quando", "TimeGenerated"), ("Alerta", "AlertName"), ("Sev", "AlertSeverity"), ("Produto", "ProviderName"), ("Status", "Status")]
    audit_cols = [("Quando", "TimeGenerated"), ("Operação", "OperationName"), ("Iniciador", "Initiator"), ("Resultado", "Result")]
    dev_cols = [("Device", "DeviceName"), ("Logons", "Logons"), ("Primeiro", "First"), ("Último", "Last")]

    geo = _trunc_times(data.get("geo", []))
    ca = data.get("auth_ca", [])
    risky = _trunc_times(data.get("risky", []))
    alerts = _trunc_times(data.get("alerts", []))
    audit = _trunc_times(data.get("audit", []))
    devices = _trunc_times(data.get("devices", []))

    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Forensic — {html.escape(target)}</title>
<style>
body{{margin:0;background:#0a0e1a;color:#e7eef9;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.5}}
.wrap{{max-width:980px;margin:0 auto;padding:24px}}
.hd{{background:linear-gradient(135deg,#1a3a8c,#0078d4);border-radius:14px;padding:26px}}
.hd h1{{margin:0;font-size:23px}} .hd p{{margin:6px 0 0;opacity:.85;font-size:13px}}
.badge{{display:inline-block;margin-top:14px;padding:8px 18px;border-radius:999px;font-weight:800;font-size:18px;background:{vc}22;color:{vc};border:2px solid {vc}}}
.cards{{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}}
.card{{flex:1;min-width:140px;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;padding:18px;text-align:center}}
.card .n{{font-size:28px;font-weight:800}} .card .l{{font-size:12px;color:#93a1bd;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;overflow:hidden;font-size:12.5px;margin-bottom:8px}}
th{{background:#16203a;text-align:left;padding:10px 12px;font-size:11.5px;color:#9ec5ff}}
td{{padding:8px 12px;border-top:1px solid #1f2c47}}
h2{{font-size:16px;margin:26px 0 10px}} .ft{{margin-top:24px;color:#647394;font-size:12px;text-align:center}}
</style></head><body><div class="wrap">
<div class="hd"><h1>🔬 Forensic User Investigation</h1>
<p>{html.escape(target)} · janela {lookback}d · {now}</p>
<div class="badge">{summary['verdict']}</div></div>
<div class="cards">
<div class="card"><div class="n">{_i(ov.get('Total')):,}</div><div class="l">Sign-ins</div></div>
<div class="card"><div class="n" style="color:#ff8c00">{_i(ov.get('Fail')):,}</div><div class="l">Falhas</div></div>
<div class="card"><div class="n">{_i(ov.get('Countries'))}</div><div class="l">Países</div></div>
<div class="card"><div class="n" style="color:#d13438">{summary['risk_count']}</div><div class="l">Sign-ins de risco</div></div>
</div>
<h2>🌍 Distribuição geográfica</h2>
<table><tr>{th(geo_cols)}</tr>{table(geo, geo_cols)}</table>
<h2>🔐 Auth & Conditional Access</h2>
<table><tr>{th(ca_cols)}</tr>{table(ca, ca_cols)}</table>
<h2>⚠️ Sign-ins de risco / IOC</h2>
<table><tr>{th(risky_cols)}</tr>{table(risky, risky_cols)}</table>
<h2>🚨 Alertas correlacionados</h2>
<table><tr>{th(alert_cols)}</tr>{table(alerts, alert_cols)}</table>
<h2>📋 Operações de diretório</h2>
<table><tr>{th(audit_cols)}</tr>{table(audit, audit_cols)}</table>
<h2>💻 Device logons</h2>
<table><tr>{th(dev_cols)}</tr>{table(devices, dev_cols)}</table>
<div class="ft">forensic-user-investigation · collector↔renderer · gerado pelo SOC Autônomo</div>
</div></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="forensic-user-investigation report generator")
    ap.add_argument("--workspace", help="Log Analytics workspace GUID (self-collect mode)")
    ap.add_argument("--target", required=True, help="Target UPN (single user — required)")
    ap.add_argument("--from-json", dest="from_json", help="Render from pre-collected results JSON")
    ap.add_argument("--no-graph", dest="no_graph", action="store_true",
                    help="Pula o runHuntingQuery XDR (device logons) no modo self-collect")
    ap.add_argument("--queries", default=str(HERE / "queries.yaml"))
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    q = load_queries(args.queries)
    lookback = q.get("parameters", {}).get("lookback_days", 30)

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif args.workspace:
        data = collect(args, q)
    else:
        ap.error("provide --workspace (self-collect) or --from-json (render)")

    data["_lookback"] = lookback
    ov, summary = classify(data)
    htmlout = render_html(args.target, ov, summary, data)

    safe = args.target.replace("@", "_at_").replace(".", "_")
    out = args.output or str(HERE / "reports" /
                             f"forensic_{safe}_{dt.datetime.utcnow():%Y%m%d_%H%M%S}.html")
    pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(htmlout)
    print(f"✅ {SKILL}: {args.target} · {summary['verdict']} · "
          f"{_i(ov.get('Total'))} sign-ins · {summary['alerts']} alerts · {summary['risk_count']} risk")
    print(f"📄 {out}")


if __name__ == "__main__":
    main()

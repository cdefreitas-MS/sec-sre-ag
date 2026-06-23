#!/usr/bin/env python3
"""
graph-least-privilege — deterministic collector + renderer.

Pattern: collector↔renderer (queries.yaml = CAPTURE, this = RENDER).
Concept ported from Mynster9361/Least_Privileged_MSGraph (MIT) into the SOC Autônomo stack.

Cross-references GRANTED Microsoft Graph application permissions (per app registration)
against ACTUALLY-USED endpoints in MicrosoftGraphActivityLogs, surfacing:
  • DORMANT apps  — granted perms but zero Graph calls in the window
  • EXCESS scopes — granted scope whose endpoint family was never observed (heuristic)
  • throttling    — HTTP 429 per app
META: highlights the SRE Agent's own UAMI. Recommend-only — never removes a permission.

Modes:
  1. Self-collect: KQL via `az monitor log-analytics query` + Graph via `az rest`.
  2. --from-json : render from results captured by the SRE Agent tool.

Usage:
  python generate_html_report.py --workspace <LA_GUID> [--days 30] [--output out.html]
  python generate_html_report.py --from-json results.json

results.json shape:
  {"app_activity":[...], "app_errors":[...], "graph_sp":{...}, "service_principals":{...}}
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

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Resolve the Azure CLI executable (az.cmd on Windows) so subprocess can find it.
AZ = shutil.which("az") or shutil.which("az.cmd") or "az"

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

HERE = pathlib.Path(__file__).parent
SKILL = "graph-least-privilege"


def load_queries(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def subst(text, params):
    out = text
    for k, v in params.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def _val(resp):
    if isinstance(resp, dict):
        v = resp.get("value")
        return v if isinstance(v, list) else []
    if isinstance(resp, list):
        return resp
    return []


def _num(x, d=0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return d


def run_kql(workspace, kql):
    # Flatten to a single line: a multi-line arg is truncated at the first newline when
    # the az.cmd batch wrapper is invoked via cmd.exe on Windows (KQL stays valid one-lined).
    kql = " ".join(part.strip() for part in kql.splitlines() if part.strip())
    cmd = [AZ, "monitor", "log-analytics", "query",
           "--workspace", workspace, "--analytics-query", kql, "-o", "json"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip())
    return json.loads(res.stdout or "[]")


def run_graph(spec):
    url = spec.split(" ", 1)[1] if spec.lower().startswith("get ") else spec
    if sys.platform == "win32":
        # az is a .cmd batch wrapper; '&' in the OData URL is split by cmd.exe unless the
        # whole URL is double-quoted, so run a quoted command string via the shell.
        res = subprocess.run(f'"{AZ}" rest --method get --url "{url}" -o json',
                             capture_output=True, text=True, shell=True)
    else:
        res = subprocess.run([AZ, "rest", "--method", "get", "--url", url, "-o", "json"],
                             capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip())
    return json.loads(res.stdout or "{}")


def run_graph_paged(spec):
    """GET a Graph resource; if it's a collection with @odata.nextLink, follow ALL pages
    and return a single {"value": [...all...]}. Single-object resources pass through."""
    resp = run_graph(spec)
    if isinstance(resp, dict) and isinstance(resp.get("value"), list):
        value = list(resp["value"])
        nxt = resp.get("@odata.nextLink")
        pages = 0
        while nxt and pages < 50:
            page = run_graph(nxt)
            value.extend(page.get("value", []))
            nxt = page.get("@odata.nextLink")
            pages += 1
        resp["value"] = value
        resp.pop("@odata.nextLink", None)
    return resp


def collect(args, q):
    params = dict(q.get("parameters", {}))
    params["days"] = args.days or params.get("days", 30)
    data = {}
    for name in ("app_activity", "app_errors"):
        kql = subst(q["queries"][name], params)
        try:
            data[name] = run_kql(args.workspace, kql)
        except Exception as e:
            print(f"  ! KQL '{name}' failed: {e}", file=sys.stderr)
            data[name] = []
    # graph_sp = single object (with expanded appRoleAssignedTo); service_principals = paged collection.
    for name, fn in (("graph_sp", run_graph), ("service_principals", run_graph_paged)):
        try:
            data[name] = fn(q["graph"][name])
        except Exception as e:
            print(f"  ! Graph '{name}' failed: {e}", file=sys.stderr)
            data[name] = {}
    return data


def _families(fams):
    return {str(f).lower() for f in (fams or []) if f}


def analyze(data, q):
    params = q.get("parameters", {})
    scoring = q.get("scoring", {})
    smap = {k: [x.lower() for x in v] for k, v in (q.get("scope_endpoint_map", {}) or {}).items()}
    excess_warn = int(_num(scoring.get("excess_warn", 1)))
    excess_high = int(_num(scoring.get("excess_high", 3)))
    uami_appid = str(params.get("uami_appid", "")).lower()

    # Microsoft Graph SP: appRoles dictionary + granted assignments per app SP
    gsp = data.get("graph_sp") or {}
    if isinstance(gsp, dict) and isinstance(gsp.get("value"), list):
        gsp = gsp["value"][0] if gsp["value"] else {}
    role_name = {}
    for ar in (gsp.get("appRoles") or []):
        role_name[str(ar.get("id"))] = ar.get("value") or ar.get("displayName") or str(ar.get("id"))
    granted = {}  # spObjectId -> {name, appId, scopes:set}
    for a in (gsp.get("appRoleAssignedTo") or []):
        sid = str(a.get("principalId") or "")
        if not sid:
            continue
        g = granted.setdefault(sid, {"name": a.get("principalDisplayName") or sid,
                                     "appId": "", "scopes": set()})
        nm = role_name.get(str(a.get("appRoleId")))
        if nm:
            g["scopes"].add(nm)

    # SP catalog by objectId
    sp_cat = {str(sp.get("id")): sp for sp in _val(data.get("service_principals"))}

    # activity keyed by SP objectId and AppId
    act_by_sp, act_by_app = {}, {}
    for r in _val(data.get("app_activity")):
        rec = {"calls": int(_num(r.get("Calls"))), "throttled": int(_num(r.get("Throttled"))),
               "families": _families(r.get("Families")), "last": r.get("Last")}
        if r.get("ServicePrincipalId"):
            act_by_sp[str(r.get("ServicePrincipalId"))] = rec
        if r.get("AppId"):
            act_by_app[str(r.get("AppId")).lower()] = rec

    apps = []
    for sid, g in granted.items():
        cat = sp_cat.get(sid, {})
        appid = str(cat.get("appId") or g.get("appId") or "")
        act = act_by_sp.get(sid) or act_by_app.get(appid.lower()) or \
            {"calls": 0, "throttled": 0, "families": set(), "last": None}
        scopes = sorted(g["scopes"])
        fams = act["families"]
        unused = []
        for sc in scopes:
            fam_list = smap.get(sc)
            if fam_list is None:
                continue  # unmapped scope → don't flag (avoid false positives)
            if not any(f in fams for f in fam_list):
                unused.append(sc)
        if scopes and act["calls"] == 0:
            verdict = ("DORMANT", "#d13438")
        elif len(unused) >= excess_high:
            verdict = ("EXCESS", "#d13438")
        elif len(unused) >= excess_warn:
            verdict = ("EXCESS", "#ffb900")
        else:
            verdict = ("TIGHT", "#107c10")
        apps.append({"name": g["name"], "appId": appid,
                     "type": cat.get("servicePrincipalType", ""), "scopes": scopes,
                     "granted_n": len(scopes), "calls": act["calls"],
                     "throttled": act["throttled"], "unused": unused, "last": act["last"],
                     "verdict": verdict, "is_uami": appid.lower() == uami_appid})

    order = {"DORMANT": 0, "EXCESS": 1, "TIGHT": 2}
    apps.sort(key=lambda a: (order.get(a["verdict"][0], 3), -len(a["unused"]), -a["calls"]))

    rollup = {"apps_with_perms": len(apps),
              "apps_dormant": sum(1 for a in apps if a["verdict"][0] == "DORMANT"),
              "apps_excess": sum(1 for a in apps if a["unused"]),
              "total_excess": sum(len(a["unused"]) for a in apps),
              "throttled_apps": sum(1 for a in apps if a["throttled"] > 0)}
    return apps, rollup


def _chips(scopes, bg, fg):
    if not scopes:
        return "<span style='color:#6b7280'>—</span>"
    return " ".join(f"<span style='background:{bg};color:{fg};padding:2px 7px;"
                    f"border-radius:6px;font-size:11px'>{html.escape(s)}</span>" for s in scopes)


def render_html(apps, rollup, days):
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    dormant = rollup["apps_dormant"]
    excess = rollup["apps_excess"]
    overall_color = "#d13438" if (dormant or rollup["total_excess"] >= 3) else \
        "#ffb900" if excess else "#107c10"
    overall = "AÇÃO" if dormant else "REVISAR" if excess else "ENXUTO"

    rows = ""
    for a in apps[:40]:
        v, vc = a["verdict"]
        badges = ""
        if a["is_uami"]:
            badges = ('<span style="background:#3b1a5a;color:#d8b4fe;padding:2px 7px;'
                      'border-radius:6px;font-size:11px;margin-left:6px">UAMI</span>')
        thr = (f'<span style="color:#ff8c00">{a["throttled"]}</span>' if a["throttled"]
               else '<span style="color:#6b7280">0</span>')
        rows += (f'<tr><td>{html.escape(str(a["name"]))}{badges}<br>'
                 f'<span style="color:#6b7280;font-size:11px">{html.escape(str(a["type"] or "—"))}</span></td>'
                 f'<td style="text-align:center;font-weight:700">{a["granted_n"]}</td>'
                 f'<td style="text-align:center">{a["calls"]:,}</td>'
                 f'<td>{_chips(a["unused"], "#3a1010", "#ffb4b4")}</td>'
                 f'<td style="text-align:center">{thr}</td>'
                 f'<td style="text-align:center;color:{vc};font-weight:700">{v}</td></tr>')
    rows = rows or '<tr><td colspan="6" style="color:#6b7280">Sem app registrations com permissões Graph + atividade no período.</td></tr>'

    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Graph Least Privilege — {now}</title>
<style>
body{{margin:0;background:#0a0e1a;color:#e7eef9;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.5}}
.wrap{{max-width:980px;margin:0 auto;padding:24px}}
.hd{{background:linear-gradient(135deg,#3b1a5a,#6366f1);border-radius:14px;padding:26px}}
.hd h1{{margin:0;font-size:24px}} .hd p{{margin:6px 0 0;opacity:.85;font-size:13px}}
.badge{{display:inline-block;margin-top:14px;padding:8px 18px;border-radius:999px;font-weight:800;font-size:18px;background:{overall_color}22;color:{overall_color};border:2px solid {overall_color}}}
.cards{{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}}
.card{{flex:1;min-width:150px;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;padding:18px;text-align:center}}
.card .n{{font-size:30px;font-weight:800}} .card .l{{font-size:12px;color:#93a1bd;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;overflow:hidden;font-size:13px;margin-bottom:8px}}
th{{background:#16203a;text-align:left;padding:11px 13px;font-size:12px;color:#c4b5fd}}
td{{padding:10px 13px;border-top:1px solid #1f2c47;vertical-align:top}}
h2{{font-size:17px;margin:28px 0 12px}} .note{{color:#93a1bd;font-size:13px;margin:10px 0}}
.ft{{margin-top:24px;color:#647394;font-size:12px;text-align:center}}
</style></head><body><div class="wrap">
<div class="hd"><h1>🔐 Graph Least Privilege</h1>
<p>{now} · janela {days}d · concedido × usado (MicrosoftGraphActivityLogs) · recommend-only</p>
<div class="badge">{overall}</div></div>

<div class="cards">
<div class="card"><div class="n">{rollup['apps_with_perms']}</div><div class="l">Apps com permissão Graph</div></div>
<div class="card"><div class="n" style="color:#d13438">{rollup['apps_dormant']}</div><div class="l">Dormentes (0 chamadas)</div></div>
<div class="card"><div class="n" style="color:#ffb900">{rollup['apps_excess']}</div><div class="l">Com scope em excesso</div></div>
<div class="card"><div class="n" style="color:#ff8c00">{rollup['total_excess']}</div><div class="l">Scopes a revisar</div></div>
<div class="card"><div class="n" style="color:#93a1bd">{rollup['throttled_apps']}</div><div class="l">Apps com throttling</div></div>
</div>

<h2>Apps por risco de excesso</h2>
<table><tr><th>App / Service Principal</th><th>Concedidos</th><th>Chamadas ({days}d)</th>
<th>Scopes sem uso observado</th><th>429</th><th>Verdict</th></tr>{rows}</table>
<div class="note">⚠️ Recommend-only — não remove nenhuma permissão. O mapa endpoint→scope é
<b>heurístico</b> (espelha o disclaimer do módulo upstream): valide cada app antes de revogar.
DORMANT = permissão concedida mas 0 chamadas no período (candidato a remoção). EXCESS = scope
concedido cuja família de endpoint nunca apareceu nos logs de atividade.</div>
<div class="ft">graph-least-privilege · collector↔renderer · conceito de Mynster9361/Least_Privileged_MSGraph (MIT) · gerado pelo SOC Autônomo</div>
</div></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="graph-least-privilege report generator")
    ap.add_argument("--workspace", help="Log Analytics workspace GUID (self-collect mode)")
    ap.add_argument("--days", type=int, default=0, help="Lookback window (default from queries.yaml)")
    ap.add_argument("--from-json", dest="from_json", help="Render from pre-collected results JSON")
    ap.add_argument("--queries", default=str(HERE / "queries.yaml"))
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    q = load_queries(args.queries)
    days = args.days or int(_num(q.get("parameters", {}).get("days", 30)))

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif args.workspace:
        data = collect(args, q)
    else:
        ap.error("provide --workspace (self-collect) or --from-json (render)")

    apps, rollup = analyze(data, q)
    htmlout = render_html(apps, rollup, days)

    out = args.output or str(HERE / "reports" /
                             f"graph-least-privilege_{dt.datetime.utcnow():%Y%m%d_%H%M%S}.html")
    pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(htmlout)
    print(f"✅ {SKILL}: {overall_summary(rollup)} · {rollup['apps_with_perms']} apps · "
          f"{rollup['apps_dormant']} dormentes · {rollup['total_excess']} scopes a revisar")
    print(f"📄 {out}")


def overall_summary(rollup):
    if rollup["apps_dormant"]:
        return "AÇÃO"
    if rollup["apps_excess"]:
        return "REVISAR"
    return "ENXUTO"


if __name__ == "__main__":
    main()

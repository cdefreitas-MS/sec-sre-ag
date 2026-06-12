#!/usr/bin/env python3
"""SPN Scope Drift Report - HTML Report Generator.
Usage: python3 generate_html_report.py <data_json> [--output-dir reports/spn-scope-drift/]
"""
import argparse, html as H, json, sys
from datetime import datetime, timezone
from pathlib import Path

CSS = """*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',system-ui,sans-serif;font-size:13.5px;line-height:1.5;color:#e0e0e0;background:#111820;padding:16px}.ctr{max-width:1700px;margin:0 auto;background:#161f2b;border-radius:8px;box-shadow:0 4px 24px rgba(0,0,0,0.5)}.hdr{background:linear-gradient(135deg,#7b2ff7,#0078d4,#00b7c3);color:white;padding:20px 28px;border-radius:8px 8px 0 0}.hdr h1{font-size:1.8em;margin:0}.hdr .meta{font-size:0.85em;opacity:0.9;margin-top:6px}.content{padding:16px 20px}.metrics{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin-bottom:16px}.metric{background:#1c2836;border-radius:6px;padding:14px;text-align:center;border-top:3px solid #0078d4}.metric .mv{font-size:1.5em;font-weight:700;color:white}.metric .ml{font-size:0.8em;color:#aaa;margin-top:2px}.section{background:#1c2836;border-radius:6px;padding:16px 20px;margin-bottom:14px;border-left:3px solid #0078d4}.section.q4{border-left-color:#7b2ff7}.section.alert{border-left-color:#d13438}.section h2{font-size:1.2em;color:#00b7c3;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid #2a3a4a}.section h3{font-size:1.05em;color:#e0e0e0;margin:12px 0 8px}.section p{color:#c0c0c0;margin:4px 0}table{width:100%;border-collapse:collapse;font-size:0.9em;margin:8px 0 12px}th{background:#243447;color:#00b7c3;padding:8px 10px;text-align:left;font-weight:600;border-bottom:2px solid #2a3a4a}td{padding:6px 10px;border-bottom:1px solid #1f2f3f;vertical-align:top}tr:nth-child(even){background:rgba(255,255,255,0.02)}tr:hover{background:rgba(0,183,195,0.05)}tr.highlight{background:rgba(123,47,247,0.12);border-left:3px solid #7b2ff7}.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:700}.badge-new{background:#d13438;color:white}.badge-ipdrift{background:#ff8c00;color:#1a1a1a}.badge-stable{background:#107c10;color:white}.badge-dormant{background:#555;color:#ddd}.score-pill{display:inline-block;padding:2px 10px;border-radius:12px;font-weight:700;font-size:0.85em;color:white}.res-tag{display:inline-block;background:#1a3a5c;color:#50e6ff;padding:1px 8px;border-radius:3px;font-size:0.82em;margin:1px 2px}.ip-tag{display:inline-block;background:#3a2a1c;color:#ffb900;padding:1px 8px;border-radius:3px;font-size:0.82em;margin:1px 2px}.ftr{background:#1c2836;padding:12px 24px;text-align:center;font-size:0.8em;color:#555;border-top:1px solid #2a3a4a;border-radius:0 0 8px 8px}details summary{cursor:pointer;font-weight:600;color:#00b7c3;padding:6px 0}@media print{body{background:white;color:#222}.ctr{box-shadow:none}th{background:#eee;color:#222}.section{background:#f9f9f9}}"""

def esc(s): return H.escape(str(s))

def render_html(data):
    meta, summary = data["meta"], data["summary"]
    uami, drifters = data.get("uamiAudit", {}), data.get("drifters", [])
    gen = meta.get("generated", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    ws = esc(meta.get("workspace", "Unknown"))

    # Metrics
    mc = lambda v, l, c: f'<div class="metric" style="border-top-color:{c}"><div class="mv" style="color:{c}">{v}</div><div class="ml">{l}</div></div>'
    metrics = '<div class="metrics">' + ''.join([
        mc(summary["totalIdentities"],"Identities","#0078d4"), mc(summary["activeRecent"],"Active","#00b7c3"),
        mc(summary["dormant"],"Dormant","#888"), mc(summary["newIdentities"],"New","#d13438"),
        mc(summary["ipDrift"],"IP Drift","#ff8c00"), mc(summary["stable"],"Stable","#107c10"),
        mc(summary["totalNewResources"],"New Res","#d13438"), mc(summary["totalNewIPs"],"New IPs","#ff8c00"),
        mc(f'{summary["totalSignInsRecent7d"]:,}',"Recent","#3498db"), mc(f'{summary["totalSignInsBaseline83d"]:,}',"Baseline","#9b59b6"),
    ]) + '</div>'

    # UAMI Q4
    q4 = ""
    if uami:
        bd = ''.join(f'<tr><td class="res-tag">{esc(r["resource"])}</td><td>{r["hits"]}</td><td>{esc(r["firstSeen"][:19])}</td><td>{esc(r["lastSeen"][:19])}</td></tr>' for r in uami.get("resourceBreakdown",[]))
        q4 = f'<div class="section q4"><h2>Q4 UAMI Self-Audit ({esc(uami["name"])})</h2><p>AppId: <code>{esc(uami["appId"])}</code> | {esc(uami.get("verdictDetail",""))}</p><table><thead><tr><th>Resource</th><th>Hits</th><th>First</th><th>Last</th></tr></thead><tbody>{bd}</tbody></table></div>'

    # Drift table
    sd = sorted(drifters, key=lambda x: (-x["driftScore"], -x["recentHits"]))
    active = [d for d in sd if d["recentHits"] > 0]
    dormant = [d for d in sd if d["verdict"] == "DORMANT"]
    rows = ""
    for i, d in enumerate(active, 1):
        cls = {"NEW":"badge-new","IP_DRIFT":"badge-ipdrift","STABLE":"badge-stable"}.get(d["verdict"],"badge-stable")
        hl = ' class="highlight"' if d["appId"] == uami.get("appId","") else ""
        sc = "#d13438" if d["driftScore"]>=50 else "#ff8c00" if d["driftScore"]>0 else "#107c10"
        res = ''.join(f'<span class="res-tag">{esc(r)}</span>' for r in d.get("newRes",[])) or "-"
        ips = ''.join(f'<span class="ip-tag">{esc(ip)}</span>' for ip in d.get("newIPs",[])[:3]) or "-"
        rows += f'<tr{hl}><td>{i}</td><td><b>{esc(d["name"])}</b></td><td class="badge {cls}">{d["verdict"]}</td><td><span class="score-pill" style="background:{sc}">{d["driftScore"]}</span></td><td>{d["baselineHits"]:,}</td><td>{d["recentHits"]:,}</td><td>{res}</td><td>{ips}</td></tr>'

    dtbl = f'<div class="section alert"><h2>Scope Drift - Active Identities</h2><table><thead><tr><th>#</th><th>Identity</th><th>Verdict</th><th>Score</th><th>Base</th><th>Recent</th><th>New Res</th><th>New IPs</th></tr></thead><tbody>{rows}</tbody></table></div>'

    dorm = ""
    if dormant:
        dr = ''.join(f'<tr><td>{esc(d["name"])}</td><td>{d["baselineHits"]:,}</td></tr>' for d in dormant)
        dorm = f'<div class="section" style="border-left-color:#555"><h2>Dormant ({len(dormant)})</h2><table><thead><tr><th>Identity</th><th>Baseline</th></tr></thead><tbody>{dr}</tbody></table></div>'

    return f'<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SPN Drift - {ws}</title><style>{CSS}</style></head><body><div class="ctr"><div class="hdr"><h1>SPN Scope Drift</h1><div class="meta">Workspace: {ws} | Baseline: {meta["baselineDays"]}d vs Recent: {meta["recentDays"]}d | {esc(gen)}</div></div><div class="content"><div class="section"><h2>Summary</h2>{metrics}</div>{q4}{dtbl}{dorm}</div><div class="ftr">Generated by spn-scope-drift | Azure SRE Agent</div></div></body></html>'

def main():
    p = argparse.ArgumentParser()
    p.add_argument('data_json')
    p.add_argument('--output-dir', default='reports/spn-scope-drift/')
    args = p.parse_args()
    with open(args.data_json) as f: data = json.load(f)
    html = render_html(data)
    outdir = Path(args.output_dir); outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H%M%S')
    ws = data['meta'].get('workspace','ws').replace(' ','_')
    out = outdir / f'SPN_Scope_Drift_{ws}_{ts}.html'
    out.write_text(html, encoding='utf-8')
    print(f'HTML report: {out} ({round(out.stat().st_size/1024,1)} KB)')

if __name__ == '__main__': main()

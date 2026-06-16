#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soc-executive-brief / generate_html_report.py  (collector ↔ renderer)

UM brief executivo (1 email) consolidando 3 sinais de SOC num veredito só:
  • Threat Pulse    — incidentes recentes, abertos high-sev, MTTR
  • Identity Posture — sign-ins, usuários de risco, MFA, contas privilegiadas
  • MITRE Coverage  — % de táticas cobertas por regras habilitadas + regras sem tag

Substitui 3 emails separados por 1 executivo. 100% READ-ONLY — nunca muta o workspace.

Dois modos:
  --from-json inventory.json            → render determinístico/offline (caminho primário)
  --workspace <GUID> --sub --rg --ws    → auto-coleta (az rest + az monitor)

Saída: --format both (default) → HTML (dark, email) + Markdown (repo).
"""
from __future__ import annotations
import argparse, datetime as dt, html, json, os, re, shutil, subprocess, sys

# --- portabilidade: resolve az.CMD no Windows; achata KQL p/ az.cmd não truncar -------------
AZ = shutil.which("az") or "az"

def _flatten_kql(kql: str) -> str:
    lines = []
    for ln in kql.splitlines():
        ln = re.sub(r"//.*$", "", ln).strip()
        if ln:
            lines.append(ln)
    return " ".join(lines)

# =============================================================================
# helpers de leitura tolerante
# =============================================================================
def prop(obj, path, default=None):
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur if cur is not None else default

def as_list(x):
    if x is None:
        return []
    if isinstance(x, dict) and "value" in x and isinstance(x["value"], list):
        return x["value"]
    if isinstance(x, list):
        return x
    return [x]

def num(x, default=0.0):
    try:
        if x is None or x == "":
            return default
        return float(x)
    except (TypeError, ValueError):
        return default

def esc(s):
    return html.escape("" if s is None else str(s))

# 14 táticas MITRE ATT&CK Enterprise (sentinelShortName)
MITRE_TACTICS = [
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact",
]

# =============================================================================
# Sanitizer: tira templates que vazaram p/ alert_rules (regra deployed tem `enabled`;
# template nunca). Mesmo discriminador do sentinel-documenter.
# =============================================================================
def _split_rules_templates(rules):
    rules = as_list(rules)
    if not rules:
        return [], []
    def has_enabled(r):
        if not isinstance(r, dict):
            return False
        if "enabled" in r:
            return True
        p = r.get("properties")
        return isinstance(p, dict) and "enabled" in p
    def is_template_type(r):
        return "alertruletemplates" in str(prop(r, "type", "")).lower()
    any_enabled = any(has_enabled(r) for r in rules)
    kept, leaked = [], []
    for r in rules:
        if is_template_type(r) or (any_enabled and not has_enabled(r)):
            leaked.append(r)
        else:
            kept.append(r)
    return kept, leaked

def build_inventory(data: dict) -> dict:
    rules, leaked = _split_rules_templates(data.get("alert_rules"))
    return {
        "ThreatPulse": (as_list(data.get("threat_pulse")) or [{}])[0],
        "ThreatTop": as_list(data.get("threat_top")),
        "IdentitySignins": (as_list(data.get("identity_signins")) or [{}])[0],
        "IdentityPrivileged": (as_list(data.get("identity_privileged")) or [{}])[0],
        "MitreFiring": as_list(data.get("mitre_firing")),
        "AlertRules": rules,
        "LeakedTemplateRules": len(leaked),
    }

# =============================================================================
# PAINÉIS — cada um devolve {score: int|None, available: bool, metrics: {...}}
# Painel sem dado avaliável → score None (n/a); nunca conta como 100.
# =============================================================================
def panel_threat(inv, params, sc):
    tp = inv["ThreatPulse"]
    if not tp:
        return {"score": None, "available": False, "metrics": {}}
    total = num(tp.get("Total")); highsev = num(tp.get("HighSev"))
    openc = num(tp.get("Open")); highopen = num(tp.get("HighSevOpen"))
    closed = num(tp.get("Closed")); mttr_min = num(tp.get("AvgMTTRmin"))
    cfg = sc["threat"]
    pen_open = min(num(cfg["open_cap"]),
                   highopen * num(cfg["per_highsev_open"]) + openc * num(cfg["per_open"]))
    pen_mttr = num(cfg["mttr_penalty"]) if mttr_min > num(params.get("mttr_threshold_min", 1440)) else 0
    score = max(0, round(100 - pen_open - pen_mttr))
    return {"score": score, "available": True,
            "metrics": {"total": total, "highsev": highsev, "open": openc, "highopen": highopen,
                        "closed": closed, "mttr_h": (mttr_min / 60.0) if mttr_min else 0.0,
                        "top": inv["ThreatTop"]}}

def panel_identity(inv, params, sc):
    si = inv["IdentitySignins"]; pv = inv["IdentityPrivileged"]
    total = num(si.get("Total")) if si else 0
    if not si or total == 0:
        return {"score": None, "available": False, "metrics": {}}
    users = num(si.get("Users")); risky = num(si.get("RiskyUsers"))
    mfa = num(si.get("MfaSatisfied"))
    mfa_rate = round(100.0 * mfa / total, 1) if total else 0.0
    priv = num(pv.get("Privileged")) if pv else None
    cfg = sc["identity"]
    pen_risky = min(num(cfg["risky_cap"]), risky * num(cfg["per_risky_user"]))
    pen_mfa = max(0.0, num(cfg["mfa_floor_pct"]) - mfa_rate) * num(cfg["mfa_weight"])
    score = max(0, round(100 - pen_risky - pen_mfa))
    return {"score": score, "available": True,
            "metrics": {"users": users, "risky": risky, "mfa_rate": mfa_rate,
                        "privileged": priv, "signins": total}}

def panel_mitre(inv, params, sc):
    rules = [r for r in inv["AlertRules"]
             if str(prop(r, "kind", "")) in ("Scheduled", "NRT") and prop(r, "properties.enabled", False)]
    firing = inv["MitreFiring"]
    firing_tactics = sorted({str(x.get("Tactic")) for x in firing if x.get("Tactic")})
    if not rules:
        # sem regras coletadas não dá p/ pontuar cobertura; mostra firing como contexto
        return {"score": None, "available": False,
                "metrics": {"firing": firing_tactics, "rules": 0}}
    covered, untagged = set(), 0
    for r in rules:
        tac = prop(r, "properties.tactics", []) or []
        if tac:
            for t in tac:
                covered.add(str(t))
        else:
            untagged += 1
    total_t = int(num(sc["mitre"]["total_tactics"], 14)) or 14
    cov_pct = round(100.0 * len(covered) / total_t, 1)
    pen_untag = min(num(sc["mitre"]["untagged_cap"]), untagged * num(sc["mitre"]["per_untagged_rule"]))
    score = max(0, round(cov_pct - pen_untag))
    gaps = [t for t in MITRE_TACTICS if t not in covered]
    return {"score": score, "available": True,
            "metrics": {"covered": len(covered), "total": total_t, "cov_pct": cov_pct,
                        "untagged": untagged, "rules": len(rules),
                        "firing": firing_tactics, "gaps": gaps}}

def overall_soc(panels, weights, verdict_cfg):
    parts = [(num(weights[k]), panels[k]["score"]) for k in ("threat", "identity", "mitre")
             if panels[k]["score"] is not None]
    if not parts:
        return {"score": None, "label": "n/a", "emoji": "⚪", "klass": "na"}
    wsum = sum(w for w, _ in parts)
    score = round(sum(w * s for w, s in parts) / wsum) if wsum else None
    label, emoji = verdict_cfg[-1]["label"], verdict_cfg[-1]["emoji"]
    for v in verdict_cfg:
        if score >= num(v["min"]):
            label, emoji = v["label"], v["emoji"]
            break
    klass = {"FORTE": "good", "MODERADA": "warn", "FRACA": "bad"}.get(label, "na")
    return {"score": score, "label": label, "emoji": emoji, "klass": klass}

def next_action(panels):
    t, i, m = panels["threat"], panels["identity"], panels["mitre"]
    if t.get("available") and num(t["metrics"].get("highopen")) > 0:
        return f"Triar {int(num(t['metrics']['highopen']))} incidente(s) HIGH aberto(s) — maior risco operacional agora."
    if i.get("available") and num(i["metrics"].get("risky")) > 0:
        return f"Investigar {int(num(i['metrics']['risky']))} usuário(s) de risco (sign-in high/medium) — possível comprometimento."
    if t.get("available") and t["metrics"].get("mttr_h", 0) > 24:
        return f"Reduzir MTTR (~{t['metrics']['mttr_h']:.0f}h) — automação + tuning de regras barulhentas."
    if m.get("available") and m["metrics"].get("gaps"):
        return f"Cobrir táticas MITRE sem detecção: {', '.join(m['metrics']['gaps'][:3])} (onboard rules do Content Hub)."
    if m.get("available") and num(m["metrics"].get("untagged")) > 0:
        return f"Taguear {int(num(m['metrics']['untagged']))} regra(s) sem MITRE — melhora a visibilidade de cobertura."
    return "Postura saudável — manter monitoramento e revisar tendências semanais."

# =============================================================================
# RENDER — HTML (dark, email) + Markdown
# =============================================================================
SEV_COLOR = {"High": "#ff4d6d", "Medium": "#ffb454", "Low": "#7aa2f7", "Informational": "#7d8590"}
PCOL = {"good": "#36d399", "warn": "#ffb454", "bad": "#ff4d6d", "na": "#7d8590"}

def _pcol(score):
    if score is None:
        return PCOL["na"]
    return "#36d399" if score >= 75 else "#ffb454" if score >= 50 else "#ff4d6d"

def _score_txt(p):
    return "n/a" if p["score"] is None else str(p["score"])

def _mttr_disp(tm):
    """MTTR legível: '—' se nada fechado; minutos se < 1h; senão horas."""
    if num(tm.get("closed")) <= 0:
        return "—"
    h = tm.get("mttr_h", 0) or 0
    if h <= 0:
        return "—"
    return f"{h*60:.0f} min" if h < 1 else f"{h:.1f} h"

def render_html(ctx) -> str:
    inv = ctx["inv"]; panels = ctx["panels"]; soc = ctx["soc"]; na = ctx["next_action"]
    ws = ctx.get("ws", "workspace"); now = dt.datetime.now().strftime("%d/%m/%Y %H:%M")
    wd = int(num(ctx["params"].get("window_days", 7)))
    scol = PCOL[soc["klass"]]
    t, i, m = panels["threat"], panels["identity"], panels["mitre"]

    # painel threat
    tm = t["metrics"]
    mttr_disp = _mttr_disp(tm)
    top_rows = ""
    for r in (tm.get("top") or [])[:5]:
        sev = str(r.get("Severity", "")); c = SEV_COLOR.get(sev, "#7d8590")
        top_rows += (f"<tr><td><b>#{esc(r.get('IncidentNumber'))}</b> {esc(r.get('Title'))}</td>"
                     f"<td><span class='pill' style='background:{c}22;color:{c};border:1px solid {c}55'>{esc(sev)}</span></td></tr>")
    threat_body = (f"<div class='kv'><span>Incidentes ({wd}d)</span><b>{int(num(tm.get('total')))}</b></div>"
                   f"<div class='kv'><span>Abertos</span><b>{int(num(tm.get('open')))}</b></div>"
                   f"<div class='kv'><span>HIGH abertos</span><b style='color:#ff4d6d'>{int(num(tm.get('highopen')))}</b></div>"
                   f"<div class='kv'><span>MTTR médio</span><b>{mttr_disp}</b></div>"
                   + (f"<table class='mini'>{top_rows}</table>" if top_rows else "<div class='sub'>Nenhum incidente aberto. 🎉</div>")) \
                  if t["available"] else "<div class='sub'>Sem dados de incidentes neste run (n/a).</div>"

    # painel identity
    im = i["metrics"]
    priv_txt = "—" if im.get("privileged") is None else str(int(num(im.get("privileged"))))
    identity_body = (f"<div class='kv'><span>Usuários ativos ({wd}d)</span><b>{int(num(im.get('users')))}</b></div>"
                     f"<div class='kv'><span>Usuários de risco</span><b style='color:{'#ff4d6d' if num(im.get('risky'))>0 else '#36d399'}'>{int(num(im.get('risky')))}</b></div>"
                     f"<div class='kv'><span>Cobertura MFA</span><b>{im.get('mfa_rate',0):.0f}%</b></div>"
                     f"<div class='kv'><span>Contas privilegiadas</span><b>{priv_txt}</b></div>") \
                    if i["available"] else "<div class='sub'>Sem sign-ins na janela (n/a).</div>"

    # painel mitre
    mm = m["metrics"]
    if m["available"]:
        gaps = mm.get("gaps") or []
        gap_txt = ", ".join(gaps[:4]) + (" …" if len(gaps) > 4 else "") if gaps else "nenhuma 🎉"
        mitre_body = (f"<div class='kv'><span>Táticas cobertas</span><b>{int(num(mm.get('covered')))}/{int(num(mm.get('total')))}</b></div>"
                      f"<div class='kv'><span>Cobertura</span><b>{mm.get('cov_pct',0):.0f}%</b></div>"
                      f"<div class='kv'><span>Regras habilitadas</span><b>{int(num(mm.get('rules')))}</b></div>"
                      f"<div class='kv'><span>Regras sem tag</span><b style='color:{'#ffb454' if num(mm.get('untagged'))>0 else '#36d399'}'>{int(num(mm.get('untagged')))}</b></div>"
                      f"<div class='sub' style='margin-top:6px'>Gaps: {esc(gap_txt)}</div>")
    else:
        fir = mm.get("firing") or []
        mitre_body = ("<div class='sub'>Regras não coletadas (n/a p/ cobertura).</div>"
                      + (f"<div class='sub'>Táticas disparando: {esc(', '.join(fir[:6]))}</div>" if fir else ""))

    def card(title, emoji, p, body):
        c = _pcol(p["score"])
        return (f"<div class='card'><div class='chead'><span>{emoji} {title}</span>"
                f"<span class='badge' style='background:{c}22;color:{c};border:1px solid {c}55'>{_score_txt(p)}</span></div>{body}</div>")

    socscore = "n/a" if soc["score"] is None else str(soc["score"])
    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Executive Brief — {esc(ws)}</title>
<style>
:root{{color-scheme:dark}} *{{box-sizing:border-box}}
body{{margin:0;background:#0b0e14;color:#c9d1d9;font:14px/1.5 'Segoe UI',system-ui,sans-serif}}
.wrap{{max-width:980px;margin:0 auto;padding:26px}}
h1{{font-size:21px;margin:0 0 2px}}
.sub{{color:#7d8590;font-size:12.5px}}
.hero{{display:flex;gap:18px;align-items:center;margin:16px 0;padding:18px;background:#11151d;border:1px solid #1f2733;border-radius:14px}}
.score{{font-size:46px;font-weight:800;color:{scol};line-height:1}}
.verdict{{font-size:20px;font-weight:800;color:{scol}}}
.na{{margin-left:auto;max-width:54%;background:#0d1320;border:1px solid #1f2733;border-radius:10px;padding:10px 14px}}
.na b{{color:#e6edf3}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:6px}}
.card{{background:#11151d;border:1px solid #1f2733;border-radius:12px;padding:14px}}
.chead{{display:flex;justify-content:space-between;align-items:center;font-weight:700;color:#e6edf3;border-bottom:1px solid #1f2733;padding-bottom:8px;margin-bottom:10px}}
.badge{{padding:2px 10px;border-radius:20px;font-size:13px;font-weight:800}}
.kv{{display:flex;justify-content:space-between;padding:3px 0;font-size:13px}}
.kv span{{color:#8b949e}} .kv b{{color:#e6edf3}}
.pill{{padding:1px 8px;border-radius:20px;font-size:11px;font-weight:700}}
.mini{{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px}}
.mini td{{padding:4px 2px;border-bottom:1px solid #1a212b;vertical-align:top}}
.foot{{margin-top:26px;padding-top:12px;border-top:1px solid #1f2733;color:#586069;font-size:11.5px;text-align:center}}
@media(max-width:760px){{.grid{{grid-template-columns:1fr}}.na{{max-width:100%}}}}
</style></head><body><div class="wrap">
<h1>🛡️ SOC Executive Brief</h1>
<div class="sub">{esc(ws)} · gerado {now} · janela {wd}d · <b>read-only</b></div>

<div class="hero">
  <div><div class="score">{socscore}</div><div class="sub">SOC Score</div></div>
  <div><div class="verdict">{soc['emoji']} {esc(soc['label'])}</div>
       <div class="sub">Threat {_score_txt(t)} · Identity {_score_txt(i)} · MITRE {_score_txt(m)}</div></div>
  <div class="na"><div class="sub">▶ Próxima ação</div><b>{esc(na)}</b></div>
</div>

<div class="grid">
  {card("Threat Pulse", "🔥", t, threat_body)}
  {card("Identity Posture", "🔐", i, identity_body)}
  {card("MITRE Coverage", "🎯", m, mitre_body)}
</div>

<div class="foot">
  Parte do <b>SOC Autônomo</b> · skill <code>soc-executive-brief</code> · consolida Threat Pulse + Identity Posture + MITRE num brief só<br>
  Read-only · não modifica o workspace · score por painel 100×ponderado; painel sem dado = n/a (nunca 100)
</div>
</div></body></html>"""

def render_md(ctx) -> str:
    panels = ctx["panels"]; soc = ctx["soc"]; ws = ctx.get("ws", "workspace")
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M"); wd = int(num(ctx["params"].get("window_days", 7)))
    t, i, m = panels["threat"], panels["identity"], panels["mitre"]
    socscore = "n/a" if soc["score"] is None else f"{soc['score']}/100"
    out = [f"# SOC Executive Brief — `{ws}`",
           f"_Gerado {now} · janela {wd}d · read-only_\n",
           f"**SOC Score: {socscore} ({soc['emoji']} {soc['label']})** · "
           f"Threat {_score_txt(t)} · Identity {_score_txt(i)} · MITRE {_score_txt(m)}\n",
           f"**▶ Próxima ação:** {ctx['next_action']}\n",
           "## 🔥 Threat Pulse"]
    if t["available"]:
        tm = t["metrics"]
        out += [f"- Incidentes ({wd}d): **{int(num(tm.get('total')))}** · abertos {int(num(tm.get('open')))} · "
                f"HIGH abertos **{int(num(tm.get('highopen')))}** · MTTR {_mttr_disp(tm)}"]
        for r in (tm.get("top") or [])[:5]:
            out.append(f"  - #{r.get('IncidentNumber')} [{r.get('Severity')}] {r.get('Title')}")
    else:
        out.append("- _Sem dados de incidentes (n/a)._")
    out.append("\n## 🔐 Identity Posture")
    if i["available"]:
        im = i["metrics"]; priv = "—" if im.get("privileged") is None else int(num(im.get("privileged")))
        out.append(f"- Usuários ativos: **{int(num(im.get('users')))}** · risco **{int(num(im.get('risky')))}** · "
                   f"MFA {im.get('mfa_rate',0):.0f}% · privilegiadas {priv}")
    else:
        out.append("- _Sem sign-ins na janela (n/a)._")
    out.append("\n## 🎯 MITRE Coverage")
    if m["available"]:
        mm = m["metrics"]
        out.append(f"- Táticas: **{int(num(mm.get('covered')))}/{int(num(mm.get('total')))}** "
                   f"({mm.get('cov_pct',0):.0f}%) · regras {int(num(mm.get('rules')))} · "
                   f"sem tag {int(num(mm.get('untagged')))}")
        if mm.get("gaps"):
            out.append(f"- Gaps: {', '.join(mm['gaps'][:6])}")
    else:
        out.append("- _Regras não coletadas (n/a)._")
    out.append("\n---\n_SOC Autônomo · skill `soc-executive-brief` · 1 brief = Threat Pulse + Identity Posture + MITRE_")
    return "\n".join(out)

# =============================================================================
# COLLECTOR (auto) — best effort; caminho primário é --from-json
# =============================================================================
def run_kql(ws_guid, kql):
    try:
        out = subprocess.run([AZ, "monitor", "log-analytics", "query", "--workspace", ws_guid,
                              "--analytics-query", _flatten_kql(kql), "-o", "json"],
                             capture_output=True, text=True, timeout=180)
        if out.returncode == 0 and out.stdout.strip():
            return json.loads(out.stdout)
    except Exception as e:
        print(f"  [kql] {e}", file=sys.stderr)
    return []

def run_rest(url):
    try:
        out = subprocess.run([AZ, "rest", "--method", "get", "--url", url, "-o", "json"],
                             capture_output=True, text=True, timeout=120)
        if out.returncode == 0 and out.stdout.strip():
            return json.loads(out.stdout)
    except Exception as e:
        print(f"  [rest] {e}", file=sys.stderr)
    return None

def collect(q, args):
    p = q["parameters"]; c = q["collector"]; base = c["rest"]["base"]; api = c["rest"]
    wd = str(int(num(p.get("window_days", 7)))); sd = str(int(num(p.get("stale_days", 90))))
    def fmt_rest(s):
        return (s.replace("{sub}", args.sub).replace("{rg}", args.rg).replace("{ws}", args.ws)
                 .replace("{api_securityinsights}", api["api_securityinsights"]))
    def fmt_kql(s):
        return s.replace("{window_days}", wd).replace("{stale_days}", sd)
    data = {}
    print("• coletando REST (alertRules)…", file=sys.stderr)
    data["alert_rules"] = run_rest(fmt_rest(base + api["endpoints"]["alert_rules"]))
    print("• coletando KQL…", file=sys.stderr)
    for key in ("threat_pulse", "threat_top", "identity_signins", "identity_privileged", "mitre_firing"):
        data[key] = run_kql(args.workspace, fmt_kql(c["kql"][key]))
    return data

def load_yaml(path):
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML necessário: pip install pyyaml")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)

# =============================================================================
def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="SOC Executive Brief — 1 email, 3 painéis (read-only)")
    ap.add_argument("--from-json", help="inventário pré-coletado (modo offline/primário)")
    ap.add_argument("--workspace", help="GUID do workspace (auto-coleta KQL)")
    ap.add_argument("--sub"); ap.add_argument("--rg"); ap.add_argument("--ws")
    ap.add_argument("--queries", default=os.path.join(here, "queries.yaml"))
    ap.add_argument("--format", choices=["html", "md", "both"], default="both")
    ap.add_argument("--output", default=os.path.join(here, "tmp", "soc-brief"))
    ap.add_argument("--save-raw", action="store_true")
    args = ap.parse_args()

    q = load_yaml(args.queries)
    params = q["parameters"]; sc = q["scoring"]

    if args.from_json:
        with open(args.from_json, encoding="utf-8") as f:
            data = json.load(f)
    elif args.workspace and args.sub and args.rg and args.ws:
        data = collect(q, args)
        # guarda Modo A: tudo vazio = falha de auth/coleta (não renderiza brief "vazio").
        if all(not data.get(k) for k in ("threat_pulse", "identity_signins", "alert_rules", "mitre_firing")):
            sys.exit("❌ Modo A falhou: todas as fontes vieram vazias (auth/coleta). "
                     "Use o Modo B: colete via ferramentas nativas e rode com --from-json.")
        if args.save_raw:
            os.makedirs(args.output, exist_ok=True)
            with open(os.path.join(args.output, "_raw.json"), "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
    else:
        ap.error("informe --from-json OU (--workspace --sub --rg --ws)")

    inv = build_inventory(data)
    if inv.get("LeakedTemplateRules"):
        print(f"⚠  {inv['LeakedTemplateRules']} item(ns) com cara de template removidos de alert_rules "
              "(colete /alertRuleTemplates separado).", file=sys.stderr)
    panels = {"threat": panel_threat(inv, params, sc),
              "identity": panel_identity(inv, params, sc),
              "mitre": panel_mitre(inv, params, sc)}
    soc = overall_soc(panels, sc["weights"], sc["verdict"])
    na = next_action(panels)
    ctx = {"inv": inv, "panels": panels, "soc": soc, "next_action": na,
           "params": params, "ws": args.ws or args.workspace or "workspace"}

    os.makedirs(args.output, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    written = []
    if args.format in ("html", "both"):
        ph = os.path.join(args.output, f"soc-brief-{stamp}.html")
        with open(ph, "w", encoding="utf-8") as f:
            f.write(render_html(ctx))
        written.append(ph)
    if args.format in ("md", "both"):
        pm = os.path.join(args.output, f"soc-brief-{stamp}.md")
        with open(pm, "w", encoding="utf-8") as f:
            f.write(render_md(ctx))
        written.append(pm)

    sx = "n/a" if soc["score"] is None else f"{soc['score']}/100"
    print(f"\n✅ SOC Score {sx} ({soc['label']}) · "
          f"Threat {_score_txt(panels['threat'])} · Identity {_score_txt(panels['identity'])} · "
          f"MITRE {_score_txt(panels['mitre'])}")
    print(f"   ▶ {na}")
    for w in written:
        print("   →", w)

if __name__ == "__main__":
    main()

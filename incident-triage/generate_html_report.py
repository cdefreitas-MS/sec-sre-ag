#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
incident-triage / generate_html_report.py  (collector ↔ renderer)

Relatório determinístico de triagem de UM incidente (Sentinel / Defender XDR), pensado
para o loop autônomo (sem analista no meio):
  header → alertas → entidades (usuários/hosts/IPs) → MITRE (táticas nativas + inferência
  por texto via shared/mitre_map.py) → plano de resposta gateado (shared/action_safety.py)
  → veredito (TRUE POSITIVE PROVÁVEL / REQUER ANÁLISE / PROVÁVEL BENIGNO) + próxima ação.

100% READ-ONLY — nunca muta o workspace e nunca executa ações (só RECOMENDA, com gate).

Dois modos:
  --from-json inventory.json                         → render determinístico/offline (primário)
  --workspace <GUID> --sub --rg [--incident-number]  → auto-coleta (az monitor log-analytics)

Saída: --format both (default) → HTML (dark, email) + Markdown (repo).
"""
from __future__ import annotations
import argparse, datetime as dt, html, json, os, re, shutil, subprocess, sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import yaml
except ImportError:
    print("ERRO: PyYAML ausente — `pip install pyyaml`.", file=sys.stderr)
    raise

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

def _first(rows):
    rows = as_list(rows)
    return rows[0] if rows else {}

# =============================================================================
# config.json (walk-up) — fonte dos recipients e do tenant
# =============================================================================
def load_config():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(8):
        cand = os.path.join(d, "config.json")
        if os.path.isfile(cand):
            try:
                with open(cand, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return {}

# =============================================================================
# Utilitários compartilhados (shared/) — invocados como SUBPROCESSO (convenção do repo).
# Localiza shared/<name> subindo a árvore; degrada (None) se não achar.
# =============================================================================
def _find_shared(name):
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(8):
        cand = os.path.join(d, "shared", name)
        if os.path.isfile(cand):
            return cand
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return None

def _run_shared_json(path, args):
    if not path:
        return None
    try:
        p = subprocess.run([sys.executable, path, *args],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        if p.returncode not in (0, 2, 3):   # 2/3 são vereditos válidos (gate/no-match)
            return None
        return json.loads(p.stdout) if (p.stdout and p.stdout.strip()) else None
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None

# =============================================================================
# Self-collect (Modo A) — KQL via az monitor log-analytics query
# =============================================================================
def run_kql(ws_guid, kql):
    try:
        out = subprocess.run(
            [AZ, "monitor", "log-analytics", "query", "--workspace", ws_guid,
             "--analytics-query", _flatten_kql(kql), "-o", "json"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
        if out.returncode != 0:
            print(f"  [kql] erro: {out.stderr.strip()[:200]}", file=sys.stderr)
            return []
        return json.loads(out.stdout or "[]")
    except (subprocess.SubprocessError, json.JSONDecodeError) as e:
        print(f"  [kql] exceção: {e}", file=sys.stderr)
        return []

def fmt(kql, **kw):
    for k, v in kw.items():
        kql = kql.replace("{" + k + "}", str(v))
    return kql

def collect_live(q, ws_guid, params, incident_number):
    kq = q["collector"]["kql"]
    wd = params.get("window_days", 7)
    ld = params.get("lookback_days", 90)
    # escolhe incidente se nenhum foi dado
    if not incident_number:
        picked = run_kql(ws_guid, fmt(kq["pick_incident"], window_days=wd))
        incident_number = (_first(picked) or {}).get("IncidentNumber")
        if not incident_number:
            return {"incident_header": [], "incident_alerts": [], "_picked": None}
    header = run_kql(ws_guid, fmt(kq["incident_header"], lookback_days=ld, incident_number=incident_number))
    alerts = run_kql(ws_guid, fmt(kq["incident_alerts"], lookback_days=ld, incident_number=incident_number))
    return {"incident_header": header, "incident_alerts": alerts, "_picked": incident_number}

# =============================================================================
# Entidades — parse defensivo do campo Entities (JSON) dos alertas
# =============================================================================
def _load_entities(raw):
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return []
    return as_list(raw)

def extract_entities(alerts):
    users, hosts, ips = {}, {}, {}
    for a in alerts:
        for e in _load_entities(a.get("Entities")):
            if not isinstance(e, dict):
                continue
            etype = str(e.get("Type", "")).lower()
            if etype == "account":
                name = e.get("Name") or e.get("DisplayName") or ""
                suffix = e.get("UpnSuffix") or ""
                upn = f"{name}@{suffix}" if name and suffix else (e.get("Upn") or name)
                if upn:
                    users[upn] = True
            elif etype == "host":
                h = e.get("HostName") or e.get("NetBiosName") or e.get("DnsDomain") or ""
                if h:
                    hosts[h] = True
            elif etype == "ip":
                ip = e.get("Address") or ""
                if ip:
                    ips[ip] = True
    return {"users": sorted(users), "hosts": sorted(hosts), "ips": sorted(ips)}

# =============================================================================
# MITRE — táticas nativas (campo Tactics dos alertas) + inferência por texto (mitre_map.py)
# =============================================================================
def collect_mitre(header, alerts):
    native = set()
    for a in alerts:
        t = a.get("Tactics")
        if not t:
            continue
        for part in re.split(r"[;,]", str(t)):
            part = part.strip()
            if part:
                native.add(part)
    text = " ".join([str(header.get("Title", ""))] + [str(a.get("AlertName", "")) for a in alerts])
    inferred = []
    res = _run_shared_json(_find_shared("mitre_map.py"), ["map", text])
    if isinstance(res, dict):
        inferred = res.get("techniques", []) or []
    return {"native_tactics": sorted(native), "inferred": inferred,
            "util_available": res is not None}

# =============================================================================
# Plano de resposta — ações por tipo de entidade, cada uma gateada via action_safety.py
# =============================================================================
def build_response_plan(q, entities):
    pb = q.get("response_playbook", {}) or {}
    by_entity = pb.get("by_entity", {}) or {}
    actions = list(pb.get("always", []) or [])
    if entities["users"]:
        actions += by_entity.get("user", [])
    if entities["hosts"]:
        actions += by_entity.get("host", [])
    if entities["ips"]:
        actions += by_entity.get("ip", [])
    seen, ordered = set(), []
    for a in actions:
        if a not in seen:
            ordered.append(a); seen.add(a)
    safety_path = _find_shared("action_safety.py")
    plan, util_ok = [], safety_path is not None
    for action in ordered:
        ev = _run_shared_json(safety_path, ["evaluate", action]) if util_ok else None
        if ev:
            plan.append(ev)
        else:
            plan.append({"action": action, "risk_level": "?", "approval_required": True,
                         "reversible": None, "rollback_action": None,
                         "impact_description": "(gate indisponível — revisar manualmente)",
                         "guardrails": [], "warnings": []})
    return {"actions": plan, "util_available": util_ok}

# =============================================================================
# Veredito determinístico
# =============================================================================
def compute_verdict(header, alerts):
    classification = str(header.get("Classification") or "").lower()
    sev = str(header.get("Severity") or "").lower()
    status = str(header.get("Status") or "").lower()
    high_alerts = sum(1 for a in alerts if str(a.get("AlertSeverity") or "").lower() == "high")
    if "truepositive" in classification:
        return "true_positive", high_alerts, "Já classificado como True Positive."
    if "falsepositive" in classification or "benign" in classification:
        return "benign", high_alerts, "Já classificado como Falso Positivo / Benigno."
    if sev == "high" and high_alerts >= 1 and status != "closed":
        return "true_positive", high_alerts, f"Severidade High com {high_alerts} alerta(s) high e incidente aberto."
    if sev == "low" and high_alerts == 0:
        return "benign", high_alerts, "Severidade Low e nenhum alerta high."
    return "needs_review", high_alerts, "Sinais mistos — requer análise humana."

def next_action(verdict_key, header, entities):
    n = header.get("IncidentNumber", "?")
    u = entities["users"][0] if entities["users"] else None
    h = entities["hosts"][0] if entities["hosts"] else None
    ip = entities["ips"][0] if entities["ips"] else None
    if verdict_key == "true_positive":
        if u:
            return f"Conter o usuário {u}: revoke sessions + disable + reset (ações gateadas — exigem aprovação)."
        if h:
            return f"Isolar o device {h} + AV scan (ações gateadas — exigem aprovação)."
        if ip:
            return f"Investigar/bloquear o IP {ip} e registrar a conclusão no incidente {n}."
        return f"Escalar o incidente {n} ao SOC lead — entidades não extraídas automaticamente."
    if verdict_key == "benign":
        return f"Fechar o incidente {n} como benigno/FP com comentário de justificativa."
    return f"Triar o incidente {n}: revisar alertas/entidades e comentar a conclusão."

# =============================================================================
# RENDER
# =============================================================================
_SEV_COLOR = {"high": "#ff6b6b", "medium": "#ffd96b", "low": "#7cd0ff", "informational": "#9aa4b2"}
_VERDICT_COLOR = {"true_positive": "#ff6b6b", "needs_review": "#ffd96b", "benign": "#5ed16a"}
_RISK_EMOJI = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴", "?": "⚪"}

def _short_dt(s):
    if not s:
        return "—"
    return str(s).replace("T", " ")[:16]

def build_context(q, raw, params):
    header = _first(raw.get("incident_header"))
    alerts = as_list(raw.get("incident_alerts"))
    entities = extract_entities(alerts)
    mitre = collect_mitre(header, alerts)
    plan = build_response_plan(q, entities)
    vkey, high_alerts, vwhy = compute_verdict(header, alerts)
    vcfg = (q.get("verdict", {}) or {}).get(vkey, {"label": vkey, "emoji": "•"})
    return {
        "header": header, "alerts": alerts, "entities": entities, "mitre": mitre,
        "plan": plan, "verdict_key": vkey, "verdict": vcfg, "verdict_why": vwhy,
        "high_alerts": high_alerts, "next_action": next_action(vkey, header, entities),
        "generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
    }

def render_html(ctx, q):
    h = ctx["header"]; v = ctx["verdict"]; vk = ctx["verdict_key"]
    vcol = _VERDICT_COLOR.get(vk, "#9aa4b2")
    title = esc(h.get("Title", "(sem título)"))
    incnum = esc(h.get("IncidentNumber", "?"))
    sev = str(h.get("Severity", "")).lower()
    sevcol = _SEV_COLOR.get(sev, "#9aa4b2")

    # alerts rows
    arows = ""
    for a in ctx["alerts"]:
        ac = _SEV_COLOR.get(str(a.get("AlertSeverity", "")).lower(), "#9aa4b2")
        arows += (f"<tr><td>{esc(a.get('AlertName'))}</td>"
                  f"<td><span style='color:{ac};font-weight:700'>{esc(a.get('AlertSeverity'))}</span></td>"
                  f"<td>{esc(a.get('ProductName'))}</td><td>{esc(a.get('Tactics') or '—')}</td>"
                  f"<td class='mono'>{esc(_short_dt(a.get('TimeGenerated')))}</td></tr>")
    if not arows:
        arows = "<tr><td colspan='5' style='opacity:.6'>Nenhum alerta resolvido para este incidente.</td></tr>"

    # entities chips
    def chips(items, color):
        return "".join(f"<span class='chip' style='border-color:{color}'>{esc(x)}</span>" for x in items) or "<span style='opacity:.5'>—</span>"
    ent = ctx["entities"]

    # MITRE
    mt = ctx["mitre"]
    nat = ", ".join(esc(x) for x in mt["native_tactics"]) or "—"
    inf_rows = ""
    for t in mt["inferred"]:
        inf_rows += (f"<tr><td class='mono'>{esc(t.get('technique_id'))}</td>"
                     f"<td>{esc(t.get('technique_name'))}</td><td>{esc(t.get('tactic'))}</td></tr>")
    if not inf_rows:
        inf_rows = "<tr><td colspan='3' style='opacity:.6'>Nenhuma técnica inferida do texto.</td></tr>"

    # response plan
    prows = ""
    for a in ctx["plan"]["actions"]:
        risk = str(a.get("risk_level", "?"))
        rk = _RISK_EMOJI.get(risk, "⚪")
        appr = "<b style='color:#ff6b6b'>exige aprovação</b>" if a.get("approval_required") else "<span style='color:#5ed16a'>pode prosseguir</span>"
        roll = esc(a.get("rollback_action") or "—")
        prows += (f"<tr><td class='mono'>{esc(a.get('action'))}</td>"
                  f"<td>{rk} {esc(risk)}</td><td>{appr}</td>"
                  f"<td>{esc(a.get('impact_description'))}</td><td class='mono'>{roll}</td></tr>")

    util_note = ""
    if not ctx["plan"]["util_available"] or not mt["util_available"]:
        miss = []
        if not mt["util_available"]:
            miss.append("shared/mitre_map.py")
        if not ctx["plan"]["util_available"]:
            miss.append("shared/action_safety.py")
        util_note = (f"<div class='warn'>Utilitário(s) compartilhado(s) não encontrado(s): "
                     f"<code>{esc(' · '.join(miss))}</code> — seções degradadas (sem inferência/gate).</div>")

    desc = esc((h.get("Description") or "").strip())[:600]
    inc_url = h.get("IncidentUrl") or ""
    url_link = f"<a href='{esc(inc_url)}' style='color:#7cd0ff'>abrir no portal ↗</a>" if inc_url else ""

    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Incident Triage — #{incnum}</title>
<style>
  body{{margin:0;background:#0b0f17;color:#e7edf5;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
  .wrap{{max-width:920px;margin:0 auto;padding:24px}}
  .hero{{background:linear-gradient(135deg,#121a2b,#0d1422);border:1px solid #1e2a3f;border-radius:16px;padding:22px 24px;margin-bottom:18px}}
  .hero h1{{margin:0 0 6px;font-size:20px}}
  .badge{{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:800;font-size:13px}}
  .pill{{display:inline-block;padding:2px 10px;border-radius:999px;border:1px solid #2a3852;font-size:12px;margin-right:6px}}
  h2{{font-size:15px;margin:22px 0 10px;border-left:3px solid #3a6df0;padding-left:9px}}
  table{{width:100%;border-collapse:collapse;font-size:13px;background:#0d1422;border:1px solid #1e2a3f;border-radius:10px;overflow:hidden}}
  th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #182337;vertical-align:top}}
  th{{background:#111a2b;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#9fb0c8}}
  .mono{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}
  .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}
  .card{{background:#0d1422;border:1px solid #1e2a3f;border-radius:12px;padding:14px}}
  .chip{{display:inline-block;padding:2px 9px;margin:2px;border:1px solid #2a3852;border-radius:999px;font-size:12px}}
  .next{{background:#11203a;border:1px solid #24406e;border-radius:12px;padding:14px;margin-top:14px}}
  .warn{{background:#2a1f12;border:1px solid #5a4320;border-radius:10px;padding:10px 12px;margin:12px 0;font-size:13px}}
  .meta{{color:#9fb0c8;font-size:12px}}
  @media(max-width:640px){{.grid2{{grid-template-columns:1fr}}}}
</style></head><body><div class="wrap">

  <div class="hero">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
      <h1>🚨 Incident Triage — #{incnum}</h1>
      <span class="badge" style="background:{vcol}22;color:{vcol};border:1px solid {vcol}">{esc(v.get('emoji'))} {esc(v.get('label'))}</span>
    </div>
    <div style="margin:8px 0 4px">{title}</div>
    <div>
      <span class="pill">Severidade: <b style="color:{sevcol}">{esc(h.get('Severity') or '—')}</b></span>
      <span class="pill">Status: {esc(h.get('Status') or '—')}</span>
      <span class="pill">Alertas: {len(ctx['alerts'])}</span>
      <span class="pill">Owner: {esc(h.get('Owner') or '—')}</span>
      <span class="pill">Criado: {esc(_short_dt(h.get('CreatedTime')))}</span>
    </div>
    <div class="meta" style="margin-top:8px">{esc(ctx['verdict_why'])} {url_link}</div>
  </div>

  {util_note}

  <div class="next"><b>▶ Próxima ação:</b> {esc(ctx['next_action'])}</div>

  <h2>📋 Alertas relacionados ({len(ctx['alerts'])})</h2>
  <table><tr><th>Alerta</th><th>Sev</th><th>Produto</th><th>Táticas</th><th>Quando</th></tr>{arows}</table>

  <div class="grid2" style="margin-top:14px">
    <div class="card"><b>👤 Usuários</b><div style="margin-top:8px">{chips(ent['users'], '#ff9f6b')}</div>
      <b style="display:block;margin-top:12px">💻 Hosts</b><div style="margin-top:8px">{chips(ent['hosts'], '#7cd0ff')}</div>
      <b style="display:block;margin-top:12px">🌐 IPs</b><div style="margin-top:8px">{chips(ent['ips'], '#c9a7ff')}</div>
    </div>
    <div class="card"><b>🎯 MITRE ATT&CK</b>
      <div class="meta" style="margin:8px 0">Táticas nativas dos alertas: <b>{nat}</b></div>
      <div class="meta" style="margin-bottom:4px">Técnicas inferidas (texto → shared/mitre_map.py):</div>
      <table><tr><th>ID</th><th>Técnica</th><th>Tática</th></tr>{inf_rows}</table>
    </div>
  </div>

  <h2>🛡️ Plano de resposta recomendado <span class="meta">(gateado por shared/action_safety.py — nada é executado)</span></h2>
  <table><tr><th>Ação</th><th>Risco</th><th>Gate</th><th>Impacto</th><th>Rollback</th></tr>{prows}</table>

  {f'<h2>📝 Descrição</h2><div class="card meta">{desc}</div>' if desc else ''}

  <div class="meta" style="margin-top:22px;border-top:1px solid #1e2a3f;padding-top:12px">
    incident-triage · gerado {esc(ctx['generated'])} · 100% read-only · recomenda (não executa).
  </div>
</div></body></html>"""

def render_md(ctx):
    h = ctx["header"]; v = ctx["verdict"]
    lines = [f"# 🚨 Incident Triage — #{h.get('IncidentNumber','?')}",
             f"**Veredito:** {v.get('emoji')} {v.get('label')} — {ctx['verdict_why']}",
             f"**Título:** {h.get('Title','—')}",
             f"**Severidade:** {h.get('Severity','—')} · **Status:** {h.get('Status','—')} · **Alertas:** {len(ctx['alerts'])}",
             f"\n**▶ Próxima ação:** {ctx['next_action']}\n",
             "## Alertas relacionados", "| Alerta | Sev | Produto | Táticas |", "|---|---|---|---|"]
    for a in ctx["alerts"]:
        lines.append(f"| {a.get('AlertName','')} | {a.get('AlertSeverity','')} | {a.get('ProductName','')} | {a.get('Tactics') or '—'} |")
    e = ctx["entities"]
    lines += ["\n## Entidades",
              f"- **Usuários:** {', '.join(e['users']) or '—'}",
              f"- **Hosts:** {', '.join(e['hosts']) or '—'}",
              f"- **IPs:** {', '.join(e['ips']) or '—'}",
              "\n## MITRE",
              f"- **Táticas nativas:** {', '.join(ctx['mitre']['native_tactics']) or '—'}",
              "- **Técnicas inferidas:** " + (", ".join(f"{t.get('technique_id')} {t.get('technique_name')}" for t in ctx['mitre']['inferred']) or "—"),
              "\n## Plano de resposta (gateado — nada executado)",
              "| Ação | Risco | Gate | Rollback |", "|---|---|---|---|"]
    for a in ctx["plan"]["actions"]:
        gate = "exige aprovação" if a.get("approval_required") else "pode prosseguir"
        lines.append(f"| {a.get('action')} | {a.get('risk_level')} | {gate} | {a.get('rollback_action') or '—'} |")
    lines.append(f"\n_incident-triage · gerado {ctx['generated']} · read-only · recomenda (não executa)._")
    return "\n".join(lines)

# =============================================================================
# main
# =============================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(description="incident-triage — relatório de triagem de 1 incidente.")
    ap.add_argument("--from-json", dest="from_json", help="inventory.json pré-coletado (Modo B, primário).")
    ap.add_argument("--workspace", dest="ws_guid", help="GUID do workspace (Modo A, auto-coleta).")
    ap.add_argument("--sub"); ap.add_argument("--rg"); ap.add_argument("--ws")
    ap.add_argument("--incident-number", dest="incident_number", help="Número do incidente (senão: mais recente high-sev aberto).")
    ap.add_argument("--queries", default=None, help="caminho do queries.yaml (default: ao lado do script).")
    ap.add_argument("--output", default=".", help="pasta de saída.")
    ap.add_argument("--format", choices=["html", "md", "both"], default="both")
    ap.add_argument("--save-raw", action="store_true", help="salva o inventário coletado (_raw.json).")
    args = ap.parse_args(argv)

    qpath = args.queries or os.path.join(os.path.dirname(os.path.abspath(__file__)), "queries.yaml")
    with open(qpath, "r", encoding="utf-8") as f:
        q = yaml.safe_load(f)
    params = q.get("parameters", {}) or {}

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as f:
            raw = json.load(f)
    elif args.ws_guid:
        raw = collect_live(q, args.ws_guid, params, args.incident_number)
        if not as_list(raw.get("incident_header")):
            print("Modo A não retornou cabeçalho do incidente (sem incidente no período, sem Reader, ou az sem auth). "
                  "Use Modo B (--from-json).", file=sys.stderr)
            return 2
    else:
        print("Informe --from-json <arquivo> OU --workspace <GUID> [--incident-number N].", file=sys.stderr)
        return 2

    os.makedirs(args.output, exist_ok=True)
    if args.save_raw:
        with open(os.path.join(args.output, "_raw.json"), "w", encoding="utf-8") as f:
            json.dump(raw, f, ensure_ascii=False, indent=2)

    ctx = build_context(q, raw, params)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    incnum = ctx["header"].get("IncidentNumber", "x")
    base = f"incident-triage-{incnum}-{stamp}"

    if args.format in ("html", "both"):
        p = os.path.join(args.output, base + ".html")
        with open(p, "w", encoding="utf-8") as f:
            f.write(render_html(ctx, q))
        print(f"✅ Triage #{incnum} · {ctx['verdict']['label']} · {len(ctx['alerts'])} alerta(s) · "
              f"{len(ctx['entities']['users'])} user / {len(ctx['entities']['hosts'])} host")
        print(f"   → {p}")
    if args.format in ("md", "both"):
        p = os.path.join(args.output, base + ".md")
        with open(p, "w", encoding="utf-8") as f:
            f.write(render_md(ctx))
        print(f"   → {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

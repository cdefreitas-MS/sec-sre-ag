#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""identity-anomaly-score — UEBA de identidade (lake-first) para o SOC Autônomo.

Agrega SigninLogs por identidade -> baselines robustos (robust-Z/MAD) -> Composite
Risk Score 0-100 -> fila de risco + baseline pessoal (usuário vs. próprio histórico)
-> relatório HTML/MD + feed `identity_anomaly` (attack-path / org-posture).

Engine 100% Python stdlib (roda headless no SRE Agent). Isolation Forest é OPCIONAL
(--use-iso; usa scikit-learn se presente, senão cai no rarity robust-Z, degrade gracioso).

Portado (não-verbatim) do notebook de David Alonso — Dalonso-Security-Repo (MIT).

Modos:
  --from-json <arquivo>   inventário pré-coletado {identity_features, identity_daily?, risky_users?}
  --workspace <guid>      self-collect via `az monitor log-analytics query`
  --demo                  dados sintéticos (3 outliers plantados) p/ smoke
"""
from __future__ import annotations
import argparse, datetime as dt, html, json, math, os, random, re, shutil, subprocess, sys, statistics

AZ = shutil.which("az") or "az"
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import yaml
except Exception:
    yaml = None


def esc(s):
    return html.escape("" if s is None else str(s))


def _flatten_kql(q):
    return " ".join(l.strip() for l in str(q).splitlines() if l.strip() and not l.strip().startswith("//"))


def _num(v, d=0.0):
    try:
        if v is None or v == "":
            return d
        return float(v)
    except Exception:
        return d


# ─────────────────────────── coleta ───────────────────────────
def run_kql(workspace, kql):
    """Roda KQL no Log Analytics via az monitor. Retorna lista de dicts (ou [])."""
    flat = _flatten_kql(kql)
    try:
        cmd = [AZ, "monitor", "log-analytics", "query", "--workspace", workspace,
               "--analytics-query", flat, "-o", "json"]
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=180)
        if r.returncode != 0:
            print(f"  [kql] falhou: {r.stderr.strip()[:200]}", file=sys.stderr)
            return []
        return json.loads(r.stdout or "[]")
    except Exception as e:
        print(f"  [kql] erro: {e}", file=sys.stderr)
        return []


def collect_live(q, workspace):
    p = q.get("parameters", {}) or {}
    ld = str(int(p.get("lookback_days", 30)))
    def fmt(kql):
        return str(kql).replace("{lookback_days}", ld)
    qs = q["queries"]
    inv = {}
    inv["identity_features"] = run_kql(workspace, fmt(qs["identity_features"]))
    inv["identity_daily"] = run_kql(workspace, fmt(qs["identity_daily"]))
    # corroboração (best-effort; cada uma degrada p/ [] se a tabela não existe)
    for k in ("identity_signals", "ip_ioc", "active_alerts"):
        if k in qs:
            inv[k] = run_kql(workspace, fmt(qs[k]))
    return inv


# ─────────────────────────── demo sintético ───────────────────────────
def demo_data(n=400, seed=42):
    rng = random.Random(seed)
    rows = []
    for u in range(n):
        base = rng.randint(60, 900)
        rows.append({
            "UserPrincipalName": f"user{u:03d}@contoso.com",
            "SignIns": base,
            "Failed": rng.randint(0, 12),
            "Success": base,
            "DistinctIPs": rng.randint(1, 2),
            "DistinctCountries": 1,
            "DistinctApps": rng.randint(1, 4),
            "Night": rng.randint(0, 30),
            "FailRatio": 0.0,
        })
    # 3 outliers plantados (compromisso/insider)
    for u in ("user007@contoso.com", "user099@contoso.com", "user250@contoso.com"):
        for r in rows:
            if r["UserPrincipalName"] == u:
                r.update(SignIns=6000, Failed=3600, Success=2400, DistinctIPs=9,
                         DistinctCountries=5, DistinctApps=3, Night=450)
    for r in rows:
        r["FailRatio"] = round(r["Failed"] / (r["SignIns"] + 1), 4)
    daily = []
    # série diária só p/ os outliers (baseline pessoal ilustrativo)
    for u in ("user007@contoso.com",):
        for d in range(30):
            spike = d >= 27
            daily.append({"UserPrincipalName": u,
                          "Date": (dt.date.today() - dt.timedelta(days=29 - d)).isoformat(),
                          "SignIns": 200 if spike else rng.randint(8, 20),
                          "Failed": 120 if spike else rng.randint(0, 2),
                          "DistinctIPs": 9 if spike else 1,
                          "DistinctCountries": 5 if spike else 1,
                          "Night": 15 if spike else rng.randint(0, 1)})
    # corroboração sintética (cada outlier c/ evidência diferente p/ ilustrar os vereditos)
    ip_ioc = [{"UserPrincipalName": "user099@contoso.com", "IPAddress": "45.146.164.110",
               "ThreatType": "Botnet", "ConfidenceScore": 85,
               "Description": "Known C2 node"}]
    identity_signals = [
        {"UserPrincipalName": "user007@contoso.com", "RiskySuccess": 4, "ImpossibleTravel": 2, "Anonymized": 1},
        {"UserPrincipalName": "user250@contoso.com", "RiskySuccess": 0, "ImpossibleTravel": 3, "Anonymized": 0},
    ]
    active_alerts = [{"UserPrincipalName": "user007@contoso.com", "Alerts": 2,
                      "Sample": "Suspicious sign-in from anonymous IP", "MaxSev": "High"}]
    return {"identity_features": rows, "identity_daily": daily,
            "ip_ioc": ip_ioc, "identity_signals": identity_signals, "active_alerts": active_alerts}


# ─────────────────────────── engine ───────────────────────────
def _col_stats(rows, col):
    vals = [_num(r.get(col)) for r in rows]
    n = len(vals)
    mean = statistics.fmean(vals) if n else 0.0
    std = statistics.pstdev(vals) if n > 1 else 0.0
    med = statistics.median(vals) if n else 0.0
    mad = statistics.median([abs(v - med) for v in vals]) if n else 0.0
    return mean, (std or 1.0), med, (mad or 1.0)


def score_identities(rows, cfg, use_iso=False):
    feats = cfg["features"]
    sc = cfg["scoring"]
    W, T = sc["weights"], sc["thresholds"]
    stats = {c: _col_stats(rows, c) for c in feats}

    # z e robust-z (spikes positivos)
    for r in rows:
        for c in feats:
            mean, std, med, mad = stats[c]
            x = _num(r.get(c))
            r[c + "_z"] = max(0.0, (x - mean) / std)
            r[c + "_rz"] = max(0.0, 0.6745 * (x - med) / mad)

    # rarity multi-dimensional: soma dos robust-z, normalizada no fleet (0..1)
    raw = [sum(r[c + "_rz"] for c in feats) for r in rows]
    lo, hi = (min(raw), max(raw)) if raw else (0.0, 1.0)
    span = (hi - lo) or 1e-9
    for r, rr in zip(rows, raw):
        r["rarity"] = (rr - lo) / span

    # Isolation Forest opcional (substitui rarity nos 30 pts) — degrade gracioso
    iso_used = False
    if use_iso:
        try:
            from sklearn.ensemble import IsolationForest
            zc = [c + "_z" for c in feats]
            X = [[r[c] for c in zc] for r in rows]
            clf = IsolationForest(n_estimators=200, contamination=cfg["parameters"]["contamination"],
                                  random_state=42)
            clf.fit(X)
            dfn = [-s for s in clf.decision_function(X)]
            lo2, hi2 = min(dfn), max(dfn)
            span2 = (hi2 - lo2) or 1e-9
            for r, s in zip(rows, dfn):
                r["rarity"] = (s - lo2) / span2
            iso_used = True
        except Exception as e:
            print(f"  [iso] scikit-learn indisponível ({e}) — usando rarity robust-Z", file=sys.stderr)

    bands = sc["severity_bands"]

    def severity(score):
        for upper, label in bands:
            if score <= upper:
                return label
        return bands[-1][1]

    for r in rows:
        comp = {
            "rarity": W["rarity"] * r["rarity"],
            "country": W["country"] if _num(r.get("DistinctCountries")) > T["country_gt"] else 0,
            "zspike": W["zspike"] if r.get("SignIns_z", 0) > T["z_gt"] else 0,
            "fail": W["fail"] if _num(r.get("Failed")) >= T["fail_ge"] else 0,
            "night": W["night"] if _num(r.get("Night")) > 0 else 0,
            "ip": W["ip"] if _num(r.get("DistinctIPs")) > T["ip_gt"] else 0,
        }
        score = int(round(max(0.0, min(100.0, sum(comp.values())))))
        r["Score"] = score
        r["Severity"] = severity(score)
        # drivers legíveis (explicabilidade)
        drv = []
        if comp["country"]: drv.append(f"{int(_num(r.get('DistinctCountries')))} países")
        if comp["ip"]: drv.append(f"{int(_num(r.get('DistinctIPs')))} IPs")
        if comp["fail"]: drv.append(f"{int(_num(r.get('Failed')))} falhas")
        if comp["night"]: drv.append(f"{int(_num(r.get('Night')))} logins noturnos")
        if comp["zspike"]: drv.append("volume atípico")
        # top feature por robust-z
        topf = max(feats, key=lambda c: r.get(c + "_rz", 0))
        if r.get(topf + "_rz", 0) >= 3 and topf not in ("Failed",):
            drv.append(f"{topf} raro (z{r[topf + '_rz']:.0f})")
        r["Drivers"] = drv
    rows.sort(key=lambda r: r["Score"], reverse=True)
    return rows, iso_used


def personal_baseline(daily_rows, upn, cfg):
    """robust-z dos últimos detect_days vs baseline do próprio usuário. §7b."""
    sig = cfg["scoring"]["personal_baseline_sigma"]
    dd = cfg["parameters"]["detect_days"]
    u = sorted([r for r in daily_rows if r.get("UserPrincipalName") == upn],
               key=lambda r: r.get("Date", ""))
    if len(u) <= dd:
        return None
    metrics = ["SignIns", "Failed", "DistinctIPs", "DistinctCountries", "Night"]
    base, detect = u[:-dd], u[-dd:]
    flags = []
    for m in metrics:
        bv = [_num(r.get(m)) for r in base]
        med = statistics.median(bv)
        mad = statistics.median([abs(v - med) for v in bv]) or (statistics.pstdev(bv) if len(bv) > 1 else 1.0) or 1.0
        for r in detect:
            z = 0.6745 * (_num(r.get(m)) - med) / mad
            if abs(z) >= sig:
                flags.append({"date": r.get("Date"), "metric": m, "value": _num(r.get(m)),
                              "baseline": round(med, 1), "z": round(z, 1)})
    return {"upn": upn, "base_days": len(base), "detect_days": len(detect), "flags": flags}


def corroborate(scored, inv, cfg, risky_lc, daily):
    """Anexa a cada identidade os CORROBORADORES independentes (IP↔IOC, sucesso c/ risco
    Entra, alerta ativo, viagem impossível, IdP risky, desvio do próprio baseline) e um
    VEREDITO DE RISCO REAL. Anomalia rara + corroboração = risco real (não só ruído)."""
    cc = cfg.get("corroboration", {}) or {}
    V = cc.get("verdict", {})
    ioc, sig, alr = {}, {}, {}
    for r in (inv.get("ip_ioc") or []):
        ioc.setdefault(str(r.get("UserPrincipalName", "")).lower(), []).append(r)
    for r in (inv.get("identity_signals") or []):
        sig[str(r.get("UserPrincipalName", "")).lower()] = r
    for r in (inv.get("active_alerts") or []):
        alr[str(r.get("UserPrincipalName", "")).lower()] = r
    sg = cfg["scoring"]["personal_baseline_sigma"]
    for r in scored:
        upn = str(r.get("UserPrincipalName", "")).lower()
        cor = []
        for h in ioc.get(upn, []):
            cor.append({"key": "ioc_ip", "strong": True, "label": "IP em IOC",
                        "ev": f"{h.get('IPAddress')} = {h.get('ThreatType') or 'IOC'} (conf {h.get('ConfidenceScore', '?')})"})
        s = sig.get(upn)
        if s:
            if _num(s.get("RiskySuccess")) > 0:
                cor.append({"key": "risky_success", "strong": True, "label": "Sucesso c/ risco Entra",
                            "ev": f"{int(_num(s.get('RiskySuccess')))} sign-in(s) de sucesso com risco alto/médio"})
            if _num(s.get("ImpossibleTravel")) > 0:
                cor.append({"key": "impossible_travel", "strong": False, "label": "Viagem impossível",
                            "ev": f"{int(_num(s.get('ImpossibleTravel')))} evento(s)"})
            if _num(s.get("Anonymized")) > 0:
                cor.append({"key": "anonymized_ip", "strong": False, "label": "IP anonimizado (Tor/VPN)",
                            "ev": f"{int(_num(s.get('Anonymized')))} sign-in(s)"})
        a = alr.get(upn)
        if a and _num(a.get("Alerts")) > 0:
            cor.append({"key": "active_alert", "strong": True, "label": "Alerta ativo",
                        "ev": f"{int(_num(a.get('Alerts')))}× — {a.get('Sample') or 'detecção'}"})
        if upn in risky_lc:
            cor.append({"key": "idp_risky", "strong": False, "label": "Entra ID Protection",
                        "ev": "marcado como risky user"})
        if daily and _num(r.get("Score")) >= 40:   # só p/ identidades já relevantes (perf em tenant grande)
            pb = personal_baseline(daily, r.get("UserPrincipalName"), cfg)
            if pb and pb.get("flags"):
                cor.append({"key": "personal_deviation", "strong": False, "label": "Desvio do próprio baseline",
                            "ev": f"{len(pb['flags'])} métrica-dia |z|≥{sg}"})
        strong_n = sum(1 for c in cor if c["strong"])
        total = len(cor)
        if strong_n >= 1 or total >= 2:
            r["real_risk"], r["rr_klass"] = V.get("real", "RISCO REAL PROVÁVEL"), "real"
        elif total == 1:
            r["real_risk"], r["rr_klass"] = V.get("suspect", "SUSPEITO — investigar"), "suspect"
        else:
            r["real_risk"], r["rr_klass"] = V.get("noise", "PROVÁVEL RUÍDO"), "noise"
        r["corroborators"] = cor
    return scored


def build_context(q, inv, use_iso=False):
    rows = [dict(r) for r in (inv.get("identity_features") or [])]
    scored, iso_used = score_identities(rows, q, use_iso) if rows else ([], False)
    sev_order = ["Critical", "High", "Medium", "Low", "Normal"]
    counts = {s: 0 for s in sev_order}
    for r in scored:
        counts[r["Severity"]] = counts.get(r["Severity"], 0) + 1
    n_hi = counts["Critical"] + counts["High"]
    verdict = ("CRÍTICO" if counts["Critical"] else "ELEVADO" if counts["High"] else
               "ATENÇÃO" if counts["Medium"] else "ESTÁVEL")
    # baseline pessoal p/ o topo da fila (quando há série diária)
    daily = inv.get("identity_daily") or []
    top_upn = scored[0]["UserPrincipalName"] if scored else None
    pb = personal_baseline(daily, top_upn, q) if (daily and top_upn) else None
    # risky users corroboração
    risky = {(u.get("userPrincipalName") or u.get("UserPrincipalName") or "").lower()
             for u in (inv.get("risky_users") or [])}
    # camada de corroboração + veredito de risco real
    corroborate(scored, inv, q, risky, daily)
    n_real = sum(1 for r in scored if r.get("rr_klass") == "real")
    n_suspect = sum(1 for r in scored if r.get("rr_klass") == "suspect")
    real_rows = [r for r in scored if r.get("rr_klass") in ("real", "suspect")]
    n_ioc = sum(1 for r in scored if any(c["key"] == "ioc_ip" for c in r.get("corroborators", [])))
    # feed identity_anomaly: score alto OU corroborado (real/suspect)
    minf = q.get("feed", {}).get("min_score", 60)
    feed = [{"upn": r["UserPrincipalName"], "score": r["Score"], "severity": r["Severity"],
             "drivers": r["Drivers"], "real_risk": r.get("real_risk"), "rr_klass": r.get("rr_klass"),
             "corroborators": [c["label"] for c in r.get("corroborators", [])],
             "idp_risky": r["UserPrincipalName"].lower() in risky}
            for r in scored if r["Score"] >= minf or r.get("rr_klass") in ("real", "suspect")]
    return {"rows": scored, "counts": counts, "n_hi": n_hi, "verdict": verdict,
            "iso_used": iso_used, "personal": pb, "feed": feed, "n_total": len(scored),
            "n_risky": len(risky), "n_real": n_real, "n_suspect": n_suspect,
            "real_rows": real_rows, "n_ioc": n_ioc}


# ─────────────────────────── render ───────────────────────────
_SEV_COLOR = {"Critical": "#ff4d6d", "High": "#ff8c66", "Medium": "#ffb454",
              "Low": "#7cd0ff", "Normal": "#5ed16a"}


def _svg_donut(counts):
    total = sum(counts.values()) or 1
    order = ["Critical", "High", "Medium", "Low", "Normal"]
    segs = [(s, counts.get(s, 0)) for s in order if counts.get(s, 0) > 0]
    if not segs:
        return ""
    r, cx, cy = 52, 60, 60
    a0 = -math.pi / 2
    out = []
    for s, v in segs:
        frac = v / total
        a1 = a0 + frac * 2 * math.pi
        large = 1 if frac > 0.5 else 0
        x0, y0 = cx + r * math.cos(a0), cy + r * math.sin(a0)
        x1, y1 = cx + r * math.cos(a1), cy + r * math.sin(a1)
        out.append(f"<path d='M{cx:.1f},{cy:.1f} L{x0:.1f},{y0:.1f} "
                   f"A{r},{r} 0 {large} 1 {x1:.1f},{y1:.1f} Z' fill='{_SEV_COLOR[s]}'/>")
        a0 = a1
    out.append(f"<circle cx='{cx}' cy='{cy}' r='30' fill='#0b0e14'/>")
    out.append(f"<text x='{cx}' y='{cy-2}' text-anchor='middle' fill='#e6edf3' "
               f"font-size='20' font-weight='800'>{total}</text>")
    out.append(f"<text x='{cx}' y='{cy+14}' text-anchor='middle' fill='#8b949e' "
               f"font-size='9'>identidades</text>")
    return f"<svg viewBox='0 0 120 120' width='120' height='120'>{''.join(out)}</svg>"


_STYLE = """
body{margin:0;background:#0b0e14;color:#c9d1d9;font:14px/1.5 'Segoe UI',system-ui,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 2px} .meta{color:#7d8590;font-size:13px}
.hero{display:flex;gap:22px;align-items:center;margin:18px 0;padding:18px;background:#11151d;border:1px solid #1f2733;border-radius:14px;flex-wrap:wrap}
.verdict{font-size:26px;font-weight:800}
.kpis{display:flex;gap:10px;flex-wrap:wrap;margin-left:auto}
.kpi{background:#0b0e14;border:1px solid #1f2733;border-radius:10px;padding:9px 15px;text-align:center;min-width:92px}
.kpi b{display:block;font-size:22px} .kpi span{font-size:11px;color:#8b949e}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
th,td{padding:7px 9px;text-align:left;border-bottom:1px solid #1f2733}
th{color:#8b949e;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.4px}
.sev{padding:2px 9px;border-radius:20px;font-size:11px;font-weight:800;white-space:nowrap;color:#0b0e14}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.drv{color:#adbac7;font-size:12px}
.card{background:#11151d;border:1px solid #1f2733;border-radius:12px;padding:14px 16px;margin:14px 0}
.feed{margin-top:12px;padding:12px 14px;background:#0d1320;border:1px solid #243049;border-radius:10px}
.feed b{color:#9bd1ff}
.pb{background:#1a1206;border:1px solid #3a2e10;border-radius:10px;padding:10px 14px;color:#ffd98a;font-size:12.5px;margin-top:10px}
.rr{padding:2px 9px;border-radius:20px;font-size:11px;font-weight:800;white-space:nowrap}
.rr-real{background:#ff4d6d22;color:#ff6b82;border:1px solid #ff4d6d66}
.rr-suspect{background:#ffb45422;color:#ffc477;border:1px solid #ffb45466}
.rr-noise{background:#5a636e22;color:#8b949e;border:1px solid #5a636e55}
.chip{display:inline-block;background:#0d1320;border:1px solid #243049;border-radius:16px;padding:2px 10px;font-size:11.5px;margin:2px 4px 2px 0;color:#c9d1d9}
.chip.s{border-color:#ff4d6d66;color:#ff8fa3}
.rrcard{background:#160b0e;border:1px solid #3a1620;border-radius:12px;padding:12px 15px;margin:10px 0}
.rrcard .u{font-family:ui-monospace,Consolas,monospace;font-size:13px;color:#e6edf3}
.foot{color:#5a636e;font-size:11px;margin-top:20px;border-top:1px solid #1f2733;padding-top:10px}
"""


def _sev_badge(s):
    return f"<span class='sev' style='background:{_SEV_COLOR.get(s,'#8b949e')}'>{esc(s)}</span>"


def _rr_badge(r):
    k = r.get("rr_klass", "noise")
    return f"<span class='rr rr-{k}'>{esc(r.get('real_risk',''))}</span>"


def _chips(cor):
    return "".join(f"<span class='chip{' s' if c['strong'] else ''}'>{esc(c['label'])}: {esc(c['ev'])}</span>"
                   for c in cor) or "<span class='meta'>sem corroboração</span>"


def render_html(ctx, cfg, scope):
    c = ctx["counts"]
    rows = ctx["rows"][:20]
    body = []
    body.append("<div class='wrap'>")
    body.append("<h1>🛡️ Identity Anomaly Score — UEBA de identidade</h1>")
    body.append(f"<div class='meta'>Escopo <b>{esc(scope)}</b> · {ctx['n_total']} identidades · "
                f"janela {cfg['parameters']['lookback_days']}d · "
                f"rarity via {'Isolation Forest' if ctx['iso_used'] else 'robust-Z'} · "
                f"gerado {dt.datetime.now():%Y-%m-%d %H:%M}</div>")
    # hero
    body.append("<div class='hero'>")
    body.append(_svg_donut(c))
    body.append(f"<div><div class='verdict' style='color:{_SEV_COLOR['Critical'] if ctx['verdict']=='CRÍTICO' else _SEV_COLOR['High'] if ctx['verdict']=='ELEVADO' else _SEV_COLOR['Medium'] if ctx['verdict']=='ATENÇÃO' else _SEV_COLOR['Normal']}'>{esc(ctx['verdict'])}</div>"
                f"<div class='meta'>{ctx['n_hi']} identidade(s) em risco alto/crítico</div></div>")
    body.append("<div class='kpis'>"
                f"<div class='kpi'><b style='color:#ff6b82'>{ctx.get('n_real',0)}</b><span>🔴 risco real</span></div>"
                f"<div class='kpi'><b style='color:#ff8fa3'>{ctx.get('n_ioc',0)}</b><span>🎯 IP↔IOC</span></div>"
                f"<div class='kpi'><b style='color:{_SEV_COLOR['Critical']}'>{c['Critical']}</b><span>🔴 Crítico</span></div>"
                f"<div class='kpi'><b style='color:{_SEV_COLOR['High']}'>{c['High']}</b><span>🟠 Alto</span></div>"
                f"<div class='kpi'><b>{ctx['n_risky']}</b><span>ID Protection</span></div>"
                "</div>")
    body.append("</div>")
    # 🔴 RISCO REAL (corroborado) — o que separa anomalia de ameaça
    rr = ctx.get("real_rows", [])
    if rr:
        body.append("<div class='card'><h3 style='margin:0 0 4px'>🔴 Risco real (corroborado) "
                    "<span class='meta'>· anomalia + evidência independente — investigar</span></h3>")
        for r in rr[:12]:
            body.append(
                f"<div class='rrcard'><div style='display:flex;gap:10px;align-items:center;flex-wrap:wrap'>"
                f"<span class='u'>{esc(r['UserPrincipalName']) or '(sem UPN)'}</span>{_rr_badge(r)}"
                f"<span class='meta'>Score {r['Score']} · {esc(r['Severity'])}</span></div>"
                f"<div style='margin-top:6px'>{_chips(r.get('corroborators', []))}</div></div>")
        body.append("</div>")
    else:
        body.append("<div class='card'><h3 style='margin:0 0 4px'>🔴 Risco real (corroborado)</h3>"
                    "<div class='meta'>Nenhuma identidade anômala com corroboração independente (IP↔IOC, "
                    "sucesso c/ risco, alerta ativo, viagem impossível). As anômalias abaixo são "
                    "estatisticamente raras, mas <b>sem evidência de ameaça real</b> — provável ruído.</div></div>")
    # fila de risco
    body.append("<div class='card'><h3 style='margin:0 0 4px'>🔎 Fila de risco de identidade "
                "<span class='meta'>· top 20 por Composite Risk Score (0–100)</span></h3>")
    body.append("<table><tr><th>Identidade</th><th>Score</th><th>Severidade</th><th>Risco real</th>"
                "<th>Por quê (drivers)</th><th>SignIns</th><th>Falhas</th><th>IPs</th></tr>")
    for r in rows:
        idp = " 🔺" if r["UserPrincipalName"].lower() in {f["upn"].lower() for f in ctx["feed"] if f["idp_risky"]} else ""
        body.append(
            f"<tr><td class='mono'>{esc(r['UserPrincipalName'])}{idp}</td>"
            f"<td><b>{r['Score']}</b></td><td>{_sev_badge(r['Severity'])}</td>"
            f"<td>{_rr_badge(r)}</td>"
            f"<td class='drv'>{esc(' · '.join(r['Drivers']) or '—')}</td>"
            f"<td>{int(_num(r.get('SignIns')))}</td><td>{int(_num(r.get('Failed')))}</td>"
            f"<td>{int(_num(r.get('DistinctIPs')))}</td></tr>")
    body.append("</table><div class='meta' style='margin-top:6px'>🔺 = também sinalizado pelo Entra ID Protection</div></div>")
    # baseline pessoal
    pb = ctx["personal"]
    if pb and pb["flags"]:
        body.append(f"<div class='card'><h3 style='margin:0 0 4px'>📈 Baseline pessoal — {esc(pb['upn'])} "
                    "<span class='meta'>· desvio do PRÓPRIO histórico (insider/comprometimento)</span></h3>")
        body.append(f"<div class='meta'>baseline {pb['base_days']}d vs. últimos {pb['detect_days']}d · "
                    f"{len(pb['flags'])} métrica-dia com |z|≥{cfg['scoring']['personal_baseline_sigma']}</div>")
        body.append("<table><tr><th>Data</th><th>Métrica</th><th>Valor</th><th>Baseline</th><th>Desvio (z)</th></tr>")
        for f in pb["flags"][:12]:
            body.append(f"<tr><td>{esc(f['date'])}</td><td>{esc(f['metric'])}</td>"
                        f"<td><b>{int(f['value'])}</b></td><td>{f['baseline']}</td>"
                        f"<td style='color:{_SEV_COLOR['Critical']};font-weight:700'>{f['z']}σ</td></tr>")
        body.append("</table></div>")
    # feed
    if ctx["feed"]:
        body.append(f"<div class='feed'>🔗 <b>Feed identity_anomaly</b> — {len(ctx['feed'])} identidade(s) "
                    "High/Crítico exportadas p/ <b>attack-path</b> (exposure fusion) e <b>org-posture</b> "
                    "(pilar Identidade). Comportamento ativo eleva um caminho de teórico p/ real.</div>")
    body.append("</div>")
    return f"<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'><title>Identity Anomaly Score</title><style>{_STYLE}</style></head><body>{''.join(body)}</body></html>"


def render_md(ctx, cfg, scope):
    L = [f"# Identity Anomaly Score — UEBA ({scope})", "",
         f"**Veredito: {ctx['verdict']}** · 🔴 {ctx.get('n_real',0)} risco real corroborado · 🎯 {ctx.get('n_ioc',0)} IP↔IOC · "
         f"{ctx['n_hi']} em risco alto/crítico · {ctx['n_total']} avaliadas · "
         f"rarity via {'Isolation Forest' if ctx['iso_used'] else 'robust-Z'}", "",
         f"🔴 {ctx['counts']['Critical']} · 🟠 {ctx['counts']['High']} · 🟡 {ctx['counts']['Medium']} · "
         f"🔵 {ctx['counts']['Low']} · 🟢 {ctx['counts']['Normal']}", ""]
    rr = ctx.get("real_rows", [])
    if rr:
        L += ["## 🔴 Risco real (corroborado)", "",
              "| Identidade | Score | Veredito | Evidência |", "|---|---|---|---|"]
        for r in rr[:12]:
            ev = " · ".join(f"{c['label']}: {c['ev']}" for c in r.get("corroborators", [])) or "—"
            L.append(f"| {r['UserPrincipalName'] or '(sem UPN)'} | {r['Score']} | {r.get('real_risk','')} | {ev} |")
        L.append("")
    L += ["## Fila de risco (top 15)", "",
          "| Identidade | Score | Severidade | Risco real | Drivers |", "|---|---|---|---|---|"]
    for r in ctx["rows"][:15]:
        L.append(f"| {r['UserPrincipalName']} | {r['Score']} | {r['Severity']} | {r.get('real_risk','')} | {' · '.join(r['Drivers']) or '—'} |")
    if ctx["feed"]:
        L += ["", f"## Feed identity_anomaly ({len(ctx['feed'])})", "",
              "Identidades corroboradas / High-Crítico exportadas p/ attack-path + org-posture."]
    return "\n".join(L)


# ─────────────────────────── main ───────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(description="identity-anomaly-score — UEBA de identidade.")
    ap.add_argument("--from-json", dest="from_json")
    ap.add_argument("--workspace", dest="ws")
    ap.add_argument("--demo", action="store_true", help="dados sintéticos (smoke)")
    ap.add_argument("--use-iso", action="store_true", help="usar Isolation Forest (scikit-learn) p/ rarity")
    ap.add_argument("--queries", default=None)
    ap.add_argument("--output", default=".")
    ap.add_argument("--format", choices=["html", "md", "both"], default="both")
    ap.add_argument("--emit-feed", action="store_true", help="grava _identity_anomaly_feed.json")
    ap.add_argument("--save-raw", action="store_true")
    args = ap.parse_args(argv)

    qpath = args.queries or os.path.join(os.path.dirname(os.path.abspath(__file__)), "queries.yaml")
    if yaml is None:
        print("PyYAML necessário.", file=sys.stderr); return 2
    with open(qpath, "r", encoding="utf-8") as f:
        q = yaml.safe_load(f)

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as f:
            inv = json.load(f)
        scope = "tenant (from-json)"
    elif args.ws:
        inv = collect_live(q, args.ws)
        scope = f"workspace {args.ws[:8]}…"
        if not inv.get("identity_features"):
            print("Sem dados de SigninLogs (workspace sem acesso ou vazio). Use --from-json ou --demo.", file=sys.stderr)
            return 2
    elif args.demo:
        inv = demo_data()
        scope = "DEMO (sintético)"
    else:
        print("Informe --from-json <arquivo> · OU --workspace <guid> · OU --demo.", file=sys.stderr)
        return 2

    ctx = build_context(q, inv, use_iso=args.use_iso)
    os.makedirs(args.output, exist_ok=True)
    if args.save_raw:
        json.dump(inv, open(os.path.join(args.output, "_raw.json"), "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    base = f"identity-anomaly-{stamp}"
    if args.format in ("html", "both"):
        p = os.path.join(args.output, base + ".html")
        open(p, "w", encoding="utf-8").write(render_html(ctx, q, scope))
        print(f"   → {p}")
    if args.format in ("md", "both"):
        p = os.path.join(args.output, base + ".md")
        open(p, "w", encoding="utf-8").write(render_md(ctx, q, scope))
        print(f"   → {p}")
    if args.emit_feed:
        fp = os.path.join(args.output, "_identity_anomaly_feed.json")
        json.dump({"identity_anomaly": ctx["feed"]}, open(fp, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
        print(f"   → {fp} (feed cross-domain p/ attack-path/org-posture)")
    print(f"✅ {ctx['verdict']} · 🔴 {ctx.get('n_real',0)} risco real ({ctx.get('n_ioc',0)} IP↔IOC) · "
          f"{ctx['n_hi']} alto/crítico · {ctx['n_total']} identidades · feed {len(ctx['feed'])} · "
          f"rarity {'iso' if ctx['iso_used'] else 'robust-Z'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

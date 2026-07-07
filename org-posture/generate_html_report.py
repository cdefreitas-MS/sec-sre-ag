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
  {"secure_scores": <graph>, "incidents": <graph>, "risky_users": <graph>, "exposure_score": <mde>,
   "subscribed_skus": <graph>, "attack_sim_user_coverage": <graph>, "attack_sim_training_coverage": <graph>,
   "attack_sim_repeat_offenders": <graph>, "attack_sim_simulations": <graph>}
The last five feed the two INFORMATIONAL sections (licensing/FinOps + human-risk); they do NOT
affect the Org Posture Index and degrade to "omitted" when their data/permission is unavailable.
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

# Force UTF-8 stdout/stderr on Windows so the emoji summary doesn't crash a cp1252 console.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

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


def _parse_dt(s):
    """Parse an ISO8601 datetime (Graph returns ...Z) → aware datetime or None."""
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def _val(resp):
    if isinstance(resp, dict):
        return resp.get("value", []) or []
    if isinstance(resp, list):
        return resp
    return []


def _clamp(v, lo=0.0, hi=100.0):
    return max(lo, min(hi, v))


# Microsoft Secure Score reader — MIRRORS the canonical shared/secure_score.py (production repo).
# org-posture lives in the workspace (not the sec-sre-ag repo), so it can't import shared/ today;
# when promoted to the repo, replace this with:  from secure_score import latest_secure_score.
# advisor-impact uses that same canonical reader, so the Secure Score number matches across reports.
def _secure_score(resp):
    """Most recent /security/secureScores entry → (current, max, pct)."""
    rows = [r for r in _val(resp) if isinstance(r, dict)]
    rows.sort(key=lambda s: str(s.get("createdDateTime", "")), reverse=True)
    p = rows[0] if rows else {}
    cur, mx = _num(p.get("currentScore")), _num(p.get("maxScore"))
    return cur, mx, (round(cur / mx * 100, 1) if mx else 0.0)


def compute(data, params, scoring):
    w = scoring["weights"]
    pen = scoring.get("incident_penalty", {})
    rup = scoring.get("risky_user_penalty", 12)

    # --- Identity (Secure Score %) — canonical reader (mirror of shared/secure_score.py) ---
    cur, mx, ss_pct = _secure_score(data.get("secure_scores"))
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

    # --- Identity risk (high-risk users + UEBA corroborated-real behaviour) ---
    risky = _val(data.get("risky_users"))
    n_risky = len(risky)
    # feed identity-anomaly-score: risco REAL corroborado pesa mais que um flag estático do IdP
    ueba = _val(data.get("identity_anomaly"))
    n_ueba_real = sum(1 for u in ueba if str(u.get("rr_klass")) == "real")
    n_ueba_suspect = sum(1 for u in ueba if str(u.get("rr_klass")) == "suspect")
    urp = scoring.get("ueba_real_penalty", 18)
    usp = scoring.get("ueba_suspect_penalty", 6)
    identity_risk = _clamp(100 - n_risky * rup - n_ueba_real * urp - n_ueba_suspect * usp)

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
         "driver": f"{n_risky} usuários de alto risco" +
                   (f" · UEBA {n_ueba_real} risco real / {n_ueba_suspect} suspeito"
                    if (n_ueba_real or n_ueba_suspect) else "")},
    ]
    return {"index": index, "grade": grade, "posture": posture, "pillars": pillars,
            "secure_pct": ss_pct, "exposure": exposure,
            "incidents": len(incidents), "risky": n_risky, "sev_counts": sev_counts,
            "ueba_real": n_ueba_real, "ueba_suspect": n_ueba_suspect}


# --- Informational sections (do NOT affect the Org Posture Index) ----------------------------
def analyze_licenses(data, cfg):
    """subscribedSkus → per-SKU total/assigned/idle/util + tenant totals. None when no data."""
    skus = _val(data.get("subscribed_skus"))
    if not skus:
        return None
    warn_pct = _num((cfg or {}).get("idle_warn_pct", 15))
    warn_min = _num((cfg or {}).get("idle_warn_min", 5))
    rows, tot_enabled, tot_consumed = [], 0, 0
    for sku in skus:
        enabled = int(_num((sku.get("prepaidUnits") or {}).get("enabled")))
        consumed = int(_num(sku.get("consumedUnits")))
        if enabled <= 0:
            continue
        idle = max(0, enabled - consumed)
        util = round(consumed / enabled * 100, 1) if enabled else 0.0
        flagged = idle >= warn_min and (idle / enabled * 100) >= warn_pct
        rows.append({"sku": sku.get("skuPartNumber", "?"), "enabled": enabled,
                     "consumed": consumed, "idle": idle, "util": util, "flagged": flagged})
        tot_enabled += enabled
        tot_consumed += consumed
    if not rows:
        return None
    rows.sort(key=lambda r: r["idle"], reverse=True)
    tot_idle = tot_enabled - tot_consumed
    return {"rows": rows, "tot_enabled": tot_enabled, "tot_consumed": tot_consumed,
            "tot_idle": tot_idle,
            "overall_util": round(tot_consumed / tot_enabled * 100, 1) if tot_enabled else 0.0,
            "flagged_n": sum(1 for r in rows if r["flagged"])}


def analyze_human_risk(data, cfg):
    """Attack Simulation Training → simulated users, click rate, training %, repeat offenders."""
    cov = _val(data.get("attack_sim_user_coverage"))
    train = _val(data.get("attack_sim_training_coverage"))
    repeat = _val(data.get("attack_sim_repeat_offenders"))
    sims = _val(data.get("attack_sim_simulations"))
    if not (cov or train or repeat or sims):
        return None
    simulated_users = len(cov)
    compromised_users = sum(1 for u in cov if _num(u.get("compromisedCount")) > 0)
    total_sims = sum(_num(u.get("simulationCount")) for u in cov)
    total_compromised = sum(_num(u.get("compromisedCount")) for u in cov)
    if total_sims:
        click_rate = round(total_compromised / total_sims * 100, 1)
    elif simulated_users:
        click_rate = round(compromised_users / simulated_users * 100, 1)
    else:
        click_rate = 0.0
    train_total, train_done = len(train), 0
    for u in train:
        items = (u.get("attackSimulationTrainingUserTrainings")
                 or u.get("trainings") or [])
        if items and all(str(t.get("trainingStatus", "")).lower() == "completed"
                         or t.get("completionDateTime") for t in items):
            train_done += 1
    train_pct = round(train_done / train_total * 100, 1) if train_total else None

    def _sdt(x):
        return x.get("completionDateTime") or x.get("launchDateTime") or ""
    sims_sorted = sorted([s for s in sims if isinstance(s, dict)], key=_sdt, reverse=True)
    last = sims_sorted[0] if sims_sorted else None
    warn, high = _num((cfg or {}).get("click_rate_warn", 10)), _num((cfg or {}).get("click_rate_high", 20))
    if click_rate >= high:
        verdict = ("\U0001F534", "#d13438")
    elif click_rate >= warn:
        verdict = ("\U0001F7E0", "#ffb900")
    else:
        verdict = ("\u2705", "#107c10")
    return {"simulated_users": simulated_users, "compromised_users": compromised_users,
            "click_rate": click_rate, "train_pct": train_pct, "repeat_n": len(repeat),
            "last_name": (last or {}).get("displayName") if last else None,
            "last_date": (_sdt(last)[:10] if last else None), "verdict": verdict,
            "total_sims": int(total_sims)}


def analyze_nhi_governance(data, cfg):
    """App registrations + service principals → NHI/agent identity credential-hygiene posture.
    Rubric from the agent-identity-governance guidance: federation/cert over client secrets."""
    apps = _val(data.get("applications"))
    sps = _val(data.get("service_principals"))
    if not (apps or sps):
        return None
    cfg = cfg or {}
    exp_days = int(_num(cfg.get("secret_expiring_days", 90)))
    long_days = int(_num(cfg.get("secret_long_lived_days", 180)))
    now = dt.datetime.now(dt.timezone.utc)
    apps_total = len(apps)
    apps_with_secret = secrets_expired = secrets_expiring = secrets_long = 0
    for a in apps:
        pwds = a.get("passwordCredentials") or []
        if pwds:
            apps_with_secret += 1
        for c in pwds:
            end = _parse_dt(c.get("endDateTime"))
            start = _parse_dt(c.get("startDateTime"))
            if end:
                if end < now:
                    secrets_expired += 1
                elif (end - now).days <= exp_days:
                    secrets_expiring += 1
            if start and end and (end - start).days > long_days:
                secrets_long += 1
    secret_pct = round(apps_with_secret / apps_total * 100, 1) if apps_total else 0.0
    warn = _num(cfg.get("secret_pct_warn", 30))
    high = _num(cfg.get("secret_pct_high", 60))
    if secrets_expired > 0 or secret_pct >= high:
        verdict = ("\U0001F534", "#d13438")
    elif secret_pct >= warn or secrets_expiring > 0:
        verdict = ("\U0001F7E0", "#ffb900")
    else:
        verdict = ("\u2705", "#107c10")
    return {"apps_total": apps_total, "sps_total": len(sps),
            "apps_with_secret": apps_with_secret, "secret_pct": secret_pct,
            "secrets_expired": secrets_expired, "secrets_expiring": secrets_expiring,
            "secrets_long": secrets_long, "verdict": verdict}


POSTURE_COLOR = {"FORTE": "#107c10", "MODERADA": "#ffb900", "FRACA": "#d13438"}

# Microsoft Security logo (MS-Security_logo_horiz_c-white_rgb.png — white, horizontal) embedded
# as base64 so the report stays self-contained (same pattern as the rest of the suite).
# Filled at build time; if empty / non-data, the logo is omitted (graceful).
_LOGO_DATA_URI = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAC6EAAAODCAYAAAD3/OZSAAAACXBIWXMAAC4jAAAuIwF4pT92AAAgAElEQVR4nOzawUkDURRA0adkK6SEgAVoB64swA4sISWkIwtwYwmxAHsQLCCCZCFk4TWuEs+Bz8Aws3nvL+/FbrcbAAAAAAAAAAAAAAAoLk0JAAAAAAAAAAAAAIBKhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAAAAAAQCZCBwAAAAAAAAAAAAAgE6EDAAAAAAAAAAAAAJCJ0AEAAAAAAAAAAAAAyEToAAAAAAAAAAAAAABkInQAAAAAAAAAAAAAADIROgAAAAAAAAAAAAAAmQgdAAAAAAAAAAAAAIBMhA4AAAAAAAAA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AAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAAkInQAQAAAAAAAAAAAADIROgAAAAAAAAAAAAAAGQidAAAAAAAAAAAAAAAMhE6AAAAAAAAAAAAAACZCB0AAAAAAAAAAAAAgEyEDgAAAAAAAAAAAABAJkIHAAAAAAAAAAAAACAToQMAAAAAAAAAAAAA0MzM3573oXWCnAm2AAAAAElFTkSuQmCC"


def bar(score, color):
    return (f'<div style="background:#1f2c47;border-radius:6px;height:10px;overflow:hidden">'
            f'<div style="width:{_clamp(score)}%;height:100%;background:{color}"></div></div>')


def render_nhi_governance(g):
    """🤖 NHI / agent identity governance section (informational; '' when no data)."""
    if not g:
        return ""
    emoji, col = g["verdict"]
    return (f"<h2>🤖 Governança de Identidades de Agente / NHI</h2>"
            f"<p style='color:#93a1bd;font-size:12px;margin:0 0 10px'>Informativo — não afeta o índice. "
            f"Higiene de credenciais da população não-humana (segredo vs federação/certificado). "
            f"Aprofundamento (permissão concedida × usada): skill <b>graph-least-privilege</b>.</p>"
            f"<div class='cards'>"
            f"<div class='card'><div class='n'>{g['apps_total']}</div><div class='l'>App registrations</div></div>"
            f"<div class='card'><div class='n'>{g['sps_total']}</div><div class='l'>Service principals</div></div>"
            f"<div class='card'><div class='n' style='color:{col}'>{emoji} {g['secret_pct']}%</div><div class='l'>Apps com client secret</div></div>"
            f"<div class='card'><div class='n' style='color:#d13438'>{g['secrets_expired']}</div><div class='l'>Segredos expirados</div></div>"
            f"<div class='card'><div class='n' style='color:#ffb900'>{g['secrets_expiring']}</div><div class='l'>Vencendo ≤ 90d</div></div>"
            f"<div class='card'><div class='n' style='color:#ffb900'>{g['secrets_long']}</div><div class='l'>Validade > 180d</div></div>"
            f"</div>")


def render_human_risk(hr):
    """🎓 Attack Simulation Training section (informational; '' when no data)."""
    if not hr:
        return ""
    emoji, col = hr["verdict"]
    tp = f"{hr['train_pct']}%" if hr["train_pct"] is not None else "n/d"
    last = (f"{html.escape(str(hr['last_name']))} ({hr['last_date']})"
            if hr["last_name"] else "n/d")
    return (f"<h2>🎓 Risco Humano — Attack Simulation Training</h2>"
            f"<p style='color:#93a1bd;font-size:12px;margin:0 0 10px'>Informativo — não afeta o índice. "
            f"Última simulação: {last}.</p>"
            f"<div class='cards'>"
            f"<div class='card'><div class='n'>{hr['simulated_users']}</div><div class='l'>Usuários simulados</div></div>"
            f"<div class='card'><div class='n' style='color:{col}'>{emoji} {hr['click_rate']}%</div><div class='l'>Taxa de comprometimento</div></div>"
            f"<div class='card'><div class='n' style='color:#9ec5ff'>{tp}</div><div class='l'>Treinamento concluído</div></div>"
            f"<div class='card'><div class='n' style='color:#d13438'>{hr['repeat_n']}</div><div class='l'>Reincidentes</div></div>"
            f"</div>")


def render_licenses(lic):
    """🪪 Licensing / FinOps section (informational; '' when no data)."""
    if not lic:
        return ""
    rows = ""
    for r in lic["rows"][:15]:
        col = "#ffb900" if r["flagged"] else "#93a1bd"
        flag = " ⚠️" if r["flagged"] else ""
        rows += (f"<tr><td>{html.escape(str(r['sku']))}{flag}</td>"
                 f"<td style='text-align:right'>{r['enabled']}</td>"
                 f"<td style='text-align:right'>{r['consumed']}</td>"
                 f"<td style='text-align:right;color:{col};font-weight:700'>{r['idle']}</td>"
                 f"<td style='text-align:right'>{r['util']}%</td></tr>")
    return (f"<h2>🪪 Licenciamento &amp; Governança (FinOps)</h2>"
            f"<p style='color:#93a1bd;font-size:12px;margin:0 0 10px'>Informativo — não afeta o índice. "
            f"{lic['flagged_n']} SKU(s) subutilizada(s) · {lic['tot_idle']} licenças ociosas de "
            f"{lic['tot_enabled']} ({lic['overall_util']}% de utilização global).</p>"
            f"<table><tr><th>SKU</th><th style='text-align:right'>Total</th>"
            f"<th style='text-align:right'>Atribuídas</th><th style='text-align:right'>Ociosas</th>"
            f"<th style='text-align:right'>Utilização</th></tr>{rows}</table>")


def render_html(s):
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    pc = POSTURE_COLOR.get(s["posture"], "#ffb900")
    logo = (f'<img class="mslogo" src="{_LOGO_DATA_URI}" alt="Microsoft Security">'
            if _LOGO_DATA_URI.startswith("data:") else "")

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
.mslogo{{height:56px;display:block;margin:0 0 14px}}
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
<div class="hd"><div>{logo}<h1>🛡️ Org Security Posture</h1>
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
{render_human_risk(s.get("human_risk"))}
{render_nhi_governance(s.get("nhi_governance"))}
{render_licenses(s.get("licenses"))}
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
    sec = q.get("sections", {})
    s["licenses"] = analyze_licenses(data, sec.get("licensing", {}))
    s["human_risk"] = analyze_human_risk(data, sec.get("human_risk", {}))
    s["nhi_governance"] = analyze_nhi_governance(data, sec.get("nhi_governance", {}))
    htmlout = render_html(s)

    out = args.output or str(HERE / "reports" / f"orgposture_{dt.datetime.utcnow():%Y%m%d_%H%M%S}.html")
    pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(htmlout)
    print(f"✅ {SKILL}: POSTURA {s['posture']} · nota {s['grade']} · índice {s['index']}/100 · "
          f"SS {s['secure_pct']}% · exp {s['exposure']} · inc {s['incidents']} · risky {s['risky']}")
    extra = []
    if s.get("human_risk"):
        extra.append(f"🎓 click {s['human_risk']['click_rate']}% · reincid {s['human_risk']['repeat_n']}")
    if s.get("licenses"):
        extra.append(f"🪪 ociosas {s['licenses']['tot_idle']} · util {s['licenses']['overall_util']}%")
    if s.get("nhi_governance"):
        extra.append(f"🤖 secret {s['nhi_governance']['secret_pct']}% · expirados {s['nhi_governance']['secrets_expired']}")
    if extra:
        print("   " + " · ".join(extra) + "  (seções informativas — não afetam o índice)")
    print(f"📄 {out}")


if __name__ == "__main__":
    main()

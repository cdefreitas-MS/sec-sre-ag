---
name: identity-anomaly-score
description: 'Lake-first UEBA identity-risk engine for the SOC — aggregates SigninLogs per identity, computes robust statistical baselines (robust-Z / median+MAD) and a Composite Risk Score 0-100 (5 severity bands), ranks a risk queue, and derives a PERSONAL baseline (each identity vs its OWN history = the insider/compromise signal). Adds a REAL-RISK corroboration layer that adjudicates whether an anomaly is a GENUINE risk — cross-checking each identity''s sign-in IPs against Threat Intelligence IOCs (IP↔IOC), risky-yet-successful sign-ins, and active SecurityAlerts — so the queue separates "probable real risk" from noise. 100% Python stdlib (runs headless in the SRE Agent); Isolation Forest is an OPTIONAL enhancement (scikit-learn, --use-iso, graceful fallback to robust-Z). Emits a cross-domain feed `identity_anomaly` (with the real-risk verdict + corroborators) that attack-path (exposure fusion) and org-posture (Identity pillar) consume — turning an active-behavior anomaly into a real, not theoretical, attack-path weight. Ported (non-verbatim) from David Alonso''s Identity-Anomaly-Detection notebook (MIT). Use for: ueba, identity anomaly, user behavior analytics, identity risk score, anomalous sign-ins, insider threat, compromised account detection, personal baseline deviation, robust-z identity scoring, unified identity risk score, risky user queue, real risk adjudication, ip ioc correlation, threat intelligence indicator match, is this a real risk.'
tools: [RunAzCliReadCommands, QueryLogAnalyticsByWorkspaceId]
---

# identity-anomaly-score — UEBA de identidade (lake-first)

Turns raw `SigninLogs` into a **ranked, analyst-ready identity risk queue** with an explainable
**Composite Risk Score 0–100**, plus a **personal baseline** (identity vs. its own normal). Every
flag is attributable (no black box). Complements native Sentinel UEBA and the rule-based drift
skills (aitm-dashboard, user/spn-scope-drift) with a **statistical/ML anomaly layer**.

## Why it matters
Our other identity skills are threshold/rule based. This adds **multi-dimensional rarity** (robust-Z
across features; Isolation Forest optional) + **user-vs-self deviation** — the core insider /
account-compromise signal — and a **unified identity risk score** that feeds the rest of the suite.

## Posture / Verdict
`Composite Risk Score = 30·rarity + 20·(countries>2) + 15·(SignIns_z>3) + 15·(Failed≥20) + 10·(Night>0) + 10·(IPs>3)`, clamped 0–100.
- **CRÍTICO** (any Critical, score >80) · **ELEVADO** (any High, 60–80) · **ATENÇÃO** (Medium, 40–60) · **ESTÁVEL**.
- Severity bands: Normal ≤20 · Low ≤40 · Medium ≤60 · High ≤80 · Critical ≤100.
- `rarity` = min-max-normalized sum of positive robust-Z (stdlib) **or** Isolation Forest anomaly (`--use-iso`, scikit-learn).
- **Personal baseline (§7b)**: robust-Z of the last `detect_days` vs the identity's own baseline; flags `|z| ≥ 3`.

## Real-risk corroboration (score ≠ real risk)
A high score says *anomalous*, not *dangerous*. A corroboration layer adjudicates each identity and
emits a **veredito** (`rr_klass`): **RISCO REAL PROVÁVEL** · **SUSPEITO — investigar** · **PROVÁVEL RUÍDO**.
- **Strong corroborators** (any one alone → real risk):
  - `ioc_ip` — a sign-in IP matches an **Active ThreatIntelligenceIndicator** (IP↔IOC: ThreatType/Confidence).
  - `risky_success` — a `SigninLogs` event with `RiskLevelDuringSignIn` high/med **AND** `ResultType == 0` (risky sign-in that *succeeded*).
  - `active_alert` — a non-Dismissed `SecurityAlert` on the UPN.
- **Weak corroborators** (need ≥ 2, or 1 + a strong): `impossible_travel`, `anonymized_ip`, `idp_risky` (riskyUsers), `personal_deviation` (only computed for Score ≥ 40 — perf guard).
- **Verdict:** ≥ 1 strong **OR** ≥ 2 total → `real`; exactly 1 → `suspect`; else `noise`. The report leads with a **🔴 Risco real (corroborado)** section (evidence chips) and a **🎯 IP↔IOC** KPI.

## Files
| File | Purpose |
|---|---|
| [generate_html_report.py](generate_html_report.py) | collector (KQL / from-json / demo) + robust-Z/MAD engine + composite score + personal baseline + **real-risk corroboration (IP↔IOC / risky-success / active-alert)** + HTML/MD renderer + `identity_anomaly` feed |
| [queries.yaml](queries.yaml) | KQL (identity_features + identity_daily + identity_signals + ip_ioc + active_alerts), scoring weights/thresholds/bands, corroboration verdict cfg, feed cfg |

## Modes
- **Mode A — self-collect**: `python generate_html_report.py --workspace <LA_GUID> --format both --emit-feed`
  (KQL lake-first via `az monitor log-analytics query`; 1 compact row per identity).
- **Mode B — prefetch** (recommended in the SRE Agent): agent runs the KQL, writes
  `{ "identity_features": [...], "identity_daily": [...], "identity_signals": [...], "ip_ioc": [...], "active_alerts": [...], "risky_users": [...] }`, then
  `python generate_html_report.py --from-json inventory.json --format both --emit-feed`.
- **Demo**: `--demo` (synthetic, 3 planted outliers) for smoke.
- **Isolation Forest**: add `--use-iso` (needs scikit-learn; falls back to robust-Z if absent).

## Data shape (Mode B `inventory.json`)
| Key | Source | Required |
|---|---|---|
| `identity_features` | KQL `identity_features` (per-identity aggregate) | ✅ drives the score |
| `identity_daily` | KQL `identity_daily` (per-identity per-day) | optional — drives the personal baseline |
| `identity_signals` | KQL `identity_signals` (RiskySuccess / ImpossibleTravel / Anonymized per UPN) | optional — corroboration |
| `ip_ioc` | KQL `ip_ioc` (SigninLogs IPs ⨚ `ThreatIntelligenceIndicator` where Active) | optional — **strong** corroboration (IP↔IOC) |
| `active_alerts` | KQL `active_alerts` (`SecurityAlert` non-Dismissed by UPN) | optional — **strong** corroboration |
| `risky_users` | Graph `/identityProtection/riskyUsers` | optional — weak corroboration (🔺 marker) |

## Cross-domain feed
`--emit-feed` writes `_identity_anomaly_feed.json` → `{ "identity_anomaly": [{upn, score, severity, drivers, real_risk, rr_klass, corroborators, idp_risky}] }`
for identities scoring ≥ `feed.min_score` (default 60) **or** corroborated (`rr_klass` real/suspect). Consumers:
- **attack-path** — exposure fusion: a **corroborated-real** identity (`rr_klass: real`) marks every path through it as **🔴 ativo agora** (elevates a path from theoretical to real, with a `🔴 UEBA:` evidence chip).
- **org-posture** — Identity-risk pillar penalizes `real` (×18) and `suspect` (×6) on top of the raw riskyUsers count — a confirmed anomaly weighs more than a static IdP flag.
- **forensic-user-investigation** — pull the personal-baseline deviation + corroborators for a target UPN.

## Delivery (archive → link → notify)
Follows the canonical sequence (`shared/sharepoint-archival.md`): archive to SharePoint first
(capture `webUrl`/`folderUrl`), then email (attach <3MB + folder link), then Teams (webhook only,
"Abrir no SharePoint"). Never email-only; never Teams via Graph.

## Permissions
Log Analytics Reader on the Sentinel workspace — reads `SigninLogs` (score/baseline),
`ThreatIntelligenceIndicator` + `SecurityAlert` (real-risk corroboration). Optional
`IdentityRiskyUser.Read.All` (Graph) for the riskyUsers corroboration — every corroboration
source degrades gracefully if absent (the score still renders; the verdict just uses fewer signals).

## Attribution
Methodology ported (non-verbatim, Python stdlib) from **David Alonso — Dalonso-Security-Repo /
Notebook/Identity-Anomaly-Detection** (MIT). Isolation Forest / SHAP / peer-group / UMAP are
notebook-analyst tooling; this skill ships the batch-scoring core + personal baseline + feed.

---
name: soc-executive-brief
description: 'ONE executive SOC email consolidating three signals into a single verdict: (1) Threat Pulse — recent incidents, open High-severity, MTTR; (2) Identity Posture — sign-ins, risky users, MFA coverage, privileged accounts; (3) MITRE Coverage — % of tactics covered by enabled rules + untagged rules. Computes a weighted SOC Score (0-100, FORTE/MODERADA/FRACA) and the single next action to take. Collector↔renderer, deterministic, 100% READ-ONLY (GET/query only). Replaces three separate emails with one executive brief. Use for: brief executivo, soc daily brief, consolidado SOC, threat pulse + identity + mitre, email executivo de segurança, postura SOC diária.'
---

# SOC Executive Brief — Instructions

## Purpose

Collapse three daily SOC analyses into **one executive email** with a single headline verdict and a clear *next action*. Instead of sending Threat Pulse, Identity Posture and MITRE Coverage as three reports, this skill collects only the **headline signal** of each, scores them, and renders a 3-panel brief a leader can read in 30 seconds.

| Panel | Signal | Headline metrics |
|-------|--------|------------------|
| 🔥 **Threat Pulse** | `SecurityIncident` | incidents (window), open, **High open**, MTTR |
| 🔐 **Identity Posture** | `SigninLogs` (+ `IdentityInfo`) | active users, **risky users**, MFA coverage %, privileged accounts |
| 🎯 **MITRE Coverage** | Sentinel `alertRules` (+ `SecurityAlert`) | **tactics covered / 14**, coverage %, enabled rules, untagged rules |

**SOC Score** = Σ weight·panel_score (Threat 0.40 · Identity 0.30 · MITRE 0.30). A panel with no assessable data is **n/a** (excluded from the mean — never counted as 100).

**Entity Type:** Sentinel workspace (`subscription`, `resourceGroup`, `workspaceName`, `workspaceGuid`).

---

## Skill Files

| File | Purpose | When used |
|------|---------|-----------|
| [generate_html_report.py](generate_html_report.py) | collector + 3-panel scoring + HTML/MD renderer | execution |
| [queries.yaml](queries.yaml) | collector endpoints/KQL + scoring weights/thresholds | read at runtime by the script |

> ⚠️ **READ-ONLY.** Every call is a GET / KQL query. No PUT/PATCH/DELETE, no containment, no rule changes.

---

## File Resolution (codeRefs-first — On Skill Activation)

`generate_html_report.py` loads `queries.yaml` from its own directory (`Path(__file__).resolve().parent`). Both files must be co-located.

```
1. codeRefs/sec-sre-ag/soc-executive-brief/   → if both files exist, use as <SKILL_DIR>, run from here.
2. tmp/soc-executive-brief/                    → if both exist (previous materialization), use it.
3. Neither → read_skill_file() each missing file → CreateFile("tmp/soc-executive-brief/<file>") → use tmp/.
```

> Dependency: **PyYAML** (`pip install pyyaml` if missing). No other third-party packages.

---

## Execution Environment Constraints

| Capability | Available | Notes |
|------------|-----------|-------|
| Azure Monitor MCP (KQL) | ✅ | `monitor-client` workspace query |
| `az rest` (Sentinel REST) | ✅ | alertRules |
| Microsoft Graph MCP | ❌ | not needed here |
| Sentinel Data Lake | ❌ | not used |

---

## Architecture (two modes)

```
 MODE A — Direct (terminal az works)
   generate_html_report.py --workspace <guid> --sub --rg --ws --save-raw
     → script runs az rest / az monitor itself → inventory → score → HTML + MD
     → GUARD: if all sources come back empty (auth/collect failure) it exits and points to Mode B.

 MODE B — Prefetch (terminal az blocked by MI token cache) [RECOMMENDED]
   LLM collects each collector query via native tools (RunAzCliReadCommands + monitor MCP)
     → assembles inventory.json → generate_html_report.py --from-json inventory.json
     → score + render (no Azure calls) → HTML + MD

 Both emit: tmp/soc-executive-brief/soc-brief-<ts>.{html,md}. Rendering is DETERMINISTIC.
```

---

## Workflow

### Step 1 — Resolve coordinates
`subscription`, `resourceGroup`, `workspaceName`, `workspaceGuid` from the connected workspace.
(For `LA-HERBEST-SENTINEL`: sub `4dd2fd28-6aaf-4431-883a-de5572c458c5`, rg `RG-SEC-HERBEST`, ws `LA-HERBEST-SENTINEL`, guid `2a24da1d-2114-4d5a-b5a1-ce0ecf06fe8a`.)

### Step 2 — Collect (choose a mode)
**Mode A (try first):**
```bash
python3 <SKILL_DIR>/generate_html_report.py --workspace <guid> --sub <sub> --rg <rg> --ws <ws> \
  --save-raw --output tmp/soc-executive-brief --format both
```
If terminal `az` fails (token cache / auth), fall back to **Mode B**.

**Mode B (prefetch — recommended):** run each `collector` query from `queries.yaml` via native tools and assemble `tmp/soc-executive-brief/inventory.json` (omit any key you cannot collect — its panel becomes *n/a*, never falsely scored):

| JSON key | Source (queries.yaml) | Shape |
|----------|-----------------------|-------|
| `threat_pulse` | KQL `threat_pulse` | `[{Total,HighSev,Open,HighSevOpen,Closed,AvgMTTRmin}]` |
| `threat_top` | KQL `threat_top` | `[{IncidentNumber,Title,Severity,Status,CreatedTime}…]` |
| `identity_signins` | KQL `identity_signins` | `[{Users,RiskyUsers,MfaSatisfied,Total}]` |
| `identity_privileged` | KQL `identity_privileged` | `[{Privileged,Known}]` (optional → privileged shows `—`) |
| `mitre_firing` | KQL `mitre_firing` | `[{Tactic,Alerts}…]` |
| `alert_rules` | REST `alert_rules` (`/alertRules` — **deployed only**) | `{value:[…]}` — keep `properties.enabled`. Do **NOT** put `/alertRuleTemplates` here (the renderer strips them and logs a warning). |

```bash
python3 <SKILL_DIR>/generate_html_report.py --from-json tmp/soc-executive-brief/inventory.json \
  --output tmp/soc-executive-brief --format both
```

### Step 3 — Read the result
The script prints `SOC Score N/100 (verdict) · Threat x · Identity y · MITRE z` and the **next action**, then writes HTML + MD.

### Step 4 — Deliver (archive → link → notify, read-only)
Follow the [canonical delivery sequence](../../shared/sharepoint-archival.md#canonical-delivery-sequence-archive--link--notify):
- **SharePoint (first)**: `python shared/sharepoint_upload.py upload --site "<config: sharepoint.site_id>" --skill soc-executive-brief --file <html>` (and the `.md`). Capture the `webUrl` from stdout; skip/error → `webUrl=null`, continue.
- **send-email-report**: subject `🛡️ SOC Executive Brief: {verdict} · {score}/100 ({date})`. Small report (< 3 MB) → **attach the HTML and** add the link line `🗄️ Arquivo (SharePoint): <webUrl>` when present.
- **send-teams-notification**: Adaptive Card with SOC Score, verdict, the 3 panel sub-scores, and the next action + **Open report (SharePoint)** action → `webUrl` when present.

### Step 5 — Chat summary
```
🛡️ SOC EXECUTIVE BRIEF — {score}/100 · {🟢 FORTE | 🟡 MODERADA | 🔴 FRACA}
   🔥 Threat {t} · 🔐 Identity {i} · 🎯 MITRE {m}
   ▶ Próxima ação: {next_action}
   📧 Email + 💬 Teams + 🗄️ SharePoint
```

---

## Scoring & Verdict

- **Panel sub-scores (0-100):**
  - **Threat** = `100 − penalty(open incidents, High-open weighted) − MTTR penalty` (MTTR > `mttr_threshold_min`).
  - **Identity** = `100 − penalty(risky users) − MFA gap penalty` (below `mfa_floor_pct`). n/a if no sign-ins.
  - **MITRE** = `tactic_coverage% − untagged penalty`. n/a if rules not collected.
- **SOC Score** = weighted mean of available panels → **🟢 FORTE ≥ 75 · 🟡 MODERADA ≥ 50 · 🔴 FRACA < 50**.
- **Next action** = the single most urgent lever (High-open incidents → risky users → MTTR → MITRE gaps → untagged rules).
- All weights/thresholds live in `queries.yaml` under `scoring:` — never a black box.

## Rules

- ✅ **READ-ONLY** — GET/query only; never mutates the workspace.
- ✅ **empty ≠ ok** — a panel with no data shows **n/a**, never a fabricated score.
- ✅ `alert_rules` = deployed `/alertRules` only; `/alertRuleTemplates` goes elsewhere (renderer self-defends + warns).
- ✅ Weights/thresholds are data-driven in `queries.yaml`.
- ⛔ **NEVER** write a post-processing script to "add" panels — all three are already rendered by `generate_html_report.py`.

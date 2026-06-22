---
name: incident-triage
description: 'One-shot, autonomous, deterministic triage report for a SINGLE security incident (Microsoft Sentinel / Defender XDR). Collects the incident header + related alerts, extracts affected entities (users/hosts/IPs), tags MITRE techniques (native alert Tactics + free-text inference via shared/mitre_map.py), builds a recommended RESPONSE PLAN where every action is risk-gated via shared/action_safety.py (risk/approval/rollback/guardrails), and closes with a verdict (TRUE POSITIVE PROVÁVEL / REQUER ANÁLISE / PROVÁVEL BENIGNO) + the single next action. Collector↔renderer, HTML (dark, email) + Markdown. 100% READ-ONLY — it RECOMMENDS, never executes. Complements (does NOT replace) the interactive incident-investigation. Use for: triagem de incidente, triage incident, brief de incidente, incident triage report, plano de resposta do incidente, veredito do incidente, autonomous incident triage.'
threat_pulse_domains: [incidents]
drill_down_prompt: 'Triage incident {entity} — header, alerts, entities, MITRE tagging, gated response plan, verdict + next action'
---

# Incident Triage — One-Shot Autonomous Brief

## Purpose

Produce a **deterministic, one-shot triage report for a single incident** designed for the autonomous *analyse → act → notify → audit* loop (no analyst in the middle). It is the unattended counterpart to the interactive, multi-phase `incident-investigation`:

| Section | Source | What it shows |
|---------|--------|---------------|
| 🚨 **Header** | `SecurityIncident` | number, title, severity, status, owner, created, alert count, portal link |
| 📋 **Alerts** | `SecurityAlert` (via `AlertIds`) | related alerts: name, severity, product, native Tactics, time |
| 👤 **Entities** | alert `Entities` | affected users / hosts / IPs (parsed defensively) |
| 🎯 **MITRE** | alert `Tactics` + `shared/mitre_map.py` | native tactics + techniques **inferred** from incident/alert text |
| 🛡️ **Response plan** | `shared/action_safety.py` | recommended actions per entity type, **each risk-gated** (risk · approval · rollback · guardrails) |
| ✅ **Verdict** | heuristic | TRUE POSITIVE PROVÁVEL / REQUER ANÁLISE / PROVÁVEL BENIGNO + **next action** |

**Verdict heuristic (deterministic):** classified TruePositive → TP; classified FalsePositive/Benign → benign; else High + ≥1 high alert + open → TP; Low + 0 high alerts → benign; otherwise needs-review.

**Entity Type:** a single incident (by number, or the most recent High open incident if none given).

---

## Skill Files

| File | Purpose | When used |
|------|---------|-----------|
| [generate_html_report.py](generate_html_report.py) | collector + entity/MITRE/plan/verdict + HTML/MD renderer | execution |
| [queries.yaml](queries.yaml) | KQL (pick/header/alerts) + response playbook + verdict labels | read at runtime by the script |

> ⚠️ **READ-ONLY.** Every call is a GET / KQL query. The response plan is a **recommendation** — no action is ever executed by this skill.

### Shared utilities (subprocess, optional — graceful degrade)

The renderer invokes two repo-shared utilities **as subprocesses** (it never imports them):

- `shared/mitre_map.py map "<text>"` — infers ATT&CK techniques from the incident/alert text.
- `shared/action_safety.py evaluate <action>` — risk-gates each recommended response action.

It locates `shared/` by walking up from its own directory. If a utility is absent, the matching section **degrades gracefully** (MITRE shows native tactics only; the plan lists actions without the risk gate) and a banner notes which utility was missing.

---

## File Resolution (codeRefs-first — On Skill Activation)

`generate_html_report.py` loads `queries.yaml` from its own directory (`Path(__file__).resolve().parent`). Both files must be co-located.

```
1. codeRefs/sec-sre-ag/incident-triage/   → if both files exist, use as <SKILL_DIR>, run from here.
2. tmp/incident-triage/                    → if both exist (previous materialization), use it.
3. Neither → read_skill_file() each missing file → CreateFile("tmp/incident-triage/<file>") → use tmp/.
```

> Dependency: **PyYAML** (`pip install pyyaml` if missing). No other third-party packages. The `shared/` utilities are resolved at runtime by walking up the tree (optional).

---

## Execution Environment Constraints

| Capability | Available | Notes |
|------------|-----------|-------|
| Azure Monitor MCP (KQL) | ✅ | `monitor-client` workspace query — pass `--subscription` always |
| `az monitor log-analytics query` | ✅ | Mode A self-collect |
| Microsoft Graph MCP | ❌ | not needed (incident + alerts come from Sentinel KQL) |
| Sentinel Data Lake | ❌ | not used |

---

## Architecture (two modes)

```
 MODE A — Direct (terminal az works)
   generate_html_report.py --workspace <guid> --sub --rg [--incident-number N] --save-raw
     → picks the incident (most recent High open if no number) → header + alerts
     → entities + MITRE + gated plan + verdict → HTML + MD
     → GUARD: if no incident header is returned (auth/collect failure) it exits, points to Mode B.

 MODE B — Prefetch (terminal az blocked by MI token cache) [RECOMMENDED]
   LLM collects pick_incident → incident_header → incident_alerts via native tools
     → assembles inventory.json → generate_html_report.py --from-json inventory.json
     → entities + MITRE + plan + verdict (no Azure calls) → HTML + MD

 Both emit: tmp/incident-triage/incident-triage-<num>-<ts>.{html,md}. Rendering is DETERMINISTIC.
```

### Mode B — inventory.json shape

```json
{
  "incident_header": [ { "IncidentNumber": 492, "Title": "...", "Severity": "High",
                          "Status": "New", "Classification": "", "Owner": "",
                          "CreatedTime": "...", "ClosedTime": "None",
                          "AlertIds": "[\"<guid>\"]", "IncidentUrl": "...",
                          "Description": "...", "ProviderName": "Microsoft XDR" } ],
  "incident_alerts": [ { "AlertName": "...", "AlertSeverity": "High", "Status": "New",
                          "Tactics": "InitialAccess, Reconnaissance", "ProductName": "Azure Sentinel",
                          "TimeGenerated": "...",
                          "Entities": "[{\"Type\":\"ip\",\"Address\":\"8.231.238.26\"}]" } ]
}
```

`AlertIds` and `Entities` may arrive as JSON **strings** (as the KQL connector returns them) or native arrays — the renderer handles both.

---

## Output & Delivery

- HTML (dark, email-ready) + Markdown (repo). Subject prefix `[SOC Triage]`.
- Follow the [canonical delivery sequence](../../shared/sharepoint-archival.md#canonical-delivery-sequence-archive--link--notify): **archive to SharePoint first** (`python shared/sharepoint_upload.py upload --site "<config: sharepoint.site_id>" --skill incident-triage --file <html>` + `.md`; capture `webUrl`), then `send-email-report` (dual recipients) + `send-teams-notification`.
- **Sensitive → link-only:** incident triage carries incident-level entity/PII detail → **do not attach the HTML**; put the SharePoint link in the email body (`🗄️ Relatório (SharePoint): <webUrl>`) and an **Open report** CTA in the Teams card. (Data minimization: a link respects site ACLs; an attachment can be forwarded freely.)

## Rules

- ✅ **READ-ONLY** — never mutates the workspace; the response plan is advisory only.
- ✅ Always show the verdict + the gated plan together (risk is never hidden).
- ✅ Entities not extracted → say so (escalate), never invent.
- ⛔ **NEVER** execute any action from the response plan — that is the job of the gated response skills, after approval.

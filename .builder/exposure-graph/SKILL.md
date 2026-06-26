---
name: exposure-graph
description: 'Synthesized attack-surface / blast-radius report. Correlates Microsoft Defender for Endpoint exposure (org exposure score, most-exposed machines, exploitable exposed recommendations) with Microsoft Graph identity context (privileged identities = crown jewels, high-risk users = entry points) to compute heuristic attack paths (risky entry → privileged target) and an exposure verdict BAIXA/MODERADA/ALTA. Renders an executive HTML and delivers via email + Teams. Read-only. Trigger on "exposure graph", "attack paths", "blast radius", "attack surface", "exposure management", "where can an attacker go". Synthesizes from already-granted MDE + Graph permissions; if Microsoft Security Exposure Management native attack paths are licensed, can be swapped in.'
tools:
  - RunAzCliReadCommands
---

# Exposure Graph & Blast Radius Skill

## Purpose

Answer the board question **"if one account or device is popped, how far can the attacker go?"** without requiring a dedicated Exposure Management license. It **synthesizes** an attack-surface graph from data already in reach: Defender for Endpoint's org **exposure score**, the **most-exposed machines**, and **exploitable exposed** recommendations — correlated with **privileged identities** (crown jewels) and **high-risk users** (live entry points) from Microsoft Graph. The output is a heuristic blast-radius (entry points × privileged targets = potential paths) plus a clear exposure verdict.

## Configuration

Reads from `config.json` at workspace root:
- `subscription_id`, `email.*`, `teams.*`
Tunables (`queries.yaml` → `parameters`): `top_machines`, `top_recommendations`, `exposure_good=30`, `exposure_moderate=50`, `privileged_roles[]`.

## When to Use

- Explicit: "exposure graph", "attack paths", "blast radius", "attack surface", "exposure management".
- Scheduled: monthly attack-surface review for leadership.
- Auto: after `vulnerability-exposure` (ALTA) or `secure-score-leadership` (FRACA) → run this to translate weaknesses into *paths to crown jewels*.

## Exposure Verdict

- **ALTA** (red): `exposureScore > moderate (50)` **OR** (entry points > 0 **and** privileged targets > 0 **and** exploitable-exposed > 0).
- **MODERADA** (yellow): `exposureScore > good (30)` **OR** entry points > 0 **OR** exploitable-exposed > 0.
- **BAIXA** (green): none of the above.

**Blast radius** = `#entry_points × #privileged_targets` (potential attack paths). Entry points = high-risk users + exposed machines. Crown jewels = members of privileged directory roles.

## Workflow

### Step 1: Read config + acquire tokens
- MDE token (`https://api.securitycenter.microsoft.com`) and Graph token (`https://graph.microsoft.com`).

### Step 2: Collect — `RunAzCliReadCommands` (REST GET)
**MDE (TVM):**
- `GET /api/exposureScore` → org exposure score (0–100, lower is better).
- `GET /api/machines?$top=4000` → fields `computerDnsName`, `osPlatform`, `exposureLevel`, `riskScore`, `healthStatus`.
- `GET /api/recommendations?$top=4000` → `recommendationName`, `severityScore`, `exposedMachinesCount`, `publicExploit`, `remediationType`, `relatedComponent`.

**Graph (identity context):**
- `GET /v1.0/directoryRoles?$expand=members` → privileged roles + members (crown jewels).
- `GET /v1.0/identityProtection/riskyUsers?$filter=riskLevel eq 'high'` → live entry points.

### Step 3: Synthesize (in the agent)
- **Entry points** = high-risk users **+** machines with `exposureLevel`/`riskScore` in High/Medium (weight = `level_weight[exposureLevel] + level_weight[riskScore]`).
- **Crown jewels** = distinct members of `privileged_roles`.
- **Exploitable exposed** = recommendations with `exposedMachinesCount > 0` **and** (`publicExploit` **or** `severityScore ≥ 8`).
- **Blast radius** = `entry_points × privileged_targets`. Verdict per the rules above.

### Step 4: Render HTML
`reports/exposure/<YYYYMMDD_HHMMSS>.html` with: exposure badge + 5 cards (exposure score / entry points / crown jewels / exploitable exposed / blast radius), a synthesized **attack-paths** banner, then tables for risky users, exposed machines, crown jewels, and exploitable exposed recommendations.

### Step 5: Deliver (archive → link → notify)

> Follow the [canonical delivery sequence](../../shared/sharepoint-archival.md#canonical-delivery-sequence-archive--link--notify) — reuse the delivery skills (do **not** re-implement transport). Never email-only; if `sharepoint.site_id` / `teams.webhook_url` is missing in config, report it instead of skipping.

1. **SharePoint (first)**: `python shared/sharepoint_upload.py upload --site "<config: sharepoint.site_id>" --skill exposure-graph --file <html>` (and the `.md`). Capture `webUrl` + `folderUrl` from stdout; skip/error → continue (best-effort, never blocks email/Teams).
2. **send-email-report**: title "🕸️ Exposure Graph ({date})", verdict color. Small report (< 3 MB) → **attach the HTML** + body link `📂 Abrir no SharePoint: <folderUrl>` when present. 🔴 The link MUST be the SharePoint `folderUrl` — never a `teams.microsoft.com` / webhook link. 5 cards + path narrative.
3. **send-teams-notification**: Adaptive Card with exposure verdict, blast radius, top crown jewels at risk + **Abrir no SharePoint** action → `folderUrl` (webhook only; never Graph).

### Step 6: Audit + chat
Save `reports/exposure/<timestamp>.json`. Then:
```
🕸️ EXPOSURE GRAPH
   Exposição: {BAIXA|MODERADA|ALTA} · exposure score {n}
   🚪 Entry points: {n}  ·  👑 Crown jewels: {n}  ·  🎯 Exploráveis expostas: {n}
   🧭 Blast radius: {n} caminhos potenciais
   📧 Email + 💬 Teams enviados
```

## Enhancements (optional)

If **Microsoft Security Exposure Management** (XSPM) is licensed and `ExposureManagement.Read.All` is granted, replace the synthesized paths with native attack paths (Graph beta `/security/exposureManagement/*`). The renderer keeps the same card/verdict layout — only the `attack-paths` source changes. The synthesized model remains the safe default and works with the permissions already granted.

## Common Errors

| Error | Meaning | Fix |
|---|---|---|
| `exposureScore` empty / machines `[]` | No devices onboarded in MDE | Exposure score reads 0; entry points come from identity side only — note "sem devices MDE onboarded" |
| `directoryRoles` members empty | Roles not activated / PIM-eligible only | Use `roleManagement/directory/roleAssignments` to include eligible; note PIM |
| `riskyUsers` 403 | Missing `IdentityRiskyUser.Read.All` | Already granted in this tenant; if 403, re-check the grant |
| `directoryRoles` 403 | Missing `Directory.Read.All`/`RoleManagement.Read.Directory` | Request the read perm; crown jewels degrade to empty otherwise |
| Blast radius = 0 | No entry points OR no privileged targets found | Verdict will be BAIXA; still report exposure score |

## Rules

- ✅ **READ-ONLY** — this skill never writes. No containment handoff.
- ✅ **ALWAYS** deliver triple (email + Teams) and save the audit JSON.
- ✅ Default to the **synthesized** model (granted perms); native Exposure Management is an opt-in enhancement.
- ⛔ **NEVER** expose secrets/tokens in the report; only identity UPNs + machine names.
- ⛔ **NEVER** attempt git operations.

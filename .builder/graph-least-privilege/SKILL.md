---
name: graph-least-privilege
description: 'Right-sizes Microsoft Graph APPLICATION permissions per app registration by cross-referencing GRANTED app roles against ACTUALLY-USED endpoints in MicrosoftGraphActivityLogs (Log Analytics). Surfaces DORMANT apps (perms granted, zero Graph calls), EXCESS scopes (granted scope whose endpoint family was never observed — via a heuristic endpoint→scope map), and HTTP 429 throttling per app. META: highlights the SRE Agent''s own UAMI (self-audit). 100% READ-ONLY, recommend-only — never removes a permission (right-sizing is a human decision). Collector↔renderer, deterministic. Operational depth-layer of the org-posture 🤖 NHI section. Concept ported from Mynster9361/Least_Privileged_MSGraph (MIT), re-implemented in Python (UAMI auth, no client secret). Use for: least privilege, graph permissions, permissões em excesso, over-privileged apps, unused scopes, dormant app registrations, right-size permissions, app permission audit, NHI permission review, which apps have too many graph permissions.'
---

# Graph Least Privilege — Instructions

## Purpose

Answer **"which app registrations are over-permissioned on Microsoft Graph, and which scopes can we safely remove?"** — from evidence, not theory. The skill compares each app's **granted** Graph application permissions against the **endpoints it actually called** (from `MicrosoftGraphActivityLogs`), then classifies each app.

| Source | API | What it brings |
|--------|-----|----------------|
| **Microsoft Graph** `servicePrincipals(appId='00000003-…')?$expand=appRoleAssignedTo` | Graph (`Application.Read.All`) | The Graph `appRoles` dictionary (GUID→name) **and** every app's granted application permissions, in one call |
| **Microsoft Graph** `servicePrincipals?$select=id,appId,displayName,servicePrincipalType` | Graph (`Application.Read.All`) | Service principal catalog (names, types) |
| **MicrosoftGraphActivityLogs** (KQL) | Log Analytics (`Log Analytics Reader`) | Per-app endpoint families actually called, call counts, HTTP 429, last seen |

**Verdict per app** (recommend-only):
- 🔴 **DORMANT** — app holds ≥ 1 Graph app role but made **0 calls** in the window (strongest over-provisioning signal; candidate for removal/decommission).
- 🔴 **EXCESS** (≥ `excess_high` unused scopes) / 🟠 (≥ `excess_warn`) — granted scope whose endpoint family **never appeared** in the activity logs.
- ✅ **TIGHT** — every mapped granted scope has matching observed activity.

**Headline:** **AÇÃO** (any dormant) · **REVISAR** (any excess) · **ENXUTO** (all tight).

This is the **operational depth** of the **org-posture** 🤖 *NHI / Agent Identity Governance* section (that section summarizes credential hygiene; this skill does the per-app permission forensics). It directly serves the least-privilege guardrail (`Sites.Selected` over `Sites.Read.All`, etc.).

**Entity Type:** Tenant-wide (all app registrations + service principals).

---

## Skill Files

| File | Purpose | When used |
|------|---------|-----------|
| [generate_html_report.py](generate_html_report.py) | collector (KQL + Graph) + analysis engine + HTML renderer | execution |
| [queries.yaml](queries.yaml) | KQL queries + Graph endpoints + `scope_endpoint_map` (heuristic) + thresholds | read at runtime by the script |

> ⚠️ **100% READ-ONLY.** KQL queries + Graph GET only. Recommends scope removals, **never applies them**.

---

## File Resolution (codeRefs-first — On Skill Activation)

`generate_html_report.py` loads `queries.yaml` from its own directory (`Path(__file__).resolve().parent`). Both files must be co-located.

```
1. codeRefs/sec-sre-ag/graph-least-privilege/  → if both files exist, use as <SKILL_DIR>, run from here.
2. tmp/graph-least-privilege/                  → if both exist (previous materialization), use it.
3. Neither → read_skill_file() each missing file → CreateFile("tmp/graph-least-privilege/<file>") → use tmp/.
```

> Dependency: **PyYAML** (`pip install pyyaml` if missing). No other third-party packages.

---

## Prerequisites

- **`MicrosoftGraphActivityLogs`** flowing to the workspace (Entra → Diagnostic settings → `MicrosoftGraphActivityLogs` → Log Analytics). Requires **Entra ID P1/P2**. Without it, the "actual usage" half is empty and every app reads as DORMANT — annotate the gap.
- **`Application.Read.All`** Microsoft Graph application permission on the agent identity (UAMI already holds it).
- **Log Analytics Reader** on the workspace.

---

## Execution Environment Constraints

| Capability | Available | Notes |
|------------|-----------|-------|
| `QueryLogAnalyticsByWorkspaceId` (KQL) | ✅ | `app_activity` + `app_errors` against `MicrosoftGraphActivityLogs` |
| `RunAzCliReadCommands` (`az rest`) | ✅ | 2 Graph GETs (granted assignments + SP catalog) |
| Microsoft Graph application perms | ✅ | `Application.Read.All` (UAMI) |
| Sentinel Data Lake | ❌ | Not used |

---

## Architecture (two modes)

```
 MODE A — Self-collect (terminal az + KQL available)
   generate_html_report.py --workspace <LA_GUID> [--days 30]
     → script runs the KQL via `az monitor log-analytics query` and the Graph GETs via `az rest`
     → join granted × used → interactive HTML.

 MODE B — Prefetch (recommended; agent collects) [PRIMARY, deterministic]
   LLM collects via QueryLogAnalyticsByWorkspaceId (KQL) + RunAzCliReadCommands (az rest)
     → assembles results.json → generate_html_report.py --from-json results.json
     → analysis + render (no Azure calls).
```

> **Windows note (Mode A local):** the script resolves `az.cmd` via `shutil.which`, quotes the Graph URL through the shell (the OData `&` would otherwise be split by `cmd.exe`), and flattens the KQL to a single line (a multi-line arg is truncated at the first newline when the `az.cmd` batch wrapper runs). On the Linux sandbox these are no-ops.

---

## Workflow

### Step 1 — Collect

**KQL — `QueryLogAnalyticsByWorkspaceId`** (workspace `sentinel_workspace_id` from `config.json`):

| JSON key | What | 
|----------|------|
| `app_activity` | per-app (AppId + ServicePrincipalId) anonymized endpoint **families**, call count, 429 count, last seen |
| `app_errors` | per-app total / error / throttle rate (signal) |

**Graph REST — `RunAzCliReadCommands`** (`az rest --method get`):

| JSON key | Graph endpoint | Perm |
|----------|----------------|------|
| `graph_sp` | `/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?$select=id,appRoles&$expand=appRoleAssignedTo` | `Application.Read.All` |
| `service_principals` | `/v1.0/servicePrincipals?$top=999&$select=id,appId,displayName,servicePrincipalType,accountEnabled` | `Application.Read.All` |

Assemble into `results.json`:
```json
{
  "app_activity":       [ ... ],
  "app_errors":         [ ... ],
  "graph_sp":           { "appRoles": [...], "appRoleAssignedTo": [...] },
  "service_principals": { "value": [...] }
}
```

### Step 2 — Analyze (deterministic, in the renderer)
- Translate `appRoleId` GUIDs → scope names via the Graph SP `appRoles`.
- Join granted scopes (by SP objectId / AppId) with observed endpoint families.
- For each granted scope **with a map entry**, flag as *unused* if none of its endpoint families appears in activity (unmapped scopes are **not** flagged — avoids false positives).
- Assign the per-app verdict; compute the rollup (apps with perms, dormant, excess, total excess scopes, throttled apps).

### Step 3 — Render
`tmp/graph-least-privilege/graph-least-privilege-<ts>.html`: headline badge + 5 rollup cards + per-app table (App/SP · granted · calls · unused scopes as chips · 429 · verdict), UAMI row badged. Heuristic disclaimer in the footer.

```bash
# Mode B (prefetch):
python3 <SKILL_DIR>/generate_html_report.py --from-json tmp/graph-least-privilege/results.json \
  --output tmp/graph-least-privilege/graph-least-privilege.html
# Mode A (self-collect):
python3 <SKILL_DIR>/generate_html_report.py --workspace <LA_GUID> --days 30 \
  --output tmp/graph-least-privilege/graph-least-privilege.html
```

### Step 4 — Delivery (archive → link → notify)

Deliver via the existing delivery skills (do **not** re-implement transport), following the [canonical delivery sequence](../../shared/sharepoint-archival.md#canonical-delivery-sequence-archive--link--notify):

**Archive FIRST — SharePoint (canonical copy):**
- `python shared/sharepoint_upload.py upload --site "<config: sharepoint.site_id>" --skill graph-least-privilege --file graph-least-privilege-<ts>.html`. Capture `webUrl` + `folderUrl` from stdout (`{"ok":true,"webUrl":…,"folderUrl":…}`); on skip/error (exit 3/1) → continue.

**Email (dual recipients) — via `send-email-report`:**
- Send to **both** `default_recipients` from `config.json` in a single `toRecipients` list (⚠️ don't drop to one).
- Subject: `"🔐 Graph Least Privilege — <N> apps · <D> dormentes (<date>)"`.
- Attach the HTML if < 3 MB; always include `📂 Abrir no SharePoint: <folderUrl>` in the body. The link MUST be a `sharepoint.com` URL (never `teams.microsoft.com`/webhook/posted-message).
- Body: KPI line — `apps c/ perm | 🔴 dormentes | 🟠 com excesso | scopes a revisar | 429`. Use the numbers printed by the script.

**Teams Adaptive Card — via `send-teams-notification`:**
- Badge: `🔐 <N> apps · 🔴 <D> dormentes · <S> scopes a revisar`.
- CTA: **Abrir no SharePoint** → `folderUrl`. Post via the Power Automate **webhook only** (never Graph ChannelMessage.Send). Webhook URL from `config.json` (hardening pending: move to Key Vault).

---

## Verdict Logic

| Per app | Condition |
|---------|-----------|
| 🔴 DORMANT | granted ≥ 1 app role **and** 0 Graph calls in the window |
| 🔴 EXCESS | unused mapped scopes ≥ `excess_high` (default 3) |
| 🟠 EXCESS | unused mapped scopes ≥ `excess_warn` (default 1) |
| ✅ TIGHT | every mapped granted scope has observed activity |

Headline: **AÇÃO** (any dormant) · **REVISAR** (any excess) · **ENXUTO** (all tight).

> ⚠️ The endpoint→scope map is a **heuristic guide, not a guarantee** (mirrors the upstream module's own disclaimer): it may suggest trimming `Sites.Read.All` where `Sites.Selected` applies, or miss cross-permission calls. Validate each app before revoking.

---

## Companion Files — When to Load

| File | Load timing | Notes |
|------|------------|-------|
| `generate_html_report.py` | On skill activation | Main script |
| `queries.yaml` | On skill activation | KQL + Graph + heuristic map + thresholds |
| `results.json` | Mode B only | Prefetch artifact (LLM assembles) |

---

## Output Modes

```bash
--from-json <file>   → render from prefetched results (Mode B, primary)
--workspace <GUID>   → self-collect KQL + Graph (Mode A)
--days N             → lookback window (default from queries.yaml: 30)
```

---

## Attribution

Concept and the granted-vs-used methodology are ported from **[Mynster9361/Least_Privileged_MSGraph](https://github.com/Mynster9361/Least_Privileged_MSGraph)** (MIT) — an independent Python collector↔renderer re-implementation for this agent (UAMI auth, no client secret), not a copy of the PowerShell module. The heuristic-map disclaimer mirrors the upstream project's own.

---

## Key Differences from Other Skills

1. **Dual source:** Graph app-role grants × `MicrosoftGraphActivityLogs` (granted vs *actually used*).
2. **Permission:** `Application.Read.All` + Log Analytics Reader (not Sentinel Contributor).
3. **Drill-down:** operational depth of the org-posture 🤖 NHI section; complements `spn-scope-drift` (behavioral drift) — here it's *permission vs usage*.

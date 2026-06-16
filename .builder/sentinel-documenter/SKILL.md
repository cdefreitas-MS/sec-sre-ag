---
name: sentinel-documenter
description: 'Living, gap-scored documentation for a Microsoft Sentinel workspace. A YAML-driven Python pipeline inventories the workspace (analytic rules, data connectors, DCRs/DCEs, tables, RBAC, settings) via az rest / az monitor, runs a SCORED best-practice gap analysis against the SENT-NNN catalog (43 rules across Cost, Coverage, Operational, Identity, Network, Resilience, Hygiene, Foundation, Strategic — ported faithfully from the open-source Sentinel-As-Code Wave 4 best-practices.json v2.0.0), estimates cost (Usage GB x Azure Retail Prices + 5 GB/day Sentinel free benefit + commitment-tier what-if), and emits a Documenter Score (0-100) with verdict SAUDÁVEL / ATENÇÃO / EM RISCO / CRÍTICO. The script renders the final HTML (email) + Markdown (repo) deterministically — no LLM rendering phase. 100% READ-ONLY (GET/query/anonymous only — never mutates the workspace). Use for: documentar sentinel, sentinel documenter, workspace health, sentinel best practices, gap analysis sentinel, custo do sentinel, SENT-NNN.'
---

# Sentinel Documenter — Instructions

## Purpose

Turn a Sentinel workspace into **self-updating documentation that grades itself**. One run captures the full inventory, scores it against the **SENT-NNN best-practice catalog**, estimates cost from real Usage, and produces a board-readable HTML plus a repo-friendly Markdown. It answers three questions in one artifact: *what is in this workspace*, *what is wrong with it (and how to fix it, with learn links)*, and *what is it costing me*.

The catalog is a **faithful port** of the open-source Sentinel-As-Code Wave 4 work (`best-practices.json` v2.0.0 + `GapChecks.ps1`) — same rule IDs, severities, categories and remediation, re-implemented in this repo's collector↔renderer pattern. Reference repo is connected to this agent as **Microsoft-Sentinel-As-A-Code** (knowledge source only).

**Entity Type:** Sentinel workspace (coordinates provided at invocation: `subscription`, `resourceGroup`, `workspaceName`, `workspaceGuid`).

| Scope | Data Sources | Use Case |
|-------|--------------|----------|
| Workspace-wide (default) | Workspace/Tables/Rules/Connectors/DCRs (REST) · Usage/Heartbeat/Incidents/AlertVolumes (KQL) · RBAC (CLI) · Azure Retail Prices (anon) | Full inventory + gap score + cost |

---

## Environment & Data Gathering

> ⚠️ **This skill is READ-ONLY.** Every command is a GET / KQL query / anonymous price lookup. It performs **no** PUT/PATCH/DELETE, no containment, no rule changes.
> All queries/endpoints are pre-defined in [queries.yaml](queries.yaml) under `collector:`. No KQL or REST generation is needed at runtime.
>
> Data is gathered in one of two modes (same split as `mitre-coverage-report`):
> - **`az rest`** — Sentinel + Operational Insights + Insights REST (workspace, tables, alertRules, dataConnectors, DCRs/DCEs, Ueba, contentPackages, automationRules)
> - **`az monitor log-analytics query`** — KQL (`tables_with_data`, `ama_mma_migration`, `incidents_mttr`, `rule_volumes`)
> - **`az role assignment list`** — workspace-scoped RBAC
> - **Azure Retail Prices API** (`prices.azure.com`, anonymous) — region Log Analytics rates

---

## Architecture

```
 ┌──────────────────────────────────────────────────────────────────────────┐
 │                          TWO EXECUTION MODES                             │
 │                                                                          │
 │  MODE A — Direct (terminal az works)                                     │
 │  generate_html_report.py --workspace <guid> --sub --rg --ws --save-raw   │
 │    → script runs az rest / az monitor / az role itself → inventory       │
 │    → gap engine + cost + render → HTML + Markdown                        │
 │                                                                          │
 │  MODE B — Prefetch (terminal az blocked by MI token cache) [RECOMMENDED] │
 │  LLM gathers each collector query via native tools (RunAzCliReadCommands │
 │    for az rest/CLI, monitor-client MCP for KQL) → assembles inventory.json│
 │  → generate_html_report.py --from-json inventory.json                    │
 │    → gap engine + cost + render (no Azure calls) → HTML + Markdown        │
 │                                                                          │
 │  Both modes emit: tmp/sentinel-documenter/documenter-<ts>.{html,md}       │
 │  Rendering is DETERMINISTIC inside the script — no LLM rendering phase.   │
 └──────────────────────────────────────────────────────────────────────────┘
```

**Execution model:**
- **Mode A (Direct):** the script runs `az` directly. Works when the terminal `az` CLI has valid credentials with at least **Log Analytics Reader** / **Microsoft Sentinel Reader** on the workspace.
- **Mode B (Prefetch) — recommended in this agent:** the LLM collects each query result via native tools and writes them into a single `inventory.json` (shape below), then runs the script with `--from-json`. Use this when Managed Identity token caching blocks terminal `az` (can persist up to 24h after RBAC changes).

Unlike the LLM-rendered report skills, **this script produces the final HTML + Markdown itself** — the only LLM job after collection is to deliver the files (email/Teams) and summarize.

---

## Companion Files — When to Load

| File | Purpose | When to Load | Runtime Location |
|------|---------|--------------|------------------|
| **SKILL.md** (this file) | Architecture, modes, JSON shape, score methodology, catalog | Always — primary entry point | `read_skill_file` only |
| [generate_html_report.py](generate_html_report.py) | Collector + gap engine + cost + HTML/MD renderer | Execution only | **Must be on disk** |
| [queries.yaml](queries.yaml) | Collector endpoints/KQL + cost config + the 43-rule SENT-NNN catalog | Read at runtime by the script | **Must be on disk** (same dir as script) |

---

## File Resolution (codeRefs-first — On Skill Activation)

`generate_html_report.py` loads `queries.yaml` **from its own directory** at runtime (`Path(__file__).resolve().parent`). Both files must be co-located on disk.

🔴 **MANDATORY — IMMEDIATE:** the moment this skill activates, resolve BOTH runtime files **before anything else**.

### Resolution Cascade

```
1. codeRefs/sec-sre-ag/sentinel-documenter/
   → If both files exist here: use this directory as <SKILL_DIR> and run the script from here.
   → Do NOT copy files to tmp/.

2. tmp/sentinel-documenter/
   → If both files exist here (from a previous materialization): use as <SKILL_DIR>.

3. Neither location has both files:
   → read_skill_file() for each missing file
   → CreateFile("tmp/sentinel-documenter/<filename>", <content>)
   → Use tmp/sentinel-documenter/ as <SKILL_DIR>.
```

### Files to Resolve

| File | Required By | Format |
|------|-------------|--------|
| `generate_html_report.py` | execution | Python (stdlib + PyYAML) |
| `queries.yaml` | the script | YAML |

> Dependency: **PyYAML** (`pip install pyyaml` if the sandbox lacks it). No other third-party packages.

---

## Workflow

### Step 1 — Resolve coordinates
From the invocation / connected workspace: `subscription`, `resourceGroup`, `workspaceName`, `workspaceGuid`. (For `LA-HERBEST-SENTINEL`: sub `4dd2fd28-6aaf-4431-883a-de5572c458c5`, rg `RG-SEC-HERBEST`, ws `LA-HERBEST-SENTINEL`, guid `2a24da1d-2114-4d5a-b5a1-ce0ecf06fe8a`.)

### Step 2 — Collect (choose a mode)
**Mode A (try first):**
```bash
python3 <SKILL_DIR>/generate_html_report.py \
  --workspace <workspaceGuid> --sub <subscription> --rg <resourceGroup> --ws <workspaceName> \
  --save-raw --output tmp/sentinel-documenter --format both
```
If terminal `az` fails (token cache / auth), fall back to **Mode B**.

**Mode B (prefetch — recommended):** run each `collector` query from `queries.yaml` via native tools and assemble `tmp/sentinel-documenter/inventory.json` with these keys (omit any you cannot collect — its checks become *não avaliado*, never falsely "ok"):

| JSON key | Source (queries.yaml → collector) | Shape |
|----------|-----------------------------------|-------|
| `workspace` | REST `workspace` | ARM resource object |
| `tables` | REST `tables` | `{value:[ARM table…]}` |
| `tables_with_data` | KQL `tables_with_data` | `[{DataType,BillableLast24h,BillableLast7d,BillableLast30d,BillableLast90d}…]` |
| `alert_rules` | REST `alert_rules` | `{value:[…]}` |
| `alert_templates` | REST `alert_templates` | `{value:[…]}` |
| `data_connectors` | REST `data_connectors` | `{value:[…]}` |
| `automation_rules` | REST `automation_rules` | `{value:[…]}` |
| `dcrs` | REST `dcrs` | `{value:[…]}` |
| `ueba` | REST `ueba_settings` | settings object (or null) |
| `content_packages` | REST `content_packages` | `{value:[…]}` |
| `rbac` | CLI `az role assignment list` | `[{RoleDefinitionName,ObjectType,DisplayName}…]` |
| `incidents_mttr` | KQL `incidents_mttr` | `[{MTTRMinutes,ClosedCount,AcknowledgedCount}]` |
| `rule_volumes` | KQL `rule_volumes` | `[{AlertName,Alerts}…]` |
| `ama_mma_migration` | KQL `ama_mma_migration` | `[{MMACount,AMACount}]` |

Then:
```bash
python3 <SKILL_DIR>/generate_html_report.py --from-json tmp/sentinel-documenter/inventory.json \
  --output tmp/sentinel-documenter --format both
```

### Step 3 — Read the result
The script prints `Documenter Score N/100 (verdict) · C/W/I · k não avaliados` and writes the HTML + MD. Read the MD for the findings/cost to summarize.

### Step 4 — Deliver (hand off, read-only)
- **send-email-report**: subject "🛡️ Sentinel Documenter: {verdict} · score {n}/100 ({date})", attach the HTML.
- **send-teams-notification**: Adaptive Card with score, verdict, #Critical/#Warning, weakest category.

### Step 5 — Chat summary
```
🛡️ SENTINEL DOCUMENTER — score {n}/100 · {SAUDÁVEL|ATENÇÃO|EM RISCO|CRÍTICO}
   Achados: {c} Critical · {w} Warning · {i} Info   ({k} não avaliados)
   Top: {SENT-NNN} {título} · {SENT-NNN} {título}
   💰 ~{gb} GB billable/30d · ~US$ {x}/mês (estimado)
   📧 Email + 💬 Teams enviados
```

---

## Posture Verdict

**Documenter Score** = `100 − Σ severity_weight` (Critical −15 · Warning −7 · Info −2), clamp [0,100].

- **SAUDÁVEL** ≥ 85 · **ATENÇÃO** 65–84 · **EM RISCO** 40–64 · **CRÍTICO** < 40.

Always shown next to the findings table — never a black box. Checks whose data wasn't collected are listed as **não avaliados** (never counted as passing).

## Catalog (SENT-NNN) — anchors

| Categoria | Exemplos | Sev |
|---|---|---|
| **Foundation** | SENT-022 RP · SENT-047 CLv1 (2026-09-14) · SENT-048 MMA (2024-08-31) · SENT-049 TI legada (2025-07-31) | **Critical** |
| **Cost** | SENT-001 daily cap · SENT-003 noisy sem transform · SENT-015 commitment tier · SENT-043/044/045 split | Warning/Info |
| **Coverage** | SENT-004 conectores · SENT-005 UEBA · SENT-006 MITRE · SENT-008 templates High | Warning/Info |
| **Operational** | SENT-007 regras off · SENT-026 silent · SENT-029 MTTR · SENT-033 dominant · SENT-034 sem automation | Warning/Info |
| **Identity / Network / Resilience / Hygiene / Strategic** | SENT-009/024/039/040 · SENT-021 · SENT-020/042 · SENT-013 · SENT-014 | Warning/Info |

~30 of 43 rules are evaluated by the renderer; the rest live in the catalog and surface as **não avaliados** until their data is collected (mirrors the original's incremental design).

## Common Errors

| Error | Meaning | Fix |
|---|---|---|
| `ModuleNotFoundError: yaml` | PyYAML missing | `pip install pyyaml` |
| `az` WinError/“not found” | sandbox `az` blocked (MI token cache) | switch to **Mode B** (prefetch JSON + `--from-json`) |
| `tables_with_data` empty / cost 0 GB | no Reader on workspace OR Usage empty | table-based checks → *não avaliados*; verify RBAC |
| many *não avaliados* | several REST calls returned null | collect more keys (Mode B) — the UAMI here has Sentinel Reader/Contributor |

## Rules

- ✅ **READ-ONLY** — GET/query/anonymous only; never mutates the workspace.
- ✅ **ALWAYS** show score + findings together; list *não avaliados* (empty ≠ ok).
- ✅ **ALWAYS** include the cost disclaimer (estimate; excludes query-time/search/restore/egress/XDR meters).
- ✅ Catalog is **data-driven**: a new rule = 1 line in `queries.yaml` + 1 function in the renderer.
- ⛔ **NEVER** run git operations.

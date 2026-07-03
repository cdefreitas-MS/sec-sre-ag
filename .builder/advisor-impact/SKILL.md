---
name: advisor-impact
description: 'Remediation impact planner uniting Azure Advisor (Cost/Reliability/Performance/OperationalExcellence) + Microsoft Defender for Cloud (security assessments + Secure Score + MCSB regulatory compliance) into a PHASED EXECUTION PLAN. Risk-rates each recommendation by disruption (safe/low/medium/high), identifies cascade impact on dependent workloads, maps MITRE ATT&CK tactics/techniques, links to the official Azure Portal recommendation, and generates a staged remediation plan (quick wins → maintenance window → approval+rollback). 100% READ-ONLY (ARM GET only). Quantifies cost savings (Advisor) AND implementation cost (Azure Retail Prices API), current + potential Secure Score elevation with per-recommendation impact, and MCSB compliance posture. Optional GitHub Posture tab (--github-org/--github-json) scores a GitHub org across the 8-domain GH-NNN catalog (governance, branch protection, secrets, Actions, code security, audit log, supply chain) and emits a cross-domain feed for attack-path. Collector↔renderer, deterministic. Use for: azure advisor remediation, defender for cloud action plan, remediation planner, azure governance automation, advisor + defender consolidation, risk-rate azure recommendations, secure score elevation, MCSB compliance, regulatory compliance posture, github posture, ghas audit, github security 8 domains.'
---

# Advisor Impact — Remediation Planner Instructions

## Purpose

**Transform Azure governance tools into an actionable playbook** by uniting **Azure Advisor** recommendations with **Microsoft Defender for Cloud** security assessments, cross-referencing them against the resource inventory, and producing a **phased execution plan** that prioritizes by *operational disruption risk* — not just severity.

| Source | Categories | What it brings |
|--------|-----------|----------------|
| **Azure Advisor** | Cost, Reliability, Performance, OperationalExcellence | Optimization recommendations + annual savings estimates |
| **Defender for Cloud** | Security | Security assessments + Secure Score (current + potential) + per-recommendation impact + MITRE + official portal links + MCSB regulatory compliance |
| **Azure Retail Prices API** | Cost (public, no auth) | Implementation cost estimate for recommendations that imply new spend (geo-replication, private endpoint, NAT gateway, firewall, DDoS, WAF…) |

**Value layers** (added on top of the phased plan):
- 💰 **Cost** — Advisor savings (USD/year) *and* implementation cost (USD/month) via [Azure Retail Prices API](https://prices.azure.com) (official, unauthenticated).
- 🛡️ **Secure Score** — current % + **potential %** if all remediated + **per-recommendation impact** (which control, how many points), via `secureScoreControls` ($expand=definition).
- 🎯 **MITRE ATT&CK** — tactics/techniques per Defender recommendation (from assessment metadata).
- 🔗 **Official portal link** — deep link to each recommendation (`links.azurePortal`), not a guessed URL.
- 👤 **Owner** — remediation owner when present.
- 📋 **MCSB compliance** — Microsoft Cloud Security Benchmark posture (passed/failed/skipped controls + top failing controls). *Inspired by the public [microsoft/ESA](https://github.com/microsoft/ESA) toolkit (MIT), re-implemented in Python.*
- 🐙 **DevOps security** — recognizes Defender for Cloud **DevOps** recommendations (GitHub / Azure DevOps / GitLab connectors) by resource ID, tags them with **provider + repository**, adds a **"Repositório DevOps"** filter and a **DevOps findings** KPI. These don't affect Secure Score (shown as Impacto SS "—"), so they're triaged by **severity**; cascade/validation hints are suppressed for repos.
- 🐙 **DevOps Remediation mode** — beyond the posture *recommendations* above, ingests the granular **subassessments** (`microsoft.security/assessments/subassessments` whose id contains `/securityConnectors/`, `/devops/`, or `githubowners`) = the real **findings to fix** (dependency CVEs, code/CodeQL, IaC, secrets) surfaced by GHAS/Defender DevOps. The `devops_findings` ARG query slims them with `pack()`; `analyze_devops_findings()` drops Healthy and groups by **severity × category × repo**; the renderer emits a dedicated **🐙 DevOps Remediation** section (severity KPI strip + **repo × severity matrix**, top 20 repos) in both HTML and Markdown, and it rides the **triple delivery** (dual email + Teams). Parser accepts both flat (ARG slim `severity`/`code`) and nested (`status.severity`/`status.code`) shapes.
  - **Risk-first matrix** — the repo × severity matrix is sorted by **Critical+High** count (total as tiebreaker) so the highest-*risk* repos surface on top, not the highest-*volume* ones (`_repo_risk()`).
  - **Concise findings table** — a per-finding table (top 25 by severity) lists `Sev · Repositório · Finding · Categoria · Referência`. GHAS subassessment `displayName` carries the full advisory body, so `_short_finding()` shows only the relevant point (package/ecosystem + first sentence, capped ~140 chars). Each row links out to the recommendation: the official **portal** link when present, else the repo's **GitHub Security tab** by category (`_devops_ref_link()` → Dependency `/security/dependabot`, Code/IaC `/security/code-scanning`, Secret `/security/secret-scanning`).
- � **GitHub — visão unificada (8 domains + DevOps numa aba só)** — the *governance/posture half* the Defender DevOps connector can't see, **unified** with the *findings* we already had. With `--github-org <org>` (live `gh api`, needs `admin:org`/`security_events`) or `--github-json <file>` (offline), advisor-impact loads the modular **github-posture** engine (sibling `github-posture/` dir, via `_github_posture()` + importlib) and renders a single **🐙 GitHub** tab SECTIONED into **1·🔗 Diferencial** (cross-domain feed: leaked secret/OIDC → Azure credential, the repo→tenant path no product integrates) · **2·🛡️ Postura & Governança** (8 domains via `gh api`, **GH-NNN** score 0–100 SAUDÁVEL/ATENÇÃO/EM RISCO/CRÍTICO + importance layer 🔥×📋, **NOVO**) · **3·🐙 Remediação de código** (the existing DevOps Remediation dashboard — Dependabot/CodeQL/secret — **folded in**; the separate DevOps tab is removed when GitHub is present). Three orientation cards (DIFERENCIAL/NOVO/JÁ NO RELATÓRIO) make clear what's new, what we already had, and the unified view. Emits `_github_feed.json` (`github_secrets`/`github_oidc`) so **attack-path** can chain `repo → leaked-secret/SP → privileged role`. Skip-gracioso: no engine/token → no tab. 100% READ-ONLY (`gh api` GET).
- �🛡️ **Defender XDR recommendations** (optional) — if the prefetch JSON includes an `xdr_recommendations` dataset, `analyze_xdr_recommendations()` renders a dedicated **🛡️ Defender XDR** page (pie/donut + KPIs + per-category bars + table). Accepts **two shapes**: (A) **Microsoft Graph `GET /security/secureScoreControlProfiles`** = the **Recommended Actions** shown at `security.microsoft.com/securescore` (`title`, `controlCategory` Identity/Device/Apps/Data, `service`, `maxScore`, `actionUrl`, `controlStateUpdates[].state`, `threats`) → grouped by category, ranked by score-improvement points, table = Action/Service/Category/Status/Points/link; (B) MDE TVM `api.securitycenter.microsoft.com/api/recommendations` (`severityScore`, `exposedMachinesCount`, `publicExploit`) → grouped by severity. Not collected by ARG/ARM — provide via `--from-json` (the SRE Agent has the Graph/MDE permissions).
- 🖥️ **Single-page report UX** — the HTML is a self-contained client-side app: a **clean home screen** (brand logo + **score cards** for Microsoft Secure Score, Defender for Cloud Secure Score, Defender XDR and MCSB Compliance, Power BI style, each with a **pie** of its volume breakdown), a top nav menu, and an **📊 Executive Summary** page modeled on the ESA Power BI dashboard (score-card row + **“most critical recommendations/controls” tables** per pillar + a **volume-by-source pie** + consolidated narrative). Each pillar has its own focused page (Defender for Cloud / XDR / MCSB / DevOps) with a severity **pie/donut** + table; Advisor opens the plan pre-filtered by source (`gotoSource()`). **Light/dark theme toggle** (persisted in `localStorage`). All charts are inline SVG (`_svg_pie`/`_svg_donut`/bars) — no external libraries. Markdown output stays a flat document.
- 🏆 **Microsoft Secure Score** (optional) — if the prefetch JSON includes `m365_secure_score` (Microsoft Graph **`GET /security/secureScores?$top=1`**, fields `currentScore`/`maxScore`/`controlScores`), `analyze_m365_secure_score()` adds the **Microsoft Secure Score** card (Entra ID + Microsoft 365). Not collected by ARG/ARM — provide via `--from-json`.


**Disruption Risk Classification** (how risky to *apply*):
- 🟢 **Safe** → Quick wins (enable logging, MFA, backup) — execute anytime
- 🟡 **Low** → Low disruption (scale up, encryption) — execute during low-traffic window
- 🟠 **Medium** → Moderate disruption (private link, NSG, firewall) — schedule maintenance window
- 🔴 **High** → High disruption (ephemeral disks, JIT, restrict access) — **approval + tested rollback required**

**Cascade Detection:** "Resource X changes → dependent workloads may restart"

**Entity Type:** Azure Resource Group (`subscription`, `resourceGroup`).

---

## Skill Files

| File | Purpose | When used |
|------|---------|-----------|
| [generate_html_report.py](generate_html_report.py) | collector + risk engine + phased planner + HTML/MD renderer | execution |
| [queries.yaml](queries.yaml) | ARM endpoints + 43-pattern risk baseline + phase metadata | read at runtime by the script |
| [../github-posture/generate_html_report.py](../github-posture/generate_html_report.py) | GitHub Posture engine (GH-NNN, 8 domains) — loaded via `_github_posture()` for the optional `🐙 GitHub` tab + cross-domain feed | when `--github-org`/`--github-json` is passed |
| [../github-posture/queries.yaml](../github-posture/queries.yaml) | GH-NNN catalog (8 domains) + `gh api` collector | read by the GitHub Posture engine |

> ⚠️ **100% READ-ONLY.** Only ARM GET operations. Recommends actions, **never applies them**.

---

## File Resolution (codeRefs-first — On Skill Activation)

`generate_html_report.py` loads `queries.yaml` from its own directory (`Path(__file__).resolve().parent`). Both files must be co-located.

```
1. codeRefs/sec-sre-ag/advisor-impact/   → if both files exist, use as <SKILL_DIR>, run from here.
2. tmp/advisor-impact/                   → if both exist (previous materialization), use it.
3. Neither → read_skill_file() each missing file → CreateFile("tmp/advisor-impact/<file>") → use tmp/.
```

> **🐙 Unified GitHub tab needs the sibling engine.** For the single 🐙 GitHub tab (github-posture folded in), `../github-posture/generate_html_report.py` + `queries.yaml` must resolve as a **sibling** of `<SKILL_DIR>` — advisor-impact imports it via that relative path (`_github_posture()` + importlib). With **Code Access** (`codeRefs/sec-sre-ag`) the whole repo is synced, so the sibling exists automatically. Running standalone from `tmp/` will **skip the tab** (skip-gracioso) unless you also materialize `tmp/github-posture/{generate_html_report.py,queries.yaml}`.

> Dependency: **PyYAML** (`pip install pyyaml` if missing). No other third-party packages.

---

## Execution Environment Constraints

| Capability | Available | Notes |
|------------|-----------|-------|
| `az rest` (ARM) | ✅ | All 7 core endpoints + ARG use the ARM management API (needs **Reader**) |
| Microsoft Graph API (via **UAMI** token) | ✅ (optional) | `secureScores` + `secureScoreControlProfiles` → 🏆 Secure Score + 🛡️ Defender XDR. Mint from the **UAMI** (NOT `az rest`, which uses the system MI → **403** → tabs vanish). |
| HTTPS to prices.azure.com | ✅ (optional) | Azure Retail Prices API — **public, no auth**. Degrades to fixed fallback estimates if blocked. |
| `gh api` (GitHub CLI) | ✅ (optional) | 🐙 GitHub tab — needs a PAT/App with `admin:org` + `security_events`. |
| Microsoft Graph MCP | ❌ | Not used (Graph datasets fetched by direct `curl` with the UAMI token) |
| Sentinel Data Lake | ❌ | Not used |

---

## Required Tools & Permissions — Portal Grant Checklist (paste-ready)

Grant these **to the agent's user-assigned MI (UAMI)** *before* running so no dataset silently 403s. A 403 on the Graph datasets is exactly what makes the **🛡️ Defender XDR** / **🏆 Microsoft Secure Score** tabs disappear (the agent skips the dataset → the tab won't render). The UAMI appId / SP objectId come from `config.json` (`agent_uami_client_id`) or `<agent_identity>`.

### 1 · SRE Agent tools to enable — pick these in **"Escolher ferramentas"** (or, preferably, configure them directly on the agent)
> These are the exact tool names the portal offers. The dialog note ("Tools added here will be dynamically available when this skill is activated — for more consistent behavior, configure tools directly on the agent instead") means the **most reliable** setup is to enable them on the agent, not only on the skill.

| Tool (portal name) | Used for |
|--------------------|----------|
| **`RunAzCliReadCommands`** | collect every dataset — `az rest` GET (the 7 ARM endpoints) **+** `az rest --method post` to Azure Resource Graph (Mode C ARG — a read-only query) |
| **`RunInTerminal`** | run `python3 generate_html_report.py`, `pip install pyyaml`, `curl` (mint the **UAMI** Graph token + fetch `secureScores` / `secureScoreControlProfiles`), and `gh api` (optional 🐙 GitHub tab) |
| **`read_skill_file`** | materialize `generate_html_report.py` + `queries.yaml` (and the sibling `github-posture/` files) when they aren't already in `codeRefs` |
| **`CreateFile`** | write `inventory.json`, the `_m365.json` / `_xdr.json` temps, and the output `advisor-impact-<ts>.{html,md}` |

**Also enable (agent-level, not in the tool picker):** **Code Access** (`codeRefs/sec-sre-ag`) — synced/re-synced so `advisor-impact/` and `github-posture/` load directly.

> ⚠️ **This skill is 100% READ-ONLY — do NOT add `RunAzCliWriteCommands`** (nor `runHuntingQuery`; it isn't used here). The one-time UAMI grant commands in §3 are run **once by an admin**, not by the skill. Delivery (Step 6) is handled by the separate `send-email-report` / `send-teams-notification` skills, which carry their own tools.

### 2 · Azure RBAC (ARM) — assign to the UAMI
| Role | Scope | Unlocks |
|------|-------|---------|
| **Reader** | tenant root MG (`--tenant`) **or** each subscription (`--subs`) | Advisor · Defender for Cloud assessments/secure score/MCSB · resource inventory · `devops_findings` (ARG) |

```bash
# Tenant-wide (recommended): Reader at the root management group
az role assignment create --assignee <UAMI_OBJECT_ID> --role Reader \
  --scope /providers/Microsoft.Management/managementGroups/<TENANT_ROOT_MG>
# …or per-subscription
az role assignment create --assignee <UAMI_OBJECT_ID> --role Reader --scope /subscriptions/<SUB>
```

### 3 · Microsoft Graph application permission — assign to the UAMI (fixes the disappearing tabs)
| Permission (app role) | appRoleId | Feeds |
|-----------------------|-----------|-------|
| **`SecurityEvents.Read.All`** | `bf394140-e372-4bf9-a898-299cfc7564e5` | `secureScores` (🏆 Microsoft Secure Score) + `secureScoreControlProfiles` (🛡️ Defender XDR) |

```bash
# Grant SecurityEvents.Read.All (application) to the UAMI service principal
GRAPH_SP=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query id -o tsv)
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/<UAMI_SP_OBJECT_ID>/appRoleAssignments" \
  --headers "Content-Type=application/json" \
  --body "{\"principalId\":\"<UAMI_SP_OBJECT_ID>\",\"resourceId\":\"$GRAPH_SP\",\"appRoleId\":\"bf394140-e372-4bf9-a898-299cfc7564e5\"}"
```
> Portal path: **Entra ID → Enterprise applications → (the UAMI) → Permissions**. App-role assignments to a managed identity can take **up to ~24 h** to propagate through STS (a fresh token may still show the old role set for a while — this is replication latency, **not** a missing grant; don't re-grant).

### 4 · Optional — unified 🐙 GitHub tab (github-posture folded into advisor-impact)
The **🐙 GitHub** tab merges the *governance/posture* half (**github-posture**, 8-domain GH-NNN) with the *code findings* half (Defender DevOps — Dependabot/CodeQL/secret) into **one organized tab** (sections 1·🔗 Diferencial · 2·🛡️ Postura & Governança · 3·🐙 Remediação de código). It renders **only when all three below are in place** — otherwise it's silently omitted (skip-gracioso), which is why it "didn't show up":

| Requirement | How to satisfy |
|-------------|----------------|
| **① Companion engine present** | `../github-posture/generate_html_report.py` + `queries.yaml` co-located as a **sibling** of `advisor-impact/`. ✅ Enable **Code Access** (`codeRefs/sec-sre-ag`) so the whole repo syncs and the sibling resolves automatically. *(Standalone skill without codeRefs → also add both github-posture files to the skill, or materialize them under `tmp/github-posture/`.)* |
| **② Trigger flag** | pass **`--github-org <org>`** (live `gh api`) **or** **`--github-json <file>`** (offline). Without one, the engine never runs and the tab is omitted. *(There is no config default — the org must be given on the command line.)* |
| **③ GitHub token** | a PAT / GitHub App token with **`admin:org`** + **`security_events`** (+ `repo` for private repos), exported for `gh` (e.g. `GH_TOKEN=<token>`). Feeds the 8-domain score + findings + the `_github_feed.json` cross-domain feed that **attack-path** chains (`repo → leaked-secret/SP → privileged role`). |

> ℹ️ **The 🐙 GitHub tab does NOT need the ARG `devops_findings` (no POST required).** With `--github-org` + a `gh` token, sections **1 (🔗 Diferencial)** and **2 (🛡️ Postura & Governança — 8 domains incl. code security / Dependabot / CodeQL / secret)** render **entirely from `gh api` (GET)**. The ARG `devops_findings` dataset (Defender-for-Cloud DevOps connector) is **optional** — the renderer only folds it into section 3 **if present** (`if ctx.get("devops")`); without it the tab still renders fully. So you get the complete GitHub tab **without enabling any POST**. Only pursue the ARG POST below if you specifically want the Defender-DevOps-connector findings.

> ⚠️ **In the Azure SRE Agent, prefer `--github-json` over `--github-org`.** Code Access does **not** pass a `GITHUB_TOKEN` into the skill's subprocess, so live `--github-org` (`gh api`) runs **unauthenticated** and collects nothing. The validated pattern ("Jeito 1") is: a **GitHub Actions** workflow (`GitHub Posture Audit`) collects with the org PAT and publishes `<org>-raw.json` to the **`gh-posture-data`** branch; the agent then `git show gh-posture-data:<org>-raw.json > /tmp/<org>-raw.json` and passes **`--github-json /tmp/<org>-raw.json`**. (Live `--github-org` only works where a `gh`-authenticated token exists in-process, e.g. local runs.)

### 5 · No grant needed
- **Azure Retail Prices API** (`prices.azure.com`) — public, unauthenticated (implementation-cost estimates).

> ✅ **Reader** (RBAC) + **`SecurityEvents.Read.All`** (Graph) on the UAMI = all built-in tabs render. GitHub scopes are only for the optional 🐙 tab.

---

## Architecture (three modes)

```
 MODE A — Direct, single RG (terminal az works)
   generate_html_report.py --sub <id> --rg <name> --save-raw
     → script runs `az rest --method get --url <mgmt-url>` itself (7 ARM endpoints)
     → inventory → risk classification → interactive HTML + MD
     → GUARD: if all sources come back empty (no Reader / auth failure) it exits and points to Mode B.

 MODE B — Prefetch (terminal az blocked / recommended) [PRIMARY, deterministic]
   LLM collects each ARM endpoint via RunAzCliReadCommands (az rest)
     → assembles inventory.json → generate_html_report.py --from-json inventory.json
     → risk-rate + render (no Azure calls). Auto-detects tenant-wide if data spans >1 subscription.

 MODE C — Tenant-wide via Azure Resource Graph (ARG) [scans the whole tenant]
   generate_html_report.py --tenant            → all subscriptions the identity can read
   generate_html_report.py --subs id1,id2      → a specific set of subscriptions
     → ONE ARG query per dataset (advisorresources / securityresources / resourcecontainers)
       via `az rest --method post` to /providers/Microsoft.ResourceGraph/resources, paginated by $skipToken
     → same parsers; secure score + MCSB aggregated PER SUBSCRIPTION. Same base ARG tables the ESA uses.

 All emit: tmp/advisor-impact/advisor-impact-<ts>.{html,md}. HTML is an interactive single-file app
 (embedded JSON + client-side filters); MD is the static full dataset. Rendering is DETERMINISTIC.
```

### Interactive HTML filters (client-side, offline)
The HTML embeds the full dataset as JSON and ships a small self-contained `<script>` (no external libs / CDNs) that re-computes **everything** on filter change: KPIs, phase tables, cost totals, Secure Score bar, and the MCSB section. Filter dimensions: **Subscription · Resource Group · Source (Advisor/Defender) · Category · Risk/Phase · Severity** (checkbox groups; empty = all). Secure Score and MCSB are per-subscription metrics, so they recompute on the **Subscription** filter (summing points across selected subs); Resource-Group/Category/Source/Risk/Severity filters affect only the recommendations table + counts + cost. "Limpar filtros" resets.

---

## Workflow

### Step 1 — Resolve coordinates
- **Tenant-wide** (recommended for posture review): no coordinates needed — `--tenant` scans every subscription the identity can read via Azure Resource Graph. Optionally `--subs id1,id2` to limit.
- **Single RG** (targeted): `subscription` (ID, not name) + `resourceGroup` (exact, case-sensitive).

The user may specify:
- The whole tenant / a set of subscriptions (broad posture) — Mode C
- A specific RG to scope recommendations (targeted) — Mode A/B

### Step 2 — Verify Permissions
**RBAC Required:** **Reader** role at the subscription or resource group level.

> ⚠️ This is **different from Sentinel/Graph permissions**. The identity (UAMI / user) needs ARM resource read access.

If collector returns empty data, verify:
```bash
az role assignment list --assignee <UAMI_OBJECT_ID> --scope /subscriptions/<SUB>/resourceGroups/<RG>
```

### Step 3 — Collect (choose a mode)

**Mode C (tenant-wide via Azure Resource Graph — for posture review across the tenant):**
```bash
python3 <SKILL_DIR>/generate_html_report.py --tenant --output tmp/advisor-impact --format both
# or a specific set of subscriptions:
python3 <SKILL_DIR>/generate_html_report.py --subs <sub1>,<sub2> --output tmp/advisor-impact --format both
# …attach the unified 🐙 GitHub tab (github-posture 8 domains + DevOps findings) — needs a gh token with admin:org/security_events:
python3 <SKILL_DIR>/generate_html_report.py --tenant --github-org <org> --output tmp/advisor-impact --format both
```
Runs one ARG query per dataset over `advisorresources` / `securityresources` / `resourcecontainers`. Needs **Reader** on the subscriptions. If the sandbox `az` is blocked, prefetch the ARG results (Mode B) instead.

> ⚠️ **#1 recurring failure — `az rest --method post` (ARG) is REJECTED by `RunAzCliReadCommands`.** That tool allows **read verbs only**, and every Azure Resource Graph query is an HTTP **POST** to `/providers/Microsoft.ResourceGraph/resources`. So when Mode C direct fails (sandbox `az` can't reach ARG) and the agent "falls back to Mode B" but keeps firing the **same ARG POST** queries, **every ResourceGraph call fails (red ✗) — repeatedly.** **Do NOT retry the ARG POST.** Two ways out:
> 1. **GET-only tenant walk (preferred — stays 100% read-only):** enumerate subscriptions with `az account list -o json` (or `az rest --method get --url "https://management.azure.com/subscriptions?api-version=2020-01-01"`), then loop the **subscription-scoped GET endpoints** (drop the `/resourceGroups/{rg}` segment) for each sub and merge per dataset into `inventory.json`:
>    - `advisor_recommendations` ← `GET /subscriptions/{sub}/providers/Microsoft.Advisor/recommendations?api-version=2023-01-01`
>    - `resource_inventory` ← `GET /subscriptions/{sub}/resources?api-version=2021-04-01`
>    - `mdc_assessments` ← `GET /subscriptions/{sub}/providers/Microsoft.Security/assessments?api-version=2021-06-01`
>    - plus the already sub-scoped `mdc_secure_score`, `mdc_secure_score_controls`, `mcsb_compliance_standards`, `mcsb_compliance_controls` from the Mode B table.
>    All of these are **GET**, so `RunAzCliReadCommands` allows them. The renderer auto-detects tenant-wide when the merged data spans >1 subscription. **Exception:** `devops_findings` only exists as an ARG subassessments **POST**, so the 🐙 DevOps *findings* section needs option 2 — the rest of the report (Advisor · Defender for Cloud · Secure Score · MCSB) renders fine without it.
> 2. **Allow a POST path just for ResourceGraph (only if you need `devops_findings`):** ARG is read-only *in effect*, but it *is* the POST verb — that's the only reason the read-only tool blocks it. From narrowest to broadest: **(A)** run the ARG query via **`RunInTerminal`** instead of `RunAzCliReadCommands` — the terminal has no read-verb filter, so `az rest --method post --url ".../providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01" --body @query.json` passes (no new tool needed); **(B)** an allow-list rule that auto-approves only `az rest --method post --url *ResourceGraph/resources*`; **(C)** enable `RunAzCliWriteCommands` (simplest toggle, but broadest — allows any `az` write, so it contradicts the 100% read-only posture; last resort). Since GET to `management.azure.com` already works, ResourceGraph is reachable — the block is only the verb, so **(A)** is enough.

> **Large tenants — slim projections (built-in).** The `ARG_QUERIES` use `pack()` to rebuild `properties` with **only the fields the parsers read** (drops the bloat, e.g. the large `additionalData` on container-CVE assessments). This keeps each dataset well under the agent's **~2 MB** Mode-B scratchpad cap, so the renderer's parsers (which read `properties.*`) work unchanged. **De-risked live (2026-06): 1,173 recommendations across 2 subscriptions, one with 1,028 unhealthy assessments.**
>
> If a single subscription is still enormous, page the ARG query in **batches of ~300 records** (`$top: 300` + `$skipToken`), write each batch to a temp fragment, and merge per dataset into the final `{"value":[...]}`. `run_arg()` (Mode C direct) already paginates by `$skipToken`.

**Mode A (single RG, try first):**
```bash
python3 <SKILL_DIR>/generate_html_report.py --sub <subscription_id> --rg <rg_name> \
  --category all --save-raw --output tmp/advisor-impact --format both
```

If terminal `az` fails (token cache / auth), fall back to **Mode B**.

**Mode B (prefetch — recommended):** run each ARM endpoint from `queries.yaml` via `az rest` **GET** and assemble `tmp/advisor-impact/inventory.json`. For **tenant-wide** without ARG, use the **GET-only tenant walk** in the ⚠️ note above (enumerate subs → loop the sub-scoped GET endpoints; **no POST**, so `RunAzCliReadCommands` won't reject it):

| JSON key | ARM endpoint (from queries.yaml) | API version |
|----------|----------------------------------|-------------|
| `advisor_recommendations` | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Advisor/recommendations` | 2023-01-01 |
| `resource_inventory` | `/subscriptions/{sub}/resourceGroups/{rg}/resources` | 2021-04-01 |
| `mdc_assessments` | `/subscriptions/{sub}/providers/Microsoft.Security/assessments` | 2021-06-01 |
| `mdc_secure_score` | `/subscriptions/{sub}/providers/Microsoft.Security/secureScores` | 2020-01-01 |
| `mdc_secure_score_controls` | `/subscriptions/{sub}/providers/Microsoft.Security/secureScoreControls?$expand=definition` | 2020-01-01 |
| `mcsb_compliance_standards` | `/subscriptions/{sub}/providers/Microsoft.Security/regulatoryComplianceStandards` | 2019-01-01-preview |
| `mcsb_compliance_controls` | `/subscriptions/{sub}/providers/Microsoft.Security/regulatoryComplianceStandards/{standard}/regulatoryComplianceControls` | 2019-01-01-preview |

> `{standard}` = the MCSB standard name discovered from `mcsb_compliance_standards` (`Microsoft-cloud-security-benchmark`, or legacy `Azure-Security-Benchmark`). Mode A discovers it automatically; for Mode B, pick it from the standards list. All 7 endpoints degrade gracefully — secure-score-controls and MCSB are optional (skipped sections if Defender for Cloud / MCSB is not enabled).

#### Optional Graph datasets — 🏆 Microsoft Secure Score + 🛡️ Defender XDR (mint the **UAMI** token)

Two extra datasets power the **🏆 Microsoft Secure Score** card (`page-m365`) and the **🛡️ Defender XDR** page — the *Recommended Actions* shown at `security.microsoft.com/securescore`. They come from **Microsoft Graph** (NOT ARM), so they are **not** in the ARM table above and must be collected separately:

| JSON key | Microsoft Graph endpoint | Feeds |
|----------|--------------------------|-------|
| `m365_secure_score` | `GET https://graph.microsoft.com/v1.0/security/secureScores?$top=1` | 🏆 Microsoft Secure Score card + `page-m365` |
| `xdr_recommendations` | `GET https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles` | 🛡️ Defender XDR page (Recommended Actions) |

> ⚠️ **Identity gotcha — the real cause of "the Defender XDR / Secure Score tab disappeared".** A plain `az rest --url ... --resource https://graph.microsoft.com` mints the token from the agent's **system-assigned MI**, which holds only `Sites.Selected` → **HTTP 403** → the agent silently skips → the tabs vanish. **A 403 here is NOT "unavailable" — DO NOT skip.** These datasets require the **user-assigned MI (UAMI)** token (it holds the security scopes). Mint it explicitly — same recipe as `runHuntingQuery` / the MDE API:
>
> ```bash
> # 1) Mint a Graph token from the UAMI (client_id = agent's user-assigned MI appId; from <agent_identity> or config.json → agent_uami_client_id)
> TOKEN=$(curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
>   "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://graph.microsoft.com&client_id=<UAMI_CLIENT_ID>" \
>   | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
> # 2) Collect with the UAMI token (NOT az rest, which uses the system MI)
> curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/security/secureScores?\$top=1"        > tmp/advisor-impact/_m365.json
> curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles" > tmp/advisor-impact/_xdr.json
> ```
>
> Add the results under `m365_secure_score` and `xdr_recommendations` in `inventory.json`. Both are **optional** — omit only if genuinely unavailable (then the two tabs simply won't render). A **403 means the wrong (system-MI) token was used → re-mint from the UAMI**, don't drop the dataset.

> 🐙 **DevOps / GitHub tab (`devops_findings`).** This is an **Azure Resource Graph** dataset (`securityresources` subassessments whose id has `githubowners` / `/devops/` / `/securityconnectors/`), collected automatically in **Mode C** (`--tenant` / `--subs`). If you prefetch (Mode B) and only fetch the 7 ARM endpoints above, `devops_findings` comes back empty → the **🐙 DevOps** tab won't render. Include the `devops_findings` ARG query (from `queries.yaml`) when prefetching, or use Mode C.

Example command per endpoint:
```bash
az rest --method get --url "https://management.azure.com/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.Advisor/recommendations?api-version=2023-01-01" -o json
```

Assemble into `inventory.json`:
```json
{
  "advisor_recommendations": { "value": [...] },
  "resource_inventory": { "value": [...] },
  "mdc_assessments": { "value": [...] },
  "mdc_secure_score": { "value": [...] },
  "mdc_secure_score_controls": { "value": [...] },
  "mcsb_compliance_standards": { "value": [...] },
  "mcsb_compliance_controls": { "value": [...] },
  "m365_secure_score":   { "value": [...] },   // optional · Microsoft Graph (UAMI token) → 🏆 Secure Score + page-m365
  "xdr_recommendations": { "value": [...] },   // optional · Microsoft Graph (UAMI token) → 🛡️ Defender XDR page
  "devops_findings":     { "value": [...] }    // optional · Azure Resource Graph (Mode C) → 🐙 DevOps/GitHub tab
}
```

Then render:
```bash
python3 <SKILL_DIR>/generate_html_report.py --from-json tmp/advisor-impact/inventory.json \
  --output tmp/advisor-impact --format both
```

### Step 4 — Risk Engine (Automated)

The script applies a **43-pattern risk baseline** from `queries.yaml`:

| Risk | Patterns (substring match, case-insensitive) | Phase |
|------|----------------------------------------------|-------|
| 🟢 Safe | "enable diagnostic", "enable soft delete", "enable mfa" | Quick wins |
| 🟡 Low | "scale up", "encryption at rest", "install endpoint protection" | Low-traffic window |
| 🟠 Medium | "private link", "network security group", "firewall" | Maintenance window |
| 🔴 High | "ephemeral os disk", "just-in-time", "restrict access" | Approval + rollback |

**Default:** If no pattern matches → **Low** (most config changes are low-disruption)

### Step 5 — Output Structure

**HTML Report** (dark theme, email-ready):
- **Hero section:** KPIs (total recommendations, 🟢🟡🟠🔴 counts, 🛡️ Secure Score *current* + 🎯 *potential* %, 💰 implementation cost, 🛡️ MCSB compliance %) + Secure Score progress bar (current → potential).
- **4 Phase Tables:**
  - Source badge (Advisor vs Defender for Cloud)
  - Recommendation title (🔗 **official portal deep link** when available) + category + priority + **Impact SS** column (per-recommendation Secure Score points + control name) + resource name + **Cost** (green savings / red implementation cost)
  - **Inline annotations:**
    - 🎯 MITRE ATT&CK badges (tactics/techniques)
    - 👤 Owner (remediation owner)
    - 🟡 Cascade: "resource X changes → workloads may restart"
    - ⚠️ Amplifier: "Resource not found in inventory — verify manually"
- **🛡️ MCSB Compliance section:** compliance % + passed/failed/skipped/unsupported counts + progress bar + top failing controls table (with portal links).

**Markdown Report** (repo/docs):
- Same structure in table format (adds MITRE column + MCSB compliance section)
- No CSS/styling

**Cost Quantification:**
- **Savings:** extracts `savingsAmount`/`annualSavingsAmount` from Advisor (Cost) and totals USD/year.
- **Implementation cost:** for recommendations matching a cost-increase pattern (geo-replication, private endpoint, NAT gateway, firewall, DDoS, WAF, Log Analytics…), queries the **Azure Retail Prices API** (public) and estimates USD/month, with fixed fallbacks if the meter isn't returned.

### Step 6 — Delivery (archive → link → notify)

This skill produces **HTML + MD artifacts**. Deliver them via the existing delivery skills (do **not** re-implement transport), following the [canonical delivery sequence](../../shared/sharepoint-archival.md#canonical-delivery-sequence-archive--link--notify):

**Archive FIRST — SharePoint (canonical copy):**
- `python shared/sharepoint_upload.py upload --site "<config: sharepoint.site_id>" --skill advisor-impact --file advisor-impact-<ts>.html` (and the `.md`). Capture the `webUrl` from stdout (`{"ok":true,"webUrl":…}`); on skip/error (exit 3/1) → `webUrl=null`, continue.

**Email (dual recipients) — via `send-email-report`:**
- Recipients: send to **both** `default_recipients` from `config.json` (e.g. `admin@<tenant>.onmicrosoft.com` **and** `caiofreitas@microsoft.com`) in a single `toRecipients` list. ⚠️ Known regression: don't drop to a single recipient.
- Subject: `"🧭 Plano de Remediação — Advisor + Defender for Cloud — <scope> (<date>)"` where `<scope>` = `tenant` / `N subscriptions` / `RG <name>`.
- **Link-only (no attachment):** advisor-impact's self-contained HTML (embedded base64, ~3 MB) is **link-only by classification** — do **not** attach it. Put the SharePoint link in the body: `🗄️ Relatório (SharePoint): <webUrl>`. (Fallback only if `webUrl=null` **and** the file is < 3 MB: attach it.)
- Body (tenant-wide): KPI line — `recommendations | 🟢 quick wins | 🟡🟠 window | 🔴 approval | 🛡️ SS current→potential | 🛡️ MCSB % | 💰 impl. cost`. Use the same numbers printed by the script.

**Teams Adaptive Card — via `send-teams-notification`:**
- Badge: `🟢 N quick wins · 🔴 M high-risk · 🛡️ SS X%→Y% · MCSB Z%` across `<scope>`.
- CTA: **Open report (SharePoint)** → `webUrl` (when present), plus a link to Azure Portal → Defender for Cloud → Recommendations.
- The Power Automate webhook URL comes from `config.json` (hardening pending: move to Key Vault).

**Agent prompt pattern (tenant-wide + unified GitHub tab + triple delivery):**
> *"Run advisor-impact tenant-wide (Mode B prefetch ARG if `az` is sandboxed). Attach the unified 🐙 GitHub tab with `--github-org <org>` (github-posture folded in — needs the sibling engine via Code Access + a gh token with admin:org/security_events). Mint the UAMI Graph token for `m365_secure_score` + `xdr_recommendations`. Then deliver: email the HTML to BOTH default recipients and post the Teams card. Use the script's own KPI numbers."*

---

## Risk Baseline Highlights (from queries.yaml)

**Safe (13 patterns):**
- enable diagnostic logging
- enable soft delete / purge protection
- enable backup
- enable MFA
- auditing should be enabled

**Low (9 patterns):**
- add nodes / scale up
- security hardening
- install endpoint protection
- encryption at rest
- vulnerabilities should be remediated

**Medium (11 patterns):**
- NAT gateway
- private link / private endpoint
- network security group
- firewall
- public network access should be disabled

**High (5 patterns):**
- ephemeral OS disk
- just-in-time
- restrict access to
- IP forwarding
- management ports should be closed

---

## Companion Files — When to Load

| File | Load timing | Notes |
|------|------------|-------|
| `generate_html_report.py` | On skill activation | Main script |
| `queries.yaml` | On skill activation | Config + risk baseline |
| `../github-posture/generate_html_report.py` | When `--github-org`/`--github-json` is passed | Sibling engine for the unified 🐙 GitHub tab (loaded via `_github_posture()` + importlib) — present automatically with **Code Access** |
| `../github-posture/queries.yaml` | Same | GH-NNN catalog (8 domains) read by the engine |
| `inventory.json` | Mode B only | Prefetch artifact (user/LLM assembles) |
| `_raw.json` | Optional (--save-raw) | Debugging artifact (workspace-only, never commit) |

---

## Output Modes

```bash
--format html    → HTML only (email)
--format md      → Markdown only (repo)
--format both    → HTML + MD (default)
```

---

## Verdict Logic

No overall verdict badge (unlike other skills). This skill produces a **phased plan** where each phase has its own action guidance:

| Phase | Action | When to execute |
|-------|--------|-----------------|
| 🟢 Safe | Quick wins | Anytime |
| 🟡 Low | Low risk | Low-traffic window |
| 🟠 Medium | Medium risk | Schedule maintenance window |
| 🔴 High | High risk | Approval + tested rollback required |

---

## Key Differences from Other Skills

1. **Entity scope:** Resource Group (not Sentinel workspace)
2. **Permission:** ARM Reader (not Sentinel Contributor / Graph permissions)
3. **Dual sources:** Advisor + Defender for Cloud
4. **Output:** Phased plan (not a score/verdict)
5. **Value metric:** Cost savings (USD/year) + operational risk

---

## Example Prompts

- *"Generate the advisor-impact plan for RG-PROD in subscription X"*
- *"What are the quick wins from Advisor and Defender for Cloud in RG-SEC-HERBEST?"*
- *"Show me the high-risk remediation items that need approval"*
- *"Consolidate Azure governance recommendations for resource group Y"*
- *"What's the cost savings potential from Advisor in RG-FINANCE?"*

---

## Implementation Notes

**Portability fixes (Windows/Linux):**
- `AZ = shutil.which("az") or "az"` → resolves `az.cmd` on Windows
- `sys.stdout.reconfigure(encoding="utf-8", errors="replace")` → prevents Unicode crashes

**Error handling:**
- Empty ARM responses → graceful degradation (empty phase, not crash)
- Missing resource in inventory → amplifier annotation (warns in report)

**Reusable from SOA/internal patterns:** Re-implemented disruption risk classification from internal Azure management helpers (not verbatim). All code is original.

**Secure Score + MCSB (ESA-derived):** The Secure Score elevation math (per-control `potentialScoreIncrease`), per-recommendation impact, MITRE/owner/`links.azurePortal` enrichment, and the **MCSB regulatory compliance** pillar are re-implemented in Python from the public **[microsoft/ESA](https://github.com/microsoft/ESA)** toolkit (MIT license) — the same data model the Enterprise Security Assessment uses (ARM/Azure Resource Graph `securityresources`). Not verbatim; no Power BI assets copied.

**Cost estimation:** `fetch_implementation_cost()` queries the public Azure Retail Prices API with an in-memory cache and a fixed-USD fallback per pattern. Unit-of-measure aware (hour×730 / month / GB). MCSB standard name is auto-discovered (current + legacy) with substring fallback.

---

## Status

- ✅ Code complete (collector + risk engine + cost + Secure Score elevation + MITRE/owner/links + MCSB compliance; tenant-wide ARG; interactive HTML filters; HTML/MD renderers)
- ✅ Smoke-tested with synthetic fixtures (cost, Secure Score elevation, per-recommendation impact, MITRE, owner, official links, MCSB compliance, multi-subscription aggregation, graceful degrade)
- ✅ Live-validated tenant-wide (2026-06): 1,173 recommendations across 2 subscriptions, Secure Score 47.4% → 100%, MCSB 84% — multi-subscription aggregation confirmed with production data
- ⏳ Pending: Integration with send-email-report

---

## Related Skills

- `org-posture` — executive **scorecard** (Org Posture Index 0–100, grade A–F). **Complementary pair, not a duplicate:** org-posture answers *"what's our grade?"*; advisor-impact answers *"what to fix, in what order, at what cost/risk to **raise** it."* The two share one Secure Score source — both read Microsoft Secure Score through the canonical reader `shared/secure_score.py`, so the headline number matches.
- `send-email-report` — for email delivery
- `send-teams-notification` — for Teams Adaptive Card
- `soc-executive-brief` — consolidator skill (different domain: SOC vs governance)
- `sentinel-documenter` — Sentinel-specific governance (different scope)

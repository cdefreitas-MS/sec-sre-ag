---
name: advisor-impact
description: 'Remediation impact planner uniting Azure Advisor (Cost/Reliability/Performance/OperationalExcellence) + Microsoft Defender for Cloud (security assessments + Secure Score + MCSB regulatory compliance) into a PHASED EXECUTION PLAN. Risk-rates each recommendation by disruption (safe/low/medium/high), identifies cascade impact on dependent workloads, maps MITRE ATT&CK tactics/techniques, links to the official Azure Portal recommendation, and generates a staged remediation plan (quick wins → maintenance window → approval+rollback). 100% READ-ONLY (ARM GET only). Quantifies cost savings (Advisor) AND implementation cost (Azure Retail Prices API), current + potential Secure Score elevation with per-recommendation impact, and MCSB compliance posture. Collector↔renderer, deterministic. Use for: azure advisor remediation, defender for cloud action plan, remediation planner, azure governance automation, advisor + defender consolidation, risk-rate azure recommendations, secure score elevation, MCSB compliance, regulatory compliance posture.'
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
- 🛡️ **Defender XDR recommendations** (optional) — if the prefetch JSON includes an `xdr_recommendations` dataset (Defender Vulnerability Management / Exposure recommendations, e.g. from the MDE API `api.securitycenter.microsoft.com/api/recommendations` or Graph exposure management), `analyze_xdr_recommendations()` summarizes it (severity from `severityScore`, exposed machines, public-exploit count, by category) and the renderer emits a dedicated **🛡️ Defender XDR** page (severity donut + KPIs + per-category bars + recommendations table). Accepts flat (MDE API) or nested (`properties`) shapes. Not collected by ARG/ARM modes — provide it via `--from-json` (the SRE Agent has the MDE permissions to fetch it).
- 🖥️ **Single-page report UX** — the HTML is a self-contained client-side app: a **home screen with a brand logo**, overview KPIs and clickable **assessment cards** (Azure Advisor, Defender for Cloud, Defender XDR, MCSB, DevOps) that open focused **pages** (`showPage()`), plus a **light/dark theme toggle** (persisted in `localStorage`). Advisor and Defender for Cloud get **separate nav entries** that deep-link into the plan page pre-filtered by source (`gotoSource()`). Power BI-style visuals throughout (severity donut, stacked/count bars). No external libraries. Markdown output stays a flat document.


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

> ⚠️ **100% READ-ONLY.** Only ARM GET operations. Recommends actions, **never applies them**.

---

## File Resolution (codeRefs-first — On Skill Activation)

`generate_html_report.py` loads `queries.yaml` from its own directory (`Path(__file__).resolve().parent`). Both files must be co-located.

```
1. codeRefs/sec-sre-ag/advisor-impact/   → if both files exist, use as <SKILL_DIR>, run from here.
2. tmp/advisor-impact/                   → if both exist (previous materialization), use it.
3. Neither → read_skill_file() each missing file → CreateFile("tmp/advisor-impact/<file>") → use tmp/.
```

> Dependency: **PyYAML** (`pip install pyyaml` if missing). No other third-party packages.

---

## Execution Environment Constraints

| Capability | Available | Notes |
|------------|-----------|-------|
| `az rest` (ARM) | ✅ | All 7 endpoints use ARM management API |
| HTTPS to prices.azure.com | ✅ (optional) | Azure Retail Prices API — **public, no auth**. Degrades to fixed fallback estimates if blocked. |
| Microsoft Graph MCP | ❌ | Not needed |
| Sentinel Data Lake | ❌ | Not used |

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
```
Runs one ARG query per dataset over `advisorresources` / `securityresources` / `resourcecontainers`. Needs **Reader** on the subscriptions. If the sandbox `az` is blocked, prefetch the ARG results (Mode B) instead.

> **Large tenants — slim projections (built-in).** The `ARG_QUERIES` use `pack()` to rebuild `properties` with **only the fields the parsers read** (drops the bloat, e.g. the large `additionalData` on container-CVE assessments). This keeps each dataset well under the agent's **~2 MB** Mode-B scratchpad cap, so the renderer's parsers (which read `properties.*`) work unchanged. **De-risked live (2026-06): 1,173 recommendations across 2 subscriptions, one with 1,028 unhealthy assessments.**
>
> If a single subscription is still enormous, page the ARG query in **batches of ~300 records** (`$top: 300` + `$skipToken`), write each batch to a temp fragment, and merge per dataset into the final `{"value":[...]}`. `run_arg()` (Mode C direct) already paginates by `$skipToken`.

**Mode A (single RG, try first):**
```bash
python3 <SKILL_DIR>/generate_html_report.py --sub <subscription_id> --rg <rg_name> \
  --category all --save-raw --output tmp/advisor-impact --format both
```

If terminal `az` fails (token cache / auth), fall back to **Mode B**.

**Mode B (prefetch — recommended):** run each ARM endpoint from `queries.yaml` via `az rest` and assemble `tmp/advisor-impact/inventory.json`:

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
  "mcsb_compliance_controls": { "value": [...] }
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

### Step 6 — Delivery (triple delivery: dual email + Teams)

This skill produces **HTML + MD artifacts**. To deliver them, reuse the existing delivery skills (do **not** re-implement transport):

**Email (dual recipients) — via `send-email-report`:**
- Recipients: send to **both** `default_recipients` from `config.json` (e.g. `admin@<tenant>.onmicrosoft.com` **and** `caiofreitas@microsoft.com`) in a single `toRecipients` list. ⚠️ Known regression: don't drop to a single recipient.
- Subject: `"🧭 Plano de Remediação — Advisor + Defender for Cloud — <scope> (<date>)"` where `<scope>` = `tenant` / `N subscriptions` / `RG <name>`.
- Attachment: the generated **HTML** file (`advisor-impact-<ts>.html`).
- Body (tenant-wide): KPI line — `recommendations | 🟢 quick wins | 🟡🟠 window | 🔴 approval | 🛡️ SS current→potential | 🛡️ MCSB % | 💰 impl. cost`. Use the same numbers printed by the script.

**Teams Adaptive Card — via `send-teams-notification`:**
- Badge: `🟢 N quick wins · 🔴 M high-risk · 🛡️ SS X%→Y% · MCSB Z%` across `<scope>`.
- CTA: link to Azure Portal → Defender for Cloud → Recommendations.
- The Power Automate webhook URL comes from `config.json` (hardening pending: move to Key Vault).

**Agent prompt pattern (tenant-wide + triple delivery):**
> *"Run advisor-impact tenant-wide (Mode B prefetch ARG if `az` is sandboxed), then deliver: email the HTML to BOTH default recipients and post the Teams card. Use the script's own KPI numbers."*

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

- `send-email-report` — for email delivery
- `send-teams-notification` — for Teams Adaptive Card
- `soc-executive-brief` — consolidator skill (different domain: SOC vs governance)
- `sentinel-documenter` — Sentinel-specific governance (different scope)

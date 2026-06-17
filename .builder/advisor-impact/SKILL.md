---
name: advisor-impact
description: 'Remediation impact planner uniting Azure Advisor (Cost/Reliability/Performance/OperationalExcellence) + Microsoft Defender for Cloud (security assessments) into a PHASED EXECUTION PLAN. Risk-rates each recommendation by disruption (safe/low/medium/high), identifies cascade impact on dependent workloads, and generates a staged remediation plan (quick wins → maintenance window → approval+rollback). 100% READ-ONLY (ARM GET only). Quantifies cost savings + secure score. Collector↔renderer, deterministic. Use for: azure advisor remediation, defender for cloud action plan, remediation planner, azure governance automation, advisor + defender consolidation, risk-rate azure recommendations.'
---

# Advisor Impact — Remediation Planner Instructions

## Purpose

**Transform Azure governance tools into an actionable playbook** by uniting **Azure Advisor** recommendations with **Microsoft Defender for Cloud** security assessments, cross-referencing them against the resource inventory, and producing a **phased execution plan** that prioritizes by *operational disruption risk* — not just severity.

| Source | Categories | What it brings |
|--------|-----------|----------------|
| **Azure Advisor** | Cost, Reliability, Performance, OperationalExcellence | Optimization recommendations + annual savings estimates |
| **Defender for Cloud** | Security | Security assessments (Microsoft.Security) + Secure Score |

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
| `az rest` (ARM) | ✅ | All 4 endpoints use ARM management API |
| Microsoft Graph MCP | ❌ | Not needed |
| Sentinel Data Lake | ❌ | Not used |

---

## Architecture (two modes)

```
 MODE A — Direct (terminal az works)
   generate_html_report.py --sub <id> --rg <name> --save-raw
     → script runs `az rest --method get --url <mgmt-url>` itself
     → collects 4 ARM endpoints → inventory → risk classification → HTML + MD
     → GUARD: if all sources come back empty (no Reader / auth failure) it exits and points to Mode B.

 MODE B — Prefetch (terminal az blocked / recommended) [PRIMARY]
   LLM collects each ARM endpoint via RunAzCliReadCommands (az rest)
     → assembles inventory.json → generate_html_report.py --from-json inventory.json
     → risk-rate + render (no Azure calls) → HTML + MD

 Both emit: tmp/advisor-impact/advisor-impact-<ts>.{html,md}. Rendering is DETERMINISTIC.
```

---

## Workflow

### Step 1 — Resolve coordinates
- `subscription` (ID, not name)
- `resourceGroup` (exact name, case-sensitive)

The user may specify:
- A specific RG to scope recommendations (targeted)
- Or provide subscription-level scope (broader)

### Step 2 — Verify Permissions
**RBAC Required:** **Reader** role at the subscription or resource group level.

> ⚠️ This is **different from Sentinel/Graph permissions**. The identity (UAMI / user) needs ARM resource read access.

If collector returns empty data, verify:
```bash
az role assignment list --assignee <UAMI_OBJECT_ID> --scope /subscriptions/<SUB>/resourceGroups/<RG>
```

### Step 3 — Collect (choose a mode)

**Mode A (try first):**
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
  "mdc_secure_score": { "value": [...] }
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
- **Hero section:** KPIs (total recommendations, 🟢🟡🟠🔴 counts, secure score %, cost savings total)
- **4 Phase Tables:**
  - Source badge (Advisor vs Defender for Cloud)
  - Recommendation title + category + priority + resource name + cost delta
  - **Inline annotations:**
    - 🟡 Cascade: "resource X changes → workloads may restart"
    - ⚠️ Amplifier: "Resource not found in inventory — verify manually"

**Markdown Report** (repo/docs):
- Same structure in table format
- No CSS/styling

**Savings Quantification:** Extracts `savingsAmount` or `annualSavingsAmount` from Advisor recommendations (Cost category) and totals them.

### Step 6 — Delivery (Optional)

This skill produces **HTML + MD artifacts**. To integrate with email/Teams delivery:
- Use the existing `send-email-report` skill pattern
- Subject: `"🧭 Plano de Remediação — Advisor + Defender for Cloud (<date>)"`
- Attachment: HTML file
- Body: 4 KPI cards (recommendations | quick wins | window | approval | secure score)

**Teams Adaptive Card:**
- Badge: `🟢 N quick wins | 🔴 M high-risk`
- CTA: Link to Azure Portal → Resource Group → Recommendations

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

---

## Status

- ✅ Code complete (500+ lines Python, 200 lines YAML)
- ✅ Smoke-tested with synthetic fixture
- ⏳ Pending: Live validation against real RG
- ⏳ Pending: PR to sec-sre-ag repo
- ⏳ Pending: Integration with send-email-report

---

## Related Skills

- `send-email-report` — for email delivery
- `send-teams-notification` — for Teams Adaptive Card
- `soc-executive-brief` — consolidator skill (different domain: SOC vs governance)
- `sentinel-documenter` — Sentinel-specific governance (different scope)

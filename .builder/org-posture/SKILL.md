---
name: org-posture
description: 'Executive one-page security posture index for board/CISO. Consolidates Microsoft Secure Score (identity & configuration), Defender for Endpoint exposure score, active Microsoft 365 Defender incidents (threat pressure), and Identity Protection high-risk users into a single weighted Org Posture Index (0–100) with a letter grade A–F and posture FORTE/MODERADA/FRACA, plus a per-pillar breakdown and the top drivers. Renders an executive scorecard HTML and delivers via email + Teams. Read-only; API-native. Trigger on "org posture", "postura geral", "security scorecard", "executive posture", "board report", "estado geral de segurança". The consolidating "mega-report" of Fases A/B. Adds three informational, index-neutral sections: 🎓 Human Risk (Attack Simulation Training — simulated users, click rate, training completion, repeat offenders), 🪪 Licensing/FinOps (subscribed SKUs · idle/unused licenses · utilization) and 🤖 NHI / Agent Identity Governance (app registrations · service principals · client-secret hygiene). Use for: org posture, postura geral, security scorecard, executive posture, board report, estado geral de segurança, NHI governance, agent identity governance, licensing/FinOps, human risk / attack simulation.'
tools:
  - RunAzCliReadCommands
---

# Org Security Posture Skill (Executive Index)

## Purpose

Give leadership **one number and one grade** for the whole environment, defensibly derived. The Org Posture Index is a weighted roll-up of four pillars — **Identity & Configuration** (Secure Score), **Endpoint** (MDE exposure), **Threat pressure** (active incidents), and **Identity risk** (high-risk users) — each normalized to 0–100. It is the consolidating report that sits on top of the Fase A/B skills: where those drill into one domain, this answers "how are we doing overall, and what's dragging us down?"

## Configuration

Reads from `config.json` at workspace root: `subscription_id`, `email.*`, `teams.*`.
Tunables (`queries.yaml`): `grade_strong=80`, `grade_moderate=60`, `weights{}`, `incident_penalty{}`, `risky_user_penalty`.

## Skill Files

| File | Purpose | When used |
|------|---------|-----------|
| [generate_html_report.py](generate_html_report.py) | collector (Graph + MDE via token/urllib) + 4-pillar index engine + HTML renderer (incl. the 3 informational sections) | execution |
| [queries.yaml](queries.yaml) | Graph/MDE endpoints + pillar weights + grade thresholds + section configs (licensing, human_risk, nhi_governance) | read at runtime by the script |

> Dependency: **PyYAML**. Self-contained except for the optional `shared/sharepoint_upload.py` at delivery. 100% read-only.

## File Resolution (codeRefs-first — On Skill Activation)

`generate_html_report.py` loads `queries.yaml` from its own directory (`Path(__file__).resolve().parent`). Both files must be co-located.

```
1. codeRefs/sec-sre-ag/org-posture/   → if both files exist, use as <SKILL_DIR>, run from here.
2. tmp/org-posture/                   → if both exist (previous materialization), use it.
3. Neither → read_skill_file() each missing file → CreateFile("tmp/org-posture/<file>") → use tmp/.
```

## When to Use

- Explicit: "org posture", "postura geral", "security scorecard", "executive/board report", "estado geral de segurança".
- Scheduled: monthly executive posture snapshot.
- After a sweep: run the Fase A/B skills, then this for the consolidated headline.

## Posture Verdict

**Org Posture Index** = `0.35·Identity + 0.25·Endpoint + 0.25·Threat + 0.15·IdentityRisk` (each pillar 0–100).

- **FORTE** (green): index ≥ 80 (grade A/B).
- **MODERADA** (yellow): 60 ≤ index < 80 (grade C/D).
- **FRACA** (red): index < 60 (grade F).

Pillar sub-scores:
- **Identity** = Secure Score % (`currentScore/maxScore`).
- **Endpoint** = `100 − exposureScore` (exposure is lower-is-better).
- **Threat** = `100 − Σ incident_penalty[severity]` (active incidents).
- **IdentityRisk** = `100 − (highRiskUsers × 12)`.

## Workflow

### Step 1: Read config + acquire tokens
- Graph token (`https://graph.microsoft.com`) and MDE token (`https://api.securitycenter.microsoft.com`).

### Step 2: Collect — `RunAzCliReadCommands` (REST GET)
**Graph:**
- `GET /v1.0/security/secureScores?$top=1` → latest `currentScore`/`maxScore`.
- `GET /v1.0/security/incidents?$filter=status eq 'active'&$top=500` → severities of open incidents.
- `GET /v1.0/identityProtection/riskyUsers?$filter=riskLevel eq 'high'&$top=500` → count.

**MDE:**
- `GET /api/exposureScore` → org exposure score.

**Graph — informational sections (do NOT affect the index; degrade gracefully on 402/403/404):**
- `GET /v1.0/subscribedSkus` → 🪪 **Licensing/FinOps** (total/assigned/idle per SKU). Perm: `Organization.Read.All` / `Directory.Read.All`.
- `GET /v1.0/security/attackSimulation/simulations?$top=50` + `GET /v1.0/reports/security/getAttackSimulationSimulationUserCoverage` · `...getAttackSimulationTrainingUserCoverage` · `...getAttackSimulationRepeatOffenders` → 🎓 **Human Risk** (simulated users, click rate, training %, repeat offenders). Perm: `AttackSimulation.Read.All` (may need a one-time grant on the agent identity).
- `GET /v1.0/applications?$top=500&$select=id,displayName,passwordCredentials,keyCredentials` + `GET /v1.0/servicePrincipals?$top=500&$select=id,displayName,servicePrincipalType,accountEnabled` → 🤖 **NHI / Agent Identity Governance** (app registrations · service principals · % apps with client secret · expired/expiring ≤ 90d · long-lived > 180d). Perm: `Application.Read.All`. Rubric: federation/cert over client secrets (agent-identity-governance guidance).

### Step 3: Score (in the agent)
- Compute the four pillar sub-scores; clamp each to [0,100].
- Weighted sum → index; map to grade (`[[90,A],[80,B],[70,C],[60,D],[0,F]]`) and posture.
- Capture the **driver** string per pillar (raw numbers) for transparency.

### Step 4: Render HTML
`reports/org-posture/<YYYYMMDD_HHMMSS>.html`: big **grade** + index, posture badge, 4 raw-metric cards (Secure Score % / Exposure / Active incidents / Risky users), and a **pillar breakdown** table with sub-score bars, weights, contributions and drivers.

Below the pillar table, three **informational sections** render when their data is available — they **do not** change the Org Posture Index (kept pure/comparable): **🎓 Risco Humano** (Attack Simulation: usuários simulados · taxa de comprometimento 🔴/🟠/✅ · treinamento concluído % · reincidentes), **🪪 Licenciamento & Governança (FinOps)** (SKUs por total/atribuídas/ociosas/utilização, com flag ⚠️ de subutilização) and **🤖 Governança de Identidades de Agente / NHI** (app registrations · service principals · % apps com client secret 🔴/🟠/✅ · segredos expirados · vencendo ≤ 90d · validade > 180d — higiene de credenciais da população não-humana). Each is **omitted** when its source returns no data/permission.

### Step 5: Deliver (archive → link → notify)

> Follow the [canonical delivery sequence](../../shared/sharepoint-archival.md#canonical-delivery-sequence-archive--link--notify) — reuse the delivery skills (do **not** re-implement transport). Never email-only; if `sharepoint.site_id` / `teams.webhook_url` is missing in config, report it instead of skipping.

1. **SharePoint (first)**: `python shared/sharepoint_upload.py upload --site "<config: sharepoint.site_id>" --skill org-posture --file <html>` (and the `.md`). Capture `webUrl` + `folderUrl` from stdout; skip/error → continue (best-effort, never blocks email/Teams).
2. **send-email-report**: title "🛡️ Org Posture: {grade} ({date})", posture color. Small report (< 3 MB) → **attach the HTML** + body link `📂 Abrir no SharePoint: <folderUrl>` when present. 🔴 The link MUST be the SharePoint `folderUrl` (a `sharepoint.com` URL) — never a `teams.microsoft.com` / webhook link. Grade + 4 cards + pillar table.
3. **send-teams-notification**: Adaptive Card with grade, index, posture, weakest pillar + **Abrir no SharePoint** action → `folderUrl` (webhook only; never Graph).

### Step 6: Audit + chat
Save `reports/org-posture/<timestamp>.json`. Then:
```
🛡️ ORG POSTURE — nota {A–F} · índice {n}/100 · {FORTE|MODERADA|FRACA}
   🔑 Secure Score {pct}%  ·  💻 Exposure {n}  ·  🚨 Incidentes ativos {n}  ·  ⚠️ Risky users {n}
   Pilar mais fraco: {pilar} ({sub-score})
   📧 Email + 💬 Teams + 🗄️ SharePoint
```

## Related skills

- **advisor-impact** — the **remediation plan** that complements this scorecard. Where org-posture gives the *grade*, advisor-impact gives the prioritized *plan* (Azure Advisor + Defender for Cloud recommendations, phased by impact/cost/risk) to **raise** it. **Drill-down:** after presenting the index, recommend running **advisor-impact** to act on the Identity/Endpoint pillars ("📋 Plano para subir a nota → advisor-impact").
- **graph-least-privilege** — the **operational depth** of the 🤖 NHI section. Where org-posture summarizes credential hygiene (counts, secret %), graph-least-privilege right-sizes Graph **permissions per app** (granted × actually-used from `MicrosoftGraphActivityLogs`), flagging dormant apps and excess scopes. **Drill-down:** when the NHI section flags secrets/over-provisioning, recommend running **graph-least-privilege** ("🔐 Right-sizing de permissões → graph-least-privilege").
- **Shared Secure Score:** the Identity pillar reads Microsoft Secure Score by the same canonical *latest-by-`createdDateTime`* method as `shared/secure_score.py`; advisor-impact uses that shared reader, so the number matches across both reports.

## Common Errors

| Error | Meaning | Fix |
|---|---|---|
| `secureScores` empty | No score history / missing `SecurityEvents.Read.All` | Identity pillar = 0; note the gap (most common when newly onboarded) |
| `exposureScore` empty | No MDE devices onboarded | Endpoint pillar reads 100 − 0 = 100 (no exposure); annotate "sem devices MDE" so it isn't read as a strength |
| `security/incidents` 403 | Missing `SecurityIncident.Read.All` | Already granted here; if 403, re-check the grant |
| `riskyUsers` empty | P2/Identity Protection not licensed | Identity-risk pillar = 100; annotate the licensing caveat |
| `subscribedSkus` 403 | Missing `Organization.Read.All` / `Directory.Read.All` | 🪪 Licensing section **omitted** (informational — index unaffected) |
| attackSimulation 403 / 404 | Missing `AttackSimulation.Read.All`, or ATS not configured / O365 unlicensed | 🎓 Human Risk section **omitted** (informational) — grant the perm to enable, or ignore |
| `applications` / `servicePrincipals` 403 | Missing `Application.Read.All` | 🤖 NHI Governance section **omitted** (informational — index unaffected); UAMI already holds `Application.Read.All` here |
| Index looks high but tenant is new | Empty data ≠ good posture | Show the drivers; flag pillars whose source returned no data |

## Rules

- ✅ **READ-ONLY** — never writes; no containment handoff.
- ✅ **ALWAYS** show the per-pillar breakdown + drivers (the index must be defensible, never a black box).
- ✅ **ALWAYS** annotate pillars whose source returned no data (empty ≠ healthy).
- ✅ **ALWAYS** deliver triple (email + Teams) and save the audit JSON.
- ⛔ **NEVER** attempt git operations.

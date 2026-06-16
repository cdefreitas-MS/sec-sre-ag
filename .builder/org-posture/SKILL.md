---
name: org-posture
description: Executive one-page security posture index for board/CISO. Consolidates Microsoft Secure Score (identity & configuration), Defender for Endpoint exposure score, active Microsoft 365 Defender incidents (threat pressure), and Identity Protection high-risk users into a single weighted Org Posture Index (0–100) with a letter grade A–F and posture FORTE/MODERADA/FRACA, plus a per-pillar breakdown and the top drivers. Renders an executive scorecard HTML and delivers via email + Teams. Read-only; API-native. Trigger on "org posture", "postura geral", "security scorecard", "executive posture", "board report", "estado geral de segurança". The consolidating "mega-report" of Fases A/B.
tools:
  - RunAzCliReadCommands
---

# Org Security Posture Skill (Executive Index)

## Purpose

Give leadership **one number and one grade** for the whole environment, defensibly derived. The Org Posture Index is a weighted roll-up of four pillars — **Identity & Configuration** (Secure Score), **Endpoint** (MDE exposure), **Threat pressure** (active incidents), and **Identity risk** (high-risk users) — each normalized to 0–100. It is the consolidating report that sits on top of the Fase A/B skills: where those drill into one domain, this answers "how are we doing overall, and what's dragging us down?"

## Configuration

Reads from `config.json` at workspace root: `subscription_id`, `email.*`, `teams.*`.
Tunables (`queries.yaml`): `grade_strong=80`, `grade_moderate=60`, `weights{}`, `incident_penalty{}`, `risky_user_penalty`.

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

### Step 3: Score (in the agent)
- Compute the four pillar sub-scores; clamp each to [0,100].
- Weighted sum → index; map to grade (`[[90,A],[80,B],[70,C],[60,D],[0,F]]`) and posture.
- Capture the **driver** string per pillar (raw numbers) for transparency.

### Step 4: Render HTML
`reports/org-posture/<YYYYMMDD_HHMMSS>.html`: big **grade** + index, posture badge, 4 raw-metric cards (Secure Score % / Exposure / Active incidents / Risky users), and a **pillar breakdown** table with sub-score bars, weights, contributions and drivers.

### Step 5: Deliver (triple)
1. **send-email-report**: title "🛡️ Org Posture: {grade} ({date})", posture color, attach HTML, grade + 4 cards + pillar table.
2. **send-teams-notification**: Adaptive Card with grade, index, posture, weakest pillar.

### Step 6: Audit + chat
Save `reports/org-posture/<timestamp>.json`. Then:
```
🛡️ ORG POSTURE — nota {A–F} · índice {n}/100 · {FORTE|MODERADA|FRACA}
   🔑 Secure Score {pct}%  ·  💻 Exposure {n}  ·  🚨 Incidentes ativos {n}  ·  ⚠️ Risky users {n}
   Pilar mais fraco: {pilar} ({sub-score})
   📧 Email + 💬 Teams enviados
```

## Common Errors

| Error | Meaning | Fix |
|---|---|---|
| `secureScores` empty | No score history / missing `SecurityEvents.Read.All` | Identity pillar = 0; note the gap (most common when newly onboarded) |
| `exposureScore` empty | No MDE devices onboarded | Endpoint pillar reads 100 − 0 = 100 (no exposure); annotate "sem devices MDE" so it isn't read as a strength |
| `security/incidents` 403 | Missing `SecurityIncident.Read.All` | Already granted here; if 403, re-check the grant |
| `riskyUsers` empty | P2/Identity Protection not licensed | Identity-risk pillar = 100; annotate the licensing caveat |
| Index looks high but tenant is new | Empty data ≠ good posture | Show the drivers; flag pillars whose source returned no data |

## Rules

- ✅ **READ-ONLY** — never writes; no containment handoff.
- ✅ **ALWAYS** show the per-pillar breakdown + drivers (the index must be defensible, never a black box).
- ✅ **ALWAYS** annotate pillars whose source returned no data (empty ≠ healthy).
- ✅ **ALWAYS** deliver triple (email + Teams) and save the audit JSON.
- ⛔ **NEVER** attempt git operations.

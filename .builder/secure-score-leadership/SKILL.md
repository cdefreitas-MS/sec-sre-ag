---
name: secure-score-leadership
description: 'Executive Microsoft Secure Score report for leadership (board / CISO). Pulls the Graph Secure Score API (current score, 30/90-day trend, comparative averages vs all tenants / similar seat count / industry) and the control profiles catalog, then surfaces the highest-ROI "quick wins" (max score gain × low implementation cost × low user impact) and a per-category breakdown (Identity, Data, Device, Apps, Infrastructure). Renders a clean executive HTML and delivers it via email + Teams. Trigger on "secure score report", "postura secure score", "leadership security posture", or scheduled (weekly/monthly). Read-only. Uses Graph SecurityEvents.Read.All (already granted).'
tools:
  - RunAzCliReadCommands
---
# Secure Score Leadership Skill

## Purpose

Produce an **executive-grade Microsoft Secure Score report** for leadership. Answers: *Where do we stand? Are we improving? How do we compare to peers? What are the highest-ROI actions to raise the score?* — in a clean, board-ready format. Low effort, high appeal: reuses Graph read permissions already granted, no new infrastructure.

## Configuration

Reads from `config.json` at workspace root:
- `subscription_id` (for the token), `email.*`, `teams.*` (delivery)

Constants:
- Graph API: `https://graph.microsoft.com` (v1.0)
- Permission: `SecurityEvents.Read.All` (Application) — part of the granted Security perms. If 403 → grant `SecurityEvents.Read.All` to the UAMI.

Tunables:
- `TREND_SNAPSHOTS = 90` (daily score snapshots to pull)
- `QUICK_WINS = 8` (top controls to recommend)
- `STRONG = 70`, `MODERATE = 50` (posture % thresholds)

## When to Use

- Explicit: "secure score report", "relatório de secure score", "postura para liderança", "como estamos no Secure Score"
- Scheduled: weekly or monthly leadership cadence

## Workflow

### Step 1: Read config + acquire Graph token
⛔ Use the verified Python token-via-file pattern (operational-patterns §4). `az rest --body @file` is broken.
```bash
az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv --subscription <SUB_ID>
```
Save to `tmp/securescore/graph_token.txt`. `rm -f` after use.

### Step 2: Collect — two Graph GETs (via Python urllib)

**G1 — Secure Score snapshots (trend)**
```
GET https://graph.microsoft.com/v1.0/security/secureScores?$top=90
```
Each item: `currentScore`, `maxScore`, `createdDateTime`, `activeUserCount`, `licensedUserCount`, `enabledServices[]`, `averageComparativeScores[]` (each = {basis, averageScore} where basis ∈ AllTenants / TotalSeats / IndustryTypes / CurrentRank), `controlScores[]` (each = {controlName, score, controlCategory, description, scoreInPercentage}).

**G2 — Control profiles catalog (remediation + cost/impact)**
```
GET https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?$top=300
```
Each item: `id` (controlName), `title`, `maxScore`, `rank`, `controlCategory`, `actionType`, `implementationCost` (Low/Moderate/High), `userImpact` (Low/Moderate/High), `tier`, `threats[]`, `remediation`, `service`, `deprecated`.

### Step 3: Compute (in the agent)

Sort G1 by `createdDateTime` desc. `latest = scores[0]`.

- **Posture**: `pct = round(latest.currentScore / latest.maxScore * 100, 1)`
  - `pct ≥ 70` → **FORTE** (green) · `50–70` → **MODERADA** (yellow) · `< 50` → **FRACA** (red)
- **Trend**: find snapshot ~7d ago and ~30d ago by date; `delta7 = current − score7`, `delta30 = current − score30`. Arrow ▲/▼/▬.
- **Comparative**: from `latest.averageComparativeScores`, pull `AllTenants`, `TotalSeats` (similar size), `IndustryTypes`. Show our score vs each average (ahead/behind).
- **Category breakdown**: group `latest.controlScores` by `controlCategory` (Identity, Data, Device, Apps, Infrastructure) → sum(score)/sum(maxScore of matching profiles) per category.
- **Quick wins**: join `controlScores` (current score) with G2 profiles on controlName. Keep controls where `score < maxScore` and `deprecated != true`. Rank by ROI:
  ```
  ROI = (maxScore − score)                      # potential gain
        × costWeight(implementationCost)         # Low=1.0, Moderate=0.6, High=0.3
        × impactWeight(userImpact)               # Low=1.0, Moderate=0.7, High=0.4
  ```
  Take top `QUICK_WINS`. For each show: title, +points available, implementationCost, userImpact, service, 1-line remediation, threats.

### Step 4: Render executive HTML
`reports/secure-score/<YYYYMMDD_HHMMSS>.html` with:
- Posture badge (FORTE/MODERADA/FRACA) + big `currentScore / maxScore (pct%)`
- 4 metric cards: Score % | Δ 30d | vs Tenants Médios | vs Mesmo Porte
- Trend sparkline/line (last 90d) — inline SVG
- Category breakdown bars (Identity/Data/Device/Apps/Infra)
- **Quick Wins table** (the leadership ask): control, +pts, custo, impacto, serviço, ação
- Footer: active users, enabled services, generation time

### Step 5: Deliver (archive → link → notify)
1. **SharePoint (first)**: `python shared/sharepoint_upload.py upload --site "<config: sharepoint.site_id>" --skill secure-score-leadership --file <html>` (and the `.md`). Capture `webUrl` + `folderUrl` from stdout; skip/error → continue (best-effort, never blocks email/Teams).
2. **send-email-report**: title "📈 Secure Score — Liderança ({date})", verdict color by posture (FORTE→green, MODERADA→yellow, FRACA→red), subject timestamp suffix. Small report (< 3 MB) → **attach the HTML** + body link `📂 Abrir no SharePoint: <folderUrl>` when present. 🔴 The link MUST be the SharePoint `folderUrl` — never a `teams.microsoft.com` / webhook link. Fill 4 metric cards + top quick wins as findings.
3. **send-teams-notification**: Adaptive Card with posture, score %, Δ30d, top 3 quick wins + **Abrir no SharePoint** action → `folderUrl` (webhook only; never Graph).

### Step 6: Audit + chat
Save `reports/secure-score/<timestamp>.json` (posture, score, max, pct, delta7, delta30, comparatives, top quick wins). Then:
```
📈 SECURE SCORE — {date}
   Postura: {FORTE|MODERADA|FRACA}  ·  {current}/{max} ({pct}%)
   Tendência 30d: {▲/▼ delta}
   vs Tenants médios: {ahead/behind by X}  ·  vs Mesmo porte: {…}
   🎯 Top quick win: {control} (+{pts} pts, custo {cost})
   📧 Email + 💬 Teams enviados
```

## Common Errors

| Error | Meaning | Fix |
|---|---|---|
| HTTP 403 on `/security/secureScores` | `SecurityEvents.Read.All` missing | Grant it to the UAMI; wait 15-60 min |
| `averageComparativeScores` missing a basis | Tenant too new / not enough peers | Show available bases only; note "comparativo parcial" |
| `controlScores` controlName not in profiles | Deprecated/retired control | Skip from quick wins (already filtered by `deprecated`) |
| Empty `secureScores` | No score history yet | Report current only, note "sem histórico de tendência" |
| Score % looks low | Many controls unimplemented | That's the point — surface quick wins |

## Rules

- ✅ **READ-ONLY**. This skill never changes configuration — it recommends.
- ✅ **ALWAYS** rank quick wins by ROI (gain × low-cost × low-impact), not raw points — leadership wants efficient wins.
- ✅ **ALWAYS** include the comparative (vs peers) — that's what leadership cares about most.
- ✅ **ALWAYS** deliver triple (email + Teams) and save the audit JSON.
- ⛔ **NEVER** leave the Graph token on disk — `rm -f` after use.
- ⛔ **NEVER** attempt git operations.
```

---
name: aitm-dashboard
description: Tenant-wide Adversary-in-the-Middle (AiTM) and token-theft hunt. Identity signals (sign-ins/risk/MFA) come from Microsoft Sentinel KQL (SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs); BEC inbox-rule persistence comes from Defender XDR via Microsoft Graph runHuntingQuery (CloudAppEvents — an XDR Advanced Hunting table that does not exist in Sentinel). Data is routed by origin (not a blind fallback). Surfaces the hallmark AiTM signal — risky SUCCESSFUL sign-ins where MFA was satisfied via a stolen session token — plus anomalous-token risk events, session anomalies (same user authenticating from 2+ countries in a short window = token replay / impossible travel), MFA-method tampering, and inbox-rule persistence. Computes a weighted AiTM risk score, classifies CLEAR/MONITOR/ELEVATED, renders an executive HTML, and delivers via email + Teams. Can hand off flagged users to forensic-user-investigation / contain-compromised-user. Trigger on "AiTM", "token theft", "session hijack", "MFA bypass", "phishing dashboard", "adversary in the middle". Read-only collection; action only via handoff with a safety gate.
tools:
  - RunAzCliReadCommands
  - RunAzCliWriteCommands
---

# AiTM & Token Theft Dashboard Skill

## Purpose

Hunt **Adversary-in-the-Middle** across the tenant. AiTM proxies (Evilginx, EvilProxy, Tycoon) steal the **session token after** the user completes MFA — so the malicious sign-in shows up as a **successful, MFA-satisfied, but risky** event from an anomalous location. This skill correlates that signal with token-issuer anomalies, multi-country session replay, MFA-method tampering and the classic post-compromise **BEC inbox rule**, scoring tenant-wide AiTM risk into one dashboard. Companion to `user-scope-drift` (behavioral drift) and `forensic-user-investigation` (per-user deep dive).

## Configuration

Reads from `config.json` at workspace root:
- `subscription_id`, `azure_mcp.workspace_name`, `sentinel_workspace_id`
- `email.*`, `teams.*` (delivery)

Tunables (`queries.yaml` → `parameters`):
- `LOOKBACK_DAYS = 7` (operational hunt window)
- `SESSION_WINDOW_HOURS = 1`, `SESSION_COUNTRY_MIN = 2` (token-replay / impossible-travel heuristic)

## When to Use

- Explicit: "AiTM dashboard", "token theft", "session hijack", "MFA bypass", "EvilProxy/Evilginx hunt".
- Scheduled: weekly tenant-wide AiTM sweep.
- Auto: when an alert mentions `anomalousToken` / `tokenIssuerAnomaly` → run this for the tenant picture.

## Risk Verdict

- **ELEVATED** (red): any `anomalousToken`/`tokenIssuerAnomaly` risk event, any suspicious **inbox rule** (forward/redirect/delete), or ≥3 session anomalies.
- **MONITOR** (yellow): risky successful sign-ins > 0, any MFA-method change, or ≥1 session anomaly.
- **CLEAR** (green): none of the above.

**Weighted AiTM score** = `25·anomalousToken + 30·inboxRule + 15·sessionAnomaly + 5·riskySuccess + 10·mfaChange` (inbox rule + token = strongest signals of active AiTM/BEC).

## Workflow

### Step 1: Read config
- Load `sentinel_workspace_id`, `subscription_id`.

### Step 2: Collect — roteamento por origem do dado
O AiTM cruza tabelas de origens diferentes; cada sinal vem da sua fonte de registro:
- **Sentinel KQL** (`QueryLogAnalyticsByWorkspaceId`) — tabelas AAD que vivem no Log Analytics: **Q1 overview, Q2 risky_success, Q3 anomalous_token, Q4 session_anomaly, Q5 mfa_changes, Q7 top_targets** (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`).
- **Graph runHuntingQuery** (`RunAzCliReadCommands` → `POST /security/runHuntingQuery`) — tabela **XDR-native que NÃO existe no Sentinel**: **Q6 inbox_rules** (`CloudAppEvents`).

All parameterized by `{lookback_days}`, `{session_window_hours}`, `{session_country_min}`.

**Q1 — Overview**
```kql
let win = {lookback_days}d;
SigninLogs
| where TimeGenerated >= ago(win)
| summarize TotalSignins=count(),
    RiskySuccess=countif(ResultType == 0 and RiskLevelDuringSignIn in ("high","medium")),
    AnomalousToken=countif(RiskEventTypes_V2 has_any ("anomalousToken","tokenIssuerAnomaly")),
    Unfamiliar=countif(RiskEventTypes_V2 has_any ("unfamiliarFeatures","maliciousIPAddress","suspiciousBrowser")),
    AffectedUsers=dcountif(UserPrincipalName, RiskLevelDuringSignIn in ("high","medium")),
    FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
```

**Q2 — Risky SUCCESSFUL sign-ins** (the AiTM watermark)
```kql
let win = {lookback_days}d;
SigninLogs
| where TimeGenerated >= ago(win)
| where ResultType == 0
| where RiskLevelDuringSignIn in ("high","medium") or RiskState in ("atRisk","confirmedCompromised")
| extend Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, UserPrincipalName, IPAddress, Country, AppDisplayName,
          RiskLevelDuringSignIn, RiskState, AuthenticationRequirement
| order by TimeGenerated desc | take 50
```

**Q3 — Anomalous token / token-issuer anomaly**
```kql
let win = {lookback_days}d;
SigninLogs
| where TimeGenerated >= ago(win)
| where RiskEventTypes_V2 has_any ("anomalousToken","tokenIssuerAnomaly","investigationsThreatIntelligence")
| extend Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, UserPrincipalName, IPAddress, Country, AppDisplayName,
          RiskEvents = tostring(RiskEventTypes_V2), ResultType
| order by TimeGenerated desc | take 50
```

**Q4 — Session anomaly** (token replay / impossible travel — extrai `Country` em cada perna do union p/ evitar SEM0139)
```kql
let win = {lookback_days}d;
union isfuzzy=true
  (SigninLogs | extend Country = tostring(LocationDetails.countryOrRegion)),
  (AADNonInteractiveUserSignInLogs | extend Country = tostring(LocationDetails.countryOrRegion))
| where TimeGenerated >= ago(win)
| where ResultType == 0
| summarize Countries=dcount(Country), IPs=dcount(IPAddress),
            CountryList=make_set(Country, 8), IPList=make_set(IPAddress, 8)
    by UserPrincipalName, bin(TimeGenerated, {session_window_hours}h)
| where Countries >= {session_country_min}
| project Window=TimeGenerated, UserPrincipalName, Countries, IPs,
          CountryList=tostring(CountryList), IPList=tostring(IPList)
| order by Countries desc, IPs desc | take 40
```

**Q5 — MFA method tampering**
```kql
let win = {lookback_days}d;
AuditLogs
| where TimeGenerated >= ago(win)
| where OperationName has_any ("security info", "authentication method", "StrongAuthentication")
| extend Target = tostring(TargetResources[0].userPrincipalName),
         Initiator = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, Target, Initiator, Result
| order by TimeGenerated desc | take 40
```

**Q6 — BEC inbox-rule persistence** — **XDR via Graph** (`CloudAppEvents` não existe no Sentinel → fonte de registro = Defender XDR Advanced Hunting). Resposta em `results[]`.
```http
POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
Content-Type: application/json

{"Query":"CloudAppEvents | where Timestamp >= ago({lookback_days}d) | where ActionType in ('New-InboxRule','Set-InboxRule','Update-InboxRules','UpdateInboxRules') | where RawEventData has_any ('ForwardTo','ForwardAsAttachmentTo','RedirectTo','DeleteMessage','MoveToFolder') | project Timestamp, AccountDisplayName, ActionType, IPAddress, Rule=substring(tostring(RawEventData),0,300) | order by Timestamp desc | take 40"}
```
> XDR Advanced Hunting usa `Timestamp` (não `TimeGenerated`). Perm: `ThreatHunting.Read.All` (já concedida à UAMI).

**Q7 — Top targets**
```kql
let win = {lookback_days}d;
SigninLogs
| where TimeGenerated >= ago(win)
| where RiskLevelDuringSignIn in ("high","medium")
     or RiskEventTypes_V2 has_any ("anomalousToken","tokenIssuerAnomaly","unfamiliarFeatures")
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Indicators=count(), RiskySuccess=countif(ResultType == 0),
            Countries=dcount(Country), IPs=dcount(IPAddress), LastSeen=max(TimeGenerated)
    by UserPrincipalName
| order by Indicators desc | take 25
```

### Step 3: Score + classify (in the agent)
- Apply the weighted score; pick the verdict per the **Risk Verdict** rules.
- Cross-reference Q2↔Q4↔Q7: a user appearing in risky-success **and** session-anomaly **and** with an inbox rule is a high-confidence AiTM victim.

### Step 4: Render HTML
`reports/aitm/<YYYYMMDD_HHMMSS>.html` with: verdict badge + score + affected users, 5 metric cards (anomalous token / risky success / session anomaly / inbox rules / MFA changes), then tables for each query.

### Step 5: Deliver (archive → link → notify)
1. **SharePoint (first)**: `python shared/sharepoint_upload.py upload --site "<config: sharepoint.site_id>" --skill aitm-dashboard --file <html>` (and the `.md`). Capture `webUrl` + `folderUrl` from stdout; skip/error → continue (best-effort, never blocks email/Teams).
2. **send-email-report**: title "🎣 AiTM Dashboard ({date})", verdict color. Small report (< 3 MB) → **attach the HTML** + body link `📂 Abrir no SharePoint: <folderUrl>` when present. 🔴 The link MUST be the SharePoint `folderUrl` — never a `teams.microsoft.com` / webhook link. 5 metric cards + top targets.
3. **send-teams-notification**: Adaptive Card with verdict, score, top flagged users + **Abrir no SharePoint** action → `folderUrl` (webhook only; never Graph).

### Step 6: (Conditional) hand off
- If verdict ELEVATED for specific users → recommend `forensic-user-investigation <upn>` (deep dive) and, if confirmed, `contain user <upn>`.
- **ONLY** auto-invoke containment with `--auto-contain`; never Global Admins / UAMI / sender.

### Step 7: Audit + chat
Save `reports/aitm/<timestamp>.json`. Then:
```
🎣 AiTM DASHBOARD ({window})
   Verdict: {ELEVATED|MONITOR|CLEAR} · score {n}
   🔑 Anomalous token: {n}  ·  ⚠️ Risky success: {n}  ·  🌐 Session anomaly: {n}
   📨 Inbox rules: {n}  ·  🔐 MFA changes: {n}  ·  👥 Afetados: {n}
   📧 Email + 💬 Teams enviados
   ➡️ {se ELEVATED: "Recomendado: forensic-user-investigation {top_user}"}
```

## Common Errors

| Error | Meaning | Fix |
|---|---|---|
| `RiskEventTypes_V2` / `RiskLevelDuringSignIn` blank | Entra ID P2 / Identity Protection not licensed | Rely on session-anomaly (Q4) + MFA changes (Q5); note the gap |
| `CloudAppEvents` empty (Q6 via Graph) | MDA/MDO não onboarded ou sem inbox-rule no período | Painel inbox-rules fica vazio; registre "sem telemetria de inbox-rule (XDR)". NÃO cai pro Sentinel — essa tabela não existe lá |
| `runHuntingQuery` 403 | Falta `ThreatHunting.Read.All` | Já concedida à UAMI; se 403, revalidar o grant |
| `AADNonInteractiveUserSignInLogs` huge | High volume | Keep the `bin()` + `take`; window via `{lookback_days}` |
| SEM0139 on Q4 | dynamic sub-field after `union` | Already fixed — `Country` is extracted in each union leg |
| `dcountif` not recognized | very old cluster | Replace with `dcount(iff(<cond>, UserPrincipalName, ""))` |

## Rules

- ✅ **READ-ONLY** for the hunt. The ONLY write path is the forensic/containment handoff.
- ⛔ **NEVER** auto-contain without `--auto-contain`; default is recommend-only.
- ⛔ **NEVER** target Global Admins / UAMI / sender mailbox in any handoff.
- ✅ **ALWAYS** deliver triple (email + Teams) and save the audit JSON.
- ✅ Prefer Sentinel KQL; fall back to Identity Protection / XDR Graph only when a table is empty.
- ⛔ **NEVER** attempt git operations.

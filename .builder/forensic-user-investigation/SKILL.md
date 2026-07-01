---
name: forensic-user-investigation
description: 'Deep-dive forensic investigation of ONE user account from Microsoft Sentinel + Defender signals. Builds a single-user timeline, geo distribution (sign-in countries/IPs), authentication & Conditional Access tracing, risk/IOC view (risky sign-ins, Identity Protection), correlated security alerts, directory audit operations, and device logons. Renders an executive forensic HTML and delivers via email + Teams; can hand off to contain-compromised-user when compromise is confirmed. Trigger on "investigate user X", "forensic de usuário", "deep dive on <upn>", "is <user> compromised". Requires a target UPN. Read-only collection; action only via the containment handoff with a safety gate. Uses Sentinel (Log Analytics) + Graph read perms already granted.'
tools:
  - RunAzCliReadCommands
  - RunAzCliWriteCommands
---
# Forensic User Investigation Skill

## Purpose

Produce a **deep, single-user forensic report** — the drill-down you run when a user is flagged (by `user-scope-drift`, an alert, or a tip). Assembles sign-in timeline, geomap, auth/Conditional-Access tracing, risk/IOC, correlated alerts, directory changes, and device logons into one investigator-grade HTML. Natural companion to `user-scope-drift` (detection) → this (investigation) → `contain-compromised-user` (response).

## Configuration

Reads from `config.json` at workspace root:
- `subscription_id`, `azure_mcp.workspace_name`, `sentinel_workspace_id`
- `email.*`, `teams.*` (delivery)

Tunables:
- `LOOKBACK_DAYS = 30` (forensic window — shorter + deeper than the drift skills)
- `RISK_HIGH_ELEVATES = true` (any high-risk sign-in or confirmedCompromised → ELEVATED)

## When to Use

- Explicit: "investigate user `<upn>`", "forensic de usuário", "deep dive on `<upn>`", "`<user>` está comprometido?"
- Auto: after `user-scope-drift` FLAGs a user → run this for the full picture before deciding on containment.
- **Requires a `target` UPN** (single user; not tenant-wide).

## Risk Verdict

- **ELEVATED** (red): any high-risk sign-in, `RiskState in (atRisk, confirmedCompromised)`, or a High/Critical security alert in the window.
- **MONITOR** (yellow): medium-risk sign-ins, any alert, or a Conditional-Access failure spike / new-country sign-in.
- **CLEAR** (green): none of the above.

## Workflow

### Step 1: Resolve target + read config
- Parse `target` UPN from the prompt (**required** — abort if missing). Resolve display name via Graph if useful.
- Load `sentinel_workspace_id`, `subscription_id`.

### Step 2: Collect — roteamento por origem do dado
Cada sinal vem da sua fonte de registro:
- **Sentinel KQL** (`QueryLogAnalyticsByWorkspaceId`) — tabelas AAD que vivem no Log Analytics: **Q1 overview, Q2 geo, Q3 auth_ca, Q4 risky, Q5 alerts, Q6 audit** (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `SecurityAlert`, `AuditLogs`).
- **Graph runHuntingQuery** (`RunAzCliReadCommands` → `POST /security/runHuntingQuery`) — tabela **XDR-native que NÃO existe no Sentinel**: **Q7 devices** (`DeviceLogonEvents`).

All queries parameterized by `{target}` (the UPN) and `{lookback_days}`.

**Q1 — Overview**
```kql
let target = "{target}";
// extrair sub-campos dynamic DENTRO de cada perna do union (evita KQL SEM0139 no summarize pós-union)
union isfuzzy=true
  (SigninLogs | extend Country=tostring(LocationDetails.countryOrRegion), DeviceId=tostring(DeviceDetail.deviceId)),
  (AADNonInteractiveUserSignInLogs | extend Country=tostring(LocationDetails.countryOrRegion), DeviceId=tostring(DeviceDetail.deviceId))
| where TimeGenerated >= ago({lookback_days}d)
| where UserPrincipalName =~ target
| summarize Total=count(), Success=countif(ResultType == "0"), Fail=countif(ResultType != "0"),
            Apps=dcount(AppDisplayName), Resources=dcount(ResourceDisplayName),
            IPs=dcount(IPAddress), Countries=dcount(Country), Devices=dcount(DeviceId),
            RiskHigh=countif(RiskLevelDuringSignIn == "high"),
            RiskMedium=countif(RiskLevelDuringSignIn == "medium"),
            FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
```

**Q2 — Geo distribution (geomap/heatmap)**
```kql
let target = "{target}";
SigninLogs
| where TimeGenerated >= ago({lookback_days}d)
| where UserPrincipalName =~ target
| extend Country = tostring(LocationDetails.countryOrRegion), City = tostring(LocationDetails.city)
| summarize Count=count(), Fails=countif(ResultType != "0") by Country, City, IPAddress
| order by Count desc
| take 50
```

**Q3 — Auth & Conditional Access tracing**
```kql
let target = "{target}";
SigninLogs
| where TimeGenerated >= ago({lookback_days}d)
| where UserPrincipalName =~ target
| summarize Count=count(), Fails=countif(ResultType != "0")
    by ConditionalAccessStatus, AuthenticationRequirement
| order by Count desc
```

**Q4 — Risky sign-ins / IOC**
```kql
let target = "{target}";
SigninLogs
| where TimeGenerated >= ago({lookback_days}d)
| where UserPrincipalName =~ target
| where RiskLevelDuringSignIn in ("high", "medium") or RiskState in ("atRisk", "confirmedCompromised")
| project TimeGenerated, IPAddress, Country=tostring(LocationDetails.countryOrRegion),
          AppDisplayName, RiskLevelDuringSignIn, RiskState, ResultType
| order by TimeGenerated desc
| take 50
```

**Q5 — Correlated security alerts**
```kql
let target = "{target}";
SecurityAlert
| where TimeGenerated >= ago({lookback_days}d)
| where Entities has target or CompromisedEntity =~ target
| project TimeGenerated, AlertName, AlertSeverity, ProviderName, Status
| order by TimeGenerated desc
| take 30
```

**Q6 — Directory audit operations (on/by the user)**
```kql
let target = "{target}";
AuditLogs
| where TimeGenerated >= ago({lookback_days}d)
| where tostring(TargetResources[0].userPrincipalName) =~ target
     or tostring(InitiatedBy.user.userPrincipalName) =~ target
| project TimeGenerated, OperationName,
          Initiator = tostring(InitiatedBy.user.userPrincipalName), Result
| order by TimeGenerated desc
| take 30
```

**Q7 — Device logons** — **XDR via Graph** (`DeviceLogonEvents` não existe no Sentinel → fonte de registro = Defender XDR Advanced Hunting). Usa `AccountName` (não `AccountUpn`) e `Timestamp`. Resposta em `results[]`.
```http
POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
Content-Type: application/json

{"Query":"DeviceLogonEvents | where Timestamp >= ago({lookback_days}d) | where AccountName =~ tostring(split('{target}','@')[0]) | summarize Logons=count(), First=min(Timestamp), Last=max(Timestamp) by DeviceName, DeviceId | order by Logons desc | take 20"}
```
> Perm: `ThreatHunting.Read.All` (já concedida à UAMI).

### Step 3: Score + classify (in the agent)
- Verdict from Q1/Q4/Q5 per the **Risk Verdict** rules above.
- Highlight: new countries (Q2 vs the user's norm), CA failures (Q3), confirmedCompromised (Q4), High alerts (Q5), suspicious directory ops like MFA re-registration / owner-add (Q6).

### Step 4: Render forensic HTML
`reports/forensic-user/<upn>_<YYYYMMDD_HHMMSS>.html` with:
- Verdict badge + target UPN + window
- 4 metric cards: Sign-ins | Falhas | Países | Sign-ins de risco
- **Geo distribution** table (country/city/IP + count + fails)
- **Auth & CA** table (CA status × auth requirement)
- **Risky sign-ins / IOC** table
- **Security alerts** table
- **Directory operations** + **Device logons** tables

### Step 5: Deliver (archive → link → notify)
1. **SharePoint (first)**: `python shared/sharepoint_upload.py upload --site "<config: sharepoint.site_id>" --skill forensic-user-investigation --file <html>` (and the `.md`). Capture `webUrl` + `folderUrl` from stdout; skip/error → continue (best-effort, never blocks email/Teams).
2. **send-email-report**: title "🔬 Forensic — {upn} ({date})", verdict color, subject timestamp suffix. **Sensitive → link-only:** per-user forensic detail — do **not** attach the HTML; put the SharePoint link in the body (`📂 Abrir no SharePoint: <folderUrl>`). 🔴 The link MUST be the SharePoint URL — never a `teams.microsoft.com` / webhook link. 4 metric cards + key findings in the body.
3. **send-teams-notification**: Adaptive Card with verdict, key metrics, top findings + **Abrir no SharePoint** action → `folderUrl` (webhook only; never Graph).

### Step 6: (Conditional) hand off to containment
- If verdict ELEVATED with `confirmedCompromised` or a High alert → print a recommendation + ready-to-run `contain user {upn}`.
- **ONLY** auto-invoke `contain-compromised-user` if the prompt has `--auto-contain` (single user; never Global Admins/UAMI/sender).

### Step 7: Audit + chat
Save `reports/forensic-user/<upn>_<timestamp>.json`. Then:
```
🔬 FORENSIC — {upn} ({window})
   Verdict: {ELEVATED|MONITOR|CLEAR}
   Sign-ins: {total} ({fails} falhas) · Países: {n} · Risco: {riskCount}
   🚨 Alertas: {alerts}  ·  🌍 Novos países: {newGeo}
   📧 Email + 💬 Teams enviados
   ➡️ {se ELEVATED: "Recomendado: contain user {upn}"}
```

## Common Errors

| Error | Meaning | Fix |
|---|---|---|
| Missing `target` | No UPN provided | Abort; this skill is single-user — ask for the UPN |
| `DeviceLogonEvents` empty (Q7 via Graph) | MDE não onboarded / sem devices | Painel de devices fica vazio; registre "sem devices MDE". NÃO cai pro Sentinel — a tabela não existe lá |
| `runHuntingQuery` 403 | Falta `ThreatHunting.Read.All` | Já concedida à UAMI; se 403, revalidar o grant |
| `RiskLevelDuringSignIn` blank | Entra ID P2 / Identity Protection not licensed | Risk view limited; rely on alerts (Q5) |
| `ConditionalAccessStatus` all "notApplied" | No CA policies targeting the user | Report as-is (gap worth noting) |
| `Entities has target` slow | Large SecurityAlert table | Keep the `take`; scope window via `{lookback_days}` |

## Rules

- ✅ **READ-ONLY** for the investigation. The ONLY write path is the containment handoff.
- ⛔ **NEVER** auto-contain without `--auto-contain`; default is recommend-only.
- ⛔ **NEVER** target Global Admins / UAMI / sender mailbox in any handoff.
- ✅ **ALWAYS** require a `target` UPN (single-user skill).
- ✅ **ALWAYS** deliver triple (email + Teams) and save the audit JSON.
- ⛔ **NEVER** attempt git operations.
```

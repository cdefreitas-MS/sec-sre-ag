---
name: user-scope-drift
description: 'Autonomous behavioral drift analysis for USER accounts. Compares a 90-day baseline vs a 7-day recent window across 7 dimensions (volume, apps, resources, IPs, locations, devices, failure rate), computes a weighted drift score with a low-volume floor, and overlays independent exfiltration signals (outbound email surge, CloudApp surge, MFA re-registration). Flags compromised/insider behavior and — when FLAG/Critical with an exfil indicator — hands off to contain-compromised-user. Trigger on "user scope drift", "drift de usuário", "who is behaving anomalously", or scheduled. Read-only collection; action only via the containment handoff with a safety gate. Uses Sentinel (Log Analytics) + Graph read perms already granted.'
tools:
  - RunAzCliReadCommands
  - RunAzCliWriteCommands
---
# User Scope Drift Skill

## Purpose

Detect **users behaving anomalously** by measuring behavioral drift between a baseline period (90d) and a recent window (7d). Surfaces account takeover, insider risk, and **data exfiltration** patterns — the canonical example being a sudden spike in outbound email volume (the single strongest exfil indicator).

This is the **detection front-end** of the autonomous response loop: when it flags a user with high confidence, it can hand off to `contain-compromised-user` (revoke → disable → reset → isolate). Analysis → action → audit, closed.

## Configuration

Reads from `config.json` at workspace root (same as the other skills):
- `subscription_id`, `azure_mcp.workspace_name`, `sentinel_workspace_id`
- `email.*` (for delivery), `teams.*` (for the Adaptive Card)

Tunables (defaults; override from prompt):
- `BASELINE_DAYS = 90`, `RECENT_DAYS = 7`
- `LOW_VOLUME_FLOOR = 10` (min baseline sign-ins/day used as denominator)
- `FLAG_THRESHOLD = 150`, `CRITICAL_THRESHOLD = 250`
- `EMAIL_SURGE_PCT = 300`, `CLOUDAPP_SURGE_PCT = 300` (independent escalation triggers)

## When to Use

- Explicit: "user scope drift", "drift de usuário", "quem está se comportando de forma anômala", "analyze user X for drift"
- Scoped to ONE user (`target = upn`) for deep-dive, or ALL users (`target = ""`) for the top-N drifters
- Scheduled (e.g., daily after Threat Pulse) to catch creeping compromise

## Drift Score Model

```
DriftScore = 0.25·Vol + 0.20·Apps + 0.10·Res + 0.15·IP + 0.10·Loc + 0.10·Dev + 0.10·Fail
```

| Dimension | Weight | Ratio = (recent / baseline) × 100 |
|---|---|---|
| Volume/day | 25% | sign-ins per day |
| Apps | 20% | distinct applications |
| Resources | 10% | distinct target resources |
| IPs | 15% | distinct source IPs |
| Locations | 10% | distinct geographies |
| Devices | 10% | distinct devices |
| Failure rate | 10% | **additive** delta: `100 + (recentFailRate − baselineFailRate) × 10` |

**Low-volume floor**: if baseline daily avg < `LOW_VOLUME_FLOOR`, force the volume denominator to `LOW_VOLUME_FLOOR` (prevents tiny baselines inflating the score).

**Verdict bands**: `<80 Contracting · 80–120 Stable · 120–150 Monitor · >150 FLAG · >250 Critical`

**Independent escalation (overrides a Stable score)** — these alone justify a FLAG:
- 📤 Outbound email volume surge ≥ `EMAIL_SURGE_PCT` (exfiltration)
- ☁️ CloudApp activity surge ≥ `CLOUDAPP_SURGE_PCT`
- 🔐 New-country sign-in **+** MFA/security-info re-registration in the recent window (AiTM / token theft pattern)

## Workflow

### Step 1: Resolve scope + read config
- Parse `target` (UPN) from prompt, or empty for tenant-wide top-N.
- Load `sentinel_workspace_id`, `subscription_id` from `config.json`.

### Step 2: Collect — run the KQL via `QueryLogAnalyticsByWorkspaceId`

> All queries are parameterized by `target` (empty = all users). Run against `sentinel_workspace_id`.

**Q1 — Sign-in drift (the 7 dimensions)**
```kql
let BASELINE_DAYS = 90;
let RECENT_DAYS = 7;
let FLOOR = 10.0;
let target = "";   // "" = all users; or "user@domain.com"
let baseStart = ago(BASELINE_DAYS * 1d);
let recentStart = ago(RECENT_DAYS * 1d);
let signins =
    union isfuzzy=true
      (SigninLogs
        | project TimeGenerated, UserPrincipalName, AppDisplayName, ResourceDisplayName,
                  IPAddress, Location, DeviceId = tostring(DeviceDetail.deviceId), ResultType),
      (AADNonInteractiveUserSignInLogs
        | project TimeGenerated, UserPrincipalName, AppDisplayName, ResourceDisplayName,
                  IPAddress, Location, DeviceId = tostring(DeviceDetail.deviceId), ResultType)
    | where TimeGenerated >= baseStart
    | where isempty(target) or UserPrincipalName =~ target
    | extend Period = iff(TimeGenerated >= recentStart, "recent", "baseline");
let baseline = signins | where Period == "baseline"
    | summarize blSignIns=count(), blApps=dcount(AppDisplayName), blRes=dcount(ResourceDisplayName),
                blIPs=dcount(IPAddress), blLoc=dcount(Location), blDev=dcount(DeviceId),
                blFail=countif(ResultType != "0")
      by UserPrincipalName;
let recent = signins | where Period == "recent"
    | summarize rSignIns=count(), rApps=dcount(AppDisplayName), rRes=dcount(ResourceDisplayName),
                rIPs=dcount(IPAddress), rLoc=dcount(Location), rDev=dcount(DeviceId),
                rFail=countif(ResultType != "0")
      by UserPrincipalName;
baseline | join kind=inner recent on UserPrincipalName
| extend blDaily = blSignIns / (BASELINE_DAYS * 1.0), rDaily = rSignIns / (RECENT_DAYS * 1.0)
| extend blFailRate = iff(blSignIns>0, todouble(blFail)/blSignIns*100, 0.0),
         rFailRate  = iff(rSignIns>0,  todouble(rFail)/rSignIns*100,  0.0)
| extend volDenom = max_of(blDaily, FLOOR)
| extend VolRatio = rDaily/volDenom*100,
         AppRatio = todouble(rApps)/max_of(blApps,1)*100,
         ResRatio = todouble(rRes)/max_of(blRes,1)*100,
         IPRatio  = todouble(rIPs)/max_of(blIPs,1)*100,
         LocRatio = todouble(rLoc)/max_of(blLoc,1)*100,
         DevRatio = todouble(rDev)/max_of(blDev,1)*100,
         FailRatio = 100 + ((rFailRate - blFailRate) * 10)
| extend DriftScore = round(0.25*VolRatio + 0.20*AppRatio + 0.10*ResRatio + 0.15*IPRatio
                          + 0.10*LocRatio + 0.10*DevRatio + 0.10*FailRatio, 1)
| extend Verdict = case(DriftScore > 250, "Critical",
                        DriftScore > 150, "FLAG",
                        DriftScore > 120, "Monitor",
                        DriftScore >= 80, "Stable", "Contracting")
| project UserPrincipalName, DriftScore, Verdict, VolRatio, AppRatio, ResRatio, IPRatio,
          LocRatio, DevRatio, FailRatio, blDaily=round(blDaily,1), rDaily=round(rDaily,1),
          blFailRate=round(blFailRate,1), rFailRate=round(rFailRate,1)
| order by DriftScore desc
| take 25
```

**Q2 — Exfiltration signal: outbound email surge** (MDO `EmailEvents`)
```kql
let target = "";
let baseDays = 83.0;   // 90 - 7
EmailEvents
| where TimeGenerated >= ago(90d)
| where EmailDirection == "Outbound"
| where isempty(target) or SenderFromAddress =~ target
| summarize baselineSent = countif(TimeGenerated < ago(7d)),
            recentSent   = countif(TimeGenerated >= ago(7d))
    by SenderFromAddress
| extend baselineDaily = baselineSent / baseDays, recentDaily = recentSent / 7.0
| extend SurgePct = round((recentDaily - baselineDaily) / max_of(baselineDaily, 0.1) * 100, 0)
| where SurgePct >= 300
| project SenderFromAddress, baselineDaily=round(baselineDaily,1), recentDaily=round(recentDaily,1), SurgePct
| order by SurgePct desc
```
> ⚠️ Use `countif` por período (acima), **não** `evaluate pivot()` — colunas geradas pelo pivot dão KQL SEM0100 no `extend` seguinte (confirmado no run ao vivo 12/06).

**Q3 — MFA / security-info re-registration + new geography** (`AuditLogs` + `SigninLogs`)
```kql
let target = "";
let recentStart = ago(7d);
let mfa = AuditLogs
  | where TimeGenerated >= recentStart
  | where OperationName has_any ("security info", "registered security info", "Reset password")
  | extend UPN = tostring(TargetResources[0].userPrincipalName)
  | where isempty(target) or UPN =~ target
  | summarize MfaEvents = count(), MfaOps = make_set(OperationName) by UPN;
let newGeo = SigninLogs
  | where TimeGenerated >= ago(90d)
  | where isempty(target) or UserPrincipalName =~ target
  | extend Country = tostring(LocationDetails.countryOrRegion)
  | summarize baselineCountries = make_set_if(Country, TimeGenerated < recentStart),
              recentCountries   = make_set_if(Country, TimeGenerated >= recentStart) by UserPrincipalName
  | extend NewCountries = set_difference(recentCountries, baselineCountries)
  | where array_length(NewCountries) > 0;
mfa | join kind=leftouter newGeo on $left.UPN == $right.UserPrincipalName
| project UPN, MfaEvents, MfaOps, NewCountries
```

> Q3 is the AiTM/token-theft combo signal. If a user appears here AND has a new country in the recent window, escalate even if the drift score is Stable.

**Q4 — Correlated alerts for flagged users** (`SecurityAlert`)
```kql
let flagged = dynamic(["user1@x.com","user2@x.com"]);  // fill from Q1 FLAG/Critical
SecurityAlert
| where TimeGenerated >= ago(7d)
| where Entities has_any (flagged) or CompromisedEntity in (flagged)
| project TimeGenerated, AlertName, AlertSeverity, ProviderName, Status, CompromisedEntity
| order by TimeGenerated desc
```

### Step 3: Score + classify (in the agent)
- Take Q1 results. For each user, you already have `DriftScore` + `Verdict`.
- Overlay Q2/Q3: if a Stable/Monitor user has email surge (Q2) or MFA+new-geo (Q3), **upgrade verdict to FLAG** and tag the reason (`exfil-email-surge`, `aitm-pattern`).
- Pick the **overall report verdict**: Critical > FLAG > Monitor > Stable > Contracting (worst user wins). Map to the email/Teams verdict:
  - Critical/FLAG → **ELEVATED** (red)
  - Monitor → **MONITOR** (yellow)
  - Stable/Contracting → **CLEAR** (green)

### Step 4: Render HTML report
Build a professional HTML report (`reports/user-scope-drift/<YYYYMMDD_HHMMSS>.html`) with:
- Verdict badge + generation timestamp + window (90d vs 7d)
- 4 metric cards: Users Analyzed | FLAG/Critical | Exfil Signals | Avg Drift Score
- Drift ranking table (top drifters: UPN, score, verdict, the strongest dimension)
- Per-flagged-user detail: dimension breakdown + which independent signal fired
- Recommendations block (per flagged user: investigate vs contain)

### Step 5: Deliver (archive → link → notify)
1. **SharePoint (first)**: `python shared/sharepoint_upload.py upload --site "<config: sharepoint.site_id>" --skill user-scope-drift --file <html>` (and the `.md`). Capture `webUrl` + `folderUrl` from stdout; skip/error → continue (best-effort, never blocks email/Teams).
2. Invoke **send-email-report**: title "📊 User Scope Drift — {date}", verdict from Step 3, subject timestamp suffix (dedup rule). Small report (< 3 MB) → **attach the HTML** + body link `📂 Abrir no SharePoint: <folderUrl>` when present. 🔴 The link MUST be the SharePoint `folderUrl` — never a `teams.microsoft.com` / webhook link. Fill the 4 metric cards + findings.
3. Invoke **send-teams-notification**: Adaptive Card with the same verdict, metrics, and top findings + **Abrir no SharePoint** action → `folderUrl` (webhook only; never Graph).

### Step 6: (Conditional) Hand off to containment
If any user is **FLAG/Critical AND has an exfil/AiTM signal**:
- **DEFAULT**: do NOT auto-contain. Print a recommendation block and a ready-to-run command:
  `contain user {upn}` (so the human decides).
- **ONLY** if the prompt contains the exact token `--auto-contain`: invoke `contain-compromised-user` for that single user (which itself enforces its own safety gate / plan + confirmation). Never bulk-contain.
- Never target Global Admins, the UAMI, or the sender mailbox (the containment skill re-checks this).

### Step 7: Audit
Save `reports/user-scope-drift/<timestamp>.json`:
```json
{
  "window": {"baseline_days": 90, "recent_days": 7},
  "users_analyzed": 0,
  "flagged": [{"upn":"...","score":0,"verdict":"FLAG","signals":["exfil-email-surge"]}],
  "overall_verdict": "ELEVATED",
  "delivered": {"email": true, "teams": true},
  "containment_triggered": false,
  "executed_by": "sreagent-teste UAMI 7e2ec058-..."
}
```

### Step 8: Report to chat
```
📊 USER SCOPE DRIFT — {date} ({window})
   👥 Analyzed: N users
   🚩 FLAG/Critical: M  (top: {upn} @ {score})
   📤 Exfil signals: K  (email surge / AiTM)
   📧 Email + 💬 Teams delivered
   ➡️ Recommended: contain {upn}   (run `contain user {upn}` or re-run with --auto-contain)
```

## Common Errors

| Error | Meaning | Fix |
|---|---|---|
| `EmailEvents` not found | MDO connector not streaming to Sentinel | Skip Q2; note "exfil signal unavailable" |
| `AADNonInteractiveUserSignInLogs` empty | Connector not enabled | Q1 still works with `SigninLogs` only |
| `pivot` column missing (`baseline`/`recent`) | A user had activity in only one period | `coalesce(...,0)` already guards; inner join in Q1 drops single-period users by design |
| Huge result set | Tenant-wide with many users | Keep `take 25`; scope to a `target` for deep-dive |
| FailRatio negative | Recent fail rate < baseline (good) | Expected; it lowers the score |

## Rules

- ✅ **ALWAYS** read-only for detection (KQL). The ONLY write path is the containment handoff.
- ⛔ **NEVER** auto-contain without the `--auto-contain` token; default is recommend-only.
- ⛔ **NEVER** bulk-contain; one user per containment invocation.
- ⛔ **NEVER** target Global Admins / UAMI / sender mailbox.
- ✅ **ALWAYS** apply the low-volume floor (avoid false FLAGs on tiny baselines).
- ✅ **ALWAYS** overlay the independent exfil/AiTM signals — a Stable drift score can still be a real compromise.
- ✅ **ALWAYS** deliver triple (email + Teams) and save the audit JSON.
- ⛔ **NEVER** attempt git operations.
- ⛔ **NEVER** leave token files on disk (if any are created for Graph reads).
```

---
name: spn-scope-drift
description: 'Autonomous behavioral drift analysis for SERVICE PRINCIPALS (workload identities). Compares a 90-day baseline vs a 7-day recent window with an additive model (new resources ×10, new non-fabric IPs ×5, brand-new identity +50), IPv6 fd00: Microsoft-fabric correction, and a low-volume floor. Verdicts: NEW / IP_DRIFT / STABLE / DORMANT. Overlays AuditLogs credential/consent/permission-escalation signals and dead-SPN (100% failure) detection. META-SECURITY: explicitly self-audits the SRE Agent''s own UAMI and Copilot/agent SPNs. Trigger on "spn scope drift", "drift de service principal", "audit workload identities", "is the agent itself drifting", or scheduled. Read-only; recommend-only (no destructive auto-action on SPNs). Uses Sentinel (Log Analytics) read perms already granted.'
tools:
  - RunAzCliReadCommands
---
# SPN Scope Drift Skill

## Purpose

Detect **service principals / workload identities behaving anomalously** by measuring behavioral drift (90d baseline vs 7d recent) across 5 dimensions, and correlating with AuditLogs credential/consent/permission events. Catches compromised app credentials, rogue consent grants, privilege escalation, and dead SPNs (100% failure = attack surface to decommission).

**META-SECURITY angle**: this skill explicitly audits the SOC's **own** identity — the SRE Agent UAMI (`AppId 7e2ec058-8773-435e-95a5-436fe10f3289`) — plus Copilot Studio / Security Copilot agent SPNs. *The autonomous SOC watches itself and the whole agent fleet.* Complements the 3 UAMI audit rules in `_sre-agent-kb/08-sentinel-rules-uami-audit.md`.

> ⚠️ **Recommend-only**. Unlike `contain-compromised-user`, this skill performs **NO destructive auto-action** on SPNs (disabling a first-party SPN — including the UAMI itself — can break the SOC). It detects, scores, and recommends (rotate credential / review consent / decommission). Remediation is always a human decision.

## Configuration

Reads from `config.json` at workspace root:
- `subscription_id`, `azure_mcp.workspace_name`, `sentinel_workspace_id`
- `email.*`, `teams.*` (delivery)

Constants & tunables:
- `UAMI_APPID = "7e2ec058-8773-435e-95a5-436fe10f3289"` (the SOC's own identity — always highlighted)
- `BASELINE_DAYS = 90`, `RECENT_DAYS = 7`, `LOW_VOLUME_FLOOR = 10`
- `FLAG_THRESHOLD = 150`, `CRITICAL_THRESHOLD = 250`

## When to Use

- Explicit: "spn scope drift", "drift de service principal", "audita as workload identities", "o agente está driftando?"
- Scoped to ONE SPN (`target = AppId or name`) or ALL (`target = ""`) for the top-N drifters
- Scheduled (e.g., weekly) to catch credential abuse / consent drift / agent compromise

## Drift Score Model (CANONICAL — repo sec-sre-ag, live-proven)

```
DriftScore = NewResourceCount×10 + NewIPCount×5 + (BaselineHits==0 & RecentHits>0 ? 50 : 0)
```

Aditivo e explicável — provado ao vivo contra o LA-HERBEST-SENTINEL (34 identidades).

| Sinal | Pontos | Significado |
|---|---|---|
| Novo recurso acessado | ×10 cada | SPN/MI alcançou um alvo que não usava no baseline |
| Novo IP (não-fabric) | ×5 cada | novo IP de origem (após colapsar `fd00:` → `AzureFabric`) |
| Identidade nova | +50 | sem atividade no baseline, só recente |

- **Correção IPv6 `fd00:`**: IPs começando com `fd00:` são **fabric interno** da Microsoft (Copilot/MCAS/agents) — colapsados num único bucket `AzureFabric`, NÃO contados como IP adversário novo.
- **Filtro low-volume**: `TotalHits >= LOW_VOLUME_FLOOR` remove identidades quase-silenciosas do ranking.
- **Verdict (4 estados)**: `NEW` (sem baseline) · `IP_DRIFT` (novos IPs não-fabric) · `DORMANT` (sem atividade recente) · `STABLE`.

**Independent escalation (overrides a Stable score)** — these alone justify a FLAG:
- 🔑 New credential added in recent window ("Add service principal credentials" / "Certificates and secrets") → **credential abuse**
- ✋ New consent grant ("Consent to application") → **permission acquisition**
- ⬆️ New app role assignment / delegated permission grant / owner added → **privilege escalation**
- 💀 100% failure rate (baseline AND recent) → **dead SPN** = attack surface to decommission

## Workflow

### Step 1: Resolve scope + read config
- Parse `target` (AppId or SPN name) from prompt, or empty for tenant-wide top-N.
- Load `sentinel_workspace_id`, `subscription_id`.

### Step 2: Collect — run KQL via `QueryLogAnalyticsByWorkspaceId`

**Q1 — SPN sign-in drift (5 dimensions, fd00: corrected)**
```kql
let baseline_start = ago(90d);
let recent_start = ago(7d);
let target = "";   // "" = all SPNs/MIs; or AppId / ServicePrincipalName
// UAMIs (incl. the SRE Agent's own) log ONLY in AADManagedIdentitySignInLogs — union both
let combined = union AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs
    | where TimeGenerated > baseline_start
    | where isempty(target) or ServicePrincipalName =~ target or AppId == target
    | extend IPCorrected = iff(IPAddress startswith "fd00:", "AzureFabric", IPAddress)
    | extend Period = iff(TimeGenerated > recent_start, "Recent", "Baseline");
combined
| summarize
    BaselineResources = make_set_if(ResourceDisplayName, Period == "Baseline"),
    RecentResources   = make_set_if(ResourceDisplayName, Period == "Recent"),
    BaselineIPs       = make_set_if(IPCorrected, Period == "Baseline"),
    RecentIPs         = make_set_if(IPCorrected, Period == "Recent"),
    BaselineHits      = countif(Period == "Baseline"),
    RecentHits        = countif(Period == "Recent"),
    FailCount         = countif(ResultType != "0" and Period == "Recent"),
    TotalHits         = count()
  by AppId, ServicePrincipalName
| extend NewResources = set_difference(RecentResources, BaselineResources)
| extend NewIPs = set_difference(RecentIPs, BaselineIPs)
| extend NewResourceCount = array_length(NewResources), NewIPCount = array_length(NewIPs)
| extend DriftScore = NewResourceCount*10 + NewIPCount*5 + iff(BaselineHits==0 and RecentHits>0, 50, 0)
| extend Verdict = case(RecentHits==0, "DORMANT", BaselineHits==0 and RecentHits>0, "NEW", NewIPCount>0, "IP_DRIFT", "STABLE")
| extend IsUAMI = (AppId == "7e2ec058-8773-435e-95a5-436fe10f3289")
| where TotalHits >= 10
| project ServicePrincipalName, AppId, IsUAMI, DriftScore, Verdict,
          BaselineHits, RecentHits, NewResourceCount, NewIPCount, NewResources, NewIPs, FailCount
| order by DriftScore desc, NewResourceCount desc
| take 40
```

**Q2 — Credential / consent / permission escalation (AuditLogs)**
```kql
let target = "";
AuditLogs
| where TimeGenerated >= ago(7d)
| where OperationName has_any (
    "Add service principal credentials", "Update application – Certificates and secrets",
    "Add application", "Consent to application", "Add app role assignment grant to user",
    "Add delegated permission grant", "Add owner to service principal", "Add owner to application")
| extend SpnName = tostring(TargetResources[0].displayName)
| where isempty(target) or SpnName =~ target
| project TimeGenerated, OperationName, SpnName,
          Initiator = tostring(InitiatedBy.user.userPrincipalName), Result
| order by TimeGenerated desc
```

**Q3 — Dead SPNs (100% failure = decommission candidate)**
```kql
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(7d)
| summarize Total=count(), Fail=countif(ResultType != "0") by ServicePrincipalName, AppId
| extend FailRate = round(todouble(Fail)/Total*100, 1)
| where FailRate == 100 and Total > 5
| order by Total desc
```

**Q4 — UAMI self-audit (the meta angle — always run)**
```kql
// UAMI logs ONLY in AADManagedIdentitySignInLogs (NOT the SP sign-in table)
let UAMI_APPID = "7e2ec058-8773-435e-95a5-436fe10f3289";
AADManagedIdentitySignInLogs
| where TimeGenerated >= ago(7d)
| where AppId == UAMI_APPID
| summarize SignIns=count(), Resources=make_set(ResourceDisplayName),
            IPs=dcount(IPAddress), Countries=make_set(LocationDetails.countryOrRegion),
            Fail=countif(ResultType != "0")
  by bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```
> If the UAMI shows new resources, new countries, or a failure spike vs its norm → **Critical** alert: the SOC's own identity may be compromised.

### Step 3: Score + classify (in the agent)
- Take Q1. Apply the low-volume floor + fd00: correction (already in the query).
- Overlay Q2: any SPN with a recent credential add / consent grant / permission escalation → **upgrade to FLAG** with the reason tag (`credential-abuse`, `consent-grant`, `privilege-escalation`).
- Overlay Q3: dead SPNs → list under "Hygiene — decommission candidates" (not a compromise, but attack surface).
- Overlay Q4: if the UAMI drifted → **Critical**, top of report.
- Overall report verdict → **ELEVATED** if any `NEW`/`IP_DRIFT` verdict, any AuditLogs signal, or UAMI drift; else **CLEAR**.

### Step 4: Render HTML report
`reports/spn-scope-drift/<YYYYMMDD_HHMMSS>.html` with:
- Verdict badge + window + generation time
- 4 metric cards: SPNs Analyzed | NEW/IP_DRIFT | Credential/Consent Events | Dead SPNs
- **UAMI Self-Audit panel** at top (the meta highlight): the agent's own drift status
- Drift ranking table (top SPNs: name, AppId, score, verdict, strongest dimension, LowVolume/fabric flags)
- Per-flagged detail: dimension breakdown + which AuditLogs signal fired
- Hygiene section: dead SPNs to decommission
- Recommendations (rotate credential / review consent / decommission) — **no auto-action**

### Step 5: Deliver (archive → link → notify)
1. **SharePoint (first)**: `python shared/sharepoint_upload.py upload --site "<config: sharepoint.site_id>" --skill spn-scope-drift --file <html>` (and the `.md`). Capture `webUrl` + `folderUrl` from stdout; skip/error → continue (best-effort, never blocks email/Teams).
2. **send-email-report**: title "🤖 SPN Scope Drift — {date}", verdict from Step 3, subject timestamp suffix (dedup rule). Small report (< 3 MB) → **attach the HTML** + body link `📂 Abrir no SharePoint: <folderUrl>` when present. 🔴 The link MUST be the SharePoint `folderUrl` — never a `teams.microsoft.com` / webhook link. 4 metric cards + findings.
3. **send-teams-notification**: Adaptive Card, same verdict + metrics + top findings (highlight UAMI status) + **Abrir no SharePoint** action → `folderUrl` (webhook only; never Graph).

### Step 6: Audit
`reports/spn-scope-drift/<timestamp>.json`:
```json
{
  "window": {"baseline_days": 90, "recent_days": 7},
  "spns_analyzed": 0,
  "uami_self_audit": {"appId":"7e2ec058-...","status":"stable|drifted","note":"..."},
  "flagged": [{"name":"...","appId":"...","score":0,"verdict":"FLAG","signals":["credential-abuse"]}],
  "dead_spns": [{"name":"...","appId":"...","failRate":100}],
  "overall_verdict": "ELEVATED",
  "delivered": {"email": true, "teams": true},
  "action": "recommend-only",
  "executed_by": "sreagent-teste UAMI 7e2ec058-..."
}
```

### Step 7: Report to chat
```
🤖 SPN SCOPE DRIFT — {date} ({window})
   🛡️ UAMI self-audit: {stable|DRIFTED} — {note}
   🔧 Analyzed: N SPNs
   🚩 NEW/IP_DRIFT: M  (top: {name} @ {score})
   🔑 Credential/Consent/Escalation events: K
   💀 Dead SPNs (decommission): D
   📧 Email + 💬 Teams delivered
   ⚠️ Recommend-only — no auto-action on SPNs
```

## Common Errors

| Error | Meaning | Fix |
|---|---|---|
| `AADServicePrincipalSignInLogs` empty | SP sign-in logs connector not enabled | Enable in Entra ID → Diagnostic settings → ServicePrincipalSignInLogs to the workspace |
| Many `fd00:` IPs inflating drift | Copilot/MCAS fabric rotation | Already excluded via `IsFabric`; reported separately as benign |
| SPN flagged but it's first-party | Microsoft operational change (e.g., MDA Copilot Studio) | Correlate Q2 — if no credential/consent change, mark "Microsoft operational, not adversary" |
| `OperationName` strings differ | Tenant uses different audit branding | Broaden Q2 with `has` on "credential"/"consent"/"permission" |
| MI rows lack IPAddress/Location | Managed identities often have no IP/geo | `IPCorrected` tolerates null; NewIP count may under-report for MIs (expected) |

## Rules

- ✅ **READ-ONLY + recommend-only**. NEVER auto-disable/modify any SPN (especially the UAMI — it would break the SOC).
- ✅ **ALWAYS** run Q4 (UAMI self-audit) and surface it at the top — this is the skill's signature value.
- ✅ **ALWAYS** apply the low-volume floor and the `fd00:` fabric correction (avoid false FLAGs on Copilot agents).
- ✅ **ALWAYS** correlate drift with AuditLogs (Q2) before calling something a compromise — a high score with no credential/consent change is usually a planned expansion or Microsoft operational change.
- ✅ **ALWAYS** deliver triple (email + Teams) and save the audit JSON.
- ⛔ **NEVER** treat `fd00:` IPs as adversary indicators.
- ⛔ **NEVER** attempt git operations.
```

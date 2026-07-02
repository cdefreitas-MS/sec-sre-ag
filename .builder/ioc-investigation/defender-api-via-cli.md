# MDE API Calls via RunAzCliReadCommands

## Purpose

This document provides the exact `RunAzCliReadCommands` tool calls to access
Microsoft Defender for Endpoint (MDE) API data that is NOT available through
Log Analytics KQL queries.

These calls replace the Sentinel Triage MCP tools (`GetDefenderIpAlerts`,
`GetDefenderFileInfo`, `ListDefenderIndicators`, `ListDefenderMachinesByVulnerability`, etc.)
which are NOT available in this environment.

---

## ⛔ Critical: Identity & Transport (READ FIRST)

> **The MDE API roles live on the UAMI — a plain `az rest` uses the WRONG identity.**
> The agent has **two** managed identities: a **system-assigned** MI (the DEFAULT for
> `az` / `az rest` / `az account get-access-token` / `RunAzCliReadCommands`) that holds only a
> minimal role set (e.g. `Sites.Selected`, **no MDE roles**), and a **user-assigned** MI
> (**UAMI**) that holds the **WindowsDefenderATP** app roles (`Ti`/`Ip`/`File`/`Vulnerability`/`Machine`
> `.Read.All` — the "MDE" grants). A plain `az rest --resource https://api.securitycenter.microsoft.com`
> uses the **system-assigned** MI → **403** → the SRE Agent then offers the **OBO** prompt
> ("Conceder permissões"). **This is the exact same root cause as the Graph `runHuntingQuery` 403.**
> (Observed live: `/api/indicators` succeeded but `/api/ips/{ip}/stats` 403'd on the default identity
> — per-endpoint role inconsistency. Minting the **UAMI** token fixes ALL endpoints uniformly.)
>
> ✅ **DO:** mint a token from the **UAMI** for the MDE resource and call the API with `curl` via
> **`RunInTerminal`** (recipe below). *(The old note "az is not in the shell PATH / never use
> RunInTerminal" was WRONG — in the SRE Agent sandbox `az`/`curl` in `RunInTerminal` run as the
> agent and work; this was proven with `runHuntingQuery`.)*
>
> ⛔ **DON'T:**
> - **Do NOT click "Conceder permissões" (OBO)** — it runs as the human's delegated creds, not the
>   autonomous UAMI. If the OBO prompt appears, **Cancel** and use the UAMI-token recipe; if the UAMI
>   token itself 403s, treat it as "MDE not accessible" and **skip ALL MDE calls** (KQL-only mode).
> - **Do NOT use `RunAzCliWriteCommands`** — it OBO-403s (delegated perms not configured).
> - **Do NOT rely on `RunAzCliReadCommands` / plain `az rest`** for MDE — it defaults to the
>   system-MI (no MDE roles) → 403 → OBO loop (this is the recurring failure).

---

## MDE API Base URL + how to call it (UAMI token)

All MDE API calls use this base URL:

```
https://api.securitycenter.microsoft.com/api/
```

**Call recipe (mint UAMI token → `curl` the API):** the `az rest ... --resource "https://api.securitycenter.microsoft.com"` snippets below are the **URL/shape reference only** — execute each one as a `curl` with an explicit **UAMI** Bearer token. Resolve the UAMI `client_id` from the agent's `<agent_identity>` settings or from `config.json` → `agent_uami_client_id`:

```bash
# 1) Mint a UAMI token for the MDE API resource (once per run; reuse $TOKEN)
TOKEN=$(curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://api.securitycenter.microsoft.com&client_id=<UAMI_CLIENT_ID>" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 2) Call any MDE endpoint with the explicit UAMI Bearer token
curl -s "https://api.securitycenter.microsoft.com/api/ips/<IP_ADDRESS>/stats" \
  -H "Authorization: Bearer $TOKEN"
```

> Run both via **`RunInTerminal`**. The same `$TOKEN` works for every endpoint in this document
> (alerts, stats, files, indicators, vulnerabilities/machineReferences) — only the URL changes.
> **Optional token check:** base64url-decode the JWT payload and confirm `appid` == the UAMI
> `client_id` and the MDE roles are in `roles`.
> **Fallback:** if the UAMI token call still returns **403** → the UAMI lacks MDE roles in this
> tenant → **skip ALL MDE calls** and note "MDE API not accessible — KQL-only mode".

---

## Decision Flow

```
Mint UAMI token for https://api.securitycenter.microsoft.com (recipe above)
  ├─ Token OK → call the MDE endpoints below with: curl -H "Authorization: Bearer $TOKEN"
  │         └─ If 403 (even with the UAMI token) → UAMI lacks MDE roles in this tenant
  │              └─ Skip ALL MDE API enrichment · note "MDE API not accessible — KQL-only mode"
  │              └─ Rely on KQL queries from SKILL.md (Q1–Q14) + Graph runHuntingQuery
  └─ Cannot mint UAMI token (no IDENTITY_ENDPOINT / no client_id) → skip MDE enrichment
           └─ Rely on KQL queries from SKILL.md (Q1–Q14)

⛔ If the SRE Agent shows the "Conceder permissões" (OBO) prompt → CANCEL it (do NOT grant).
   The OBO uses the human's delegated creds, not the autonomous UAMI. Use the UAMI-token
   recipe; if that 403s, skip MDE (above). NEVER loop on OBO.
```

---

## IP Address Calls

### MDE-IP-ALERTS: Get Alerts for IP

**Replaces:** `GetDefenderIpAlerts` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/ips/<IP_ADDRESS>/alerts" --resource "https://api.securitycenter.microsoft.com"
```

**Returns:** All security alerts associated with the IP address.

**Key fields in response:**
- `value[]` array with: `id`, `title`, `severity`, `status`, `category`, `assignedTo`, `investigationState`, `firstEventTime`, `lastEventTime`, `machineId`

---

### MDE-IP-STATS: Get IP Statistics

**Replaces:** `GetDefenderIpStatistics` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/ips/<IP_ADDRESS>/stats" --resource "https://api.securitycenter.microsoft.com"
```

**Returns:** Organization prevalence, device count, and communication statistics.

**Key fields in response:**
- `orgPrevalence`, `orgFirstSeen`, `orgLastSeen`

---

### MDE-FIND-MACHINES: Find Devices by IP

**Replaces:** `FindDefenderMachinesByIp` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/machines/findbyip(ip='<IP_ADDRESS>',timestamp=<DATETIME>)" --resource "https://api.securitycenter.microsoft.com"
```

**Parameters:**
- `<IP_ADDRESS>`: Target IP address
- `<DATETIME>`: ISO 8601 timestamp (e.g., `2026-05-30T00:00:00Z`). Returns devices that communicated with the IP ±15 minutes of this timestamp.

**Returns:** Devices that communicated with the IP.

**Key fields:** `id`, `computerDnsName`, `osPlatform`, `osVersion`, `riskScore`, `exposureLevel`, `lastSeen`

---

## File Hash Calls

### MDE-FILE-INFO: Get File Info

**Replaces:** `GetDefenderFileInfo` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/files/<FILE_HASH>" --resource "https://api.securitycenter.microsoft.com"
```

**Parameters:**
- `<FILE_HASH>`: SHA1 or SHA256 hash of the file

**Returns:** File details including global prevalence, threat determination, signer info.

**Key fields:** `sha1`, `sha256`, `md5`, `size`, `globalPrevalence`, `globalFirstObserved`, `globalLastObserved`, `signer`, `signerHash`, `isPeFile`, `fileType`, `filePublisher`, `fileProductName`, `determinationType`, `determinationValue`

---

### MDE-FILE-STATS: Get File Statistics

**Replaces:** `GetDefenderFileStatistics` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/files/<FILE_HASH>/stats" --resource "https://api.securitycenter.microsoft.com"
```

**Returns:** Organization-level statistics for the file.

**Key fields:** `orgPrevalence`, `orgFirstSeen`, `orgLastSeen`, `topFileNames`

---

### MDE-FILE-ALERTS: Get File Alerts

**Replaces:** `GetDefenderFileAlerts` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/files/<FILE_HASH>/alerts" --resource "https://api.securitycenter.microsoft.com"
```

**Returns:** All alerts associated with the file hash.

**Key fields in response:** `value[]` array with: `id`, `title`, `severity`, `status`, `category`, `machineId`, `firstEventTime`, `lastEventTime`

---

### MDE-FILE-MACHINES: Get Devices with File

**Replaces:** `GetDefenderFileRelatedMachines` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/files/<FILE_HASH>/machines" --resource "https://api.securitycenter.microsoft.com"
```

**Returns:** All devices where the file was observed.

**Key fields in response:** `value[]` array with: `id`, `computerDnsName`, `osPlatform`, `osVersion`, `riskScore`, `exposureLevel`, `lastSeen`

---

## Custom IOC List

### MDE-IOC: Search Custom Indicators

**Replaces:** `ListDefenderIndicators` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/indicators" --resource "https://api.securitycenter.microsoft.com"
```

**Returns:** ALL custom indicators in the tenant.

**⚠️ CRITICAL: Processing Custom IOC List Results**

The MDE indicators API returns ALL custom indicators in the tenant (potentially thousands). You MUST filter the results manually.

**MANDATORY Processing Steps:**

1. **Receive the full response** — the `value` array contains all indicators
2. **Manually filter** for the target IoC:
   ```python
   # Filter logic (case-insensitive)
   matches = [ind for ind in response["value"] 
              if ind.get("indicatorValue", "").lower() == target_ioc.lower()]
   ```
3. **Report results:**
   - Found: "Found X custom indicator(s) matching [IoC]: [action], [severity], [title]"
   - Not found: "No custom indicators match [IoC]"

**Key fields per indicator:** `indicatorValue`, `indicatorType`, `action` (Alert/Block/Allow), `severity`, `title`, `description`, `createdBy`, `creationTimeDateTimeUtc`, `expirationTime`

**Indicator types:**
- `IpAddress` — for IP IoCs
- `DomainName` — for domain IoCs
- `Url` — for URL IoCs
- `FileSha1` — for SHA1 hash IoCs
- `FileSha256` — for SHA256 hash IoCs
- `FileMd5` — for MD5 hash IoCs

**🔴 PROHIBITED:**
- ❌ Assuming "large result = no match" without filtering
- ❌ Reporting "Not in IOC list" without verifying the actual content
- ❌ Skipping processing due to result size

**Alternative — Filtered Query (if supported):**

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/indicators?\$filter=indicatorValue+eq+'<IOC_VALUE>'" --resource "https://api.securitycenter.microsoft.com"
```

> **Note:** OData filtering may not work on all MDE API versions. If the filtered query returns an error, fall back to the unfiltered query and filter manually.

---

## Vulnerability Management

### MDE-CVE-MACHINES: Get Devices Affected by CVE

**Replaces:** `ListDefenderMachinesByVulnerability` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/vulnerabilities/<CVE_ID>/machineReferences" --resource "https://api.securitycenter.microsoft.com"
```

**Parameters:**
- `<CVE_ID>`: CVE identifier (e.g., `CVE-2024-1234`)

**Returns:** All devices vulnerable to the specified CVE.

**Key fields in response:** `value[]` array with: `id` (device ID), `computerDnsName`, `osPlatform`, `osVersion`, `rbacGroupName`, `rbacGroupId`

**Usage pattern:**
```
For each CVE_ID extracted from Q12 or Shodan enrichment:
  1. Call MDE-CVE-MACHINES with the CVE_ID
  2. Collect affected devices
  3. Aggregate across all CVEs
  4. Report total unique affected devices
```

---

### MDE-DEVICE-VULNS: Get Vulnerabilities for a Device

**Replaces:** `GetDefenderMachineVulnerabilities` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/machines/<DEVICE_ID>/vulnerabilities" --resource "https://api.securitycenter.microsoft.com"
```

**Parameters:**
- `<DEVICE_ID>`: MDE device ID (GUID)

**Returns:** All CVEs affecting the specified device.

**Key fields in response:** `value[]` array with: `id` (CVE ID), `name`, `description`, `severity`, `cvssV3`, `exploitTypes`, `exploitUris`, `publicExploit`, `exploitVerified`, `exposedMachines`

---

## Error Handling

| HTTP Status | Meaning | Action |
|-------------|---------|--------|
| **200** | Success | Process the response |
| **400** | Bad request | Check parameters (invalid IP format, hash length, CVE format) |
| **401** | Unauthorized | Token expired — retry once, then skip MDE enrichment |
| **403** | Forbidden | You called with the **system-MI** (plain `az rest`) which has no MDE roles → mint the **UAMI** token (recipe at top) and retry with `curl`. If it **still** 403s (UAMI lacks MDE roles) → skip ALL MDE calls, note "KQL-only mode". **Never** accept the OBO prompt. |
| **404** | Not found | IoC/CVE not in MDE scope — not an error, just no data. Continue with KQL |
| **429** | Rate limited | Wait and retry with exponential backoff (1s, 2s, 4s) |
| **500+** | Server error | Retry once, then skip and note in report |

### Fallback Strategy

If MDE API is entirely inaccessible (403 on first call):

1. **Skip ALL `az rest` calls** in this document
2. **Rely entirely on KQL queries** from SKILL.md (Q1–Q14)
3. **Note in investigation report:**
   ```
   ⚠️ MDE API not accessible (403 Forbidden). Investigation limited to Log Analytics data.
   Missing: Custom IOC list, file global prevalence, MDE-specific alerts, TVM vulnerability data.
   ```
4. **For CVE correlation:** Note CVEs found in alerts but report "Affected device enumeration unavailable (MDE API required)"

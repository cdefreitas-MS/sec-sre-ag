# Device Context via Azure CLI (Graph API)

## Purpose

This document provides the exact Azure CLI (`az rest`) calls to retrieve Entra ID
device context when Graph API permissions are available. This is the **primary method**
for collecting device profile, owners, registered users, and compliance data.

Use `RunAzCliReadCommands` tool (if available) or Azure CLI terminal (`az rest`).

If Graph API returns **403 Forbidden**, skip this entirely and use the
**KQL Fallback Queries (Q0a, Q0b)** documented in SKILL.md.

---

## ⛔ Critical: Tool Selection

> **ALWAYS** use `RunAzCliReadCommands` for ALL calls in this document.
>
> **NEVER** use `RunAzCliWriteCommands` — even though the calls are `az rest --method GET` (read-only), `RunAzCliWriteCommands` has a different authorization flow:
> 1. It first tries Managed Identity (same as `RunAzCliReadCommands`)
> 2. If MI returns 403, it falls back to **On-Behalf-Of (OBO)** flow
> 3. OBO requires **Delegated permissions** which are NOT configured → **403 error**
>
> `RunAzCliReadCommands` uses MI directly with **Application permissions** → works correctly.
>
> **NEVER** use `RunInTerminal` with `az` commands — the `az` binary may not be in the shell PATH.

---

## Decision Flow

```
Can I use RunAzCliReadCommands tool or az CLI?
  ├─ YES → Use the calls below (this document)
  │         └─ If 403 on Step 1 → Stop. Use KQL Fallback (Q0)
  └─ NO → Use KQL Fallback (Q0) directly
```

---

## Step-by-Step Calls

### Step 1: Find Device by Name (MUST be first — provides device object IDs)

```
az rest --method GET --url "https://graph.microsoft.com/v1.0/devices?\$filter=displayName eq '<DEVICE_NAME>'&\$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,registrationDateTime,approximateLastSignInDateTime,mdmAppId,profileType,manufacturer,model,enrollmentType,deviceOwnership" --subscription <SUBSCRIPTION_ID>
```

**Extract from response:**
- `entra_object_id` = response `id` field (Entra Device Object ID — used in Steps 2–4)
- `entra_device_id` = response `deviceId` field (Entra Device ID GUID — different from object ID)
- Device properties: displayName, OS, trustType, compliance, managed, manufacturer, model

**If this returns 403:** STOP all Graph API calls. Proceed to KQL Fallback (Q0).

> **Note:** `id` and `deviceId` are DIFFERENT. `id` is the Entra Object ID (used for Graph API calls). `deviceId` is the Entra Device Registration ID.

---

### Step 2: Get Device Owners (requires entra_object_id from Step 1)

```
az rest --method GET --url "https://graph.microsoft.com/v1.0/devices/<ENTRA_OBJECT_ID>/registeredOwners?\$select=id,displayName,userPrincipalName" --subscription <SUBSCRIPTION_ID>
```

**Extract:** Array of owner objects with displayName and UPN.

---

### Step 3: Get Registered Users (requires entra_object_id from Step 1)

```
az rest --method GET --url "https://graph.microsoft.com/v1.0/devices/<ENTRA_OBJECT_ID>/registeredUsers?\$select=id,displayName,userPrincipalName" --subscription <SUBSCRIPTION_ID>
```

**Extract:** Array of user objects with displayName and UPN.

---

### Step 4: Get Intune Managed Device Details (optional — if MDM enrolled)

```
az rest --method GET --url "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?\$filter=deviceName eq '<DEVICE_NAME>'&\$select=id,deviceName,managedDeviceOwnerType,complianceState,managementAgent,lastSyncDateTime,osVersion,azureADRegistered,azureADDeviceId,deviceEnrollmentType,deviceCategoryDisplayName,serialNumber,userPrincipalName" --subscription <SUBSCRIPTION_ID>
```

**If 403 or 404:** Device may not be Intune-enrolled or permissions insufficient. Note as data gap.

---

### Step 5: Get BitLocker Recovery Keys (optional — requires BitLockerKey.Read.All)

```
az rest --method GET --url "https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys?\$filter=deviceId eq '<ENTRA_DEVICE_ID>'" --subscription <SUBSCRIPTION_ID>
```

**If 403:** BitLocker key recovery permissions not granted. Note as data gap — this is expected in most environments.

---

## Error Reference

| Error | Meaning | Action |
|-------|---------|--------|
| 403 Forbidden | Identity lacks Graph permissions | Use KQL Fallback (Q0) |
| 403 Forbidden (from `RunAzCliWriteCommands`) | Wrong tool used — OBO fallback failed | Switch to `RunAzCliReadCommands` |
| 404 Not Found (device) | Device name doesn't match any Entra device | Verify device name spelling; try partial match |
| 404 Not Found (Intune) | Device not MDM-enrolled | Normal — note Intune data as unavailable |
| 401 Unauthorized | Token expired or wrong tenant | Check subscription parameter |
| Empty `value` array | Device exists but no owners/users registered | Normal for some device types |

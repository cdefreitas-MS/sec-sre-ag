# SharePoint Report Archival — Historical Retention

Archive every report a skill generates (HTML + MD) to the **SOC** SharePoint site, one
folder per skill plus a `YYYY/MM` hierarchy, so the team keeps a browsable, versioned
history separate from the agent's Knowledge base.

```
SOC (site) › Documents › SOC Reports/
   advisor-impact/2026/06/advisor-impact-2026-06-19.html (+ .md)
   threat-pulse/2026/06/...
   <one folder per report-producing skill>
```

> **Knowledge Sources vs SharePoint:** Knowledge Sources is a *reference* library for
> semantic search (curated runbooks/summaries). SharePoint is the *historical archive* of
> point-in-time reports. Don't dump every report into Knowledge — it pollutes retrieval.

## Two upload paths

| Path | Use for | Why |
|------|---------|-----|
| **Graph util** (`shared/sharepoint_upload.py`) — *recommended, uniform* | every report, **any size** | streams bytes from disk → no body-size limit; runs at generation time |
| **SharePoint connector** (`Create file`) | small text reports only (e.g. threat-pulse MD, < ~50 KB) | content travels in the request **body** → large self-contained HTML (advisor-impact ~3 MB base64) **exceeds the limit** |

**Rule of thumb:** call `sharepoint_upload.py` at generation time for all artifacts. Large
self-contained HTML *cannot* be re-uploaded retroactively through the connector — archive
it while the content is still on disk.

## Graph util — wiring

After a skill writes its files, archive both (best-effort — must NOT block email/Teams):

```bash
python shared/sharepoint_upload.py upload --site "<SOC-siteId>" --skill advisor-impact --file report.html
python shared/sharepoint_upload.py upload --site "<SOC-siteId>" --skill advisor-impact --file report.md
```

- `--site` accepts a Graph `siteId` (`host,guid,guid`) **or** a `host:/sites/SOC` path.
- Auth (first available): `--token` · `--token-file` · env `GRAPH_TOKEN` · ManagedIdentityCredential (UAMI).
- `--dry-run` prints the intended path/method with no token/network (offline test).
- Exit codes: `0` ok · `3` skipped (no `--site`, best-effort) · `1` error (log + continue delivery).
- Parent folders (`<skill>/<YYYY>/<MM>`) are created automatically by Graph path-addressing.

### Least privilege (one-time admin)

The UAMI needs Graph **`Sites.Selected`** with `write` granted **only on the SOC site** —
not `Sites.ReadWrite.All` / `Sites.FullControl.All`.

```http
GET  https://graph.microsoft.com/v1.0/sites/{tenant}.sharepoint.com:/sites/SOC      # → siteId
POST https://graph.microsoft.com/v1.0/sites/{SOC-siteId}/permissions
{ "roles": ["write"],
  "grantedToIdentities": [{ "application": { "id": "<UAMI-app-id>", "displayName": "SRE Agent UAMI" } }] }
```

## Connector tool policy (for scheduled / autonomous runs)

So routine archiving doesn't pause for approval, while destructive/permission actions stay gated:

| Action | Policy |
|--------|--------|
| Create new folder · Create file · Update file · Get file metadata · List folder | **Allow** |
| Delete item / file · Grant access · Create / Stop sharing link · Send HTTP request to SharePoint · Move / Copy | **Ask** |

The real blast-radius control is the **connection identity** of the SharePoint connector —
scope it to the SOC site, not a broad/admin account.

## Guardrails

- **Additive only:** never delete, move, or share. Only create/update files and folders.
- **Best-effort:** catch archive errors, log them, and continue — delivery (email/Teams) is independent.
- **No email/Teams from this step:** notifications are handled by separate skill steps.

## Verification

List the archive root to confirm one folder per skill (read-only):

```
GET https://graph.microsoft.com/v1.0/sites/{SOC-siteId}/drive/root:/SOC Reports:/children
```

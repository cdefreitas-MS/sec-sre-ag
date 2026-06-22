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

## Canonical delivery sequence (archive → link → notify)

🔴 **All report-producing skills MUST follow this order so the SharePoint link is surfaced
to recipients** (the archive is the canonical copy; email/Teams point at it):

1. **Archive FIRST — SharePoint.** After the renderer writes the HTML (+ MD), upload them
   with `shared/sharepoint_upload.py` (see [wiring](#graph-util--wiring)). The CLI prints
   `{"ok": true, "webUrl": "<file>", "folderUrl": "<parent folder>"}` to **stdout** on
   success → **capture both `webUrl` (the file) and `folderUrl` (the library folder)**.
   - Best-effort: on exit code `3` (no `--site`) or `1` (error) there is **no `webUrl`** →
     set `webUrl = null`, omit the link line, and **continue** (never block email/Teams).
2. **Email — `send-email-report`.** Apply the **size-aware attach policy** below.
   - **When the HTML is attached** (small class) → the body link should **open SharePoint
     without re-downloading the report**: link the **`folderUrl`** (`📂 Abrir no SharePoint`).
     ⚠️ Do **not** link the file `webUrl` here — SharePoint forces a **download** for `.html`
     files, which is redundant since the attachment is already the read copy.
   - **When link-only** (no attachment) → link the file **`webUrl`** (it's the only copy).
3. **Teams — `send-teams-notification`.** Add an **`Abrir no SharePoint`** action/CTA:
   use **`folderUrl`** when the email attached the HTML (opens the library, no download),
   else the file **`webUrl`** (link-only). Keep any portal CTA.

> **Why the folder link:** SharePoint Online does not render `.html` inline — opening a
> file `webUrl` triggers a download. The `folderUrl` opens the document library in the
> browser (no download); the attachment (or, for link-only, the file in that folder) is the
> report itself.

### Size-aware attach policy (email)

| Report class | On-disk HTML | Attach? | Always include link? |
|--------------|--------------|---------|----------------------|
| **Small** (Pulse MD, soc-executive-brief, sentinel-documenter) | < 3 MB | ✅ Attach HTML **and** link | ✅ |
| **Large / self-contained** (advisor-impact — embedded base64 ~3 MB) | ≥ 3 MB | ⛔ **Link-only** (no attachment) | ✅ |
| **Sensitive** (incident-level PII/entity detail, e.g. incident-triage) | any size | ⛔ **Link-only** (data minimization) | ✅ |

**Rules:**
- The **SharePoint link is always the canonical reference** — include it whenever `webUrl`
  is present, in **both** email body and Teams card.
- **Attach the HTML only** when the file is **< 3 MB** *and* the report is **not** classified
  Sensitive. A large self-contained HTML (advisor-impact) routinely exceeds the connector
  attachment limit and bloats mailboxes → **link-only by classification**.
- A full SOC report emailed as an attachment can be freely forwarded; a SharePoint link
  respects site ACLs and leaves an access trail → **link-only is the safer default for
  Sensitive reports.**
- If `webUrl` is `null` (archive skipped/failed) **and** the report is link-only class,
  fall back to attaching the HTML if it is < 3 MB; otherwise note in the body that the
  report is available on disk and state why the archive was skipped. Never silently drop it.

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

- `--site` accepts a Graph `siteId` (`host,guid,guid`) **or** a `host:/sites/SOC` path. **Its value is read from `config.json` → `sharepoint.site_id`** (see [Site id from config.json](#site-id-from-configjson)); if absent, the script is called **without** `--site` and exits `3` (skipped, best-effort).
- Auth (first available): `--token` · `--token-file` · env `GRAPH_TOKEN` · `ManagedIdentityCredential` → the agent's **system-assigned MI** (the *archiver* identity that holds `Sites.Selected` + site write — NOT the UAMI used for the security Graph calls).
- `--dry-run` prints the intended path/method with no token/network (offline test).
- Exit codes: `0` ok · `3` skipped (no `--site`, best-effort) · `1` error (log + continue delivery).
- Parent folders (`<skill>/<YYYY>/<MM>`) are created automatically by Graph path-addressing.

### Site id from config.json

The `--site` value comes from the runtime `config.json` so it is set once, not hardcoded per skill:

```json
"sharepoint": {
  "site_id": "<host,siteGuid,webGuid>   OR   <host>:/sites/SOC",
  "container": "SOC Reports"
}
```

Discover the `site_id` once (admin, read-only):

```http
GET https://graph.microsoft.com/v1.0/sites/{tenant}.sharepoint.com:/sites/SOC   # → .id
```

If `sharepoint.site_id` is absent the archive step is skipped (exit `3`) and delivery proceeds with the attachment only — never blocked.

### Least privilege (one-time admin)

The **archiver identity** — the agent's **system-assigned managed identity** ("SRE Agent SP"),
which is what `ManagedIdentityCredential()` resolves to — needs Graph **`Sites.Selected`** with
`write` granted **only on the SOC site** (not `Sites.ReadWrite.All` / `Sites.FullControl.All`).
The UAMI that runs the security Graph calls is a *different* identity and intentionally does
**not** hold this grant (it has `Sites.Read.All` only).

```http
GET  https://graph.microsoft.com/v1.0/sites/{tenant}.sharepoint.com:/sites/SOC      # → siteId
POST https://graph.microsoft.com/v1.0/sites/{SOC-siteId}/permissions
{ "roles": ["write"],
  "grantedToIdentities": [{ "application": { "id": "<archiver-MI-app-id>", "displayName": "SRE Agent SP" } }] }
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

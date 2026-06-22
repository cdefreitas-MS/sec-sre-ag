"""
SharePoint report archival — upload a generated report to the SOC SharePoint site.

Companion to the report-producing skills (advisor-impact, threat-pulse, etc.). After a
skill generates its HTML/MD, this util streams the file to SharePoint via Microsoft Graph
**at generation time**, so large self-contained reports (advisor-impact HTML ~3 MB with
embedded base64) archive cleanly — they're read from disk and chunk-uploaded, NOT routed
through a connector request body (which caps out on big files).

Path layout (one folder per skill + year/month):
    <library-root>/<container>/<skill>/<YYYY>/<MM>/<filename>
    e.g.            SOC Reports/advisor-impact/2026/06/advisor-impact-2026-06-19.html

Auth (first available wins):
    --token <jwt>  ·  --token-file <path>  ·  env GRAPH_TOKEN  ·  ManagedIdentityCredential (UAMI)
Least privilege: the UAMI only needs Graph **Sites.Selected** with `write` granted on the
SOC site (not Sites.ReadWrite.All / Sites.FullControl.All).

Best-effort by design: a failed archive must NEVER block email/Teams delivery. On any error
this exits non-zero and prints to stderr; the caller should log and continue.

Usage:
    python sharepoint_upload.py upload --site <siteId> --skill advisor-impact --file report.html
    python sharepoint_upload.py upload --site <siteId> --skill advisor-impact --file report.html --dry-run
    python sharepoint_upload.py upload --site host:/sites/SOC --skill threat-pulse --file r.md --token-file tok.txt

Importable:
    from sharepoint_upload import upload_file, build_item_path
    url = upload_file(site="...", skill="advisor-impact", file_path="report.html")
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from urllib.parse import quote

# Force UTF-8 stdout/stderr on Windows so emoji don't crash a cp1252 console.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
SIMPLE_MAX = 4 * 1024 * 1024          # <4 MB → single PUT; >= → chunked upload session
CHUNK = 10 * 320 * 1024               # 3 276 800 bytes — must be a multiple of 320 KiB
DEFAULT_CONTAINER = "SOC Reports"


# ---------------------------------------------------------------------------
# Pure helpers (no network) — unit-testable, used by --dry-run too.
# ---------------------------------------------------------------------------
def build_item_path(skill, filename, when=None, container=DEFAULT_CONTAINER):
    """Server-relative item path under the drive root: container/skill/YYYY/MM/filename."""
    when = when or dt.datetime.now()
    skill = (skill or "misc").strip().strip("/")
    name = os.path.basename(filename)
    return f"{container}/{skill}/{when:%Y}/{when:%m}/{name}"


def _graph_path_url(base, item_path):
    """Graph path-addressing URL: .../root:/<url-encoded path>:/<verb>. Slashes kept literal."""
    enc = "/".join(quote(seg) for seg in item_path.split("/") if seg != "")
    return f"{base}/root:/{enc}:"


def upload_method(size):
    return "simple" if size < SIMPLE_MAX else "session"


# ---------------------------------------------------------------------------
# Auth + HTTP (lazy imports so --dry-run needs no extra packages installed).
# ---------------------------------------------------------------------------
def acquire_token(token=None, token_file=None):
    """First available: explicit token → token file → GRAPH_TOKEN env → Managed Identity."""
    if token:
        return token.strip()
    if token_file:
        with open(token_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    env = os.environ.get("GRAPH_TOKEN")
    if env:
        return env.strip()
    # Managed Identity (the SRE Agent UAMI). Lazy import so offline/dry-run doesn't need it.
    from azure.identity import ManagedIdentityCredential
    cred = ManagedIdentityCredential()
    return cred.get_token(GRAPH_SCOPE).token


def _drive_base(site, drive=None):
    """Graph drive base URL. Resolves a `host:/sites/Name` site path to an id if needed."""
    import requests  # lazy
    if drive:
        return f"{GRAPH}/drives/{drive}", None
    site_id = site
    if site and "," not in site and ":" in site:           # looks like host:/sites/Name → resolve
        r = requests.get(f"{GRAPH}/sites/{site}", headers=_HDR, timeout=30)
        r.raise_for_status()
        site_id = r.json()["id"]
    return f"{GRAPH}/sites/{site_id}/drive", site_id


_HDR = {}  # set in upload_file once token is known


def upload_file(site, skill, file_path, drive=None, when=None, container=DEFAULT_CONTAINER,
                token=None, token_file=None, conflict="replace", dry_run=False):
    """Upload one file. Returns the SharePoint webUrl on success (or a dict on dry-run)."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(file_path)
    if when is None:
        when = dt.datetime.fromtimestamp(os.path.getmtime(file_path))
    size = os.path.getsize(file_path)
    item_path = build_item_path(skill, file_path, when, container)
    method = upload_method(size)

    if dry_run:
        return {"dry_run": True, "site": site, "drive": drive, "item_path": item_path,
                "size": size, "method": method, "conflict": conflict}

    global _HDR
    _HDR = {"Authorization": "Bearer " + acquire_token(token, token_file)}
    import requests  # lazy

    base, _ = _drive_base(site, drive)
    url = _graph_path_url(base, item_path)

    with open(file_path, "rb") as f:
        data = f.read()

    if method == "simple":
        r = requests.put(url + f"/content?@microsoft.graph.conflictBehavior={conflict}",
                         headers={**_HDR, "Content-Type": "application/octet-stream"},
                         data=data, timeout=120)
        r.raise_for_status()
        return r.json().get("webUrl")

    # large file → upload session (chunked)
    s = requests.post(url + "/createUploadSession", headers=_HDR,
                      json={"item": {"@microsoft.graph.conflictBehavior": conflict}}, timeout=30)
    s.raise_for_status()
    upload_url = s.json()["uploadUrl"]
    sent, last = 0, None
    while sent < size:
        chunk = data[sent:sent + CHUNK]
        end = sent + len(chunk) - 1
        last = requests.put(upload_url, headers={
            "Content-Length": str(len(chunk)),
            "Content-Range": f"bytes {sent}-{end}/{size}"}, data=chunk, timeout=120)
        if last.status_code not in (200, 201, 202):
            last.raise_for_status()
        sent += len(chunk)
    try:
        return (last.json() or {}).get("webUrl")
    except Exception:
        return "uploaded"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Archive a report file to the SOC SharePoint site (Graph).")
    sub = ap.add_subparsers(dest="cmd")
    up = sub.add_parser("upload", help="upload a file to <container>/<skill>/<YYYY>/<MM>/")
    up.add_argument("--site", help="Graph siteId (host,guid,guid) OR a `host:/sites/Name` path")
    up.add_argument("--skill", required=True, help="skill name = destination subfolder")
    up.add_argument("--file", dest="file_path", required=True, help="path to the report on disk")
    up.add_argument("--drive", default=None, help="driveId (default: site's default document library)")
    up.add_argument("--container", default=DEFAULT_CONTAINER, help='root folder (default "SOC Reports")')
    up.add_argument("--when", default=None, help="ISO date for YYYY/MM (default: file mtime)")
    up.add_argument("--token", default=None)
    up.add_argument("--token-file", dest="token_file", default=None)
    up.add_argument("--conflict", default="replace", choices=["replace", "rename", "fail"])
    up.add_argument("--dry-run", action="store_true", help="print intended action; no token/network")
    args = ap.parse_args(argv)

    if args.cmd != "upload":
        ap.print_help()
        return 2

    when = None
    if args.when:
        try:
            when = dt.datetime.fromisoformat(args.when)
        except ValueError:
            print(f"⚠ --when inválido ({args.when}); usando mtime do arquivo.", file=sys.stderr)

    # Best-effort: without a target site (and not a dry-run) we SKIP rather than fail the run.
    if not args.site and not args.dry_run:
        print("⏭ sem --site configurado — arquivamento SharePoint pulado (best-effort).", file=sys.stderr)
        return 3

    try:
        out = upload_file(site=args.site, skill=args.skill, file_path=args.file_path,
                          drive=args.drive, when=when, container=args.container,
                          token=args.token, token_file=args.token_file,
                          conflict=args.conflict, dry_run=args.dry_run)
    except FileNotFoundError as e:
        print(f"✗ arquivo não encontrado: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # best-effort: log, don't crash the delivery pipeline
        print(f"✗ falha ao arquivar no SharePoint (entrega NÃO deve ser bloqueada): {e}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(json.dumps(out, ensure_ascii=False, indent=2))
        print(f"   → {out['method'].upper()} upload de {out['size']} bytes em "
              f"{out['item_path']}", file=sys.stderr)
    else:
        # folderUrl = parent library folder (opens in browser; a file webUrl forces an
        # .html download in SharePoint). Email/Teams link at the folder when the report is
        # attached, so clicking it opens SharePoint instead of re-downloading the HTML.
        folder_url = (out.rsplit("/", 1)[0]
                      if isinstance(out, str) and out.startswith("http") and "/" in out
                      else None)
        print(json.dumps({"ok": True, "webUrl": out, "folderUrl": folder_url},
                         ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

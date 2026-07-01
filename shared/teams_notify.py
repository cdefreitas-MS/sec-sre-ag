#!/usr/bin/env python3
"""Post an Adaptive Card to a Microsoft Teams channel via a Workflows
(Power Automate) incoming webhook, resolving the webhook URL from Azure
Key Vault so the secret never appears in config.json, logs, or agent chat.

Precedence for the webhook (first that resolves wins):
  1. --webhook-secret-uri  / config teams.webhook_secret_uri   (Key Vault — preferred)
  2. --webhook-url         / config teams.webhook_url           (clear-text fallback)

The resolved URL is used only in-process and is NEVER printed. Output is a
single JSON status line ({"ok":true,"status":202,...}); the webhook value
does not appear in stdout/stderr under any code path.

Usage:
  python shared/teams_notify.py --config config.json --card card.json
  python shared/teams_notify.py --webhook-secret-uri \
      https://kvsentinel-teste.vault.azure.net/secrets/Teams-webhook --card card.json
  echo '<card json>' | python shared/teams_notify.py --config config.json
  python shared/teams_notify.py --config config.json --card card.json --dry-run

Exit codes: 0 ok · 2 error · 3 skipped (no webhook / teams disabled).
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

AZ = shutil.which("az") or "az"

_URI_RE = re.compile(
    r"^https://([A-Za-z0-9-]+)\.vault\.azure\.net/secrets/([^/?]+)", re.IGNORECASE
)


def _kv_get(vault, name):
    """Fetch a secret value via `az keyvault secret show`. The value is used
    in-process only and is never printed by this tool."""
    cmd = [AZ, "keyvault", "secret", "show", "--vault-name", vault,
           "--name", name, "--query", "value", "-o", "tsv"]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        raise RuntimeError(
            f"key vault get failed ({r.returncode}): {(r.stderr or '').strip()[:200]}"
        )
    val = (r.stdout or "").strip()
    if not val:
        raise RuntimeError("key vault secret is empty")
    return val


def resolve_webhook(teams_cfg=None, secret_uri=None, webhook_url=None):
    """Return (url, source). source is 'keyvault' or 'clear'; (None, None) if
    nothing is configured. Never returns/logs the value except as the url."""
    teams_cfg = teams_cfg or {}
    secret_uri = secret_uri or teams_cfg.get("webhook_secret_uri")
    if secret_uri:
        m = _URI_RE.match(secret_uri.strip())
        if not m:
            raise RuntimeError(
                "invalid webhook_secret_uri "
                "(expected https://<vault>.vault.azure.net/secrets/<name>)"
            )
        return _kv_get(m.group(1), m.group(2)), "keyvault"
    url = webhook_url or teams_cfg.get("webhook_url")
    if url:
        return url, "clear"
    return None, None


def post_card(url, payload, timeout=30):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def main():
    ap = argparse.ArgumentParser(description="Post an Adaptive Card to Teams (KV-backed webhook).")
    ap.add_argument("--config", help="config.json containing a teams block")
    ap.add_argument("--card", help="Adaptive Card payload JSON file (else read stdin)")
    ap.add_argument("--webhook-secret-uri", help="Key Vault secret URI for the webhook")
    ap.add_argument("--webhook-url", help="clear-text webhook (fallback only)")
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve + validate without posting; never prints the URL")
    a = ap.parse_args()

    teams_cfg = {}
    if a.config and os.path.exists(a.config):
        try:
            teams_cfg = (json.load(open(a.config, encoding="utf-8")) or {}).get("teams", {}) or {}
        except Exception as e:
            print(json.dumps({"ok": False, "error": f"config read failed: {e}"}))
            sys.exit(2)
    if teams_cfg.get("enabled") is False:
        print(json.dumps({"ok": False, "skipped": True, "reason": "teams disabled"}))
        sys.exit(3)

    try:
        url, source = resolve_webhook(teams_cfg, a.webhook_secret_uri, a.webhook_url)
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        sys.exit(2)
    if not url:
        print(json.dumps({"ok": False, "skipped": True, "reason": "no webhook configured"}))
        sys.exit(3)

    payload = None
    if a.card:
        try:
            payload = json.load(open(a.card, encoding="utf-8"))
        except Exception as e:
            print(json.dumps({"ok": False, "error": f"card read failed: {e}"}))
            sys.exit(2)
    elif not sys.stdin.isatty():
        raw = sys.stdin.read().strip()
        if raw:
            try:
                payload = json.loads(raw)
            except Exception as e:
                print(json.dumps({"ok": False, "error": f"card parse failed: {e}"}))
                sys.exit(2)

    if a.dry_run:
        print(json.dumps({"ok": True, "dry_run": True, "resolved": True,
                          "source": source, "has_card": bool(payload)}))
        sys.exit(0)

    if not payload:
        print(json.dumps({"ok": False, "error": "no card payload (--card or stdin)"}))
        sys.exit(2)

    try:
        status = post_card(url, payload)
    except urllib.error.HTTPError as e:
        print(json.dumps({"ok": False, "status": e.code, "error": "post failed"}))
        sys.exit(2)
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        sys.exit(2)

    print(json.dumps({"ok": True, "status": status, "source": source}))
    sys.exit(0)


if __name__ == "__main__":
    main()

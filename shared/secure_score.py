#!/usr/bin/env python3
"""
Canonical Microsoft Secure Score (M365 / Entra) reader — single source of truth.

Both advisor-impact (its optional "Microsoft Secure Score" dataset) and org-posture (the
"Identity & Configuration" pillar of the Org Posture Index) read the SAME Graph endpoint
`GET /security/secureScores`. This helper picks the LATEST entry by `createdDateTime` and
computes the percentage, so the headline Secure Score number can't drift between the two
reports. Stdlib only.

Importable:
    from secure_score import latest_secure_score
    ss = latest_secure_score(graph_response)   # → {current, max, pct, controls, createdDateTime} | None

CLI (repo subprocess convention):
    python shared/secure_score.py <results.json>      # file holding the /security/secureScores response
    cat results.json | python shared/secure_score.py  # or from stdin
    → prints {"current":…, "max":…, "pct":…, "controls":…, "createdDateTime":…}  (or {} when unavailable)
    exit 0 = data · 3 = no data (best-effort, per repo convention)
"""
from __future__ import annotations

import json
import sys


def _num(x, d=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return d


def _rows(resp):
    """Normalize a /security/secureScores response to a list of score entries."""
    if isinstance(resp, dict):
        if isinstance(resp.get("value"), list):
            return resp["value"]
        if "currentScore" in resp or "properties" in resp:   # single entry passed directly
            return [resp]
        return []
    if isinstance(resp, list):
        return resp
    return []


def _props(row):
    """ARG wraps the score under `properties`; Graph returns it flat."""
    if not isinstance(row, dict):
        return {}
    p = row.get("properties")
    return p if isinstance(p, dict) else row


def latest_secure_score(resp):
    """Most recent /security/secureScores entry → dict or None when unavailable."""
    rows = [_props(r) for r in _rows(resp)]
    rows = [p for p in rows if isinstance(p, dict) and p]
    if not rows:
        return None
    rows.sort(key=lambda p: str(p.get("createdDateTime", "")), reverse=True)
    p = rows[0]
    cur, mx = _num(p.get("currentScore")), _num(p.get("maxScore"))
    if mx <= 0:
        return None
    return {"current": round(cur, 1), "max": round(mx, 1),
            "pct": round(100.0 * cur / mx, 1),
            "controls": len(p.get("controlScores") or []),
            "createdDateTime": p.get("createdDateTime")}


def _main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if argv and argv[0] not in ("-", "--stdin"):
        with open(argv[0], "r", encoding="utf-8") as f:
            raw = json.load(f)
    else:
        raw = json.load(sys.stdin)
    ss = latest_secure_score(raw)
    print(json.dumps(ss or {}, ensure_ascii=False))
    return 0 if ss else 3


if __name__ == "__main__":
    raise SystemExit(_main())

"""
MITRE ATT&CK Mapper — infer ATT&CK techniques/tactics from free-text activity.

Complements the `mitre-coverage-report` skill (which scores deployed analytic-rule
coverage from the full ATT&CK catalog) by doing the inverse: a lightweight
keyword → technique heuristic. Useful when an alert title, audit activity, or hunt
finding has NO MITRE tag and you want to label it (e.g. "mimikatz on LSASS" → T1003.001).

Self-contained, read-only, no secrets. Invoke as a subprocess (matches shared/ convention):

    python mitre_map.py map "detected mimikatz dumping lsass then rdp lateral movement"
    python mitre_map.py technique T1003.001        # look up a technique by ID
    python mitre_map.py tactic "Credential Access" # all techniques under a tactic
    python mitre_map.py tactics                    # list all tactics
    python mitre_map.py list                        # the full keyword map

Importable:
    from mitre_map import MitreMapper
    for m in MitreMapper().map_activity("password spray from tor exit node"):
        print(m.technique_id, m.technique_name, m.tactic)
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass

# Force UTF-8 stdout/stderr on Windows so emoji/box-drawing chars don't crash a cp1252 console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


@dataclass
class MitreMapping:
    """A single MITRE ATT&CK mapping."""
    technique_id: str
    technique_name: str
    tactic: str
    description: str


# Keyword → MITRE technique. Substring match, case-insensitive.
# Base set ported from an internal Defender MCP helper; cloud-identity techniques
# added to align with this suite (aitm-dashboard · spn-scope-drift · forensic-user).
_TECHNIQUE_MAP: dict[str, MitreMapping] = {
    # ── Initial Access ────────────────────────────────────────────────
    "phishing": MitreMapping("T1566", "Phishing", "Initial Access", "Adversary sends phishing messages to gain access"),
    "valid accounts": MitreMapping("T1078", "Valid Accounts", "Initial Access", "Adversary uses legitimate credentials"),
    "exploit public": MitreMapping("T1190", "Exploit Public-Facing Application", "Initial Access", "Exploitation of internet-facing applications"),

    # ── Execution ─────────────────────────────────────────────────────
    "powershell": MitreMapping("T1059.001", "PowerShell", "Execution", "Use of PowerShell for command execution"),
    "cmd": MitreMapping("T1059.003", "Windows Command Shell", "Execution", "Use of cmd.exe for execution"),
    "wmi": MitreMapping("T1047", "Windows Management Instrumentation", "Execution", "WMI for execution"),
    "mshta": MitreMapping("T1218.005", "Mshta", "Execution", "Use of mshta.exe to proxy execution"),
    "regsvr32": MitreMapping("T1218.010", "Regsvr32", "Execution", "Regsvr32 for proxy execution"),
    "rundll32": MitreMapping("T1218.011", "Rundll32", "Execution", "Rundll32 for proxy execution"),

    # ── Persistence ───────────────────────────────────────────────────
    "registry run": MitreMapping("T1547.001", "Registry Run Keys / Startup Folder", "Persistence", "Persistence via Run/RunOnce registry keys"),
    "scheduled task": MitreMapping("T1053.005", "Scheduled Task", "Persistence", "Persistence via scheduled tasks"),
    "new service": MitreMapping("T1543.003", "Windows Service", "Persistence", "Persistence via Windows services"),
    "startup": MitreMapping("T1547", "Boot or Logon Autostart Execution", "Persistence", "Boot or logon autostart execution"),
    "added credential": MitreMapping("T1098.001", "Additional Cloud Credentials", "Persistence", "Secret/cert added to an app or service principal"),
    "service principal": MitreMapping("T1098.001", "Additional Cloud Credentials", "Persistence", "Credential added to a service principal / app registration"),

    # ── Privilege Escalation ──────────────────────────────────────────
    "privilege escalation": MitreMapping("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "Exploitation to gain elevated privileges"),
    "token manipulation": MitreMapping("T1134", "Access Token Manipulation", "Privilege Escalation", "Token manipulation for privilege escalation"),

    # ── Defense Evasion ───────────────────────────────────────────────
    "clear event": MitreMapping("T1070.001", "Clear Windows Event Logs", "Defense Evasion", "Clearing Windows event logs to cover tracks"),
    "disable defender": MitreMapping("T1562.001", "Disable or Modify Tools", "Defense Evasion", "Disabling security tools"),
    "timestomp": MitreMapping("T1070.006", "Timestomp", "Defense Evasion", "Modifying file timestamps"),
    "certutil": MitreMapping("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion", "Using certutil for decode operations"),
    "token theft": MitreMapping("T1550.001", "Application Access Token", "Defense Evasion", "Use of a stolen session/access token to bypass auth"),
    "stolen token": MitreMapping("T1550.001", "Application Access Token", "Defense Evasion", "Use of a stolen session/access token to bypass auth"),
    "session token": MitreMapping("T1550.001", "Application Access Token", "Defense Evasion", "Reuse of a hijacked session token"),

    # ── Credential Access ─────────────────────────────────────────────
    "mimikatz": MitreMapping("T1003.001", "LSASS Memory", "Credential Access", "Dumping credentials from LSASS"),
    "lsass": MitreMapping("T1003.001", "LSASS Memory", "Credential Access", "Targeting LSASS for credential extraction"),
    "dcsync": MitreMapping("T1003.006", "DCSync", "Credential Access", "Replicating AD credentials via DCSync"),
    "kerberoast": MitreMapping("T1558.003", "Kerberoasting", "Credential Access", "Extracting service account credentials"),
    "brute force": MitreMapping("T1110", "Brute Force", "Credential Access", "Brute force password attacks"),
    "password spray": MitreMapping("T1110.003", "Password Spraying", "Credential Access", "Trying common passwords across many accounts"),
    "adversary-in-the-middle": MitreMapping("T1557", "Adversary-in-the-Middle", "Credential Access", "AiTM proxy intercepts auth (session/credential theft)"),
    "aitm": MitreMapping("T1557", "Adversary-in-the-Middle", "Credential Access", "AiTM proxy intercepts auth (session/credential theft)"),
    "consent grant": MitreMapping("T1528", "Steal Application Access Token", "Credential Access", "Illicit OAuth consent grants an app access to data"),
    "illicit consent": MitreMapping("T1528", "Steal Application Access Token", "Credential Access", "Illicit OAuth consent grants an app access to data"),
    "oauth": MitreMapping("T1528", "Steal Application Access Token", "Credential Access", "OAuth application access-token abuse"),
    "mfa fatigue": MitreMapping("T1621", "Multi-Factor Authentication Request Generation", "Credential Access", "MFA bombing/fatigue to coerce approval"),

    # ── Lateral Movement ──────────────────────────────────────────────
    "psexec": MitreMapping("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement", "Lateral movement via PsExec/SMB"),
    "rdp": MitreMapping("T1021.001", "Remote Desktop Protocol", "Lateral Movement", "Lateral movement via RDP"),
    "winrm": MitreMapping("T1021.006", "Windows Remote Management", "Lateral Movement", "Lateral movement via WinRM"),
    "lateral movement": MitreMapping("T1021", "Remote Services", "Lateral Movement", "Use of remote services for lateral movement"),

    # ── Collection ────────────────────────────────────────────────────
    "inbox rule": MitreMapping("T1114.003", "Email Forwarding Rule", "Collection", "Malicious inbox/forwarding rule (BEC) to siphon mail"),
    "forwarding rule": MitreMapping("T1114.003", "Email Forwarding Rule", "Collection", "Malicious inbox/forwarding rule (BEC) to siphon mail"),

    # ── Exfiltration ──────────────────────────────────────────────────
    "exfiltration": MitreMapping("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "Data exfiltration over command and control"),
    "dns tunnel": MitreMapping("T1048.001", "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "Exfiltration", "Data exfiltration via DNS tunnelling"),
    "cloud upload": MitreMapping("T1567", "Exfiltration Over Web Service", "Exfiltration", "Data uploaded to cloud storage"),

    # ── Impact ────────────────────────────────────────────────────────
    "ransomware": MitreMapping("T1486", "Data Encrypted for Impact", "Impact", "Ransomware encryption activity"),
    "shadow copy": MitreMapping("T1490", "Inhibit System Recovery", "Impact", "Deletion of shadow copies/backups"),
    "wiper": MitreMapping("T1485", "Data Destruction", "Impact", "Destruction of data"),
}

# Canonical ATT&CK tactic order (for stable listing/output)
_TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]


class MitreMapper:
    """Maps security detections and activities to the MITRE ATT&CK framework."""

    def map_activity(self, activity: str) -> list[MitreMapping]:
        """Find all MITRE mappings relevant to an activity description (keyword match)."""
        activity_lower = (activity or "").lower()
        matches: list[MitreMapping] = []
        seen_ids: set[str] = set()
        for keyword, mapping in _TECHNIQUE_MAP.items():
            if keyword in activity_lower and mapping.technique_id not in seen_ids:
                matches.append(mapping)
                seen_ids.add(mapping.technique_id)
        return matches

    def map_technique_id(self, technique_id: str) -> MitreMapping | None:
        """Look up a mapping by technique ID (exact, case-insensitive)."""
        tid = (technique_id or "").upper()
        for mapping in _TECHNIQUE_MAP.values():
            if mapping.technique_id.upper() == tid:
                return mapping
        return None

    def get_tactic_techniques(self, tactic: str) -> list[MitreMapping]:
        """Return all distinct techniques under a given tactic."""
        tactic_lower = (tactic or "").lower()
        seen: set[str] = set()
        results: list[MitreMapping] = []
        for mapping in _TECHNIQUE_MAP.values():
            if mapping.tactic.lower() == tactic_lower and mapping.technique_id not in seen:
                results.append(mapping)
                seen.add(mapping.technique_id)
        return results

    def get_all_tactics(self) -> list[str]:
        """Return the tactics present in the map, in canonical ATT&CK order."""
        present = {m.tactic for m in _TECHNIQUE_MAP.values()}
        ordered = [t for t in _TACTIC_ORDER if t in present]
        # append any tactic not in the canonical list (future-proofing)
        return ordered + sorted(present - set(ordered))

    def all_techniques(self) -> list[MitreMapping]:
        """Return every distinct technique mapping (deduped by ID)."""
        seen: set[str] = set()
        out: list[MitreMapping] = []
        for m in _TECHNIQUE_MAP.values():
            if m.technique_id not in seen:
                out.append(m)
                seen.add(m.technique_id)
        return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cmd_map(mapper: MitreMapper, activity: str) -> int:
    hits = mapper.map_activity(activity)
    out = {
        "activity": activity,
        "matched": len(hits),
        "techniques": [asdict(m) for m in hits],
        "tactics": sorted({m.tactic for m in hits}),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if hits else 3  # exit 3 = no technique inferred (caller can branch)


def _cmd_technique(mapper: MitreMapper, technique_id: str) -> int:
    m = mapper.map_technique_id(technique_id)
    if m is None:
        print(json.dumps({"technique_id": technique_id, "found": False}, ensure_ascii=False, indent=2))
        return 3
    print(json.dumps(asdict(m), ensure_ascii=False, indent=2))
    return 0


def _cmd_tactic(mapper: MitreMapper, tactic: str) -> int:
    techs = mapper.get_tactic_techniques(tactic)
    out = {"tactic": tactic, "count": len(techs), "techniques": [asdict(m) for m in techs]}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if techs else 3


def _cmd_tactics(mapper: MitreMapper) -> int:
    for t in mapper.get_all_tactics():
        n = len(mapper.get_tactic_techniques(t))
        print(f"{t:<24} {n} técnica(s)")
    return 0


def _cmd_list(mapper: MitreMapper) -> int:
    rows = sorted(mapper.all_techniques(), key=lambda m: (_TACTIC_ORDER.index(m.tactic) if m.tactic in _TACTIC_ORDER else 99, m.technique_id))
    print(f"{'TÉCNICA':<12} {'TÁTICA':<22} NOME")
    print("-" * 70)
    for m in rows:
        print(f"{m.technique_id:<12} {m.tactic:<22} {m.technique_name}")
    print(f"\n{len(rows)} técnicas · {len(_TECHNIQUE_MAP)} palavras-chave · {len(mapper.get_all_tactics())} táticas.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MITRE ATT&CK mapper — infer techniques/tactics from free text.")
    sub = parser.add_subparsers(dest="command", required=True)
    p_map = sub.add_parser("map", help="Infere técnicas a partir de um texto de atividade.")
    p_map.add_argument("activity", help="Texto livre (título de alerta, atividade de audit, achado de hunt).")
    p_tech = sub.add_parser("technique", help="Consulta uma técnica por ID (ex. T1003.001).")
    p_tech.add_argument("technique_id")
    p_tac = sub.add_parser("tactic", help="Lista técnicas de uma tática (ex. 'Credential Access').")
    p_tac.add_argument("tactic")
    sub.add_parser("tactics", help="Lista todas as táticas presentes no mapa.")
    sub.add_parser("list", help="Lista todas as técnicas do mapa.")
    args = parser.parse_args(argv)

    mapper = MitreMapper()
    if args.command == "map":
        return _cmd_map(mapper, args.activity)
    if args.command == "technique":
        return _cmd_technique(mapper, args.technique_id)
    if args.command == "tactic":
        return _cmd_tactic(mapper, args.tactic)
    if args.command == "tactics":
        return _cmd_tactics(mapper)
    if args.command == "list":
        return _cmd_list(mapper)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

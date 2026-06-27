#!/usr/bin/env python3
"""
attack-path — cross-domain attack-path synthesizer (collector↔renderer).

WHAT IT DOES (the "out-of-the-box" engine):
  It does NOT add a new data source. It INGESTS the datasets your other skills
  already collect (exposure-graph, org-posture NHI, spn-scope-drift,
  graph-least-privilege, threat-correlation, advisor-impact) and SYNTHESIZES a
  directed risk graph:

      nodes  = identities · service principals · devices · resources · roles · capabilities
      edges  = ABUSABLE transitions (weak credential, role membership, granted Graph
               scope, internet exposure, public-network misconfig, app ownership,
               admin logon on an exposed host)

  Then it finds attack paths  (external attacker → pivot → crown jewel),  scores each
  by  likelihood (∏ edge feasibility) × impact (crown-jewel value),  and ranks the
  remediation CHOKEPOINTS — the single fix that breaks the MOST high-risk paths.
  That re-prioritizes remediation by BLAST-RADIUS REDUCTION, not by Secure-Score points
  — which no single Microsoft product does, because each product is single-domain.

  Edges are also annotated with the ATT&CK technique an attacker would use; if your
  detections don't cover that technique (mitre_covered) or the telemetry is silent
  (silent_sources / impaired_sensors), the path is flagged as a DETECTION BLIND SPOT.

100% READ-ONLY. Deterministic. Modes:
  python generate_html_report.py --from-json bundle.json     # PRIMARY (Mode B prefetch)
  python generate_html_report.py                             # best-effort self-collect (Mode A)

See queries.yaml for the bundle shape, scoring weights and the abuse→MITRE→remediation map.
Requires: PyYAML. Self-collect needs Azure CLI with MDE Score/SecurityRecommendation +
Graph IdentityRiskyUser/Directory/Application read.
"""
import argparse
import datetime as dt
import html
import json
import pathlib
import re
import shutil
import subprocess
import sys
import uuid

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

HERE = pathlib.Path(__file__).parent
SKILL = "attack-path"
AZ = shutil.which("az") or "az"
EXT = "ext::internet"  # single virtual external-attacker start node


# ───────────────────────────── helpers ─────────────────────────────
def load_queries(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _num(x, d=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return d


def _val(resp):
    if isinstance(resp, dict):
        return resp.get("value", []) or []
    if isinstance(resp, list):
        return resp
    return []


def _parse_dt(s):
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def _now():
    return dt.datetime.now(dt.timezone.utc)


# ───────────────────────── self-collect (Mode A) ───────────────────
def get_token(resource):
    cmd = [AZ, "account", "get-access-token", "--resource", resource,
           "--query", "accessToken", "-o", "tsv"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip())
    return res.stdout.strip()


def api_get(url, token):
    import urllib.request
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)


def collect():
    """Best-effort self-collect of the minimal bundle. --from-json is preferred."""
    out = {}
    mde, graph = "https://api.securitycenter.microsoft.com/api", "https://graph.microsoft.com/v1.0"
    try:
        mtok = get_token("https://api.securitycenter.microsoft.com")
        for k, p in {"exposure_score": "/exposureScore", "machines": "/machines",
                     "recommendations": "/recommendations"}.items():
            try:
                out[k] = api_get(mde + p, mtok)
            except Exception as e:
                print(f"  ! MDE '{k}': {e}", file=sys.stderr)
    except Exception as e:
        print(f"  ! MDE token: {e}", file=sys.stderr)
    try:
        gtok = get_token("https://graph.microsoft.com")
        eps = {
            "directory_roles": "/directoryRoles?$expand=members",
            "risky_users": "/identityProtection/riskyUsers?$filter=riskLevel%20eq%20%27high%27%20or%20riskLevel%20eq%20%27medium%27",
            "service_principals": "/servicePrincipals?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=500",
            "applications": "/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=500",
        }
        for k, p in eps.items():
            try:
                out[k] = api_get(graph + p, gtok)
            except Exception as e:
                print(f"  ! Graph '{k}': {e}", file=sys.stderr)
    except Exception as e:
        print(f"  ! Graph token: {e}", file=sys.stderr)
    return out


# ───────────────────────── graph synthesis ─────────────────────────
class Graph:
    def __init__(self):
        self.nodes = {}   # id -> node dict
        self.edges = []   # edge dicts
        self._adj = None

    def add_node(self, nid, ntype, label, kind="pivot", impact=0.0, meta=None):
        n = self.nodes.get(nid)
        if n is None:
            self.nodes[nid] = {"id": nid, "type": ntype, "label": label,
                               "kind": kind, "impact": impact, "meta": meta or {}}
        else:
            # never downgrade a jewel; keep the strongest impact / richest label
            if kind == "jewel":
                n["kind"] = "jewel"
            n["impact"] = max(n["impact"], impact)
            if meta:
                n["meta"].update(meta)
        return nid

    def add_edge(self, src, dst, rel, w, source, abuse_map):
        info = abuse_map.get(rel, {})
        self.edges.append({
            "src": src, "dst": dst, "rel": rel, "w": round(float(w), 3),
            "source": source, "mitre": info.get("mitre", ""),
            "abuse": info.get("abuse", rel), "break_with": info.get("break_with", ""),
            "blind": False,
        })

    def adj(self):
        if self._adj is None:
            self._adj = {}
            for e in self.edges:
                self._adj.setdefault(e["src"], []).append(e)
        return self._adj


def _credential_class(obj, params):
    """Classify the worst (most abusable) credential on an app/SP object."""
    now = _now()
    exp_d = params.get("secret_expiring_days", 30)
    long_d = params.get("secret_long_lived_days", 180)
    best = None  # (weight_key, detail)
    rank = {"secret_expired": 5, "secret_expiring": 4, "secret_long_lived": 3,
            "secret_present": 2, "cert_credential": 1}
    for pc in (obj.get("passwordCredentials") or []):
        end = _parse_dt(pc.get("endDateTime"))
        start = _parse_dt(pc.get("startDateTime"))
        if end is None:
            cls, detail = "secret_present", "client secret (sem validade legível)"
        elif end < now:
            cls, detail = "secret_expired", f"client secret EXPIRADO em {end.date()} (rotação não gerenciada?)"
        elif end <= now + dt.timedelta(days=exp_d):
            cls, detail = "secret_expiring", f"client secret vence em {end.date()} (≤{exp_d}d)"
        else:
            span = (end - (start or now)).days
            if span > long_d:
                cls, detail = "secret_long_lived", f"client secret válido por {span}d (>{long_d}d de janela)"
            else:
                cls, detail = "secret_present", f"client secret válido até {end.date()}"
        if best is None or rank[cls] > rank[best[0]]:
            best = (cls, detail)
    if best is None and (obj.get("keyCredentials") or []):
        best = ("cert_credential", "credencial de certificado")
    return best  # None = no secret/cert (federated/managed) → not an entry


def _is_privileged(rname, params):
    return rname.strip().lower() in {r.lower() for r in params.get("privileged_roles", [])}


def _member_node(g, member):
    """Create/locate a node for a directory-role member (user or service principal)."""
    otype = str(member.get("@odata.type", "")).lower()
    oid = member.get("id", "")
    if "serviceprincipal" in otype or member.get("appId"):
        nid = f"sp::{member.get('appId') or oid}"
        label = f"SP: {member.get('displayName', oid)}"
        g.add_node(nid, "sp", label, kind="pivot",
                   meta={"objectId": oid, "appId": member.get("appId", "")})
        return nid, "sp"
    upn = member.get("userPrincipalName") or member.get("displayName") or oid
    nid = f"user::{upn}"
    g.add_node(nid, "user", f"Usuário: {upn}", kind="pivot", meta={"objectId": oid, "upn": upn})
    return nid, "user"


def build_graph(data, params, scoring, abuse_map):
    g = Graph()
    ew = scoring.get("edge_weight", {})
    ji = scoring.get("jewel_impact", {})
    g.add_node(EXT, "ext", "Atacante externo / internet", kind="entry")

    obj_to_node, app_to_node, upn_to_node = {}, {}, {}

    # ── crown jewels: privileged directory roles + members ──────────
    for role in _val(data.get("directory_roles")):
        rname = str(role.get("displayName", ""))
        if not _is_privileged(rname, params):
            continue
        is_ga = rname.strip().lower() == "global administrator"
        rid = g.add_node(f"role::{rname}", "role", f"Papel: {rname}", kind="jewel",
                         impact=ji.get("global_admin" if is_ga else "privileged_role", 0.7))
        for m in (role.get("members") or []):
            mn, mtype = _member_node(g, m)
            g.add_edge(mn, rid, "member_of", ew.get("member_of", 1.0),
                       "exposure/directory_roles", abuse_map)
            oid = m.get("id", "")
            if mtype == "sp":
                obj_to_node[oid] = mn
                if m.get("appId"):
                    app_to_node[m["appId"]] = mn
            else:
                upn = m.get("userPrincipalName") or m.get("displayName") or oid
                upn_to_node[str(upn).lower()] = mn

    # ── service principals / applications: credential entries + scopes ──
    sps = _val(data.get("service_principals")) + _val(data.get("applications"))
    for sp in sps:
        appId = sp.get("appId", "")
        oid = sp.get("id", "")
        nid = app_to_node.get(appId) or obj_to_node.get(oid) or f"sp::{appId or oid}"
        g.add_node(nid, "sp", f"SP: {sp.get('displayName', appId or oid)}", kind="pivot",
                   meta={"objectId": oid, "appId": appId})
        if appId:
            app_to_node[appId] = nid
        if oid:
            obj_to_node[oid] = nid
        cred = _credential_class(sp, params)
        if cred:
            cls, detail = cred
            g.nodes[nid]["meta"]["credential"] = detail
            g.add_edge(EXT, nid, "weak_credential", ew.get(cls, 0.45),
                       "nhi/service_principals", abuse_map)

    # ── granted Graph app-role scopes (graph-least-privilege) ───────
    grants = data.get("app_grants") or {}
    takeover = {s.lower() for s in params.get("tenant_takeover_scopes", [])}
    high_imp = {s.lower() for s in params.get("high_impact_scopes", [])}
    for key, scopes in grants.items():
        nid = app_to_node.get(key) or obj_to_node.get(key) or f"sp::{key}"
        if nid not in g.nodes:
            g.add_node(nid, "sp", f"SP: {key}", kind="pivot", meta={"appId": key})
        for sc in (scopes or []):
            scl = str(sc).lower()
            if scl in takeover:
                cap = g.add_node("cap::tenant_takeover", "cap",
                                 "Capacidade: takeover do tenant (Graph)", kind="jewel",
                                 impact=ji.get("tenant_takeover", 1.0))
                g.add_edge(nid, cap, "granted_scope_takeover",
                           ew.get("scope_tenant_takeover", 0.85), "leastpriv/app_grants", abuse_map)
            elif scl in high_imp:
                cap = g.add_node(f"cap::{sc}", "cap", f"Capacidade: {sc}", kind="jewel",
                                 impact=ji.get("high_impact_capability", 0.55))
                g.add_edge(nid, cap, "granted_scope_impact",
                           ew.get("scope_high_impact", 0.6), "leastpriv/app_grants", abuse_map)

    # ── app owners (optional) → owns_sp edge ────────────────────────
    for key, owners in (data.get("sp_owners") or {}).items():
        nid = app_to_node.get(key) or obj_to_node.get(key) or f"sp::{key}"
        for upn in (owners or []):
            un = upn_to_node.get(str(upn).lower()) or g.add_node(
                f"user::{upn}", "user", f"Usuário: {upn}", kind="pivot", meta={"upn": upn})
            upn_to_node[str(upn).lower()] = un
            g.add_edge(un, nid, "owns_sp", ew.get("owns_sp", 0.65), "graph/owners", abuse_map)

    # ── risky users (entries) ───────────────────────────────────────
    for u in _val(data.get("risky_users")):
        upn = u.get("userPrincipalName") or u.get("id", "")
        lvl = str(u.get("riskLevel", "")).lower()
        wkey = {"high": "risky_user_high", "medium": "risky_user_medium"}.get(lvl, "risky_user_low")
        un = upn_to_node.get(str(upn).lower()) or g.add_node(
            f"user::{upn}", "user", f"Usuário: {upn}", kind="pivot", meta={"upn": upn})
        upn_to_node[str(upn).lower()] = un
        g.nodes[un]["meta"]["risk"] = lvl
        g.nodes[un]["meta"].setdefault("objectId", u.get("id", ""))
        g.add_edge(EXT, un, "risky_identity", ew.get(wkey, 0.5), "idp/risky_users", abuse_map)

    # ── exposed devices (entries) + admin-logon lateral link ────────
    recs = _val(data.get("recommendations"))
    any_public_exploit = any(bool(r.get("publicExploit")) for r in recs)
    foothold = g.add_node("jewel::foothold", "foothold", "Foothold de endpoint", kind="jewel",
                          impact=ji.get("endpoint_foothold", 0.4))
    admin_logons = data.get("admin_logons") or {}
    for mac in _val(data.get("machines")):
        el = str(mac.get("exposureLevel", "None"))
        if el not in ("High", "Medium"):
            continue
        name = mac.get("computerDnsName", mac.get("id", ""))
        did = g.add_node(f"dev::{name}", "device", f"Device: {name}", kind="pivot",
                         meta={"exposure": el, "id": mac.get("id", ""), "name": name})
        ekey = "public_exploit" if (any_public_exploit and el == "High") else (
            "exposed_high_sev" if el == "High" else "exposed")
        g.add_edge(EXT, did, "exposed_internet", ew.get(ekey, 0.4), "mde/machines", abuse_map)
        g.add_edge(did, foothold, "exposed_internet", 1.0, "mde/machines", abuse_map)
        for upn in (admin_logons.get(name) or []):
            un = upn_to_node.get(str(upn).lower())
            if un:  # link only to a known (privileged) identity → real lateral chain
                g.add_edge(did, un, "admin_logon", ew.get("admin_logon", 0.7), "mde/logons", abuse_map)

    # ── public-network misconfig resources (advisor-impact MDC) ─────
    for a in _val(data.get("mdc_assessments")):
        props = a.get("properties", {}) if isinstance(a, dict) else {}
        name = str(props.get("displayName", "")).lower()
        status = str((props.get("status") or {}).get("code", "")).lower()
        if status not in ("unhealthy", "") :
            continue
        if "public network access" in name or ("public" in name and "disabled" in name):
            rid_raw = props.get("resourceDetails", {}).get("id") or a.get("id", "")[:60]
            short = str(rid_raw).rsplit("/", 1)[-1] or "recurso"
            rn = g.add_node(f"res::{short}", "resource", f"Recurso público: {short}",
                            kind="jewel", impact=ji.get("sensitive_resource", 0.5),
                            meta={"resourceId": str(rid_raw)})
            g.add_edge(EXT, rn, "misconfig_public", ew.get("misconfig_public", 0.6),
                       "mdc/assessments", abuse_map)

    # ── blind-spot annotation (Module 2 + Module 4) ─────────────────
    covered = {str(t).upper() for t in (data.get("mitre_covered") or [])}
    silent = {str(s).lower() for s in (data.get("silent_sources") or [])}
    impaired = {str(s).lower() for s in (data.get("impaired_sensors") or [])}
    have_cov = bool(covered)
    for e in g.edges:
        tech = (e["mitre"] or "").upper()
        blind = have_cov and tech and tech.split(".")[0] not in covered and tech not in covered
        dn = g.nodes.get(e["dst"], {})
        if dn.get("type") == "device":
            nm = str(dn.get("meta", {}).get("name", dn.get("label", ""))).lower()
            if any(s in nm for s in impaired):
                blind = True
        if e["source"].split("/")[0] in silent:
            blind = True
        e["blind"] = bool(blind)
    return g


# ───────────────────────── path finding + scoring ──────────────────
DOMAIN = {
    "weak_credential": "credencial", "owns_sp": "credencial",
    "member_of": "privilégio", "granted_scope_takeover": "privilégio",
    "granted_scope_impact": "privilégio",
    "risky_identity": "identidade", "admin_logon": "identidade",
    "exposed_internet": "exploração", "misconfig_public": "exploração",
}


def find_paths(g, params):
    max_depth = int(params.get("max_path_depth", 5))
    adj = g.adj()
    paths = []

    def dfs(node, visited, chain):
        if len(chain) >= max_depth:
            return
        for e in adj.get(node, []):
            dst = e["dst"]
            if dst in visited:
                continue
            ndst = g.nodes.get(dst, {})
            newchain = chain + [e]
            if ndst.get("kind") == "jewel":
                paths.append(list(newchain))
            dfs(dst, visited | {dst}, newchain)

    dfs(EXT, {EXT}, [])
    return paths


def score_paths(g, paths, scoring):
    crit_like = scoring.get("verdict", {}).get("critical_path_likelihood", 0.5)
    scored = []
    for chain in paths:
        likelihood = 1.0
        for e in chain:
            likelihood *= e["w"]
        terminal = g.nodes.get(chain[-1]["dst"], {})
        impact = terminal["impact"]
        risk = round(100.0 * likelihood * impact, 1)
        domains = {DOMAIN.get(e["rel"], e["rel"]) for e in chain}
        node_ids = [EXT] + [e["dst"] for e in chain]
        scored.append({
            "edges": chain,
            "nodes": [g.nodes[n]["label"] for n in node_ids],
            "node_ids": node_ids,
            "likelihood": round(likelihood, 3),
            "impact": round(impact, 2),
            "risk": risk,
            "terminal": terminal["label"],
            "takeover": impact >= 1.0,
            "novel": len(domains) >= 2,
            "domains": sorted(domains),
            "blind": any(e["blind"] for e in chain),
            "critical": impact >= 1.0 and likelihood >= crit_like,
        })
    # dedupe identical node-id sequences, keep highest risk
    best = {}
    for p in scored:
        k = tuple(p["node_ids"])
        if k not in best or p["risk"] > best[k]["risk"]:
            best[k] = p
    out = sorted(best.values(), key=lambda p: (p["risk"], p["novel"], p["blind"]), reverse=True)
    return out


def chokepoints(g, scored, params):
    """Aggregate the remediation that breaks the most high-risk paths."""
    agg = {}
    for p in scored:
        seen = set()  # count each path at most once per chokepoint
        for e in p["edges"]:
            # the actionable asset of an ENTRY edge (src == ext) is its destination
            # (rotate THAT secret / contain THAT user / patch THAT device); for an
            # internal edge it's the source (remove THAT role / revoke THAT scope).
            asset = e["dst"] if e["src"] == EXT else e["src"]
            label = g.nodes.get(asset, {}).get("label", asset)
            key = (asset, e["rel"])
            if key in seen:
                continue
            seen.add(key)
            row = agg.setdefault(key, {
                "fix": e["break_with"] or e["rel"], "on": label, "asset": asset, "rel": e["rel"],
                "mitre": e["mitre"], "paths": 0, "risk_removed": 0.0, "critical": 0,
                "blind": False,
            })
            row["paths"] += 1
            row["risk_removed"] += p["risk"]
            row["critical"] += 1 if p["critical"] else 0
            row["blind"] = row["blind"] or p["blind"]
    rows = sorted(agg.values(), key=lambda r: (r["risk_removed"], r["paths"]), reverse=True)
    for r in rows:
        r["risk_removed"] = round(r["risk_removed"], 1)
    return rows[:int(params.get("top_chokepoints", 20))]


def compute(data, params, scoring, abuse_map):
    g = build_graph(data, params, scoring, abuse_map)
    scored = score_paths(g, find_paths(g, params), scoring)
    chokes = chokepoints(g, scored, params)
    n_crit = sum(1 for p in scored if p["critical"])
    n_blind = sum(1 for p in scored if p["blind"])
    n_novel = sum(1 for p in scored if p["novel"])
    top_risk = scored[0]["risk"] if scored else 0.0

    crit_like = scoring.get("verdict", {}).get("critical_path_likelihood", 0.5)
    elev = scoring.get("verdict", {}).get("elevated_path_risk", 35.0)
    if any(p["takeover"] and p["likelihood"] >= crit_like for p in scored):
        verdict = "CRÍTICA"
    elif top_risk >= elev:
        verdict = "ELEVADA"
    elif scored:
        verdict = "MODERADA"
    else:
        verdict = "CONTIDA"

    return {
        "verdict": verdict, "n_paths": len(scored), "n_crit": n_crit,
        "n_blind": n_blind, "n_novel": n_novel, "top_risk": top_risk,
        "top_choke_risk": chokes[0]["risk_removed"] if chokes else 0.0,
        "n_nodes": len(g.nodes), "n_edges": len(g.edges),
        "paths": scored[:int(params.get("top_paths", 40))],
        "chokepoints": chokes,
    }


# ───────────────────────────── render ──────────────────────────────
VERDICT_COLOR = {"CRÍTICA": "#d13438", "ELEVADA": "#ff8c00",
                 "MODERADA": "#ffb900", "CONTIDA": "#107c10"}
REL_ICON = {"weak_credential": "🔑", "member_of": "👑", "granted_scope_takeover": "⚡",
            "granted_scope_impact": "📤", "risky_identity": "🎭", "admin_logon": "🖥️",
            "exposed_internet": "🌐", "misconfig_public": "🛟", "owns_sp": "🧷"}
NODE_ICON = {"ext": "🌐", "sp": "🤖", "user": "👤", "device": "💻",
             "resource": "🗄️", "role": "👑", "cap": "⚡", "foothold": "🎯"}


def _chain_html(g, p):
    parts = []
    ids = p["node_ids"]
    for i, e in enumerate(p["edges"]):
        src_lbl = p["nodes"][i]
        ic = NODE_ICON.get(g.nodes.get(ids[i], {}).get("type", ""), "•")
        parts.append(f'<span class="nd">{ic} {html.escape(src_lbl)}</span>')
        rel_ic = REL_ICON.get(e["rel"], "→")
        blind = ' <span class="bl">⚠️ sem detecção</span>' if e["blind"] else ""
        parts.append(f'<span class="rel" title="{html.escape(e["abuse"])}">'
                     f'{rel_ic} {html.escape(e["mitre"])}{blind}</span>')
    last_ic = NODE_ICON.get(g.nodes.get(ids[-1], {}).get("type", ""), "•")
    parts.append(f'<span class="nd jw">{last_ic} {html.escape(p["nodes"][-1])}</span>')
    return '<span class="arrow">→</span>'.join(parts)


def _trunc(s, n=22):
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def _risk_color(r):
    return "#d13438" if r >= 60 else "#ff8c00" if r >= 35 else "#5b6b86"


def _svg_attack_graph(g, paths, compact=False):
    """Layered box-and-arrow diagram: Atacante → Entrada → Pivô → Alvo (até onde chega)."""
    if not paths:
        return '<div style="color:#647394;padding:18px">Sem caminhos para diagramar.</div>'
    e_risk, e_blind, n_risk, entry_set = {}, {}, {}, set()
    for p in paths:
        for e in p["edges"]:
            k = (e["src"], e["dst"], e["rel"])
            e_risk[k] = max(e_risk.get(k, 0.0), p["risk"])
            e_blind[k] = e_blind.get(k, False) or e["blind"]
            if e["src"] == EXT:
                entry_set.add(e["dst"])
        for nid in p["node_ids"]:
            n_risk[nid] = max(n_risk.get(nid, 0.0), p["risk"])
    nodes = set(n_risk) | {EXT}
    edges = list(e_risk.keys())
    meta = {}
    for e in g.edges:
        meta.setdefault((e["src"], e["dst"], e["rel"]), e)

    # longest-path layering, then right-align all crown jewels into the last column
    layer = {EXT: 0}
    for _ in range(len(nodes) + 2):
        changed = False
        for (s_, d_, _r) in edges:
            if s_ in layer and layer.get(d_, -1) < layer[s_] + 1:
                layer[d_] = layer[s_] + 1
                changed = True
        if not changed:
            break
    for n in nodes:
        layer.setdefault(n, 1)
    jewels = {n for n in nodes if g.nodes.get(n, {}).get("kind") == "jewel"}
    non_j = [layer[n] for n in nodes if n not in jewels] or [0]
    jewel_col = max(non_j) + 1
    for n in jewels:
        layer[n] = jewel_col
    maxlayer = max(layer.values())

    cols = {}
    for n in nodes:
        cols.setdefault(layer[n], []).append(n)
    for L in cols:
        cols[L].sort(key=lambda n: (0 if n in jewels else 1, -n_risk.get(n, 0.0),
                                    g.nodes.get(n, {}).get("label", "")))

    if compact:
        colW, boxW, boxH, rowH, padX, headerH, padB = 182, 152, 42, 54, 18, 46, 16
    else:
        colW, boxW, boxH, rowH, padX, headerH, padB = 226, 176, 46, 66, 28, 58, 28
    pos = {}
    for L, ns in cols.items():
        x = padX + L * colW
        for idx, n in enumerate(ns):
            pos[n] = (x, headerH + idx * rowH)
    maxcount = max(len(ns) for ns in cols.values())
    svgW = padX + maxlayer * colW + boxW + padX
    svgH = headerH + maxcount * rowH + padB

    defs = ('<defs>' + ''.join(
        f'<marker id="ar_{i}" markerWidth="9" markerHeight="9" refX="7.5" refY="3" '
        f'orient="auto"><path d="M0,0 L7.5,3 L0,6 Z" fill="{c}"/></marker>'
        for i, c in (("r", "#d13438"), ("o", "#ff8c00"), ("g", "#5b6b86"), ("y", "#e6c463")))
        + '</defs>')

    heads = []
    for L in range(maxlayer + 1):
        if L == 0:
            t = "🌐 Atacante"
        elif L == jewel_col:
            t = "🎯 Alvo — até onde chega"
        elif L == 1:
            t = "🚪 Camada de entrada"
        else:
            t = f"↪ Pivô (camada {L})"
        cx = padX + L * colW + boxW / 2
        heads.append(f'<text x="{cx:.0f}" y="22" text-anchor="middle" fill="#8da3c4" '
                     f'font-size="12" font-weight="600">{html.escape(t)}</text>')

    mk = {"#d13438": "r", "#ff8c00": "o", "#5b6b86": "g", "#e6c463": "y"}
    edge_svg = []
    for (s_, d_, rel) in edges:
        if s_ not in pos or d_ not in pos:
            continue
        risk = e_risk[(s_, d_, rel)]
        blind = e_blind[(s_, d_, rel)]
        color = "#e6c463" if blind else _risk_color(risk)
        sx, sy = pos[s_]
        dx, dy = pos[d_]
        x1, y1 = sx + boxW, sy + boxH / 2
        x2, y2 = dx, dy + boxH / 2
        path = f"M{x1:.0f},{y1:.0f} C{x1+52:.0f},{y1:.0f} {x2-52:.0f},{y2:.0f} {x2:.0f},{y2:.0f}"
        w = 2.6 if risk >= 60 else 1.6
        dash = ' stroke-dasharray="6,4"' if blind else ""
        em = meta.get((s_, d_, rel), {})
        tech = em.get("mitre", "")
        title = f'{tech} · {em.get("abuse", rel)} — quebra: {em.get("break_with", "")}'
        edge_svg.append(
            f'<path d="{path}" fill="none" stroke="{color}" stroke-width="{w}"{dash} '
            f'opacity="0.82" marker-end="url(#ar_{mk[color]})"><title>{html.escape(title)}</title></path>')
        if tech and (layer.get(d_, 0) - layer.get(s_, 0)) == 1:
            mx, my = (x1 + x2) / 2, (y1 + y2) / 2 - 4
            lbl = ("⚠ " if blind else "") + tech
            edge_svg.append(
                f'<text x="{mx:.0f}" y="{my:.0f}" text-anchor="middle" font-size="9" '
                f'fill="{color}">{html.escape(lbl)}</text>')

    box_svg = []
    for n in nodes:
        if n not in pos:
            continue
        x, y = pos[n]
        nd = g.nodes.get(n, {})
        is_jewel = nd.get("kind") == "jewel"
        is_entry = n in entry_set
        if n == EXT:
            border = "#9aa7bd"
        elif is_jewel:
            border = "#ffd166"
        elif is_entry:
            border = "#ff8c00"
        else:
            border = "#3b82f6"
        sw = 2.2 if is_jewel else 1.5
        icon = NODE_ICON.get(nd.get("type", ""), "•")
        label = f'{icon} {_trunc(nd.get("label", n))}'
        rc = _risk_color(n_risk.get(n, 0.0))
        risk_txt = ("" if n == EXT else
                    f'<text x="{x+15}" y="{y+35}" fill="#7d8aa6" font-size="9.5">'
                    f'risco {int(n_risk.get(n, 0))}</text>')
        box_svg.append(
            f'<g><rect x="{x}" y="{y}" width="{boxW}" height="{boxH}" rx="9" '
            f'fill="#111a2e" stroke="{border}" stroke-width="{sw}"/>'
            f'<rect x="{x}" y="{y}" width="5" height="{boxH}" rx="2.5" fill="{rc}"/>'
            f'<text x="{x+15}" y="{y+20}" fill="#e7eef9" font-size="11.5" '
            f'font-weight="600">{html.escape(label)}</text>'
            f'{risk_txt}'
            f'<title>{html.escape(nd.get("label", n))}</title></g>')

    return (f'<svg width="{svgW}" height="{svgH}" viewBox="0 0 {svgW} {svgH}" '
            f'xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI,system-ui,sans-serif">'
            + defs + "".join(heads) + "".join(edge_svg) + "".join(box_svg) + "</svg>")


# ───────────── deep links · hunting · incident proposal ─────────────
def _portal_link(g, nid):
    """Best deep link to open the object to fix (Entra / Defender / Azure Portal)."""
    nd = g.nodes.get(nid, {})
    t, m = nd.get("type"), nd.get("meta", {})
    if t == "sp" and m.get("appId"):
        return ("https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/"
                f"ApplicationMenuBlade/~/Overview/appId/{m['appId']}")
    if t == "user" and m.get("objectId"):
        return ("https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/"
                f"UserProfileMenuBlade/~/overview/userId/{m['objectId']}")
    if t == "device" and m.get("id"):
        return f"https://security.microsoft.com/machines/{m['id']}/overview"
    if t == "resource" and m.get("resourceId"):
        return f"https://portal.azure.com/#@/resource{m['resourceId']}/overview"
    if t == "role":
        return "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AllRolesBlade"
    return ""


def _flatten_kql(k):
    return " ".join(line.strip() for line in str(k).splitlines() if line.strip())


def _path_entities(g, p):
    ent = {}
    for nid in p["node_ids"]:
        nd = g.nodes.get(nid, {})
        m, t = nd.get("meta", {}), nd.get("type")
        if t == "sp":
            ent.setdefault("appId", m.get("appId", ""))
            ent.setdefault("spId", m.get("objectId", ""))
            ent.setdefault("spName", nd.get("label", "").replace("SP: ", ""))
        elif t == "user":
            ent.setdefault("upn", m.get("upn", ""))
        elif t == "device":
            ent.setdefault("device", m.get("name", nd.get("label", "").replace("Device: ", "")))
        elif t == "resource":
            ent.setdefault("resourceId", m.get("resourceId", ""))
        elif t == "role":
            ent.setdefault("role", nd.get("label", "").replace("Papel: ", ""))
    if ent.get("upn"):
        ent["adminname"] = ent["upn"].split("@")[0]
    return ent


def build_hunts(g, paths, hunting_cfg, hunt_results, top_n):
    """For each path, derive the appropriate live hunts (per edge relation) and flag
    'active now' when evidence (hunt_results) shows current behaviour."""
    hunt_results = hunt_results or {}
    hunts = {}
    for p in paths[:top_n]:
        ent = _path_entities(g, p)
        ids = []
        for e in p["edges"]:
            for tmpl in hunting_cfg.get(e["rel"], []):
                ph = set(re.findall(r"\{(\w+)\}", tmpl["kql"]))
                if any(not ent.get(k) for k in ph):
                    continue
                ekey = "|".join(f"{k}={ent[k]}" for k in sorted(ph))
                hid = f"{tmpl['id']}:{ekey}"
                if hid not in hunts:
                    q = tmpl["kql"]
                    for k in ph:
                        q = q.replace("{" + k + "}", str(ent[k]))
                    res = hunt_results.get(hid)
                    cnt = (res.get("count") if isinstance(res, dict)
                           else len(res) if isinstance(res, list) else None)
                    hunts[hid] = {"id": hid, "title": tmpl["title"], "product": tmpl["product"],
                                  "signal": tmpl.get("signal", ""), "query": q.strip(),
                                  "result": res, "count": cnt, "active": bool(cnt)}
                if hid not in ids:
                    ids.append(hid)
        p["hunt_ids"] = ids
        p["active"] = any(hunts[h]["active"] for h in ids)
    return hunts


def refresh_active(paths, hunts):
    for p in paths:
        p["active"] = any(hunts[h]["active"] for h in p.get("hunt_ids", []))


def run_hunts(hunts, workspace=None):
    """Best-effort LIVE execution (opt-in --hunt). xdr → Graph runHuntingQuery;
    sentinel → az monitor log-analytics query (needs --workspace). Never raises."""
    import urllib.request
    gtok = None
    for it in hunts.values():
        try:
            if it["product"] == "xdr":
                if gtok is None:
                    gtok = get_token("https://graph.microsoft.com")
                body = json.dumps({"Query": _flatten_kql(it["query"])}).encode()
                req = urllib.request.Request(
                    "https://graph.microsoft.com/v1.0/security/runHuntingQuery", data=body,
                    headers={"Authorization": f"Bearer {gtok}", "Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=80) as r:
                    rows = json.load(r).get("results", [])
            elif it["product"] == "sentinel" and workspace:
                res = subprocess.run(
                    [AZ, "monitor", "log-analytics", "query", "-w", workspace,
                     "--analytics-query", _flatten_kql(it["query"]), "-o", "json"],
                    capture_output=True, text=True, timeout=120)
                rows = json.loads(res.stdout or "[]") if res.returncode == 0 else []
            else:
                continue
            it["result"] = {"count": len(rows), "sample": rows[:1]}
            it["count"] = len(rows)
            it["active"] = len(rows) > 0
        except Exception as e:
            it["note"] = f"hunt não executado: {e}"


def build_incidents(g, s, inc_cfg):
    """Prepare a Sentinel incident DRAFT for each path with active behaviour (read-only).
    Creation stays gated (see create_sentinel_incident / --create-incident)."""
    title_t = inc_cfg.get("title_template", "[SOC] Attack path — {entry} → {target}")
    th = inc_cfg.get("severity_by_risk", {"high": 60, "medium": 35})
    hunts = s["hunts"]
    out = []
    for idx, p in enumerate(s["paths"], 1):
        if not p.get("active"):
            continue
        entry = p["nodes"][1] if len(p["nodes"]) > 1 else p["nodes"][0]
        target = p["nodes"][-1]
        sev = ("High" if p["risk"] >= th.get("high", 60)
               else "Medium" if p["risk"] >= th.get("medium", 35) else "Low")
        active_h = [h for h in p.get("hunt_ids", []) if hunts[h]["active"]]
        ev = "; ".join(f"{hunts[h]['title']} ({hunts[h]['count']})" for h in active_h) or "—"
        techs = ", ".join(sorted({e["mitre"] for e in p["edges"] if e["mitre"]}))
        desc = ("Attack path sintetizado COM movimentação ativa (caça confirmou comportamento). "
                f"Caminho: {' -> '.join(p['nodes'])}. "
                f"Risco {p['risk']} (prob {int(p['likelihood']*100)}% x impacto {p['impact']}). "
                f"MITRE: {techs}. Evidência de hunting: {ev}. "
                f"Correção (chokepoint): {p['edges'][0]['break_with']}.")
        out.append({"id": str(uuid.uuid4()), "path_idx": idx, "risk": p["risk"],
                    "severity": sev, "description": desc,
                    "title": title_t.replace("{entry}", _trunc(entry, 40)).replace("{target}", _trunc(target, 40))})
    return out


def create_sentinel_incident(sub, rg, ws, draft, api):
    """ACTION (opt-in --create-incident). PUT a Sentinel incident via ARM. Needs
    Microsoft Sentinel Contributor on the workspace. Returns (ok, message)."""
    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
           f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
           f"/providers/Microsoft.SecurityInsights/incidents/{draft['id']}?api-version={api}")
    body = {"properties": {"title": draft["title"], "severity": draft["severity"],
                           "status": "New", "description": draft["description"]}}
    tmp = HERE / f"_inc_{draft['id']}.json"
    try:
        tmp.write_text(json.dumps(body), encoding="utf-8")
        res = subprocess.run([AZ, "rest", "--method", "put", "--url", url,
                              "--body", f"@{tmp}", "-o", "json"],
                             capture_output=True, text=True, timeout=90)
        if res.returncode == 0:
            return True, "incidente criado"
        return False, res.stderr.strip()[:200]
    except Exception as e:
        return False, str(e)
    finally:
        try:
            tmp.unlink()
        except Exception:
            pass


def render_html(s, g):
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    vc = VERDICT_COLOR.get(s["verdict"], "#107c10")

    hunts = s.get("hunts", {})
    inc_by_path = {inc["path_idx"]: inc for inc in s.get("incidents", [])}
    inc_api = s.get("inc_api", "2024-03-01")
    entry_counts = {}
    for q in s["paths"]:
        eid = q["node_ids"][1] if len(q["node_ids"]) > 1 else q["node_ids"][0]
        entry_counts[eid] = entry_counts.get(eid, 0) + 1
    pcards = ""
    for i, p in enumerate(s["paths"], 1):
        rc = _risk_color(p["risk"])
        tags = ""
        if p["critical"]:
            tags += '<span class="b crit">🔴 takeover</span>'
        if p["novel"]:
            tags += f'<span class="b nov">🧬 {", ".join(p["domains"])}</span>'
        if p["blind"]:
            tags += '<span class="b blind">👁️ blind spot</span>'
        active = p.get("active")
        act_badge = '<span class="b hot">🔴 ativo agora</span>' if active else ""
        short = " → ".join(_trunc(x, 20) for x in p["nodes"])
        entry_id = p["node_ids"][1] if len(p["node_ids"]) > 1 else p["node_ids"][0]
        fix_link = _portal_link(g, entry_id)
        tgt_link = _portal_link(g, p["node_ids"][-1])
        fix_a = f' — <a href="{fix_link}" target="_blank">abrir objeto ↗</a>' if fix_link else ""
        tgt_a = f' <a href="{tgt_link}" target="_blank">↗</a>' if tgt_link else ""
        nshare = entry_counts.get(entry_id, 1)
        share_badge = f' <span class="b solve">💥 fecha {nshare} caminhos</span>' if nshare > 1 else ""
        minimap = _svg_attack_graph(g, [p], compact=True)
        hblock = ""
        for hid in p.get("hunt_ids", []):
            it = hunts.get(hid, {})
            hot = (f'<span class="hot">🔴 {it.get("count")} resultados</span>' if it.get("active")
                   else '<span class="muted">rodar para confirmar</span>')
            note = ""
            if isinstance(it.get("result"), dict) and it["result"].get("note"):
                note = f'<div class="muted">{html.escape(str(it["result"]["note"]))}</div>'
            hblock += (f'<div class="hi"><div class="hih">{html.escape(it.get("title", ""))} '
                       f'<span class="prod">{it.get("product", "")}</span> {hot}</div>'
                       f'<div class="muted">{html.escape(it.get("signal", ""))}</div>'
                       f'<pre>{html.escape(it.get("query", ""))}</pre>{note}</div>')
        hunt_html = (f'<div class="hunt"><div class="ht">🔬 Hunting dirigido pela correlação</div>{hblock}</div>'
                     if hblock else "")
        inc = inc_by_path.get(i)
        inc_html = ""
        if inc:
            cmd = (f'az rest --method put --url "https://management.azure.com/subscriptions/&lt;sub&gt;'
                   f'/resourceGroups/&lt;rg&gt;/providers/Microsoft.OperationalInsights/workspaces/&lt;ws&gt;'
                   f'/providers/Microsoft.SecurityInsights/incidents/{inc["id"]}?api-version={inc_api}" '
                   f'--body @incident.json')
            inc_html = (f'<div class="inc"><div class="inch">🚨 Movimentação ativa → propor incidente no Sentinel</div>'
                        f'<div><b>Severidade:</b> {inc["severity"]} · <b>Título:</b> {html.escape(inc["title"])}</div>'
                        f'<div class="muted">Criação <b>gated por aprovação</b> — a UAMI já tem Microsoft Sentinel '
                        f'Contributor. Rode <code>--create-incident --sub &lt;id&gt; --rg &lt;rg&gt; --workspace &lt;nome&gt;</code> '
                        f'para criar, ou:</div><pre>{cmd}</pre></div>')
        pcards += (f'<details class="pcard{" active" if active else ""}">'
                   f'<summary><span class="rp" style="color:{rc};border-color:{rc}">{p["risk"]}</span> '
                   f'<span class="sc">{html.escape(short)}</span> {tags}{act_badge}</summary>'
                   f'<div class="pb">'
                   f'<div class="maptitle">🗺️ Da camada de entrada até onde o ataque chega</div>'
                   f'<div class="mapwrap">{minimap}</div>'
                   f'<div class="row">🔧 <b>Correção:</b> {html.escape(p["edges"][0]["break_with"])}{fix_a}{share_badge}</div>'
                   f'<div class="row">🎯 <b>Alvo:</b> {html.escape(p["nodes"][-1])}{tgt_a}</div>'
                   f'{hunt_html}{inc_html}</div></details>')

    notice = ""
    if s.get("n_active"):
        notice = (f'<div class="lead" style="border-left-color:#d13438">🚨 <b>{s["n_active"]} caminho(s) com '
                  f'movimentação ATIVA agora</b> — a caça confirmou comportamento em andamento. '
                  f'Cada janela ativa traz um incidente do Sentinel proposto (criação gated por aprovação).</div>')
    por = ""
    if s.get("chokepoints"):
        c0 = s["chokepoints"][0]
        link = _portal_link(g, c0.get("asset"))
        la = f' <a href="{link}" target="_blank">abrir objeto ↗</a>' if link else ""
        por = (f'<div class="start">🎯 <b>Por onde começar:</b> {html.escape(c0["fix"])} '
               f'<b>em {html.escape(c0["on"])}</b> — isso fecha <b>{c0["paths"]}</b> caminho(s) de ataque de uma vez.{la}</div>')

    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Attack Path Synthesizer</title>
<style>
body{{margin:0;background:#0a0e1a;color:#e7eef9;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.5}}
.wrap{{max-width:1080px;margin:0 auto;padding:24px}}
.hd{{background:linear-gradient(135deg,#5a0b2e,#a3123f 55%,#d13438);border-radius:14px;padding:26px}}
.hd h1{{margin:0;font-size:23px}} .hd p{{margin:6px 0 0;opacity:.92;font-size:13px}}
.badge{{display:inline-block;margin-top:14px;padding:8px 18px;border-radius:999px;font-weight:800;font-size:18px;background:{vc}22;color:#fff;border:2px solid {vc}}}
.cards{{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}}
.card{{flex:1;min-width:120px;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;padding:16px;text-align:center}}
.card .n{{font-size:26px;font-weight:800}} .card .l{{font-size:11.5px;color:#93a1bd;margin-top:4px}}
h2{{font-size:16px;margin:26px 0 10px}}
.lead{{background:#111a2e;border:1px solid #1f2c47;border-left:4px solid {vc};border-radius:10px;padding:14px 18px;margin:8px 0;font-size:13.5px}}
table{{width:100%;border-collapse:collapse;background:#111a2e;border:1px solid #1f2c47;border-radius:12px;overflow:hidden;font-size:12.5px}}
th{{background:#16203a;text-align:left;padding:10px 12px;font-size:11.5px;color:#ff9db0}}
td{{padding:9px 12px;border-top:1px solid #1f2c47;vertical-align:top}}
.sub{{color:#7d8aa6;font-size:11px;margin-top:3px}}
.path{{background:#111a2e;border:1px solid #1f2c47;border-radius:10px;padding:12px 14px;margin:8px 0}}
.ph{{margin-bottom:8px}}
.chain{{display:flex;flex-wrap:wrap;align-items:center;gap:4px;font-size:12.5px}}
.nd{{background:#16203a;border:1px solid #25324f;border-radius:7px;padding:3px 8px;white-space:nowrap}}
.nd.jw{{border-color:{vc};color:#fff;font-weight:700}}
.rel{{color:#9fb0cc;font-size:11px;padding:0 2px}}
.arrow{{color:#56657f}}
.b{{display:inline-block;font-size:10.5px;padding:2px 7px;border-radius:999px;margin-right:5px;background:#1d2942;color:#bcd}}
.b.risk{{background:{vc}22;color:#fff;font-weight:700}}
.b.crit{{background:#3a0f12;color:#ff7d8a}} .b.nov{{background:#0f2a1c;color:#7fe0a8}}
.b.blind{{background:#2a230f;color:#e6c463}}
.bl{{color:#e6c463}}
.diagram{{overflow:auto;background:#0c1426;border:1px solid #1f2c47;border-radius:12px;padding:8px}}
.diagram svg{{display:block}}
.legend{{display:flex;gap:16px;flex-wrap:wrap;font-size:11.5px;color:#93a1bd;margin:10px 2px 4px}}
.legend span{{display:inline-flex;align-items:center;gap:6px}}
.legend .sw{{width:12px;height:12px;border-radius:3px;display:inline-block}}
.legend .ln{{width:20px;height:0;border-top:3px solid;display:inline-block}}
.plist{{font-size:12.5px;color:#cdd9ee;padding-left:18px}}
.plist li{{margin:8px 0}}
.muted{{color:#7d8aa6}} .chainln{{color:#aebbd4;font-size:11.5px}}
.pcards details.pcard{{background:#111a2e;border:1px solid #1f2c47;border-radius:10px;margin:8px 0;overflow:hidden}}
.pcard.active{{border-color:#d13438}}
.pcard summary{{cursor:pointer;padding:11px 14px;font-size:12.5px;list-style:none;display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.pcard summary::-webkit-details-marker{{display:none}}
.pcard summary::before{{content:"▸";color:#647394}}
.pcard[open] summary::before{{content:"▾"}}
.rp{{font-weight:800;border:1.5px solid;border-radius:7px;padding:1px 8px;font-size:12px}}
.sc{{color:#aebbd4}}
.pb{{padding:4px 16px 14px;border-top:1px solid #1f2c47}}
.pb .row{{margin:8px 0;font-size:12.5px}} .pb a{{color:#7db0ff}}
.hunt{{background:#0c1426;border:1px solid #22304e;border-radius:8px;padding:10px 12px;margin:10px 0}}
.ht{{font-size:12.5px;font-weight:700;color:#cfe0ff;margin-bottom:6px}}
.hi{{border-top:1px dashed #22304e;padding:8px 0}} .hi:first-of-type{{border-top:none}}
.hih{{font-size:12px;font-weight:600}}
.prod{{font-size:10px;background:#1d2942;color:#9fb6dd;border-radius:5px;padding:1px 6px;margin:0 4px}}
.hot{{font-size:10.5px;background:#3a0f12;color:#ff8a96;border-radius:999px;padding:2px 8px;font-weight:700}}
pre{{background:#0a1322;border:1px solid #1c2942;border-radius:7px;padding:8px 10px;font-size:11px;color:#bcd;white-space:pre-wrap;word-break:break-word;overflow:auto;margin:6px 0}}
.inc{{background:#1c0f12;border:1px solid #5a1f25;border-radius:8px;padding:10px 12px;margin:10px 0}}
.inch{{font-weight:700;color:#ff9aa6;margin-bottom:5px;font-size:12.5px}}
code{{background:#0a1322;border:1px solid #1c2942;border-radius:4px;padding:1px 5px;font-size:11px}}
.start{{background:#0f2a1c;border:1px solid #1f5a3a;border-left:4px solid #2ecc71;border-radius:10px;padding:12px 16px;margin:12px 0;font-size:13px}}
.start a{{color:#7fe0a8;white-space:nowrap}}
.b.solve{{background:#0f2a1c;color:#7fe0a8}}
.maptitle{{font-size:11.5px;color:#8da3c4;font-weight:600;margin:4px 0 2px}}
.mapwrap{{overflow:auto;background:#0c1426;border:1px solid #22304e;border-radius:8px;padding:6px;margin:2px 0 8px}}
.ft{{margin-top:24px;color:#647394;font-size:12px;text-align:center}}
</style></head><body><div class="wrap">
<div class="hd"><h1>🧬 Attack Path Synthesizer — riscos emergentes cross-domain</h1>
<p>Sintetiza caminhos de ataque a partir de exposição · higiene de credenciais (NHI) · permissões Graph · papéis privilegiados · CVEs · misconfig — e ranqueia a correção que quebra mais caminhos · {now}</p>
<div class="badge">SUPERFÍCIE {s['verdict']}</div></div>
<div class="cards">
<div class="card"><div class="n" style="color:{vc}">{s['n_paths']}</div><div class="l">Caminhos de ataque</div></div>
<div class="card"><div class="n" style="color:#ff7d8a">{s['n_crit']}</div><div class="l">→ takeover do tenant</div></div>
<div class="card"><div class="n" style="color:#7fe0a8">{s['n_novel']}</div><div class="l">🧬 cross-domain (novos)</div></div>
<div class="card"><div class="n" style="color:#e6c463">{s['n_blind']}</div><div class="l">👁️ sem detecção</div></div>
<div class="card"><div class="n" style="color:#ff4d5e">{s['n_active']}</div><div class="l">🔴 ativos agora</div></div>
</div>
<div class="lead">🧭 Cada <b>caminho de ataque</b> liga a <b>porta de entrada</b> (o que o atacante explora primeiro)
até <b>onde ele chega</b> (a joia da coroa). Nenhum produto isolado vê estes caminhos porque eles cruzam
domínios (credencial × privilégio × exposição). Clique em cada janela para ver o mapa, a caça e a correção.</div>
{por}
<div class="legend">
<span><i class="sw" style="background:#ff8c00"></i> entrada</span>
<span><i class="sw" style="background:#3b82f6"></i> pivô</span>
<span><i class="sw" style="background:#ffd166"></i> alvo (joia da coroa)</span>
<span><i class="ln" style="border-color:#d13438"></i> alto risco</span>
<span><i class="ln" style="border-color:#e6c463;border-top-style:dashed"></i> sem detecção (blind spot)</span>
</div>
{notice}<h3 style="font-size:14px;margin:18px 0 8px">Caminhos de ataque — clique para expandir cada janela</h3>
<div class="pcards">{pcards or '<div class="muted">Nenhum caminho sintetizado.</div>'}</div>
<div class="ft">attack-path · collector↔renderer · análise 100% read-only (criação de incidente gated por aprovação) · gerado pelo SOC Autônomo</div>
</div></body></html>"""


def render_md(s, g):
    L = [f"# 🧬 Attack Path Synthesizer — SUPERFÍCIE {s['verdict']}", ""]
    L.append(f"- Caminhos: **{s['n_paths']}** · → takeover: **{s['n_crit']}** · "
             f"cross-domain: **{s['n_novel']}** · sem detecção: **{s['n_blind']}** · "
             f"ativos agora: **{s.get('n_active', 0)}** · nós {s['n_nodes']} / arestas {s['n_edges']}")
    if s["chokepoints"]:
        c0 = s["chokepoints"][0]
        L += ["", "## 🎯 Por onde começar", "",
              f"**{c0['fix']}** em **{c0['on']}** — fecha **{c0['paths']}** caminho(s) de ataque de uma vez."]
    L += ["", "## 🧬 Caminhos de ataque (top)", ""]
    for i, p in enumerate(s["paths"], 1):
        chain = " → ".join(p["nodes"])
        tags = []
        if p["critical"]:
            tags.append("🔴 takeover")
        if p["novel"]:
            tags.append("🧬 " + "+".join(p["domains"]))
        if p["blind"]:
            tags.append("👁️ blind spot")
        L.append(f"{i}. **risco {p['risk']}** (prob {int(p['likelihood']*100)}% × impacto {p['impact']}) "
                 f"{' '.join(tags)}  \n   {chain}")
    if s.get("incidents"):
        L += ["", "## 🚨 Incidentes propostos (movimentação ativa — criação gated)", ""]
        for inc in s["incidents"]:
            L.append(f"- **[{inc['severity']}]** {inc['title']} — caminho #{inc['path_idx']}")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="attack-path synthesizer")
    ap.add_argument("--from-json", dest="from_json", help="Pre-collected bundle JSON")
    ap.add_argument("--queries", default=str(HERE / "queries.yaml"))
    ap.add_argument("--output", default=None)
    ap.add_argument("--format", choices=["html", "md", "both"], default="both")
    ap.add_argument("--hunt", action="store_true", help="Run the derived hunts live (best-effort)")
    ap.add_argument("--workspace", help="Log Analytics workspace GUID (for live sentinel hunts)")
    ap.add_argument("--create-incident", dest="create_incident", action="store_true",
                    help="ACTION (gated): create Sentinel incidents for ACTIVE paths")
    ap.add_argument("--sub", help="Subscription id (for --create-incident)")
    ap.add_argument("--rg", help="Resource group of the Sentinel workspace (for --create-incident)")
    ap.add_argument("--ws-name", dest="ws_name", help="Sentinel workspace NAME (for --create-incident)")
    args = ap.parse_args()

    q = load_queries(args.queries)
    params = q.get("parameters", {})
    scoring = q.get("scoring", {})
    abuse_map = q.get("abuse_map", {})

    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = collect()

    g = build_graph(data, params, scoring, abuse_map)
    scored = score_paths(g, find_paths(g, params), scoring)
    chokes = chokepoints(g, scored, params)
    n_crit = sum(1 for p in scored if p["critical"])
    n_blind = sum(1 for p in scored if p["blind"])
    n_novel = sum(1 for p in scored if p["novel"])
    crit_like = scoring.get("verdict", {}).get("critical_path_likelihood", 0.5)
    elev = scoring.get("verdict", {}).get("elevated_path_risk", 35.0)
    top_risk = scored[0]["risk"] if scored else 0.0
    if any(p["takeover"] and p["likelihood"] >= crit_like for p in scored):
        verdict = "CRÍTICA"
    elif top_risk >= elev:
        verdict = "ELEVADA"
    elif scored:
        verdict = "MODERADA"
    else:
        verdict = "CONTIDA"
    top_paths = scored[:int(params.get("top_paths", 40))]
    hunting_cfg = q.get("hunting", {})
    inc_cfg = q.get("incident", {})
    hunts = build_hunts(g, top_paths, hunting_cfg, data.get("hunt_results"), len(top_paths))
    if args.hunt:
        run_hunts(hunts, args.workspace)
        refresh_active(top_paths, hunts)
    s = {"verdict": verdict, "n_paths": len(scored), "n_crit": n_crit, "n_blind": n_blind,
         "n_novel": n_novel, "top_risk": top_risk,
         "top_choke_risk": chokes[0]["risk_removed"] if chokes else 0.0,
         "n_nodes": len(g.nodes), "n_edges": len(g.edges),
         "paths": top_paths, "chokepoints": chokes, "hunts": hunts,
         "inc_api": inc_cfg.get("api_version", "2024-03-01")}
    s["incidents"] = build_incidents(g, s, inc_cfg)
    s["n_active"] = sum(1 for p in top_paths if p.get("active"))
    if args.create_incident and s["incidents"]:
        if args.sub and args.rg and args.ws_name:
            for inc in s["incidents"]:
                ok, msg = create_sentinel_incident(args.sub, args.rg, args.ws_name, inc, s["inc_api"])
                print(f"   {'✅' if ok else '⚠️'} incidente '{inc['title'][:50]}': {msg}", file=sys.stderr)
        else:
            print("   ⚠️ --create-incident requer --sub --rg --ws-name", file=sys.stderr)

    ts = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base = pathlib.Path(args.output) if args.output else (HERE / "reports" / f"attack-path-{ts}")
    base.parent.mkdir(parents=True, exist_ok=True)
    if args.format in ("html", "both"):
        p = base.with_suffix(".html") if base.suffix != ".html" else base
        p.write_text(render_html(s, g), encoding="utf-8")
        print(f"📄 {p}")
    if args.format in ("md", "both"):
        p = base.with_suffix(".md")
        p.write_text(render_md(s, g), encoding="utf-8")
        print(f"📄 {p}")
    print(f"✅ {SKILL}: SUPERFÍCIE {s['verdict']} · {s['n_paths']} caminhos · "
          f"{s['n_crit']} → takeover · {s['n_novel']} cross-domain · {s['n_blind']} sem detecção · "
          f"{s['n_active']} ativos · top chokepoint remove {s['top_choke_risk']}")


if __name__ == "__main__":
    main()

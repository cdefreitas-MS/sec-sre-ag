---
name: attack-path
description: 'Cross-domain attack-path synthesizer + blast-radius remediation re-prioritizer. Ingests the datasets your other skills already collect (exposure-graph exposure/devices, org-posture NHI / spn-scope-drift credential hygiene, graph-least-privilege granted Graph scopes, exposure-graph privileged roles, threat-correlation/MDE exposed weaknesses, advisor-impact Defender-for-Cloud misconfig) and SYNTHESIZES a directed risk graph (nodes = identities/service-principals/devices/resources/roles/capabilities; edges = ABUSABLE transitions). Finds attack paths external-attacker -> pivot -> crown-jewel, scores each by likelihood (product of edge feasibility) x impact (crown-jewel value), and ranks the remediation CHOKEPOINTS that break the most high-risk paths — re-prioritizing fixes by BLAST-RADIUS REDUCTION, not Secure-Score points. Annotates each edge with the ATT&CK technique and flags paths that are also DETECTION BLIND SPOTS (technique not covered / telemetry silent). Finds the cross-domain toxic combinations no single Microsoft product surfaces, because each product is single-domain. 100% READ-ONLY, deterministic, collector<->renderer. Use for: attack path analysis, attack path synthesis, toxic combination, lateral movement path, privilege escalation path, blast radius, choke point remediation, what to fix first, emergent risk, cross-domain correlation, identity attack path, service principal attack path, tenant takeover path.'
---

# Attack Path — Cross-Domain Attack-Path Synthesizer

## Purpose

Microsoft's posture tools (Secure Score, Defender for Cloud, Advisor, MCSB) are **rule/benchmark engines**: they tell you the *known-bad against a known baseline*, almost always **inside a single domain** (identity OR network OR endpoint OR app). They do **not** reason across domains or hypothesize risks that **emerge from the combination** of individually-"healthy" things.

`attack-path` is the **reasoning layer on top of the suite**. It does **not** add a new data source — it **consolidates the outputs your other skills already collect** and synthesizes a **directed risk graph**, then:

1. **Finds attack paths** — `external attacker → pivot → crown jewel` (e.g. *weak SPN secret → SPN holds Global Administrator → tenant takeover*; or *internet-exposed host with public-exploit CVE → admin session on it → that admin is GA*).
2. **Scores** each path by **likelihood** (∏ edge feasibility) × **impact** (crown-jewel value).
3. **Ranks CHOKEPOINTS** — the single remediation that breaks the **most** high-risk paths → re-prioritizes the backlog by **blast-radius reduction**, not Secure-Score points.
4. **Flags DETECTION BLIND SPOTS** — annotates every edge with the ATT&CK technique an attacker would use; if your detections don't cover it (`mitre_covered`) or the telemetry is silent (`silent_sources`/`impaired_sensors`), the path is tagged 👁️.

> **The differentiator:** a chokepoint that breaks many paths jumps to the top **even if it earns few Secure-Score points** — the kind of cross-domain "toxic combination" no single product flags.

**Entity scope:** the whole tenant (the graph is global). **Permission:** the read scopes its *source* skills already use (MDE Score/SecurityRecommendation read · Graph IdentityRiskyUser/Directory/Application read). No new grant.

---

## Skill Files

| File | Purpose | When used |
|------|---------|-----------|
| [generate_html_report.py](generate_html_report.py) | graph builder + path-finder + scorer + chokepoint ranker + blind-spot annotator + HTML/MD renderer | execution |
| [queries.yaml](queries.yaml) | node/edge taxonomy · scoring weights · abuse→MITRE→remediation map · bundle shape | read at runtime |

> ⚠️ **Analysis is 100% READ-ONLY.** It recommends chokepoints and prepares incident drafts; it never applies fixes. The **only** optional write is the **approval-gated Sentinel incident creation** (`--create-incident`, off by default). Fixes it surfaces are routed to the existing response/governance skills (`advisor-impact`, `contain-compromised-user`, `graph-least-privilege`) for human-gated action.

---

## File Resolution (codeRefs-first — On Skill Activation)

`generate_html_report.py` loads `queries.yaml` from its own directory (`Path(__file__).resolve().parent`). Both must be co-located.

```
1. codeRefs/sec-sre-ag/attack-path/   → if both files exist, use as <SKILL_DIR>, run from here.
2. tmp/attack-path/                    → if both exist (previous materialization), use it.
3. Neither → read_skill_file() each missing file → CreateFile("tmp/attack-path/<file>") → use tmp/.
```

> Dependency: **PyYAML**. No other third-party packages.

---

## Architecture (two modes)

```
 MODE B — Prefetch bundle (PRIMARY, deterministic) [recommended]
   The agent assembles a single bundle.json from datasets it ALREADY collects when it
   runs the source skills (exposure-graph, org-posture NHI, graph-least-privilege,
   advisor-impact). Then:
     generate_html_report.py --from-json bundle.json --format both
   → build graph → find paths → score → chokepoints → blind-spot flags → HTML + MD.
   No Azure calls during render. Reuse a prior run's datasets to avoid re-collecting.

 MODE A — Best-effort self-collect (fallback)
   generate_html_report.py
   → acquires MDE + Graph tokens via Azure CLI and GETs the minimal endpoints
     (exposureScore, machines, recommendations, directoryRoles?$expand=members,
      riskyUsers, servicePrincipals, applications). Degrades per-endpoint on failure.
   ⚠️ az token cache is often blocked in the sandbox → prefer Mode B.

 Output: tmp/attack-path/attack-path-<ts>.{html,md}. HTML = self-contained dark report
 (chokepoints table + chain-rendered paths). Rendering is DETERMINISTIC.
```

---

## Workflow

### Step 1 — Assemble the bundle (Mode B)
Concatenate the datasets the source skills already produce into one JSON. **All keys are optional** — the graph is built from whatever is present and degrades gracefully:

| Bundle key | Source skill / endpoint | Feeds |
|------------|-------------------------|-------|
| `directory_roles` | exposure-graph · Graph `/directoryRoles?$expand=members` | crown-jewel roles + members |
| `service_principals` / `applications` | org-posture NHI · Graph `/servicePrincipals`,`/applications` (with `passwordCredentials`/`keyCredentials`) | weak-credential entries |
| `app_grants` | graph-least-privilege · map `{appId|spObjectId: [granted Graph scope]}` | takeover / high-impact capability jewels |
| `risky_users` | exposure-graph · Graph `/identityProtection/riskyUsers` | phishable/compromised entries |
| `machines` + `recommendations` | exposure-graph · MDE `/machines`,`/recommendations` | exposed-device entries + public-exploit weight |
| `admin_logons` | optional · map `{deviceName: [admin upn]}` | exposed-host → admin lateral edge |
| `sp_owners` | optional · map `{appId|spObjectId: [owner upn]}` | owner → app credential-minting edge |
| `mdc_assessments` | advisor-impact · ARM `/Microsoft.Security/assessments` | public-network misconfig entries |
| `mitre_covered` | mitre-coverage-report · `[technique IDs your detections cover]` | detection blind-spot flag |
| `silent_sources` / `impaired_sensors` | telemetry gap · `[source]` / `[device]` | telemetry blind-spot flag |

### Step 2 — Render
```bash
python3 <SKILL_DIR>/generate_html_report.py --from-json tmp/attack-path/bundle.json \
  --output tmp/attack-path/attack-path-<ts> --format both
```

### Step 3 — Read the output
- **Hero KPIs:** `# paths · # → tenant takeover · # cross-domain (novel) · # blind spots · top-chokepoint risk removed` + verdict (CRÍTICA / ELEVADA / MODERADA / CONTIDA).
- **🎯 "Por onde começar" callout:** one plain line at the top — the single fix that closes the **most** attack paths at once (with a deep link to open the object). This replaces the old chokepoints *table* (which read as abstract); the blast-radius prioritisation now lives inline and in context.
- **🪟 Expandable path windows (one self-contained story each):** every attack path is a native `<details>` card — collapsed by default for a clean, intuitive page. Expanding shows: its **own layered mini-map** (`🌐 Atacante → 🚪 Entrada → ↪ Pivô → 🎯 Alvo — até onde chega`; boxes coloured by role, edges by risk, dashed yellow = blind spot, ATT&CK technique per edge); the **🔧 correção with a deep link to open the object** (Entra app/user · Defender device · Azure resource) and a **💥 "fecha N caminhos"** badge when that one fix closes several paths; the **🔬 directed hunting** for that path; and (when active) the **🚨 Sentinel incident proposal**.
- **🔬 Directed hunting (Module 5):** for every edge relation, the skill emits the *appropriate* live hunt on the path's real entities (SP sign-ins / credential-added · Graph activity · risky sign-ins / inbox rules · role changes · device alerts / admin logons). If the bundle carries `hunt_results` (or you pass `--hunt` to run them live), confirmed behaviour lights up **🔴 ativo agora** and the path is flagged active. Hunts are `sentinel` (KQL) or `xdr` (Advanced Hunting via Graph runHuntingQuery).
- **🚨 Sentinel incident (gated action):** when hunting confirms an attack path is **active now**, the skill prepares a Sentinel incident draft (title · severity by path risk · description with chain + MITRE + evidence + chokepoint). Creation is **opt-in and approval-gated**: `--create-incident --sub <id> --rg <rg> --ws-name <name>` PUTs `Microsoft.SecurityInsights/incidents/{guid}` via ARM. The UAMI already has **Microsoft Sentinel Contributor** — no new grant. Default = draft only (the report shows the ready `az rest` command). 100% read-only unless `--create-incident` is explicitly passed.

### Step 4 — Deliver (archive → link → notify)
Follow the [canonical delivery sequence](../../shared/sharepoint-archival.md#canonical-delivery-sequence-archive--link--notify): archive to SharePoint first (capture `webUrl`/`folderUrl`), then email (link + size-aware attach), then Teams (webhook only — never Graph). Subject: `"🧬 Attack Path — caminhos de ataque & chokepoints (<date>)"`. Body KPI line = the script's own numbers.

---

## Scoring model (from queries.yaml)

- **Edge feasibility** (0..1): expired secret 0.90 · expiring 0.70 · long-lived 0.55 · cert 0.30 · public-exploit 0.90 · exposed-high-sev 0.70 · risky-user-high 0.80 · takeover scope 0.85 · high-impact scope 0.60 · misconfig-public 0.60 · admin-logon 0.70 · membership 1.00.
- **Path likelihood** = ∏ edge feasibility along the path.
- **Crown-jewel impact** (0..1): GA / tenant-takeover scope 1.00 · other privileged role 0.70 · high-impact capability 0.55 · sensitive resource 0.50 · endpoint foothold 0.40.
- **Path risk** = `round(100 × likelihood × impact, 1)`.
- **Novel (🧬)** = path crosses ≥ 2 domains (credencial / privilégio / identidade / exploração) → the cross-domain insight.
- **Verdict:** CRÍTICA if any takeover path with likelihood ≥ 0.50 · ELEVADA if top path risk ≥ 35 · MODERADA if any path · else CONTIDA.

---

## Verdict logic

| Verdict | Meaning | Action |
|---------|---------|--------|
| 🔴 CRÍTICA | A feasible path reaches tenant takeover (GA / takeover Graph scope) | Break the #1 chokepoint now |
| 🟠 ELEVADA | High-risk paths to crown jewels exist | Work the chokepoint table top-down |
| 🟡 MODERADA | Paths exist but low risk | Schedule chokepoint fixes |
| 🟢 CONTIDA | No entry→jewel path synthesized from the data | Maintain; widen the bundle to confirm |

---

## Related Skills

- `exposure-graph` — supplies entry points (risky users / exposed devices) + crown-jewel roles. attack-path **chains** them instead of multiplying counts (blast radius → real paths).
- `graph-least-privilege` — supplies `app_grants` (granted Graph scopes) → the takeover/high-impact capability jewels.
- `org-posture` / `spn-scope-drift` — supply SPN credential hygiene → the weak-credential entry edges.
- `advisor-impact` — supplies Defender-for-Cloud misconfig (public network access) → exposure edges; the **chokepoints feed back** to re-prioritize advisor-impact's phased plan by blast-radius.
- `threat-correlation` / `vulnerability-exposure` — supply exploitable CVEs on devices.
- `mitre-coverage-report` — supplies `mitre_covered` → the detection blind-spot flag.
- `contain-compromised-user` — the human-gated response a "contain the user" chokepoint routes to.

---

## Roadmap (the "junte tudo" vision)

This is **Module 1 (toxic combinations / attack-paths)** of the *emergent-risk hunter*, wired with **Module 2 (detection blind-spots)**, **Module 4 (telemetry silence)** as edge annotations, and **Module 5 (hypothesis hunting)** — directed live hunts per correlation with an active-now flag and a gated Sentinel-incident response. Future increments:
- **Module 3 — baseline anomaly** (first-seen SPN ASN / consent pattern) as a new entry-node source.
- **Device-weighted feed into advisor-impact** (registered backlog idea): push the chokepoints as a priority overlay on the phased remediation plan.
- **Hardening:** move incident-creation behind `shared/action_safety.py` gate explicitly; webhook/secret handling.

---

## Implementation Notes

- **Portability:** `AZ = shutil.which("az") or "az"`; win32 UTF-8 stdout/stderr guard.
- **Determinism:** identical bundle → identical report. Paths deduped by node sequence (highest risk kept); chokepoints count each path once per asset+relation.
- **Graceful degrade:** any missing dataset just yields fewer edges; never crashes.
- **Original code.** The graph/path/chokepoint engine is original; the abuse→MITRE mapping aligns with `shared/mitre_map.py`.

---

## Status

- ✅ Code complete (graph synthesis · DFS path-finding · likelihood×impact scoring · per-asset chokepoint ranking · detection/telemetry blind-spot annotation · HTML+MD renderers).
- ✅ Smoke-tested (`_smoke.json`): SUPERFÍCIE CRÍTICA · 10 paths · 4 → takeover · 7 cross-domain · 8 blind · top chokepoint (remove GA from the risky admin / PIM) breaks 2 critical paths (risk 143). HTML validated in browser.
- ⏳ Pending: live validation in the SRE Agent (Mode B bundle from a real exposure-graph + graph-least-privilege + org-posture run); optional Microsoft Secure Score logo header for visual parity with the suite.

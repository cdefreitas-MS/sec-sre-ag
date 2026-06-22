---
name: threat-correlation
description: 'Correlates threat intelligence with the environment''s REAL vulnerabilities and ACTIVE alerts to surface the CVEs that matter right now. Tier 1 (license-free) via Defender XDR Advanced Hunting — exposed-device count per CVE (DeviceTvmSoftwareVulnerabilities) enriched in-KQL with CVSS + exploit signal from the TVM KB (DeviceTvmSoftwareVulnerabilitiesKB), cross-referenced with active alerts on the same devices (AlertInfo + AlertEvidence) = active threat on a vulnerable asset, plus crown-jewel weighting. Tier 2 (with MDTI premium API add-on) enriches the top CVEs with actor/article/dark-web context from Microsoft Defender Threat Intelligence, degrading gracefully on 402/403. Ranks each CVE (exposed x CVSS x exploit x active-alert x asset-criticality) and renders an executive verdict per CVE (corrigir agora / janela / monitorar) as HTML + Markdown, delivered via email + Teams and archived to SharePoint. Collector<->renderer, deterministic, 100% READ-ONLY. Use for: threat correlation, ameacas que importam, quais CVEs estao sendo exploradas no meu ambiente, vulnerabilidade com ameaca ativa, MDTI, threat-vulnerability correlation, exploitable exposed CVEs, active threat on vulnerable asset.'
---

# Threat ↔ Vulnerability Correlation — Skill Instructions

## Purpose

Answer **"quais ameaças importam AGORA pra MIM?"** — not a generic vulnerability catalog, but
the intersection of (1) threat intelligence (exploit availability, exposure), (2) the CVEs that
actually exist on **my** devices, and (3) **active alerts on those same devices**. A medium-noise
CVE that is exploitable AND sits on a machine with an active alert outranks a high-CVSS bug that
is dormant and isolated.

## Configuration

Reads from `config.json` at workspace root: `subscription_id` (token), `email.*`, `teams.*`.

Tunables (`queries.yaml → parameters`):
- `lookback_days = 14` (alert window), `cvss_min = 7.0`, `top_cves = 15`, `top_threats = 5`,
  `mdti_enrich_top = 8`.

Scoring (`queries.yaml → scoring`):
```
prioridade(CVE) = exposed_devices × CVSS × severityWeight × exploitWeight × alertBonus × crownBonus
```
- `severityWeight`: Critical=1.0, High=0.6, Medium=0.3, Low=0.1
- `exploitWeight = ×3` (IsExploitAvailable=1) · `alertBonus = ×2` (device exposto c/ alerta ativo)
- `crownBonus = ×1.5` (device de alto valor / crown jewel exposto)

Verdict per CVE:
- 🔴 **corrigir agora**: exploit AND (alerta ativo OR muitos devices expostos)
- 🟠 **janela**: exploit OR muitos devices expostos
- 🟢 **monitorar**: caso contrário

## Data Routing (by origin — not a blind fallback)

| Tier | Source | Tables / endpoints | Auth |
|---|---|---|---|
| **1** (sempre) | Defender XDR Advanced Hunting via Graph `runHuntingQuery` | `DeviceTvmSoftwareVulnerabilitiesKB`, `DeviceTvmSoftwareVulnerabilities`, `AlertInfo`, `AlertEvidence`, `DeviceInfo` | `ThreatHunting.Read.All` (UAMI) |
| **2** (opcional) | Microsoft Defender Threat Intelligence (MDTI) | `/security/threatIntelligence/vulnerabilities/{cve}`, `/articles`, `/intelProfiles` | `ThreatIntelligence.Read.All` + **MDTI premium API add-on** |

> XDR Advanced Hunting uses `Timestamp` (não `TimeGenerated`).
> **MDTI premium não está licenciado no tenant demo: as APIs retornam `402 PaymentRequired`.**
> O Tier 2 degrada gracioso (marca "MDTI não licenciado" e segue só com Tier 1). Quando o add-on
> estiver presente, o enriquecimento por CVE liga automaticamente.
> **Token note:** `az account get-access-token --resource graph` NÃO carrega `ThreatHunting.Read.All`
> (403 "Missing application scopes"). Via agente, a UAMI tem o app-role → self-collect funciona.
> Localmente, usar `Connect-MgGraph -Scopes ThreatHunting.Read.All` + `Invoke-MgGraphRequest`.

## Workflow

### Step 1 — Acquire Graph token
O renderer faz isso sozinho no modo self-collect (UAMI via `az account get-access-token --resource https://graph.microsoft.com`).

### Step 2 — Collect (Tier 1, via `POST /security/runHuntingQuery`)
- **Q1 `cve_kb`** — catálogo Critical/High: `CveId, CvssScore, VulnerabilitySeverityLevel, IsExploitAvailable, PublishedDate, VulnerabilityDescription`.
- **Q2 `cve_exposure`** (ENRIQUECIDA) — `dcount(DeviceId)` + `make_set(DeviceName,8)` por CVE, **join em KQL com a KB** trazendo CVSS/exploit/severidade no mesmo row (evita o gap do teto da KB).
- **Q3 `cve_active_threat`** — join exposição ↔ devices com alerta na janela → `AlertedDevices`, `MaxAlertSeverity` por CVE.
- **Q4 `alerts_summary`** — alertas/devices por severidade (contexto).
- **Q5 `crown_jewels`** — `DeviceInfo` com `DeviceValue == 'High'` via `column_ifexists` (degrada p/ vazio se a coluna não existir no schema).

### Step 3 — Collect (Tier 2, MDTI — opcional)
Para as `mdti_enrich_top` CVEs do topo, `GET /security/threatIntelligence/vulnerabilities/{cve}`
(+ `/articles`, `/intelProfiles`). `402`/`403` → `mdti_available = False`, segue sem Tier 2.

### Step 4 — Compute (determinístico, no renderer)
Ranking pela fórmula acima; veredito por CVE; postura geral (CRÍTICA/ELEVADA/CONTROLADA);
"Top ameaças que importam pra você" = CVEs com veredito ≠ monitorar.

### Step 5 — Render
`reports/threat-correlation/<ts>.html` + `.md` (mesmo basename): badge de postura + 5 cards
(Corrigir agora · CVEs no ambiente · com exploit · c/ alerta ativo · em crown jewels) +
cards "Top ameaças" (tags 🔥 exploit / ⚠️ alerta ativo / 👑 crown jewel) +
tabela de CVEs priorizadas + chips de alertas ativos por severidade.

### Step 6 — Deliver (archive → link → notify)
Segue a [sequência canônica de entrega](../../shared/sharepoint-archival.md#canonical-delivery-sequence-archive--link--notify):
1. **SharePoint (primeiro)**: `python shared/sharepoint_upload.py upload --site "<config: sharepoint.site_id>" --skill threat-correlation --file <html>` (e o `.md`). Captura o `webUrl` + `folderUrl` do stdout; se pular/falhar (exit 3/1) → `webUrl=null`, segue mesmo assim.
2. **send-email-report**: título "🎯 Threat ↔ Vulnerability Correlation — {date}", cor por postura. HTML compacto (< 3 MB) → **anexa HTML** + linha de link `📂 Abrir no SharePoint: <folderUrl>` quando houver (abre a biblioteca; NÃO linkar o arquivo `webUrl` — `.html` baixa).
3. **send-teams-notification**: Adaptive Card com postura + Top 3 ameaças (corrigir-agora primeiro) + ação **Abrir no SharePoint** → `folderUrl` quando houver.

### Step 7 — Chat summary
```
🎯 THREAT ↔ VULNERABILITY CORRELATION — {date}
   Postura: {CRÍTICA|ELEVADA|CONTROLADA}
   🔴 Corrigir agora: {n}   🔥 com exploit: {k}   ⚠️ c/ alerta ativo: {m}
   Top ameaça: {CVE} (CVSS {x}, {devices} expostos{, alerta ativo})
   📧 Email + 💬 Teams + 🗄️ SharePoint
```

## Modes

```bash
python generate_html_report.py                    # self-collect (Tier 1 + Tier 2 se licenciado)
python generate_html_report.py --from-json p.json # render a partir de payload pré-coletado
python generate_html_report.py --no-mdti          # pular Tier 2 explicitamente
```

`results.json` shape: `{ "cve_kb":[…], "cve_exposure":[…], "cve_active_threat":[…], "alerts_summary":[…], "crown_jewels":[…], "mdti":{"available":bool,"articles":[…],"vulnerabilities":{"CVE-…":{…}}} }`.

## Shared utilities

- `shared/mitre_map.py map "<text>"` — infer ATT&CK techniques from CVE/alert text (TTP tagging — future enhancement).
- `shared/sharepoint_upload.py upload …` — archive the generated HTML/MD to the SOC SharePoint (Graph chunked for large files).

## Common Errors

| Error | Meaning | Fix |
|---|---|---|
| `runHuntingQuery` 403 "Missing application scopes" | token sem `ThreatHunting.Read.All` | Via agente a UAMI tem; local → `Connect-MgGraph -Scopes ThreatHunting.Read.All` |
| MDTI `402 PaymentRequired` | Sem add-on de API MDTI premium | Esperado → Tier 2 desliga, Tier 1 segue |
| MDTI `403` | `ThreatIntelligence.Read.All` ausente | Conceder o scope (não destrava 402) |
| `crown_jewels` BadRequest | `DeviceInfo.DeviceValue` ausente no schema | Já mitigado via `column_ifexists` → retorna vazio |
| Tabela vazia | Sem devices onboarded / sem alertas | Postura CONTROLADA + nota "sem exposição/alertas" |

## Rules

- ✅ **READ-ONLY**. Recomenda, nunca remedia.
- ✅ **SEMPRE** ranqueia por exposição × CVSS × exploit × **alerta ativo** × ativo crítico — ameaça ativa em ativo vulnerável vence CVSS cru.
- ✅ **SEMPRE** degrada gracioso sem MDTI premium (Tier 1 é o motor real).
- ✅ **SEMPRE** arquiva no SharePoint **primeiro** (HTML grande → Graph chunked via `shared/sharepoint_upload.py`), captura o `webUrl` e o inclui no email + Teams; entrega tripla (email + Teams + link SharePoint).
- ⛔ **NUNCA** deixa token em disco — `rm -f` após uso.
- ⛔ **NUNCA** tenta operações git.

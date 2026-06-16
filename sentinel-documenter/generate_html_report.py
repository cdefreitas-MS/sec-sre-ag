#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sentinel-documenter / generate_html_report.py  (collector ↔ renderer)

Documentação viva, com GAP ANALYSIS pontuada, de um workspace do Microsoft Sentinel.
Catálogo SENT-NNN portado FIEL do Sentinel-As-Code Wave 4 (best-practices.json v2.0.0 +
GapChecks.ps1, TobyG / noodlemctwoodle). 100% READ-ONLY — nunca muta o workspace.

Dois modos:
  --from-json inventory.json     → render determinístico/offline (caminho primário, testável)
  --workspace <GUID> --sub --rg --ws  → auto-coleta (az rest + az monitor + Retail Prices)

Saída:
  --format both (default) → HTML (dark, p/ email) + Markdown (index + por categoria, p/ repo)
"""
from __future__ import annotations
import argparse, datetime as dt, html, json, os, re, shutil, subprocess, sys, urllib.request

# --- portabilidade: resolve az.CMD no Windows; achata KQL p/ az.cmd não truncar -------------
AZ = shutil.which("az") or "az"

def _flatten_kql(kql: str) -> str:
    lines = []
    for ln in kql.splitlines():
        ln = re.sub(r"//.*$", "", ln).strip()
        if ln:
            lines.append(ln)
    return " ".join(lines)

# =============================================================================
# helpers de leitura tolerante (equivalente ao Get-PropOrDefault do PowerShell)
# =============================================================================
def prop(obj, path, default=None):
    """Lê caminho pontilhado (a.b.c) de dict aninhado; retorna default se ausente."""
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur if cur is not None else default

def as_list(x):
    if x is None:
        return []
    if isinstance(x, dict) and "value" in x and isinstance(x["value"], list):
        return x["value"]
    if isinstance(x, list):
        return x
    return [x]

def num(x, default=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default

def esc(s):
    return html.escape("" if s is None else str(s))

# =============================================================================
# Finding model + sentinela "não avaliável" (check exige dado que não coletamos)
# =============================================================================
class Skip(Exception):
    """Levantada por um check quando o inventário não tem o dado necessário."""

def F(evidence, detail=""):
    """Constrói o payload de um achado (rule metadata é mesclada depois)."""
    return {"evidence": evidence, "detail": detail}

# =============================================================================
# Inventário normalizado a partir do JSON (--from-json) ou _raw coletado
# =============================================================================
def build_inventory(data: dict) -> dict:
    ws = data.get("workspace") or {}
    inv = {
        "Workspace": ws,
        "Tables": as_list(data.get("tables")),
        "TablesWithData": as_list(data.get("tables_with_data")),
        "AlertRules": as_list(data.get("alert_rules")),
        "AlertRuleTemplates": as_list(data.get("alert_templates")),
        "DataConnectors": as_list(data.get("data_connectors")),
        "AutomationRules": as_list(data.get("automation_rules")),
        "Dcrs": as_list(data.get("dcrs")),
        "Ueba": data.get("ueba"),
        "ContentPackages": as_list(data.get("content_packages")),
        "Rbac": as_list(data.get("rbac")),
        "IncidentsMttr": (as_list(data.get("incidents_mttr")) or [{}])[0],
        "RuleVolumes": as_list(data.get("rule_volumes")),
        "AmaMma": (as_list(data.get("ama_mma_migration")) or [{}])[0],
        "DiagnosticSettings": data.get("diagnostic_settings"),
        "WorkspaceLocks": data.get("locks"),
        "ResourceProviders": data.get("resource_providers"),
    }
    return inv

# tabela billable em GB nas janelas
def tdata_gb(inv, datatype, window="BillableLast30d"):
    for t in inv["TablesWithData"]:
        if str(t.get("DataType", "")).lower() == datatype.lower():
            return num(t.get(window))
    return 0.0

# todas as 14 táticas MITRE (sentinelShortName)
MITRE_TACTICS = [
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact",
]
MANAGED_RULE_KINDS = {"MicrosoftSecurityIncidentCreation", "Fusion", "ThreatIntelligence", "MLBehaviorAnalytics"}

# =============================================================================
# GAP CHECKS — port fiel (subset implementável) das funções Test-* do GapChecks.ps1
# Cada função: recebe inv, retorna F(...) (achado) | None (ok) | raise Skip (não avaliável)
# =============================================================================
def c_daily_cap(inv):
    cap = num(prop(inv["Workspace"], "properties.workspaceCapping.dailyQuotaGb", -1), -1)
    if cap <= 0:
        return F("dailyQuotaGb = -1 (sem cap)", "Um conector descontrolado pode estourar a fatura sem teto.")
    return None

def c_retention90(inv):
    r = num(prop(inv["Workspace"], "properties.retentionInDays", 0))
    if r < 90:
        return F(f"retentionInDays = {int(r)}", "Upgrade 30→90d é grátis em tabelas elegíveis ao benefício Sentinel.")
    return None

def c_noisy_no_transform(inv):
    # tabelas Analytics > 50GB/30d sem transform em nenhum DCR
    transformed = _tables_with_transform(inv)
    noisy = [t for t in inv["TablesWithData"] if num(t.get("BillableLast30d")) >= 50.0]
    hits = [t["DataType"] for t in noisy if str(t.get("DataType")).lower() not in transformed]
    if hits:
        return F(f"{len(hits)} tabela(s) ≥50GB/30d sem transform", ", ".join(hits[:6]) + (" …" if len(hits) > 6 else ""))
    return None

def c_recommended_connectors(inv):
    deployed = {str(prop(c, "kind", "")).lower() for c in inv["DataConnectors"]}
    if not deployed:
        raise Skip()
    recommended = {"azureactivedirectory", "microsoftdefenderadvancedthreatprotection", "office365", "azuresecuritycenter", "threatintelligence"}
    missing = sorted(recommended - deployed)
    if missing:
        return F(f"{len(missing)} conector(es) recomendado(s) ausente(s)", ", ".join(missing))
    return None

def c_ueba(inv):
    u = inv["Ueba"]
    if u is None:
        raise Skip()
    enabled = bool(prop(u, "properties.dataSources") or prop(u, "properties.isEnabled"))
    if not enabled:
        return F("UEBA desabilitado", "Sem anomaly scores nem timelines de entidade.")
    return None

def c_mitre(inv):
    enabled = [r for r in inv["AlertRules"] if prop(r, "properties.enabled", False)]
    if not enabled:
        raise Skip()
    covered = set()
    for r in enabled:
        for t in (prop(r, "properties.tactics", []) or []):
            covered.add(str(t))
    blind = [t for t in MITRE_TACTICS if t not in covered]
    if blind:
        return F(f"{len(blind)}/14 táticas sem detecção", ", ".join(blind))
    return None

def c_rules_disabled(inv):
    bad = [r for r in inv["AlertRules"]
           if str(prop(r, "kind", "")) not in MANAGED_RULE_KINDS
           and not prop(r, "properties.enabled", False)]
    if bad:
        names = [prop(r, "properties.displayName", "?") for r in bad]
        return F(f"{len(bad)} regra(s) desabilitada(s)/erro", ", ".join(names[:6]) + (" …" if len(names) > 6 else ""))
    return None

def c_high_sev_templates(inv):
    tmpls = inv["AlertRuleTemplates"]
    if not tmpls:
        raise Skip()
    deployed_tmpl = {prop(r, "properties.alertRuleTemplateName") for r in inv["AlertRules"]}
    high = [t for t in tmpls if str(prop(t, "properties.severity", "")).lower() == "high"
            and prop(t, "name") not in deployed_tmpl]
    if len(high) >= 5:
        return F(f"{len(high)} templates High não implantados", "Quick wins de cobertura disponíveis no Content Hub.")
    return None

def c_rbac_priv(inv):
    if not inv["Rbac"]:
        raise Skip()
    over = [a for a in inv["Rbac"]
            if str(prop(a, "RoleDefinitionName", "")) in ("Owner", "Contributor")
            and str(prop(a, "ObjectType", "")).lower() in ("user", "group")]
    if over:
        who = [f"{prop(a,'DisplayName','?')} ({prop(a,'RoleDefinitionName')})" for a in over]
        return F(f"{len(over)} principal(is) Owner/Contributor", ", ".join(who[:6]))
    return None

def c_dcr_transform_missing(inv):
    custom = [t for t in inv["TablesWithData"]
              if str(t.get("DataType", "")).endswith("_CL") and num(t.get("BillableLast30d")) >= 5.0]
    if not custom:
        return None
    transformed = _tables_with_transform(inv)
    miss = [t["DataType"] for t in custom if str(t["DataType"]).lower() not in transformed]
    if miss:
        return F(f"{len(miss)} custom _CL barulhenta(s) sem transform", ", ".join(miss[:6]))
    return None

def c_onboarded_defender(inv):
    # informativo/estratégico — sempre aponta o deadline
    return F("Sentinel ainda no portal Azure", "Migração p/ Defender XDR antes de 2027-03-31.")

def c_commitment_tier(inv):
    sku = str(prop(inv["Workspace"], "properties.sku.name", ""))
    if sku.lower() != "pergb2018":
        return None
    daily = _avg_daily_gb(inv)
    for tier in (100, 200, 300, 400, 500, 1000):
        if daily >= tier * 0.85:
            return F(f"~{daily:.0f} GB/dia ≥ break-even do tier {tier}", "Commitment tier reduz custo vs PerGB2018.")
    return None

def c_high_vol_plan(inv):
    # >50GB/30d e sem regra/uso de query → candidata a Basic/Aux
    used = _tables_used_by_rules(inv)
    hits = [t["DataType"] for t in inv["TablesWithData"]
            if num(t.get("BillableLast30d")) >= 50.0 and str(t["DataType"]).lower() not in used]
    if hits:
        return F(f"{len(hits)} tabela(s) volumosa(s) candidata(s) a Basic/Aux", ", ".join(hits[:6]))
    return None

def c_retention_over_archive(inv):
    if not inv["Tables"]:
        raise Skip()
    long_interactive = [prop(t, "name") for t in inv["Tables"]
                        if num(prop(t, "properties.retentionInDays", 0)) > 90
                        and str(prop(t, "properties.plan", "Analytics")) == "Analytics"]
    if long_interactive:
        return F(f"{len(long_interactive)} tabela(s) com retenção interativa >90d", ", ".join(long_interactive[:6]))
    return None

def c_dedicated_cluster(inv):
    daily = _avg_daily_gb(inv)
    if daily >= 500.0:
        return F(f"~{daily:.0f} GB/dia sustentado", "Dedicated cluster dá CR pricing, CMK e AZ.")
    return None

def c_sentinel_benefit(inv):
    raise Skip()  # exige cruzar planos Defender — fora do inventário coletado

def c_replication(inv):
    en = prop(inv["Workspace"], "properties.replication.enabled", None)
    if en is None:
        raise Skip()
    if not en:
        return F("replication.enabled = false", "Sem mirror síncrono p/ failover de região.")
    return None

def c_public_network(inv):
    ing = str(prop(inv["Workspace"], "properties.publicNetworkAccessForIngestion", "Enabled"))
    qry = str(prop(inv["Workspace"], "properties.publicNetworkAccessForQuery", "Enabled"))
    if ing == "Enabled" or qry == "Enabled":
        return F(f"ingest={ing}, query={qry}", "Exponha via AMPLS/Private Link em vez de rede pública.")
    return None

def c_resource_providers(inv):
    rp = inv["ResourceProviders"]
    if rp is None:
        raise Skip()
    needed = {"Microsoft.SecurityInsights", "Microsoft.OperationalInsights"}
    reg = {x.get("namespace"): x.get("registrationState") for x in as_list(rp)}
    miss = [n for n in needed if reg.get(n) != "Registered"]
    if miss:
        return F(f"RP não registrado: {', '.join(miss)}", "Deploys de Sentinel falham sem isso.")
    return None

def c_datalake_candidate(inv):
    if not inv["Tables"]:
        raise Skip()
    cand = [prop(t, "name") for t in inv["Tables"]
            if num(prop(t, "properties.totalRetentionInDays", 0)) > 365
            and str(prop(t, "properties.plan", "Analytics")) == "Analytics"]
    if cand:
        return F(f"{len(cand)} tabela(s) long-tail candidata(s) a Data Lake", ", ".join(cand[:6]))
    return None

def c_disable_local_auth(inv):
    v = prop(inv["Workspace"], "properties.features.disableLocalAuth", None)
    if v is None:
        raise Skip()
    if not v:
        return F("disableLocalAuth = false", "Ingestão por shared-key permitida; force auth Entra.")
    return None

def c_access_mode(inv):
    v = prop(inv["Workspace"], "properties.features.enableLogAccessUsingOnlyResourcePermissions", None)
    if v is None:
        raise Skip()
    return None  # informativo: só sinaliza inconsistência se houver baseline; sem baseline = ok

def c_silent_tables(inv):
    hits = [t["DataType"] for t in inv["TablesWithData"]
            if num(t.get("BillableLast7d")) == 0 and num(t.get("BillableLast90d")) > 0]
    if hits:
        return F(f"{len(hits)} tabela(s) silenciosa(s) (sem dado 7d, com dado 90d)", ", ".join(hits[:6]))
    return None

def c_orphan_tables(inv):
    if not inv["Tables"]:
        raise Skip()
    have_data = {str(t.get("DataType", "")).lower() for t in inv["TablesWithData"] if num(t.get("BillableLast90d")) > 0}
    orphan = [prop(t, "name") for t in inv["Tables"]
              if str(prop(t, "properties.schema.tableType", "")) == "CustomLog"
              and str(prop(t, "name", "")).lower() not in have_data]
    if orphan:
        return F(f"{len(orphan)} custom table órfã(s) (schema, sem dado 90d)", ", ".join(orphan[:6]))
    return None

def c_connector_mismatch(inv):
    if not inv["DataConnectors"]:
        raise Skip()
    # heurística: conectores conhecidos → tabela-alvo; se conectado mas 24h==0 → mismatch
    target = {"office365": "OfficeActivity", "azureactivedirectory": "SigninLogs",
              "microsoftdefenderadvancedthreatprotection": "DeviceEvents"}
    miss = []
    for c in inv["DataConnectors"]:
        k = str(prop(c, "kind", "")).lower()
        tbl = target.get(k)
        if tbl and tdata_gb(inv, tbl, "BillableLast24h") == 0 and tdata_gb(inv, tbl, "BillableLast30d") > 0:
            miss.append(f"{k}→{tbl}")
    if miss:
        return F(f"{len(miss)} conector(es) sem dado 24h na tabela-alvo", ", ".join(miss))
    return None

def c_mttr(inv):
    m = num(prop(inv["IncidentsMttr"], "MTTRMinutes", 0))
    if m > 1440:
        return F(f"MTTR ≈ {m/60:.1f} h", "Acima do limite de 24h — SOC sobrecarregado ou automação faltando.")
    return None

def c_ack(inv):
    closed = num(prop(inv["IncidentsMttr"], "ClosedCount", 0))
    ack = num(prop(inv["IncidentsMttr"], "AcknowledgedCount", 0))
    if closed >= 10 and ack / closed < 0.5:
        return F(f"{ack:.0f}/{closed:.0f} acknowledged", ">50% fechados sem ack — possível auto-close sem revisão.")
    return None

def c_mouldy(inv):
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=365)
    old = []
    for r in inv["AlertRules"]:
        if str(prop(r, "kind", "")) in MANAGED_RULE_KINDS or not prop(r, "properties.enabled", False):
            continue
        lm = _parse_dt(prop(r, "properties.lastModifiedUtc"))
        if lm and lm < cutoff:
            old.append(prop(r, "properties.displayName", "?"))
    if old:
        return F(f"{len(old)} regra(s) sem alteração >12 meses", ", ".join(old[:6]))
    return None

def c_template_drift(inv):
    tv = {prop(t, "name"): str(prop(t, "properties.version", "")) for t in inv["AlertRuleTemplates"]}
    if not tv:
        raise Skip()
    drift = []
    for r in inv["AlertRules"]:
        tn = prop(r, "properties.alertRuleTemplateName")
        cur = str(prop(r, "properties.templateVersion", ""))
        latest = tv.get(tn)
        if tn and latest and cur and cur != latest:
            drift.append(prop(r, "properties.displayName", "?"))
    if drift:
        return F(f"{len(drift)} regra(s) atrás do template", ", ".join(drift[:6]))
    return None

def c_dominant_rule(inv):
    vols = inv["RuleVolumes"]
    total = sum(num(v.get("Alerts")) for v in vols)
    if total < 50:
        return None
    top = max(vols, key=lambda v: num(v.get("Alerts")), default=None)
    if top and num(top.get("Alerts")) / total > 0.30:
        pct = num(top.get("Alerts")) / total * 100
        return F(f"'{top.get('AlertName')}' = {pct:.0f}% dos alertas", "Candidata a tuning (threshold/exclusão).")
    return None

def c_automation_rules(inv):
    if len(inv["AutomationRules"]) == 0:
        return F("0 automation rules", "Toda triagem é manual; comece com enriquecimento.")
    return None

def c_dead_rule(inv):
    fired = {str(v.get("AlertName", "")).lower() for v in inv["RuleVolumes"] if num(v.get("Alerts")) > 0}
    if not inv["RuleVolumes"]:
        raise Skip()
    dead = []
    for r in inv["AlertRules"]:
        if str(prop(r, "kind", "")) in MANAGED_RULE_KINDS or not prop(r, "properties.enabled", False):
            continue
        nm = str(prop(r, "properties.displayName", "")).lower()
        if nm and nm not in fired:
            dead.append(prop(r, "properties.displayName", "?"))
    if dead:
        return F(f"{len(dead)} regra(s) habilitada(s) com 0 alertas/90d", ", ".join(dead[:6]))
    return None

def c_sp_priv(inv):
    if not inv["Rbac"]:
        raise Skip()
    sp = [a for a in inv["Rbac"]
          if str(prop(a, "RoleDefinitionName", "")) in ("Owner", "Contributor")
          and str(prop(a, "ObjectType", "")).lower() == "serviceprincipal"]
    if sp:
        who = [prop(a, "DisplayName", "?") for a in sp]
        return F(f"{len(sp)} service principal(is) Owner/Contributor", ", ".join(who[:6]))
    return None

def c_responder(inv):
    if not inv["Rbac"]:
        raise Skip()
    has = any("responder" in str(prop(a, "RoleDefinitionName", "")).lower() for a in inv["Rbac"])
    if not has:
        return F("Nenhuma atribuição Sentinel Responder", "SOC não consegue agir em incidente por least-privilege.")
    return None

def c_lock(inv):
    locks = inv["WorkspaceLocks"]
    if locks is None:
        raise Skip()
    if not any(str(prop(l, "properties.level", "")) == "CanNotDelete" for l in as_list(locks)):
        return F("Sem lock CanNotDelete", "Deleção acidental/maliciosa apagaria rules, watchlists e histórico.")
    return None

def _split_op(inv, datatype, label):
    gb = tdata_gb(inv, datatype, "BillableLast30d")
    if gb >= 150.0:
        return F(f"{datatype} ≈ {gb:.0f} GB/30d", f"Oportunidade de filtro/split de {label} via DCR.")
    return None

def c_cef_split(inv): return _split_op(inv, "CommonSecurityLog", "CEF")
def c_syslog_split(inv): return _split_op(inv, "Syslog", "Syslog")
def c_winevent_xpath(inv):
    for dtp in ("SecurityEvent", "WindowsEvent", "Event"):
        r = _split_op(inv, dtp, "Windows Event (XPath)")
        if r:
            return r
    return None
def c_azurediag(inv): return _split_op(inv, "AzureDiagnostics", "AzureDiagnostics → resource-specific")

def c_clv1(inv):
    if not inv["Tables"]:
        raise Skip()
    # heurística: _CL com schema CustomLog e SEM DCR associado → provável CLv1
    dcr_tables = _tables_with_transform(inv)
    clv1 = [prop(t, "name") for t in inv["Tables"]
            if str(prop(t, "name", "")).endswith("_CL")
            and str(prop(t, "properties.schema.tableType", "")) == "CustomLog"
            and str(prop(t, "name", "")).lower() not in dcr_tables]
    if clv1:
        return F(f"{len(clv1)} custom log provável CLv1", "API HTTP Data Collector aposenta 2026-09-14; migre p/ DCR.")
    return None

def c_mma(inv):
    n = num(prop(inv["AmaMma"], "MMACount", 0))
    if n > 0:
        return F(f"{int(n)} host(s) com agente MMA/OMS legado", "MMA aposentado 2024-08-31; migre p/ AMA + DCR.")
    return None

def c_legacy_ti(inv):
    if tdata_gb(inv, "ThreatIntelligenceIndicator", "BillableLast30d") > 0:
        return F("ThreatIntelligenceIndicator ainda recebe dado", "Ingestão legada parou 2025-07-31; use ThreatIntelIndicators/Objects.")
    return None

# Skips explícitos p/ checks que exigem dado não coletado no MVP
def c_diag(inv):
    if inv["DiagnosticSettings"] is None:
        raise Skip()
    if not as_list(inv["DiagnosticSettings"]):
        return F("Sem diagnostic settings", "Workspace não se auto-monitora (LAQueryLogs/SentinelHealth).")
    return None

def c_playbook_mi(inv): raise Skip()
def c_contenthub_updates(inv):
    if not inv["ContentPackages"]:
        raise Skip()
    return None

# ----- utilitários compartilhados -------------------------------------------
def _tables_with_transform(inv):
    out = set()
    for d in inv["Dcrs"]:
        for fl in (prop(d, "properties.dataFlows", []) or []):
            if prop(fl, "transformKql"):
                for s in (prop(fl, "streams", []) or []):
                    out.add(str(s).split("-")[-1].lower())
                ostream = prop(fl, "outputStream")
                if ostream:
                    out.add(str(ostream).split("-")[-1].lower())
    return out

def _tables_used_by_rules(inv):
    used = set()
    for r in inv["AlertRules"]:
        q = str(prop(r, "properties.query", "")).lower()
        for t in inv["TablesWithData"]:
            if str(t["DataType"]).lower() in q:
                used.add(str(t["DataType"]).lower())
    return used

def _avg_daily_gb(inv):
    gb30 = sum(num(t.get("BillableLast30d")) for t in inv["TablesWithData"])
    return gb30 / 30.0

def _parse_dt(s):
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None

# dispatch: nome do `check` (PascalCase do catálogo) → função Python
CHECKS = {
    "Test-DailyCapConfigured": c_daily_cap,
    "Test-WorkspaceRetentionMeetsSentinelBenefit": c_retention90,
    "Test-NoisyTableHasTransform": c_noisy_no_transform,
    "Test-RecommendedConnectorsDeployed": c_recommended_connectors,
    "Test-UebaEnabled": c_ueba,
    "Test-MitreTacticCoverage": c_mitre,
    "Test-RulesDisabledOrFailing": c_rules_disabled,
    "Test-HighSeverityTemplatesDeployed": c_high_sev_templates,
    "Test-RbacOverPrivileged": c_rbac_priv,
    "Test-DiagnosticSettingsConfigured": c_diag,
    "Test-PlaybookMiHasResponder": c_playbook_mi,
    "Test-DcrTransformMissing": c_dcr_transform_missing,
    "Test-ContentHubUpdatesAvailable": c_contenthub_updates,
    "Test-OnboardedToDefender": c_onboarded_defender,
    "Test-CommitmentTierOpportunity": c_commitment_tier,
    "Test-HighVolumeTablePlanCandidate": c_high_vol_plan,
    "Test-RetentionOverArchive": c_retention_over_archive,
    "Test-DedicatedClusterCandidate": c_dedicated_cluster,
    "Test-SentinelBenefitApplied": c_sentinel_benefit,
    "Test-ReplicationEnabled": c_replication,
    "Test-PublicNetworkAccessDisabled": c_public_network,
    "Test-ResourceProvidersRegistered": c_resource_providers,
    "Test-DataLakeMirroringCandidate": c_datalake_candidate,
    "Test-DisableLocalAuth": c_disable_local_auth,
    "Test-AccessModeConsistent": c_access_mode,
    "Test-SilentTables": c_silent_tables,
    "Test-OrphanTables": c_orphan_tables,
    "Test-ConnectorTableMismatch": c_connector_mismatch,
    "Test-IncidentMttrThreshold": c_mttr,
    "Test-IncidentClosedWithoutAcknowledgement": c_ack,
    "Test-MouldyAnalyticsRules": c_mouldy,
    "Test-AnalyticsRuleTemplateDrift": c_template_drift,
    "Test-DominantNoisyRule": c_dominant_rule,
    "Test-AutomationRulesPresent": c_automation_rules,
    "Test-DeadAnalyticsRule": c_dead_rule,
    "Test-ServicePrincipalOverPrivileged": c_sp_priv,
    "Test-ResponderRoleAssigned": c_responder,
    "Test-WorkspaceLockPresent": c_lock,
    "Test-CefSplitOpportunity": c_cef_split,
    "Test-SyslogSplitOpportunity": c_syslog_split,
    "Test-WindowsEventXPathFilterOpportunity": c_winevent_xpath,
    "Test-AzureDiagnosticsResourceSpecific": c_azurediag,
    "Test-CustomLogsV1Migration": c_clv1,
    "Test-MmaAgentStillHeartbeating": c_mma,
    "Test-LegacyThreatIntelligenceTable": c_legacy_ti,
}

SEV_WEIGHT = {"Critical": 15, "Warning": 7, "Info": 2}

def run_gaps(inv, catalog):
    findings, passed, skipped = [], [], []
    for rule in catalog:
        fn = CHECKS.get(rule.get("check"))
        if fn is None:
            skipped.append({**rule, "reason": "sem implementação no renderer"})
            continue
        try:
            res = fn(inv)
        except Skip:
            skipped.append({**rule, "reason": "dado não coletado neste inventário"})
            continue
        except Exception as e:  # check robusto: nunca derruba o relatório
            skipped.append({**rule, "reason": f"erro: {e}"})
            continue
        if res:
            findings.append({**rule, **res})
        else:
            passed.append(rule)
    # ordena por severidade
    order = {"Critical": 0, "Warning": 1, "Info": 2}
    findings.sort(key=lambda x: order.get(x["severity"], 3))
    return findings, passed, skipped

def documenter_score(findings):
    score = 100
    for f in findings:
        score -= SEV_WEIGHT.get(f["severity"], 2)
    score = max(0, score)
    if score >= 85:
        verdict, klass = "SAUDÁVEL", "good"
    elif score >= 65:
        verdict, klass = "ATENÇÃO", "warn"
    elif score >= 40:
        verdict, klass = "EM RISCO", "bad"
    else:
        verdict, klass = "CRÍTICO", "crit"
    return score, verdict, klass

# =============================================================================
# COST estimator — Usage GB × Retail Prices + benefício grátis + what-if tier
# =============================================================================
def estimate_cost(inv, cost_cfg, retail=None):
    tables = sorted(inv["TablesWithData"], key=lambda t: num(t.get("BillableLast30d")), reverse=True)
    analytics_gb30 = sum(num(t.get("BillableLast30d")) for t in tables)
    daily = analytics_gb30 / 30.0
    free = num(cost_cfg.get("free_benefit_gb_day", 5))
    price = num((retail or {}).get("analytics_usd_per_gb") or cost_cfg.get("analytics_usd_per_gb", 2.30))
    billable_daily = max(0.0, daily - free)
    monthly = billable_daily * 30 * price
    # what-if commitment tier
    tiers = cost_cfg.get("commitment_tiers_gb_day", [])
    disc = num(cost_cfg.get("commitment_discount_pct", 15)) / 100.0
    whatif = None
    for tier in tiers:
        if daily >= num(tier) * 0.85:
            whatif = {"tier": tier, "monthly": num(tier) * 30 * price * (1 - disc)}
    return {
        "tables": tables[:15],
        "analytics_gb30": analytics_gb30,
        "daily_gb": daily,
        "price_per_gb": price,
        "free_gb_day": free,
        "est_monthly_usd": monthly,
        "whatif": whatif,
        "priced": retail is not None,
    }

# =============================================================================
# RENDER — HTML (dark) + Markdown
# =============================================================================
SEV_BADGE = {"Critical": "#ff4d6d", "Warning": "#ffb454", "Info": "#7aa2f7"}

def render_html(ctx) -> str:
    inv = ctx["inv"]; findings = ctx["findings"]; passed = ctx["passed"]; skipped = ctx["skipped"]
    score = ctx["score"]; verdict = ctx["verdict"]; klass = ctx["klass"]; cost = ctx["cost"]
    ws_name = prop(inv["Workspace"], "name", ctx.get("ws", "workspace"))
    now = dt.datetime.now().strftime("%d/%m/%Y %H:%M")
    vcol = {"good": "#36d399", "warn": "#ffb454", "bad": "#ff8c66", "crit": "#ff4d6d"}[klass]

    crit = sum(1 for f in findings if f["severity"] == "Critical")
    warn = sum(1 for f in findings if f["severity"] == "Warning")
    info = sum(1 for f in findings if f["severity"] == "Info")

    rows = ""
    for f in findings:
        c = SEV_BADGE[f["severity"]]
        rows += f"""<tr>
          <td><code>{esc(f['id'])}</code></td>
          <td><span class="badge" style="background:{c}22;color:{c};border:1px solid {c}55">{esc(f['severity'])}</span></td>
          <td>{esc(f['category'])}</td>
          <td><b>{esc(f['title'])}</b><div class="ev">{esc(f['evidence'])}</div></td>
          <td class="rem">{esc(f.get('remediation',''))}<br><a href="{esc(f.get('learn',''))}">learn ↗</a></td>
        </tr>"""

    cost_rows = ""
    for t in cost["tables"]:
        cost_rows += f"<tr><td>{esc(t.get('DataType'))}</td><td class='r'>{num(t.get('BillableLast30d')):.1f}</td><td class='r'>{num(t.get('BillableLast7d')):.1f}</td></tr>"
    whatif = ""
    if cost["whatif"]:
        whatif = f"<div class='wi'>What-if commitment tier <b>{cost['whatif']['tier']} GB/dia</b>: ~US$ {cost['whatif']['monthly']:,.0f}/mês (−{int(num(ctx['cost_cfg'].get('commitment_discount_pct',15)))}%)</div>"
    priced_note = "" if cost["priced"] else "<div class='disc'>⚠ preço ilustrativo (Retail Prices API não consultada neste run). NÃO inclui query-time/search/restore/egress/XDR.</div>"

    skip_li = "".join(f"<li><code>{esc(s['id'])}</code> {esc(s['title'])} — <i>{esc(s['reason'])}</i></li>" for s in skipped)

    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Documenter — {esc(ws_name)}</title>
<style>
:root{{color-scheme:dark}}
*{{box-sizing:border-box}}
body{{margin:0;background:#0b0e14;color:#c9d1d9;font:14px/1.5 'Segoe UI',system-ui,sans-serif}}
.wrap{{max-width:1080px;margin:0 auto;padding:28px}}
h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:16px;margin:28px 0 10px;color:#e6edf3;border-bottom:1px solid #1f2733;padding-bottom:6px}}
.sub{{color:#7d8590;font-size:13px}}
.hero{{display:flex;gap:18px;align-items:center;margin:18px 0;padding:18px;background:#11151d;border:1px solid #1f2733;border-radius:14px}}
.score{{font-size:46px;font-weight:800;color:{vcol};line-height:1}}
.verdict{{font-size:18px;font-weight:700;color:{vcol}}}
.kpis{{display:flex;gap:10px;flex-wrap:wrap;margin-left:auto}}
.kpi{{background:#0b0e14;border:1px solid #1f2733;border-radius:10px;padding:8px 14px;text-align:center;min-width:78px}}
.kpi b{{display:block;font-size:20px}}
table{{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #1a212b;vertical-align:top}}
th{{color:#7d8590;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}}
.r{{text-align:right;font-variant-numeric:tabular-nums}}
.badge{{padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700;white-space:nowrap}}
code{{background:#161b22;padding:1px 6px;border-radius:5px;color:#9bd1ff;font-size:12px}}
.ev{{color:#7d8590;font-size:12px;margin-top:3px}}
.rem{{color:#adbac7;font-size:12.5px;max-width:340px}}
.rem a{{color:#58a6ff;text-decoration:none}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
.card{{background:#11151d;border:1px solid #1f2733;border-radius:12px;padding:16px}}
.big{{font-size:30px;font-weight:800;color:#e6edf3}}
.wi{{margin-top:10px;padding:8px 12px;background:#0d1b13;border:1px solid #1d3326;border-radius:8px;color:#7ee0a8;font-size:12.5px}}
.disc{{margin-top:10px;color:#ffb454;font-size:11.5px}}
details{{margin-top:10px}} summary{{cursor:pointer;color:#7d8590}}
.foot{{margin-top:34px;padding-top:14px;border-top:1px solid #1f2733;color:#586069;font-size:11.5px;text-align:center}}
ul{{margin:6px 0;padding-left:18px}} li{{margin:3px 0;font-size:12.5px;color:#8b949e}}
</style></head><body><div class="wrap">
<h1>🛡️ Sentinel Documenter</h1>
<div class="sub">{esc(ws_name)} · gerado {now} · catálogo SENT-NNN (Sentinel-As-Code Wave 4) · <b>read-only</b></div>

<div class="hero">
  <div><div class="score">{score}</div><div class="sub">Documenter Score</div></div>
  <div><div class="verdict">{esc(verdict)}</div><div class="sub">{len(findings)} achados · {len(passed)} ok · {len(skipped)} n/a</div></div>
  <div class="kpis">
    <div class="kpi" style="border-color:#ff4d6d55"><b style="color:#ff4d6d">{crit}</b>Critical</div>
    <div class="kpi" style="border-color:#ffb45455"><b style="color:#ffb454">{warn}</b>Warning</div>
    <div class="kpi" style="border-color:#7aa2f755"><b style="color:#7aa2f7">{info}</b>Info</div>
  </div>
</div>

<h2>🔎 Gap analysis</h2>
<table><thead><tr><th>ID</th><th>Sev</th><th>Categoria</th><th>Achado</th><th>Remediação</th></tr></thead>
<tbody>{rows or '<tr><td colspan=5>Nenhum gap detectado nos checks avaliados. 🎉</td></tr>'}</tbody></table>

<h2>💰 Estimativa de custo</h2>
<div class="grid2">
  <div class="card">
    <div class="sub">Ingest billable (Analytics, 30d)</div>
    <div class="big">{cost['analytics_gb30']:,.0f} GB</div>
    <div class="sub">≈ {cost['daily_gb']:.1f} GB/dia · benefício grátis {cost['free_gb_day']:.0f} GB/dia</div>
    <div class="big" style="margin-top:10px;color:{vcol}">~US$ {cost['est_monthly_usd']:,.0f}<span class="sub"> /mês</span></div>
    <div class="sub">@ US$ {cost['price_per_gb']:.2f}/GB</div>
    {whatif}{priced_note}
  </div>
  <div class="card">
    <div class="sub">Top tabelas por volume (GB)</div>
    <table><thead><tr><th>Tabela</th><th class="r">30d</th><th class="r">7d</th></tr></thead><tbody>{cost_rows}</tbody></table>
  </div>
</div>

<details><summary>Checks não avaliados ({len(skipped)}) — exigem dado fora do inventário deste run</summary>
<ul>{skip_li}</ul></details>

<div class="foot">
  Parte do <b>SOC Autônomo</b> · skill <code>sentinel-documenter</code> · porta fiel do best-practices.json v2.0.0<br>
  Read-only · não modifica o workspace · veja também <code>SOC-Autonomo-Doc-Geral.html</code> e <code>SOC-Autonomo-Showcase.html</code>
</div>
</div></body></html>"""

def render_md(ctx) -> str:
    inv = ctx["inv"]; findings = ctx["findings"]; skipped = ctx["skipped"]; cost = ctx["cost"]
    ws_name = prop(inv["Workspace"], "name", ctx.get("ws", "workspace"))
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    out = [f"# Sentinel Documenter — `{ws_name}`",
           f"_Gerado {now} · Documenter Score **{ctx['score']}/100** ({ctx['verdict']}) · read-only_\n",
           f"**{len(findings)} achados** · {len(ctx['passed'])} ok · {len(skipped)} não avaliados\n",
           "## Gap analysis\n",
           "| ID | Sev | Categoria | Achado | Evidência |",
           "|----|-----|-----------|--------|-----------|"]
    for f in findings:
        out.append(f"| `{f['id']}` | {f['severity']} | {f['category']} | {f['title']} | {f['evidence']} |")
    out.append("\n### Remediação\n")
    for f in findings:
        out.append(f"- **{f['id']} · {f['title']}** — {f.get('remediation','')} ([learn]({f.get('learn','')}))")
    out.append("\n## Custo (estimado)\n")
    out.append(f"- Ingest billable Analytics (30d): **{cost['analytics_gb30']:,.0f} GB** (~{cost['daily_gb']:.1f} GB/dia)")
    out.append(f"- Estimativa: **~US$ {cost['est_monthly_usd']:,.0f}/mês** @ US$ {cost['price_per_gb']:.2f}/GB (benefício {cost['free_gb_day']:.0f} GB/dia)")
    if cost["whatif"]:
        out.append(f"- What-if commitment tier {cost['whatif']['tier']} GB/dia: ~US$ {cost['whatif']['monthly']:,.0f}/mês")
    if not cost["priced"]:
        out.append("- ⚠ preço ilustrativo (Retail Prices API não consultada). Não inclui query-time/search/restore/egress/XDR.")
    out.append("\n<details><summary>Checks não avaliados</summary>\n")
    for s in skipped:
        out.append(f"- `{s['id']}` {s['title']} — _{s['reason']}_")
    out.append("\n</details>\n")
    out.append("\n---\n_Parte do SOC Autônomo · skill `sentinel-documenter` · porta fiel do Sentinel-As-Code Wave 4 best-practices.json v2.0.0_")
    return "\n".join(out)

# =============================================================================
# COLLECTOR (auto) — best effort; caminho primário é --from-json
# =============================================================================
def run_kql(ws_guid, kql):
    try:
        out = subprocess.run([AZ, "monitor", "log-analytics", "query", "--workspace", ws_guid,
                              "--analytics-query", _flatten_kql(kql), "-o", "json"],
                             capture_output=True, text=True, timeout=180)
        if out.returncode == 0 and out.stdout.strip():
            return json.loads(out.stdout)
    except Exception as e:
        print(f"  [kql] {e}", file=sys.stderr)
    return []

def run_rest(url):
    try:
        out = subprocess.run([AZ, "rest", "--method", "get", "--url", url, "-o", "json"],
                             capture_output=True, text=True, timeout=120)
        if out.returncode == 0 and out.stdout.strip():
            return json.loads(out.stdout)
    except Exception as e:
        print(f"  [rest] {e}", file=sys.stderr)
    return None

def collect(q, args):
    p = q["parameters"]; c = q["collector"]; base = c["rest"]["base"]
    api = c["rest"]
    def fmt(s):
        return (s.replace("{sub}", args.sub).replace("{rg}", args.rg).replace("{ws}", args.ws)
                 .replace("{api_oi}", api["api_oi"]).replace("{api_securityinsights}", api["api_securityinsights"])
                 .replace("{api_insights}", api["api_insights"]))
    data = {}
    print("• coletando REST endpoints…", file=sys.stderr)
    eps = api["endpoints"]
    data["workspace"]        = run_rest(fmt(base + eps["workspace"]))
    data["tables"]           = run_rest(fmt(base + eps["tables"]))
    data["alert_rules"]      = run_rest(fmt(base + eps["alert_rules"]))
    data["alert_templates"]  = run_rest(fmt(base + eps["alert_templates"]))
    data["data_connectors"]  = run_rest(fmt(base + eps["data_connectors"]))
    data["automation_rules"] = run_rest(fmt(base + eps["automation_rules"]))
    data["ueba"]             = run_rest(fmt(base + eps["ueba_settings"]))
    data["content_packages"] = run_rest(fmt(base + eps["content_packages"]))
    data["dcrs"]             = run_rest(fmt(base + eps["dcrs"]))
    print("• coletando KQL…", file=sys.stderr)
    for key in ("tables_with_data", "ama_mma_migration", "incidents_mttr", "rule_volumes"):
        data[key] = run_kql(args.workspace, c["kql"][key])
    print("• coletando RBAC…", file=sys.stderr)
    rid = f"/subscriptions/{args.sub}/resourceGroups/{args.rg}/providers/Microsoft.OperationalInsights/workspaces/{args.ws}"
    try:
        out = subprocess.run([AZ, "role", "assignment", "list", "--scope", rid, "-o", "json"],
                             capture_output=True, text=True, timeout=120)
        raw = json.loads(out.stdout) if out.returncode == 0 and out.stdout.strip() else []
        data["rbac"] = [{"RoleDefinitionName": a.get("roleDefinitionName"),
                         "ObjectType": a.get("principalType"),
                         "DisplayName": a.get("principalName")} for a in raw]
    except Exception:
        data["rbac"] = []
    return data

def load_yaml(path):
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML necessário: pip install pyyaml")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)

# =============================================================================
def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Sentinel Documenter — gap-scored living docs (read-only)")
    ap.add_argument("--from-json", help="inventário pré-coletado (modo offline/primário)")
    ap.add_argument("--workspace", help="GUID do workspace (auto-coleta KQL)")
    ap.add_argument("--sub"); ap.add_argument("--rg"); ap.add_argument("--ws")
    ap.add_argument("--queries", default=os.path.join(here, "queries.yaml"))
    ap.add_argument("--format", choices=["html", "md", "both"], default="both")
    ap.add_argument("--output", default=os.path.join(here, "tmp", "documenter"))
    ap.add_argument("--save-raw", action="store_true", help="grava inventário coletado em _raw.json")
    args = ap.parse_args()

    q = load_yaml(args.queries)
    catalog = q["best_practices"]; cost_cfg = q["cost"]

    if args.from_json:
        with open(args.from_json, encoding="utf-8") as f:
            data = json.load(f)
    elif args.workspace and args.sub and args.rg and args.ws:
        data = collect(q, args)
        if args.save_raw:
            os.makedirs(args.output, exist_ok=True)
            with open(os.path.join(args.output, "_raw.json"), "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
    else:
        ap.error("informe --from-json OU (--workspace --sub --rg --ws)")

    inv = build_inventory(data)
    findings, passed, skipped = run_gaps(inv, catalog)
    score, verdict, klass = documenter_score(findings)
    cost = estimate_cost(inv, cost_cfg, retail=data.get("retail"))

    ctx = {"inv": inv, "findings": findings, "passed": passed, "skipped": skipped,
           "score": score, "verdict": verdict, "klass": klass, "cost": cost,
           "cost_cfg": cost_cfg, "ws": args.ws or args.workspace or "workspace"}

    os.makedirs(args.output, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    written = []
    if args.format in ("html", "both"):
        p = os.path.join(args.output, f"documenter-{stamp}.html")
        with open(p, "w", encoding="utf-8") as f:
            f.write(render_html(ctx))
        written.append(p)
    if args.format in ("md", "both"):
        p = os.path.join(args.output, f"documenter-{stamp}.md")
        with open(p, "w", encoding="utf-8") as f:
            f.write(render_md(ctx))
        written.append(p)

    print(f"\n✅ Documenter Score {score}/100 ({verdict}) · {len(findings)} achados "
          f"({sum(1 for f in findings if f['severity']=='Critical')}C/"
          f"{sum(1 for f in findings if f['severity']=='Warning')}W/"
          f"{sum(1 for f in findings if f['severity']=='Info')}I) · {len(skipped)} n/a")
    for w in written:
        print("   →", w)

if __name__ == "__main__":
    main()

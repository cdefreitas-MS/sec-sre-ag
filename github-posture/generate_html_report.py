#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
github-posture / generate_html_report.py  (collector ↔ renderer)

Postura de segurança de uma organização GitHub nos 8 DOMÍNIOS do Programa de Trabalho:
governança/acesso, branch protection, secrets, GitHub Actions (CI/CD), code security
(Dependabot/CodeQL), audit log e supply chain. Catálogo GH-NNN portado FIEL do
github-security-audit.ps1/.sh. 100% READ-ONLY — toda chamada é GET (`gh api` ou REST com GITHUB_TOKEN).

MODULAR (3 usos):
  1) standalone        → relatório próprio HTML (email) + Markdown (repo)
  2) render_section()  → fragmento HTML p/ EMBUTIR no advisor-impact (uma entrega só)
  3) build_attack_path_feed() → emite github_secrets/github_oidc p/ o attack-path
                                 (correlação cross-domain: secret vazado → credencial Azure)

Dois modos de dado:
  --from-json inventory.json   → render determinístico/offline (caminho primário, testável)
  --org <login>                → auto-coleta: REST se GITHUB_TOKEN/GH_TOKEN no ambiente (caminho do
                                 SRE Agent), senão gh api (gh auth). Precisa scopes read:org/
                                 admin:org/security_events p/ os domínios de governança.
"""
from __future__ import annotations
import argparse, datetime as dt, html, json, os, shutil, subprocess, sys
import urllib.request, urllib.error

# gh CLI no Windows resolve gh.exe via which; no Linux acha o binário.
GH = shutil.which("gh") or "gh"
# Coleta tem 2 caminhos: (a) GITHUB_TOKEN/GH_TOKEN no ambiente -> REST direto (api.github.com),
# o caminho do SRE Agent (sem depender do gh CLI); (b) gh CLI autenticado -> gh api (dev local).
GH_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
GH_API = (os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")

# =============================================================================
# helpers de leitura tolerante
# =============================================================================
def prop(obj, path, default=None):
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
    if isinstance(x, dict):
        for k in ("value", "runners", "runner_groups", "environments"):
            if isinstance(x.get(k), list):
                return x[k]
        return [x]
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

class Skip(Exception):
    """Check exige um dado que não foi coletado neste inventário → 'não avaliado'."""

def F(evidence, detail=""):
    return {"evidence": evidence, "detail": detail}

# =============================================================================
# Inventário normalizado a partir do JSON (--from-json) ou _raw coletado
# =============================================================================
# Alertas de secret-scanning PODEM trazer o VALOR do segredo (campo `secret`) quando o token
# tem privilégio alto. O relatório só precisa do METADADO (tipo/localização/URL) — NUNCA o
# valor. Allowlist defensiva: descarta `secret`/`secret_value`/`token`/etc. antes de persistir
# ou renderizar (evita armazenar segredo em claro — endereça o achado CodeQL).
_SECRET_ALERT_KEEP = {"number", "state", "secret_type", "secret_type_display_name",
                      "html_url", "resolution", "repository", "repo", "appId",
                      "resourceId", "cloud_credential"}

def _sanitize_secret_alerts(alerts):
    """Mantém só metadados do alerta (tipo/localização/URL); remove qualquer valor de segredo."""
    out = []
    for a in as_list(alerts):
        if not isinstance(a, dict):
            continue
        clean = {k: v for k, v in a.items() if k in _SECRET_ALERT_KEEP}
        repo = clean.get("repository")
        if isinstance(repo, dict):
            clean["repository"] = {"name": repo.get("name")}
        out.append(clean)
    return out

def build_inventory(data: dict) -> dict:
    org = data.get("org") or {}
    return {
        "Org": org,
        "OrgLogin": org.get("login") or data.get("org_login") or "org",
        "Saml": data.get("saml_sso"),
        "MembersNo2fa": as_list(data.get("members_no_2fa")),
        "Pats": as_list(data.get("pats")),
        "OutsideCollaborators": as_list(data.get("outside_collaborators")),
        "Owners": as_list(data.get("owners")),
        "ActionsPermissions": data.get("actions_permissions") or {},
        "RunnerGroups": as_list(data.get("runner_groups")),
        "Runners": as_list(data.get("runners")),
        "AuditLogStreams": as_list(data.get("audit_log_streams")),
        "IpAllowList": as_list(data.get("ip_allow_list")),
        "OrgWebhooks": as_list(data.get("org_webhooks")),
        "DependabotCritical": as_list(data.get("dependabot_critical")),
        "SecretAlerts": _sanitize_secret_alerts(data.get("secret_alerts")),
        "PublicRepos": as_list(data.get("public_repos")),
        "Repos": as_list(data.get("repos")),
        # IsOrg: conta de ORGANIZAÇÃO (governança org-level só faz sentido aqui).
        # Authed: o coletor conseguiu LER security_and_analysis de algum repo (auth suficiente);
        # sem isso não dá p/ distinguir 'feature desligada' de 'sem permissão' -> checks Skipam.
        "IsOrg": str(org.get("type", "")).lower() == "organization",
        "Authed": any(isinstance(r.get("security_and_analysis"), dict)
                      for r in as_list(data.get("repos"))),
    }

def _ss(repo, *path):
    """Lê security_and_analysis.<...>.status de um repo (tolerante)."""
    return str(prop(repo, "security_and_analysis." + ".".join(path) + ".status", "") or "").lower()

def _repo_name(r):
    return str(r.get("name") or r.get("full_name") or "?")

def _names(repos, limit=10):
    out = ", ".join(_repo_name(r) for r in repos[:limit])
    return out + (" …" if len(repos) > limit else "")

def _sec_repos(inv):
    """Repos cujo security_and_analysis foi LEGÍVEL (auth suficiente). Sem isso não dá p/
    distinguir 'feature desligada' de 'sem permissão p/ ver' → o check Skipa (honesto)."""
    return [r for r in inv["Repos"] if isinstance(r.get("security_and_analysis"), dict)]

# Tipos de secret-scanning que correspondem a uma CREDENCIAL DE NUVEM (Azure/M365) →
# viram attack-path cross-domain (secret no repo == credencial válida no tenant).
AZURE_SECRET_TYPES = (
    "azure", "adafsfederationmetadata", "microsoft", "aad", "entra",
    "azure_storage_account_access_key", "azure_sql_connection_string",
    "azure_active_directory_application_secret", "azure_ad_client_secret",
    "azure_devops_personal_access_token", "azure_subscription_management_certificate",
)

def _is_cloud_secret(stype):
    s = str(stype or "").lower()
    return any(p in s for p in AZURE_SECRET_TYPES)

# =============================================================================
# GAP CHECKS — port fiel dos 8 domínios. F(...) | None (ok) | raise Skip (n/a)
# =============================================================================
# ── DOMAIN 1: GOVERNANCE & ACCESS CONTROL ───────────────────────────────────
def c_2fa_required(inv, p):
    v = prop(inv["Org"], "two_factor_requirement_enabled", None)
    if v is None:
        raise Skip()
    if not v:
        return F("two_factor_requirement_enabled = false", "Org não exige 2FA — conta sem 2FA é o vetor de entrada mais comum.")
    return None

def c_members_no_2fa(inv, p):
    if inv["Org"].get("two_factor_requirement_enabled"):
        return None  # org já exige → ninguém sem 2FA
    members = inv["MembersNo2fa"]
    if not members:
        raise Skip()
    logins = [m.get("login", "?") for m in members]
    return F(f"{len(members)} membro(s) sem 2FA", ", ".join(logins[:10]))

def c_saml_sso(inv, p):
    saml = inv["Saml"]
    if saml is None:
        raise Skip()
    if not prop(saml, "enabled", False):
        return F("SAML SSO não forçado", "Identidade não centralizada no IdP — sem revogação central de acesso.")
    return None

def c_pat_policy(inv, p):
    pats = inv["Pats"]
    if not pats:
        raise Skip()
    return F(f"{len(pats)} PAT(s) ativos na org", "Revise política de PAT; prefira fine-grained + GitHub Apps/OIDC.")

def c_base_permission(inv, p):
    bp = str(prop(inv["Org"], "default_repository_permission", "") or "").lower()
    if not bp:
        raise Skip()
    safe = [s.lower() for s in p.get("safe_base_permissions", ["read", "none"])]
    if bp in safe:
        return None
    return F(f"base permission = '{bp}'", "Acesso amplo por padrão a todos os membros — use 'read'/'none'.")

def c_outside_collabs(inv, p):
    oc = inv["OutsideCollaborators"]
    if not oc:
        return None
    logins = [m.get("login", "?") for m in oc]
    return F(f"{len(oc)} outside collaborator(es)", ", ".join(logins[:10]))

def c_owner_count(inv, p):
    owners = inv["Owners"]
    if not owners:
        raise Skip()
    mx = int(p.get("max_owners", 5))
    if len(owners) > mx:
        logins = [m.get("login", "?") for m in owners]
        return F(f"{len(owners)} org owners (recomendado ≤{mx})", ", ".join(logins[:10]))
    return None

def c_private_fork(inv, p):
    v = prop(inv["Org"], "members_can_fork_private_repositories", None)
    if v is None:
        raise Skip()
    if v:
        return F("fork de repo privado permitido", "Reduz controle sobre vazamento de código privado.")
    return None

# ── DOMAIN 2: BRANCH PROTECTION ─────────────────────────────────────────────
def _bp(repo):
    """Branch protection do repo, ou None se ausente."""
    bp = repo.get("branch_protection")
    if not bp or (isinstance(bp, str) and "not protected" in bp.lower()):
        return None
    return bp if isinstance(bp, dict) else None

def c_bp_present(inv, p):
    repos = inv["Repos"]
    if not repos or not inv.get("Authed"):
        raise Skip()  # branch protection exige auth; sem token não dá p/ afirmar "sem proteção"
    unprot = [r for r in repos if _bp(r) is None]
    if unprot:
        return F(f"{len(unprot)} repo(s) sem branch protection na branch padrão", _names(unprot))
    return None

def c_bp_strength(inv, p):
    repos = [r for r in inv["Repos"] if _bp(r) is not None]
    if not repos:
        raise Skip()
    minr = int(p.get("min_reviews", 2))
    weak = []
    for r in repos:
        bp = _bp(r)
        issues = []
        if num(prop(bp, "required_pull_request_reviews.required_approving_review_count", 0)) < minr:
            issues.append(f"reviews<{minr}")
        if not prop(bp, "required_pull_request_reviews.dismiss_stale_reviews", False):
            issues.append("stale")
        if not prop(bp, "required_pull_request_reviews.require_code_owner_reviews", False):
            issues.append("no-codeowners")
        if not prop(bp, "enforce_admins.enabled", False):
            issues.append("admins-bypass")
        if not (prop(bp, "required_status_checks.contexts", []) or []):
            issues.append("no-checks")
        if not prop(bp, "required_signatures.enabled", repo_sig(r)):
            issues.append("unsigned")
        if issues:
            weak.append(f"{_repo_name(r)} ({', '.join(issues)})")
    if weak:
        return F(f"{len(weak)} repo(s) com branch protection fraca", "; ".join(weak[:5]) + (" …" if len(weak) > 5 else ""))
    return None

def repo_sig(r):
    return bool(prop(r, "required_signatures.enabled", False) or r.get("required_signatures_enabled", False))

def c_codeowners(inv, p):
    repos = inv["Repos"]
    if not repos:
        raise Skip()
    miss = [r for r in repos if not r.get("has_codeowners")]
    if miss:
        return F(f"{len(miss)} repo(s) sem CODEOWNERS", _names(miss))
    return None

# ── DOMAIN 3: SECRETS & CREDENTIALS ─────────────────────────────────────────
def c_secret_scanning(inv, p):
    repos = _sec_repos(inv)
    if not repos:
        raise Skip()  # security_and_analysis ilegível (sem auth) → não "desabilitado"
    off = [r for r in repos if _ss(r, "secret_scanning") != "enabled"]
    if off:
        return F(f"{len(off)} repo(s) sem secret scanning", _names(off))
    return None

def c_push_protection(inv, p):
    repos = _sec_repos(inv)
    if not repos:
        raise Skip()
    off = [r for r in repos if _ss(r, "secret_scanning_push_protection") != "enabled"]
    if off:
        return F(f"{len(off)} repo(s) sem push protection", _names(off))
    return None

def c_open_secret_alerts(inv, p):
    alerts = inv["SecretAlerts"]
    if not alerts:
        return None
    cloud = [a for a in alerts if _is_cloud_secret(a.get("secret_type") or a.get("secret_type_display_name"))]
    extra = f" · {len(cloud)} é credencial de NUVEM (attack-path para o Azure)" if cloud else ""
    repos = sorted({str(prop(a, "repository.name") or a.get("repo") or "?") for a in alerts})
    return F(f"{len(alerts)} alerta(s) de secret scanning ABERTOS{extra}",
             "Repos: " + ", ".join(repos[:8]) + " — ROTACIONE o segredo na origem, não só remova do código.")

def c_environments(inv, p):
    repos = inv["Repos"]
    if not repos or not inv.get("Authed"):
        raise Skip()
    bad = []
    for r in repos:
        for env in as_list(r.get("environments")):
            if not (env.get("protection_rules") or []):
                bad.append(f"{_repo_name(r)}/{env.get('name','?')}")
    if bad:
        return F(f"{len(bad)} environment(s) sem regra de proteção", ", ".join(bad[:8]))
    return None

def c_deploy_keys(inv, p):
    repos = inv["Repos"]
    if not repos or not inv.get("Authed"):
        raise Skip()
    bad = []
    for r in repos:
        wk = [k for k in as_list(r.get("deploy_keys")) if k.get("read_only") is False]
        if wk:
            bad.append(f"{_repo_name(r)} ({len(wk)})")
    if bad:
        return F(f"{len(bad)} repo(s) com deploy key de ESCRITA", ", ".join(bad[:8]))
    return None

# ── DOMAIN 4: GITHUB ACTIONS (CI/CD) ────────────────────────────────────────
def c_actions_policy(inv, p):
    ap = inv["ActionsPermissions"]
    if not ap:
        raise Skip()
    allowed = str(ap.get("allowed_actions", "")).lower()
    if allowed == "all":
        return F("allowed_actions = all (sem restrição)", "Qualquer Action de terceiros pode rodar — restrinja a selected/verified.")
    return None

def c_github_token_default(inv, p):
    repos = inv["Repos"]
    if not repos or not inv.get("Authed"):
        raise Skip()
    bad = [r for r in repos if str(r.get("github_token_default", "")).lower() == "write"]
    if bad:
        return F(f"{len(bad)} repo(s) com GITHUB_TOKEN padrão 'write'", _names(bad))
    return None

def c_runner_groups_public(inv, p):
    groups = inv["RunnerGroups"]
    if not groups:
        raise Skip()
    pub = [g for g in groups if g.get("allows_public_repositories")]
    if pub:
        return F(f"{len(pub)} runner group(s) expostos a repos públicos", ", ".join(g.get("name", "?") for g in pub))
    return None

def c_self_hosted_runners(inv, p):
    runners = inv["Runners"]
    if not runners:
        return None
    return F(f"{len(runners)} self-hosted runner(s)", "Verifique config efêmera/isolada — runner persistente vira pivô p/ a nuvem (OIDC).")

# ── DOMAIN 5: CODE SECURITY ─────────────────────────────────────────────────
def c_dependabot(inv, p):
    repos = _sec_repos(inv)
    if not repos:
        raise Skip()
    off = [r for r in repos if _ss(r, "dependabot_alerts") != "enabled"]
    if off:
        return F(f"{len(off)} repo(s) sem Dependabot alerts", _names(off))
    return None

def c_critical_dependabot(inv, p):
    crit = inv["DependabotCritical"]
    if not crit:
        return None
    sla = int(p.get("sla_critical_days", 7))
    return F(f"{len(crit)} alerta(s) Dependabot CRÍTICO(s) aberto(s)",
             f"SLA ≤{sla}d — CVE crítica explorável em dependência = porta de entrada.")

def c_code_scanning(inv, p):
    repos = inv["Repos"]
    if not repos or not inv.get("Authed"):
        raise Skip()
    off = [r for r in repos if not r.get("code_scanning")]
    if off:
        return F(f"{len(off)} repo(s) sem code scanning (CodeQL)", _names(off))
    return None

# ── DOMAIN 6: AUDIT LOG & MONITORING ────────────────────────────────────────
def c_audit_streaming(inv, p):
    if not inv.get("IsOrg"):
        raise Skip()  # streaming de audit log é recurso de ORG; conta pessoal não tem
    streams = inv["AuditLogStreams"]
    active = [s for s in streams if s.get("enabled")]
    if not active:
        return F("audit log streaming não configurado/ativo",
                 "SIEM (Sentinel) NÃO recebe a atividade do GitHub — o SOC fica cego a ataques no GitHub.")
    return None

def c_ip_allow_list(inv, p):
    if not inv.get("IsOrg"):
        raise Skip()
    active = [x for x in inv["IpAllowList"] if x.get("is_active")]
    if not active:
        return F("IP allow list não configurada", "Considere restringir o acesso à org por rede conhecida.")
    return None

def c_org_webhooks(inv, p):
    if not inv.get("IsOrg"):
        raise Skip()
    hooks = inv["OrgWebhooks"]
    if not hooks:
        return None
    return F(f"{len(hooks)} webhook(s) de organização", "Revise os endpoints (exfil/SSRF) e a validação de assinatura.")

# ── DOMAIN 7 & 8: SUPPLY CHAIN & REPO SETTINGS ──────────────────────────────
def c_public_repos(inv, p):
    pub = inv["PublicRepos"]
    if not pub:
        return None
    return F(f"{len(pub)} repositório(s) público(s)", ", ".join(_repo_name(r) for r in pub[:10]))

def c_ghas_coverage(inv, p):
    repos = _sec_repos(inv)
    if not repos:
        raise Skip()
    off = [r for r in repos if _ss(r, "advanced_security") != "enabled"]
    if off and len(off) != len(repos):  # se NENHUM tem, provável não-elegível a GHAS → não penaliza falso
        return F(f"{len(off)}/{len(repos)} repo(s) sem GitHub Advanced Security", _names(off))
    return None

# dispatch: nome do `check` (catálogo) → função Python
CHECKS = {
    "Test-Org2faRequired": c_2fa_required,
    "Test-MembersWithout2fa": c_members_no_2fa,
    "Test-SamlSsoEnforced": c_saml_sso,
    "Test-PatPolicy": c_pat_policy,
    "Test-BasePermission": c_base_permission,
    "Test-OutsideCollaborators": c_outside_collabs,
    "Test-OwnerCount": c_owner_count,
    "Test-PrivateForkPolicy": c_private_fork,
    "Test-BranchProtectionPresent": c_bp_present,
    "Test-BranchProtectionStrength": c_bp_strength,
    "Test-Codeowners": c_codeowners,
    "Test-SecretScanning": c_secret_scanning,
    "Test-PushProtection": c_push_protection,
    "Test-OpenSecretAlerts": c_open_secret_alerts,
    "Test-Environments": c_environments,
    "Test-DeployKeys": c_deploy_keys,
    "Test-ActionsPolicy": c_actions_policy,
    "Test-GithubTokenDefault": c_github_token_default,
    "Test-RunnerGroupsPublic": c_runner_groups_public,
    "Test-SelfHostedRunners": c_self_hosted_runners,
    "Test-Dependabot": c_dependabot,
    "Test-CriticalDependabot": c_critical_dependabot,
    "Test-CodeScanning": c_code_scanning,
    "Test-AuditLogStreaming": c_audit_streaming,
    "Test-IpAllowList": c_ip_allow_list,
    "Test-OrgWebhooks": c_org_webhooks,
    "Test-PublicRepos": c_public_repos,
    "Test-GhasCoverage": c_ghas_coverage,
}

SEV_WEIGHT = {"Critical": 15, "Warning": 7, "Info": 2}
SEV_BADGE = {"Critical": "#ff4d6d", "Warning": "#ffb454", "Info": "#7aa2f7"}

# Domínio → rótulo amigável p/ agrupar no relatório
DOMAIN_LABEL = {
    "Governance": "1 · Governança & Acesso",
    "BranchProtection": "2 · Branch Protection",
    "Secrets": "3 · Secrets & Credenciais",
    "Actions": "4 · GitHub Actions (CI/CD)",
    "CodeSecurity": "5 · Code Security",
    "AuditLog": "6 · Audit Log",
    "SupplyChain": "7-8 · Supply Chain",
}

def run_gaps(inv, catalog, params):
    findings, passed, skipped = [], [], []
    for rule in catalog:
        fn = CHECKS.get(rule.get("check"))
        if fn is None:
            skipped.append({**rule, "reason": "sem implementação no renderer"})
            continue
        try:
            res = fn(inv, params)
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
    order = {"Critical": 0, "Warning": 1, "Info": 2}
    findings.sort(key=lambda x: order.get(x["severity"], 3))
    return findings, passed, skipped

def posture_score(findings):
    score = max(0, 100 - sum(SEV_WEIGHT.get(f["severity"], 2) for f in findings))
    if score >= 85:
        return score, "SAUDÁVEL", "good"
    if score >= 65:
        return score, "ATENÇÃO", "warn"
    if score >= 40:
        return score, "EM RISCO", "bad"
    return score, "CRÍTICO", "crit"

# =============================================================================
# CAMADA DE IMPORTÂNCIA — sinal × ruído (alinhada ao attack-path)
#   🔥 crítico     = severidade Critical OU achado de EXPOSIÇÃO ATIVA (active)
#   ⚡ relevante    = correlaciona cross-domain (alimenta um attack-path p/ o Azure)
#   📋 recomendação = best practice conhecida
# =============================================================================
TIER = {
    "critico":     ("🔥", "O que realmente importa", "#ff7d8a"),
    "relevante":   ("⚡", "Correlação cross-domain", "#7fe0a8"),
    "recomendacao":("📋", "Recomendação conhecida", "#7d8aa6"),
}

def classify_importance(findings):
    for f in findings:
        active = bool(f.get("active"))
        cross = bool(f.get("cross_domain"))
        if f["severity"] == "Critical" or active:
            f["_tier"] = "critico"
        elif cross:
            f["_tier"] = "relevante"
        else:
            f["_tier"] = "recomendacao"
        f["_importance"] = ((1000 if active else 0)
                            + (300 if f["severity"] == "Critical" else 0)
                            + (120 if cross else 0)
                            + SEV_WEIGHT.get(f["severity"], 2))
    findings.sort(key=lambda x: -x["_importance"])
    return findings

# =============================================================================
# FEED CROSS-DOMAIN → attack-path
#   github_secrets: alertas de secret scanning que SÃO credencial de nuvem (Azure/M365).
#                   appId preenchido quando o coletor conseguiu resolver a credencial.
#   github_oidc:    repos com Actions fraco (GITHUB_TOKEN write) e/ou federação OIDC p/ um SP Azure.
# =============================================================================
def build_attack_path_feed(inv):
    secrets = []
    for a in inv["SecretAlerts"]:
        stype = a.get("secret_type") or a.get("secret_type_display_name") or ""
        repo = str(prop(a, "repository.name") or a.get("repo") or "")
        entry = {
            "repo": repo,
            "secret_type": stype,
            "cloud_credential": _is_cloud_secret(stype),
            "html_url": a.get("html_url", ""),
        }
        if a.get("appId"):
            entry["appId"] = a["appId"]
        if a.get("resourceId"):
            entry["resourceId"] = a["resourceId"]
        secrets.append(entry)
    oidc = []
    for r in inv["Repos"]:
        fed = r.get("federated_to_appId") or r.get("oidc_appId")
        weak = str(r.get("github_token_default", "")).lower() == "write"
        if fed:
            oidc.append({
                "repo": _repo_name(r),
                "sp_appId": fed,
                "weakness": "github_token_write" if weak else "oidc_federation",
            })
    return {"github_secrets": secrets, "github_oidc": oidc}

# =============================================================================
# RENDER — fragmento embutível (render_section) + página standalone (render_html)
# =============================================================================
def _kpi_counts(findings):
    return {
        "importa": sum(1 for f in findings if f.get("_tier") == "critico"),
        "critical": sum(1 for f in findings if f["severity"] == "Critical"),
        "cross": sum(1 for f in findings if f.get("cross_domain")),
        "recs": sum(1 for f in findings if f.get("_tier") == "recomendacao"),
    }

GHP_STYLE = """
<style>
.ghp{font:14px/1.5 'Segoe UI',system-ui,sans-serif;color:#c9d1d9}
.ghp h2{font-size:18px;margin:26px 0 6px;color:#e6edf3}
.ghp .sub{color:#7d8590;font-size:13px}
.ghp .hero{display:flex;gap:18px;align-items:center;margin:14px 0;padding:16px;background:#11151d;border:1px solid #1f2733;border-radius:14px;flex-wrap:wrap}
.ghp .score{font-size:42px;font-weight:800;line-height:1}
.ghp .verdict{font-size:17px;font-weight:700}
.ghp .kpis{display:flex;gap:10px;flex-wrap:wrap;margin-left:auto}
.ghp .kpi{background:#0b0e14;border:1px solid #1f2733;border-radius:10px;padding:8px 14px;text-align:center;min-width:96px}
.ghp .kpi b{display:block;font-size:20px}
.ghp .kpi span{font-size:11px;color:#8b949e}
.ghp .pcard{background:#11151d;border:1px solid #1f2733;border-radius:12px;padding:12px 14px;margin:10px 0}
.ghp .pcard summary{cursor:pointer;list-style:none;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.ghp .pcard summary::-webkit-details-marker{display:none}
.ghp .b{padding:2px 9px;border-radius:20px;font-size:11px;font-weight:800;white-space:nowrap}
.ghp .dom{color:#9bd1ff;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px}
.ghp .ev{color:#c9d1d9;font-size:12.5px;margin:6px 0 0}
.ghp .rem{color:#adbac7;font-size:12.5px;margin-top:6px}
.ghp .rem a{color:#58a6ff;text-decoration:none}
.ghp code{background:#161b22;padding:1px 6px;border-radius:5px;color:#9bd1ff;font-size:12px}
.ghp .recsec{margin-top:12px}
.ghp .recsec>summary{cursor:pointer;color:#7d8590;font-weight:600}
.ghp .feed{margin-top:12px;padding:12px 14px;background:#0d1320;border:1px solid #243049;border-radius:10px}
.ghp .feed b{color:#9bd1ff}
.ghp .empty{color:#7d8590;font-style:italic;padding:8px 0}
.ghp .skip{margin-top:12px}
.ghp .skip ul{margin:6px 0;padding-left:18px} .ghp .skip li{font-size:12px;color:#8b949e;margin:2px 0}
.ghp .orient{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}
.ghp .ocard{flex:1;min-width:200px;background:#11151d;border:1px solid #1f2733;border-radius:12px;padding:12px 14px}
.ghp .ocard .otop{display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:15px}
.ghp .ocard .obig{font-size:26px;font-weight:800}
.ghp .ocard .osub{color:#8b949e;font-size:11.5px;margin-top:2px}
.ghp .secbadge{padding:1px 8px;border-radius:20px;font-size:10px;font-weight:800;letter-spacing:.3px}
.ghp .nv{background:#7fe0a822;color:#7fe0a8;border:1px solid #7fe0a855}
.ghp .ja{background:#7d8aa622;color:#9aa6c4;border:1px solid #7d8aa655}
.ghp .df{background:#9bd1ff22;color:#9bd1ff;border:1px solid #9bd1ff55}
.ghp .sector{margin:18px 0;padding:16px 0 2px;border-top:1px solid #1f2733}
.ghp .sechead{display:flex;align-items:center;gap:10px;margin-bottom:4px;flex-wrap:wrap}
.ghp .sechead .snum{width:24px;height:24px;border-radius:7px;background:#161b22;display:inline-flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;color:#9bd1ff;flex:none}
.ghp .sechead h3{margin:0;font-size:16px;color:#e6edf3}
.ghp .secmuted{color:#7d8590;font-style:italic;padding:10px 12px;background:#11151d;border:1px solid #1f2733;border-radius:10px}
.ghp .feed ul li{font-size:12.5px;color:#c9d1d9;margin:3px 0}
.ghp .feed a{color:#58a6ff;text-decoration:none}
.ghp h4{margin:6px 0 4px;font-size:14px;color:#e6edf3}
.ghp .covnote{margin:12px 0;padding:10px 14px;background:#1d1606;border:1px solid #3a2e10;border-radius:10px;color:#ffd98a;font-size:12.5px}
</style>"""

def _finding_card(f):
    emoji, _, col = TIER[f["_tier"]]
    sev = f["severity"]; sc = SEV_BADGE[sev]
    dom = DOMAIN_LABEL.get(f["category"], f["category"])
    return f"""<details class="pcard">
  <summary>
    <span class="b" style="background:{col}22;color:{col};border:1px solid {col}66">{emoji} {esc(TIER[f['_tier']][1])}</span>
    <span class="b" style="background:{sc}22;color:{sc};border:1px solid {sc}55">{esc(sev)}</span>
    <span class="dom">{esc(dom)}</span>
    <b style="color:#e6edf3">{esc(f['title'])}</b>
  </summary>
  <div class="ev">🔎 <b>{esc(f['evidence'])}</b>{(' — ' + esc(f['detail'])) if f.get('detail') else ''}</div>
  <div class="rem">🔧 {esc(f.get('remediation',''))} <a href="{esc(f.get('learn',''))}">docs ↗</a> · <code>{esc(f['id'])}</code></div>
</details>"""

def _hero_html(ctx):
    score = ctx["score"]; verdict = ctx["verdict"]; klass = ctx["klass"]
    findings = ctx["findings"]; skipped = ctx["skipped"]
    vcol = {"good": "#36d399", "warn": "#ffb454", "bad": "#ff8c66", "crit": "#ff4d6d"}[klass]
    k = _kpi_counts(findings)
    return f"""<div class="hero">
  <div><div class="score" style="color:{vcol}">{score}</div><div class="sub">GitHub Posture Score</div></div>
  <div><div class="verdict" style="color:{vcol}">{esc(verdict)}</div><div class="sub">{len(findings)} achados · {len(ctx['passed'])} ok · {len(skipped)} n/a</div></div>
  <div class="kpis">
    <div class="kpi" style="border-color:#ff7d8a55"><b style="color:#ff7d8a">{k['importa']}</b><span>🔥 o que importa</span></div>
    <div class="kpi" style="border-color:#ff4d6d55"><b style="color:#ff4d6d">{k['critical']}</b><span>🔴 Critical</span></div>
    <div class="kpi" style="border-color:#7fe0a855"><b style="color:#7fe0a8">{k['cross']}</b><span>⚡ cross-domain</span></div>
    <div class="kpi" style="border-color:#7d8aa655"><b style="color:#9aa6c4">{k['recs']}</b><span>📋 recomendação</span></div>
  </div>
</div>"""

def _feed_detail_html(ctx):
    feed = ctx["feed"]; secs = feed["github_secrets"]; oidc = feed["github_oidc"]
    n_cloud = sum(1 for s in secs if s.get("cloud_credential"))
    if not (secs or oidc):
        return ('<div class="secmuted">Nenhuma correlação cross-domain detectada neste run — nenhum secret vazado '
                'mapeia para credencial de nuvem e nenhum repositório federa OIDC para o Azure. 🎉</div>')
    items = ""
    for s in secs:
        tag = "🔑 credencial de nuvem" if s.get("cloud_credential") else "secret"
        appid = f" → SP <code>{esc(s['appId'])}</code>" if s.get("appId") else ""
        url = f' <a href="{esc(s["html_url"])}">abrir alerta ↗</a>' if s.get("html_url") else ""
        items += f'<li>{tag} em <code>{esc(s.get("repo","?"))}</code> ({esc(s.get("secret_type",""))}){appid}{url}</li>'
    for o in oidc:
        items += (f'<li>⚙️ Actions/OIDC em <code>{esc(o.get("repo","?"))}</code> → SP <code>{esc(o.get("sp_appId",""))}</code>'
                  f' ({esc(o.get("weakness",""))})</li>')
    return (f'<div class="feed">🔗 <b>{len(secs)} secret(s) ({n_cloud} = credencial de nuvem) · {len(oidc)} repo(s) Actions/OIDC</b> '
            f'que o <code>attack-path</code> encadeia como <code>repo → credencial/SP → papel privilegiado</code>. '
            f'<b style="color:#9bd1ff">É o caminho real do GitHub até o tenant que nenhum produto isolado mostra.</b>'
            f'<ul style="margin:8px 0 0;padding-left:18px">{items}</ul></div>')

def _findings_html(ctx):
    findings = ctx["findings"]; skipped = ctx["skipped"]
    important = [f for f in findings if f["_tier"] != "recomendacao"]
    recs = [f for f in findings if f["_tier"] == "recomendacao"]
    imp_html = "".join(_finding_card(f) for f in important) or '<div class="empty">Nenhum achado crítico/cross-domain. 🎉</div>'
    rec_html = "".join(_finding_card(f) for f in recs)
    rec_block = (f'<details class="recsec"><summary>📋 Recomendações conhecidas ({len(recs)})</summary>{rec_html}</details>'
                 if recs else "")
    skip_li = "".join(f"<li><code>{esc(s['id'])}</code> {esc(s['title'])} — <i>{esc(s['reason'])}</i></li>" for s in skipped)
    skip_block = (f'<details class="skip"><summary class="sub">Checks não avaliados ({len(skipped)}) — exigem dado fora deste run</summary><ul>{skip_li}</ul></details>'
                  if skipped else "")
    return f'<h4>🔥 O que realmente importa</h4>{imp_html}{rec_block}{skip_block}'

def _orient_html(ctx, devops_meta):
    feed = ctx["feed"]; score = ctx["score"]; verdict = ctx["verdict"]; klass = ctx["klass"]
    vcol = {"good": "#36d399", "warn": "#ffb454", "bad": "#ff8c66", "crit": "#ff4d6d"}[klass]
    n_cloud = sum(1 for s in feed["github_secrets"] if s.get("cloud_credential"))
    n_diff = n_cloud + len(feed["github_oidc"])
    dv_total = (devops_meta or {}).get("total")
    dv_crit = (devops_meta or {}).get("critical", 0)
    dv_big = str(dv_total) if dv_total is not None else "—"
    dv_sub = (f"{dv_crit} críticos · via Defender for Cloud" if dv_total is not None
              else "rode dentro do advisor-impact para ver")
    return f"""<div class="orient">
  <div class="ocard"><div class="otop"><span>🔗</span><span class="secbadge df">DIFERENCIAL</span></div>
    <div class="obig" style="color:#9bd1ff">{n_diff}</div><div class="osub">correlações GitHub→Azure (secret/OIDC) que viram attack-path</div></div>
  <div class="ocard"><div class="otop"><span>🛡️</span><span class="secbadge nv">NOVO</span></div>
    <div class="obig" style="color:{vcol}">{score}<span style="font-size:13px;color:#7d8590">/100</span></div><div class="osub">Postura &amp; Governança · 8 domínios · {esc(verdict)}</div></div>
  <div class="ocard"><div class="otop"><span>🐙</span><span class="secbadge ja">JÁ NO RELATÓRIO</span></div>
    <div class="obig" style="color:#e6edf3">{dv_big}</div><div class="osub">Remediação de código (findings) · {dv_sub}</div></div>
</div>"""

def _coverage_note(inv):
    """Aviso quando a coleta não teve auth/escopo de org — explica por que domínios Skiparam."""
    if inv.get("IsOrg") and inv.get("Authed"):
        return ""
    bits = []
    if not inv.get("IsOrg"):
        bits.append("conta pessoal (não-org) — domínios de governança org-level não se aplicam")
    if not inv.get("Authed"):
        bits.append("coleta sem token de segurança — secret scanning, branch protection, Actions e o feed "
                    "cross-domain exigem auth (<code>read:org</code>/<code>security_events</code>) e ficaram como "
                    "<b>não avaliado</b> (não significam “desabilitado”)")
    return ('<div class="covnote">⚠️ <b>Cobertura limitada:</b> ' + "; ".join(bits) +
            '. Os achados refletem só o que é observável com o acesso atual.</div>')

def render_section(ctx, devops_html=None, devops_meta=None):
    """Seção HTML UNIFICADA e SETORIZADA para a aba 🐙 GitHub do advisor-impact (ou corpo
    da página standalone). 3 setores que se complementam:
      1 · 🔗 Diferencial — correlação cross-domain (o que nenhum produto integra)
      2 · 🛡️ Postura & Governança — 8 domínios via gh api (NOVO)
      3 · 🐙 Remediação de código — findings Dependabot/CodeQL/secret (Defender DevOps, já tínhamos)
    `devops_html` = o dashboard DevOps que o advisor-impact já produz (embutido no setor 3)."""
    inv = ctx["inv"]; org = inv["OrgLogin"]
    sector3 = (devops_html if devops_html else
               '<div class="covnote">🐙 <b>Remediação de código (DevOps do Defender for Cloud) — sem dados neste relatório.</b> '
               'Os findings de dependências (Dependabot), CodeQL/SAST, IaC e <i>secrets</i> dos seus repositórios aparecem aqui quando o '
               '<b>conector DevOps do Microsoft Defender for Cloud</b> está configurado <i>e</i> o dataset <code>devops_findings</code> '
               '(Azure Resource Graph) é coletado no run. '
               '➡️ <b>Ainda não configurado no tenant?</b> Conecte GitHub / Azure DevOps / GitLab ao Defender for Cloud para passar a receber essas recomendações: '
               '<a href="https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/DevOpsSecurity" style="color:#ffd98a;text-decoration:underline">Portal · DevOps security ↗</a> · '
               '<a href="https://learn.microsoft.com/azure/defender-for-cloud/quickstart-onboard-github" style="color:#ffd98a;text-decoration:underline">guia de onboarding do GitHub ↗</a>.</div>')
    return f"""{GHP_STYLE}
<div class="ghp">
<h2>🐙 GitHub — segurança unificada</h2>
<div class="sub">Org <b>{esc(org)}</b> · 3 camadas que se complementam — a 3ª (o diferencial) nenhum produto entrega isolado · <b>read-only</b></div>
{_coverage_note(inv)}
{_orient_html(ctx, devops_meta)}

<div class="sector">
  <div class="sechead"><span class="snum">1</span><h3>🔗 Visão unificada · correlação cross-domain</h3><span class="secbadge df">o diferencial</span></div>
  <div class="sub" style="margin:-2px 0 8px">O que liga o GitHub ao Azure: um secret vazado que é credencial válida, ou um pipeline que assume um SP via OIDC. Vira um caminho de ataque real do repositório até o tenant.</div>
  {_feed_detail_html(ctx)}
</div>

<div class="sector">
  <div class="sechead"><span class="snum">2</span><h3>🛡️ Postura &amp; Governança · 8 domínios</h3><span class="secbadge nv">NOVO</span></div>
  <div class="sub" style="margin:-2px 0 8px">2FA, branch protection, secrets, Actions, code security, audit log e supply chain — a governança que o Defender não enxerga (via <code>gh api</code>).</div>
  {_hero_html(ctx)}
  {_findings_html(ctx)}
</div>

<div class="sector">
  <div class="sechead"><span class="snum">3</span><h3>🐙 Remediação de código · findings</h3><span class="secbadge ja">já no relatório</span></div>
  <div class="sub" style="margin:-2px 0 8px">Dependabot (CVEs de dependência), CodeQL (SAST) e secret scanning que o Defender for Cloud (conector DevOps) já trouxe ao Azure.</div>
  {sector3}
</div>
</div>"""

def render_html(ctx) -> str:
    inv = ctx["inv"]; score = ctx["score"]; verdict = ctx["verdict"]
    org = inv["OrgLogin"]; now = dt.datetime.now().strftime("%d/%m/%Y %H:%M")
    body = render_section(ctx)
    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GitHub Posture — {esc(org)}</title>
<style>:root{{color-scheme:dark}}*{{box-sizing:border-box}}
body{{margin:0;background:#0b0e14}} .wrap{{max-width:1040px;margin:0 auto;padding:28px}}
h1{{font-size:22px;margin:0 0 4px;color:#e6edf3;font-family:'Segoe UI',system-ui,sans-serif}}
.topfoot{{margin-top:30px;padding-top:14px;border-top:1px solid #1f2733;color:#586069;font-size:11.5px;text-align:center;font-family:'Segoe UI',system-ui,sans-serif}}</style>
</head><body><div class="wrap">
<h1>🐙 GitHub Posture</h1>
<div style="color:#7d8590;font-size:13px;font-family:'Segoe UI',system-ui,sans-serif">Org {esc(org)} · gerado {now} · GitHub Posture Score <b style="color:#9bd1ff">{score}/100</b> ({esc(verdict)})</div>
{body}
<div class="topfoot">Parte do <b>SOC Autônomo</b> · skill <code>github-posture</code> · catálogo GH-NNN (8 domínios)<br>
Read-only · não modifica a organização · alimenta o <code>attack-path</code> (correlação cross-domain)</div>
</div></body></html>"""

def render_md(ctx) -> str:
    inv = ctx["inv"]; findings = ctx["findings"]; skipped = ctx["skipped"]
    score = ctx["score"]; verdict = ctx["verdict"]; feed = ctx["feed"]
    org = inv["OrgLogin"]
    out = [f"# 🐙 GitHub Posture — {org}", "",
           f"**GitHub Posture Score: {score}/100 ({verdict})** · {len(findings)} achados · {len(skipped)} não avaliados", ""]
    k = _kpi_counts(findings)
    out.append(f"🔥 {k['importa']} o que importa · 🔴 {k['critical']} Critical · ⚡ {k['cross']} cross-domain · 📋 {k['recs']} recomendação")
    out.append("")
    n_sec = len(feed["github_secrets"]); n_cloud = sum(1 for s in feed["github_secrets"] if s.get("cloud_credential")); n_oidc = len(feed["github_oidc"])
    if n_sec or n_oidc:
        out.append(f"> 🔗 **Feed → attack-path:** {n_sec} secret-alert(s) ({n_cloud} credencial de nuvem) · {n_oidc} repo(s) Actions/OIDC para o Azure.")
        out.append("")
    out.append("| Importância | Sev | Domínio | ID | Achado | Evidência |")
    out.append("|---|---|---|---|---|---|")
    for f in findings:
        emoji = TIER[f["_tier"]][0]
        dom = DOMAIN_LABEL.get(f["category"], f["category"])
        out.append(f"| {emoji} | {f['severity']} | {dom} | `{f['id']}` | {f['title']} | {f['evidence']} |")
    if skipped:
        out.append("")
        out.append(f"### Não avaliados ({len(skipped)})")
        for s in skipped:
            out.append(f"- `{s['id']}` {s['title']} — _{s['reason']}_")
    return "\n".join(out) + "\n"

# =============================================================================
# build_report — ponto de entrada reutilizável (advisor-impact importa isto)
# =============================================================================
def build_report(data, params):
    """Roda o motor inteiro sobre `data` já coletado. Retorna ctx (com html_section pronto)."""
    catalog = params.get("_catalog") or []
    inv = build_inventory(data)
    findings, passed, skipped = run_gaps(inv, catalog, params)
    classify_importance(findings)
    score, verdict, klass = posture_score(findings)
    feed = build_attack_path_feed(inv)
    ctx = {"inv": inv, "findings": findings, "passed": passed, "skipped": skipped,
           "score": score, "verdict": verdict, "klass": klass, "feed": feed}
    ctx["html_section"] = render_section(ctx)
    return ctx

# =============================================================================
# COLLECTOR — gh api (read-only). Caminho primário é --from-json.
# =============================================================================
def _http_get(endpoint):
    """GET via REST com token no header. `endpoint` = caminho relativo (ex.: 'orgs/foo/members')
    ou URL absoluta. 403/404/sem-scope -> None (o check vira Skip, degrada gracioso)."""
    url = endpoint if str(endpoint).startswith("http") else f"{GH_API}/{str(endpoint).lstrip('/')}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "github-posture",
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode("utf-8") or "null")
    except Exception:
        return None

def _gh(endpoint):
    if GH_TOKEN:
        return _http_get(endpoint)
    try:
        out = subprocess.run([GH, "api", endpoint], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=120)
        if out.returncode != 0:
            return None
        return json.loads(out.stdout or "null")
    except Exception:
        return None

def _gh_repo_list(org, limit):
    if GH_TOKEN:
        out = _http_get(f"orgs/{org}/repos?per_page={min(int(limit), 100)}&type=all")
        if not isinstance(out, list) or not out:
            # conta pessoal (não é org): repos do usuário
            out = _http_get(f"users/{org}/repos?per_page={min(int(limit), 100)}&type=owner")
        return out if isinstance(out, list) else []
    try:
        out = subprocess.run([GH, "repo", "list", org, "--limit", str(limit),
                              "--json", "name,visibility,defaultBranchRef"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        return json.loads(out.stdout or "[]") if out.returncode == 0 else []
    except Exception:
        return []

def collect(org, params):
    mode = "REST (GITHUB_TOKEN)" if GH_TOKEN else "gh CLI"
    print(f"• coletando {org} via {mode} (read-only)…", file=sys.stderr)
    # org OU conta de usuário — o GitHub do SRE Agent pode ser um user, não uma org.
    # Endpoints de governança da org dão Skip p/ um user; os de repositório rodam mesmo assim.
    data = {"org": _gh(f"orgs/{org}") or _gh(f"users/{org}") or {}}
    data["org"]["login"] = data["org"].get("login", org)
    data["members_no_2fa"]      = _gh(f"orgs/{org}/members?filter=2fa_disabled")
    data["pats"]                = _gh(f"orgs/{org}/personal-access-tokens")
    data["outside_collaborators"]= _gh(f"orgs/{org}/outside_collaborators")
    data["owners"]              = _gh(f"orgs/{org}/members?role=admin")
    data["actions_permissions"] = _gh(f"orgs/{org}/actions/permissions")
    data["runner_groups"]       = _gh(f"orgs/{org}/actions/runner-groups")
    data["runners"]             = _gh(f"orgs/{org}/actions/runners")
    data["audit_log_streams"]   = _gh(f"orgs/{org}/audit-log/streams")
    data["ip_allow_list"]       = _gh(f"orgs/{org}/ip-allow-list")
    data["org_webhooks"]        = _gh(f"orgs/{org}/hooks")
    data["dependabot_critical"] = _gh(f"orgs/{org}/dependabot/alerts?severity=critical&state=open&per_page=100")
    data["secret_alerts"]       = _sanitize_secret_alerts(_gh(f"orgs/{org}/secret-scanning/alerts?state=open&per_page=100"))
    repo_meta = _gh_repo_list(org, params.get("max_repos", 100))
    data["public_repos"] = [r for r in repo_meta if str(r.get("visibility", "")).lower() == "public"]
    print(f"• coletando {len(repo_meta)} repo(s)…", file=sys.stderr)
    repos = []
    for rm in repo_meta:
        name = rm.get("name")
        if not name:
            continue
        rd = _gh(f"repos/{org}/{name}") or {}
        branch = (rm.get("defaultBranchRef") or {}).get("name") or rm.get("default_branch") or rd.get("default_branch") or "main"
        bp = _gh(f"repos/{org}/{name}/branches/{branch}/protection")
        sig = _gh(f"repos/{org}/{name}/branches/{branch}/protection/required_signatures")
        co = _gh(f"repos/{org}/{name}/contents/.github/CODEOWNERS")
        envs = _gh(f"repos/{org}/{name}/environments")
        keys = _gh(f"repos/{org}/{name}/keys")
        wf = _gh(f"repos/{org}/{name}/actions/permissions/workflow")
        cs = _gh(f"repos/{org}/{name}/code-scanning/analyses?per_page=1")
        rd["name"] = name
        rd["branch_protection"] = bp
        if isinstance(bp, dict) and sig:
            bp["required_signatures"] = sig
        rd["has_codeowners"] = bool(co)
        rd["environments"] = as_list(envs)
        rd["deploy_keys"] = as_list(keys)
        rd["github_token_default"] = (wf or {}).get("default_workflow_permissions", "")
        rd["code_scanning"] = bool(cs)
        repos.append(rd)
    data["repos"] = repos
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
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="GitHub Posture — gap-scored 8-domain audit (read-only)")
    ap.add_argument("--from-json", help="inventário pré-coletado (modo offline/primário)")
    ap.add_argument("--org", help="login da organização (auto-coleta: REST via GITHUB_TOKEN, senão gh api)")
    ap.add_argument("--queries", default=os.path.join(here, "queries.yaml"))
    ap.add_argument("--format", choices=["html", "md", "both"], default="both")
    ap.add_argument("--output", default=os.path.join(here, "tmp", "github-posture"))
    ap.add_argument("--save-raw", action="store_true", help="grava inventário coletado em _raw.json")
    ap.add_argument("--emit-feed", help="grava o feed cross-domain (github_secrets/github_oidc) neste caminho JSON")
    args = ap.parse_args()

    q = load_yaml(args.queries)
    catalog = q["best_practices"]
    params = dict(q.get("parameters", {}) or {})
    params["_catalog"] = catalog

    if args.from_json:
        with open(args.from_json, encoding="utf-8") as f:
            data = json.load(f)
    elif args.org:
        data = collect(args.org, params)
        if not data.get("org"):
            sys.exit("❌ coleta falhou: login não resolvido como org nem user (token sem auth/escopo, ou login errado).\n"
                     "   Defina GITHUB_TOKEN (read:org/security_events) ou `gh auth login`, ou use --from-json.")
        if args.save_raw:
            os.makedirs(args.output, exist_ok=True)
            with open(os.path.join(args.output, "_raw.json"), "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
    else:
        ap.error("informe --from-json OU --org")

    ctx = build_report(data, params)

    os.makedirs(args.output, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    written = []
    if args.format in ("html", "both"):
        p = os.path.join(args.output, f"github-posture-{stamp}.html")
        with open(p, "w", encoding="utf-8") as f:
            f.write(render_html(ctx))
        written.append(p)
    if args.format in ("md", "both"):
        p = os.path.join(args.output, f"github-posture-{stamp}.md")
        with open(p, "w", encoding="utf-8") as f:
            f.write(render_md(ctx))
        written.append(p)
    if args.emit_feed:
        with open(args.emit_feed, "w", encoding="utf-8") as f:
            json.dump(ctx["feed"], f, indent=2, ensure_ascii=False)
        written.append(args.emit_feed)

    f = ctx["findings"]
    print(f"\n✅ GitHub Posture Score {ctx['score']}/100 ({ctx['verdict']}) · {len(f)} achados "
          f"({sum(1 for x in f if x['severity']=='Critical')}C/"
          f"{sum(1 for x in f if x['severity']=='Warning')}W/"
          f"{sum(1 for x in f if x['severity']=='Info')}I) · "
          f"feed: {len(ctx['feed']['github_secrets'])} secret(s)/{len(ctx['feed']['github_oidc'])} oidc", file=sys.stderr)
    for w in written:
        print(w)

if __name__ == "__main__":
    main()

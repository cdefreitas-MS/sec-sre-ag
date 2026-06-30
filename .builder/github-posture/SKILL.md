---
name: github-posture
description: 'Living, gap-scored security posture for a GitHub organization across the 8 DOMAINS of the Security Work Program: governance/access (2FA, SAML, PATs, base permission, owners, fork policy), repository & branch protection (reviews, CODEOWNERS, signed commits), secrets & credentials (secret scanning, push protection, deploy keys), GitHub Actions/CI-CD (allowed actions, GITHUB_TOKEN default, self-hosted runners), code security (Dependabot, CodeQL), audit log (streaming, IP allow list, webhooks) and supply chain (public repos, GHAS coverage). Scores the org against the GH-NNN catalog (ported faithfully from github-security-audit.ps1/.sh) → a GitHub Posture Score (0–100) with verdict SAUDÁVEL/ATENÇÃO/EM RISCO/CRÍTICO and an IMPORTANCE layer (🔥 what matters × 📋 known recommendation). Emits a CROSS-DOMAIN feed (github_secrets/github_oidc) that attack-path ingests to chain repo → leaked-secret/SP → privileged Azure role. Modular: runs standalone (HTML+MD) AND is embedded as the 🔐 GitHub Posture tab inside advisor-impact. 100% READ-ONLY (gh api GET). Use for: github posture, ghas audit, github security audit, branch protection audit, secret scanning posture, github actions security, dependabot codeql coverage, audit log streaming, 8 domains github, programa de trabalho seguranca github.'
tools:
  - RunAzCliReadCommands
---

# GitHub Posture Skill (8-Domain GHAS & Governance Audit)

## Purpose

Turn a GitHub organization into **self-grading security documentation**. Every run audits the org against the **GH-NNN catalog** — a faithful Python port of the client **Security Work Program** (`github-security-audit.ps1/.sh`, 8 domains) — scores it, classifies findings by **importance** (signal vs noise), and ships a board-readable HTML plus a repo-friendly Markdown.

It is the **governance/posture half** of GitHub security that the Defender for Cloud DevOps connector cannot see (branch protection, 2FA, Actions policy, audit-log streaming, owners). The *findings half* (Dependabot/CodeQL/secret subassessments) already lives in **advisor-impact** 🐙 DevOps Remediation.

## Two ways it indexes

1. **Embedded in advisor-impact** (primary delivery) — advisor-impact loads this engine via `_github_posture()` and renders a single **🐙 GitHub** tab, SECTIONED into **1 · 🔗 Diferencial** (cross-domain feed) · **2 · 🛡️ Postura & Governança** (8 domains, NEW) · **3 · 🐙 Remediação de código** (the existing DevOps dashboard, folded in via `render_section(…, devops_html=…)`). One report, one delivery. Run: `advisor-impact … --github-org <org>` (or `--github-json <file>`).
2. **Standalone** — its own HTML+MD report (same sectioned layout, sector 3 muted when there's no Defender DevOps data): `python generate_html_report.py --org <login>` or `--from-json inventory.json`.

## Cross-domain feed (the differential)

After scoring, `build_attack_path_feed()` emits:
- `github_secrets` — secret-scanning alerts that are a **cloud credential** (Azure/M365), with `appId` when resolvable.
- `github_oidc` — repos with weak Actions (`GITHUB_TOKEN: write`) and/or **OIDC federation** to an Azure SP.

`attack-path` ingests both and chains `Internet → repo (leaked secret / Actions-OIDC) → SP → privileged role / tenant takeover` — the cross-domain correlation **no single product makes**. A leaked Azure secret that maps to an over-privileged SP turns a GitHub finding into a real path to the tenant.

## Posture Verdict

**GitHub Posture Score** = `100 − Σ severity_weight[finding]`, clamped to [0,100] (`Critical −15`, `Warning −7`, `Info −2`).

- **SAUDÁVEL** (green): ≥ 85 · **ATENÇÃO** (yellow): 65–84 · **EM RISCO** (orange): 40–64 · **CRÍTICO** (red): < 40.

**Importance layer** (signal vs noise, aligned with attack-path):
- 🔥 **crítico** — severity Critical OR an *active* exposure (open secret-scanning alert, open critical Dependabot CVE).
- ⚡ **relevante** — *cross-domain* (feeds an attack-path to Azure: leaked secret, Actions/OIDC, audit-log-streaming off = SOC blind).
- 📋 **recomendação** — a known best practice (collapsed by default).

## Skill Files

| File | Purpose | When used |
|------|---------|-----------|
| [generate_html_report.py](generate_html_report.py) | collector (`gh api`) + GH-NNN gap engine + score + importance + section/HTML/MD renderer + attack-path feed | execution |
| [queries.yaml](queries.yaml) | GH-NNN catalog (8 domains, data-driven) + `gh api` collector endpoints + parameters | read at runtime by the script |

> ⚠️ **100% READ-ONLY.** Every call is a `gh api` GET. Never mutates the organization.

## Workflow

### Step 1: Collect (read-only)
Org + per-repo GitHub reads. Works against an **organization** OR a **personal account** (if `orgs/{login}` 404s it falls back to `users/{login}` — the org-governance domains then Skip, repo-level checks still run). **Two auth paths** (auto-detected): `GITHUB_TOKEN`/`GH_TOKEN` in the env → **REST via `api.github.com`** (the SRE Agent path, no `gh` CLI needed); else **`gh api`** (local dev, `gh auth login`). Scopes `read:org`/`admin:org`/`security_events` unlock the governance domains; without them those checks **Skip gracefully** (repo-level checks still run on whatever the token can read). **Honest coverage:** a check that needs auth/org it doesn't have is reported as **não avaliado** (Skip), never as a false "disabled" — and a **⚠️ limited-coverage banner** explains why (unauthenticated or personal-account run). Secret-scanning data is **sanitized** to metadata only (type/location/URL) — the actual secret value is never stored or rendered. Endpoints in `queries.yaml → collector`. **Primary path is offline**: collect once, then render with `--from-json` (deterministic, no GitHub calls).

### Step 2: Gap engine + importance (in the renderer)
- `build_inventory()` normalizes org + repos into one inventory.
- `run_gaps()` dispatches every GH-NNN rule's `check` to its Python implementation → **findings** / **passed** / **skipped (não avaliados)**. Checks are robust: a missing field raises `Skip` (rule → não avaliado), never a crash.
- `classify_importance()` → 🔥/⚡/📋 tier per finding; `posture_score()` → score + verdict.
- `build_attack_path_feed()` → `github_secrets` + `github_oidc` for attack-path.

### Step 3: Render
- **Embedded** — `render_section(ctx, devops_html=…, devops_meta=…)` returns a single SECTIONED fragment (scoped `.ghp` styles) advisor-impact drops into its SPA as the 🐙 GitHub tab: orientation cards (DIFERENCIAL/NOVO/JÁ NO RELATÓRIO) + 3 sectors (cross-domain feed · 8-domain posture · the DevOps dashboard folded into sector 3).
- **Standalone** — `render_html()` wraps the same sectioned section (dark scorecard; sector 3 shows a muted note when no Defender DevOps data) and `render_md()` (repo-friendly).

### Step 4: Deliver
Rides advisor-impact's triple delivery (dual email + Teams + SharePoint archival) when embedded; standalone writes HTML+MD to `tmp/github-posture/` and `--emit-feed <file>` exports the cross-domain feed.

---

*Part of the SOC Autônomo suite · collector↔renderer · GH-NNN catalog ported faithfully from the client Security Work Program. Read-only.*

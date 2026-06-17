"""
Action Safety Framework — risk classification & approval gating for response actions.

High-impact "Age" actions (containment, device isolation, credential reset) are
classified by risk, reversibility, rollback path, and pre-checks BEFORE execution.
Read-only / low-risk actions pass; HIGH and CRITICAL actions require explicit approval.

This is the governance layer for the autonomous "analisa → AGE → notifica → audita"
loop: the agent consults it before any privileged action so every action carries a
documented risk verdict, a rollback plan, and the project guardrails.

Usage:
    python action_safety.py list                       # all registered actions
    python action_safety.py evaluate isolate_device    # full JSON verdict for one action
    python action_safety.py gate force_password_reset  # verdict + exit code (0=proceed, 2=needs approval)
    python action_safety.py evaluate disable_ad_account --target user@contoso.com

Importable:
    from action_safety import ActionSafety
    ev = ActionSafety().evaluate("isolate_device")
    if ev.approval_required: ...
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field

# Force UTF-8 stdout/stderr on Windows so emoji/box-drawing chars don't crash a cp1252 console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Project-wide guardrails — apply to every destructive identity/endpoint action.
# These encode the SOC Autônomo's hard rules (see SOC-Autonomo-Doc-Geral §Guardrails).
# ---------------------------------------------------------------------------
GUARDRAILS_IDENTITY = [
    "NUNCA executar contra Global Administrators ou contas break-glass.",
    "Authentication Administrator só cobre usuários NÃO-admin (limite do tenant).",
    "Toda ação é registrada pelas 3 regras de auditoria da UAMI no Sentinel.",
]
GUARDRAILS_ENDPOINT = [
    "Confirmar que o device não é servidor de produção / controlador de domínio.",
    "Toda ação é registrada pelas 3 regras de auditoria da UAMI no Sentinel.",
]


@dataclass
class SafetyEvaluation:
    """Result of an action safety check."""
    action: str
    category: str                    # identity, endpoint, incident, notify, cloudapp, purview
    risk_level: str                  # CRITICAL, HIGH, MEDIUM, LOW
    approval_required: bool
    reversible: bool
    impact_description: str
    rollback_action: str | None      # tool/action to undo, if reversible
    pre_checks: list[str] = field(default_factory=list)
    guardrails: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# Action registry: action -> (category, risk, reversible, impact, rollback, pre_checks)
# Scoped to what the ~72 granted permissions (Graph 47 · MDE 19 · MDA 6) actually enable.
_ACTION_REGISTRY: dict[str, tuple[str, str, bool, str, str | None, list[str]]] = {
    # ── Identity response (Microsoft Graph) ──────────────────────────────
    "revoke_user_sessions": (
        "identity", "MEDIUM", False,
        "Invalida todas as sessões ativas — o usuário precisa reautenticar.",
        None,
        ["Confirmar identidade do alvo"],
    ),
    "disable_ad_account": (
        "identity", "CRITICAL", True,
        "Desabilita a conta no Entra ID — bloqueia toda autenticação imediatamente.",
        "enable_ad_account",
        ["Confirmar comprometimento", "Confirmar com gestor ou SOC lead"],
    ),
    "enable_ad_account": (
        "identity", "MEDIUM", True,
        "Reabilita a conta no Entra ID.",
        "disable_ad_account",
        ["Confirmar que a ameaça foi mitigada"],
    ),
    "force_password_reset": (
        "identity", "HIGH", False,
        "Força troca de senha no próximo logon — o usuário perde as sessões atuais.",
        None,
        ["Confirmar identidade", "Notificar o usuário se possível"],
    ),
    "reset_mfa": (
        "identity", "HIGH", False,
        "Remove/força re-registro dos métodos de MFA do usuário.",
        None,
        ["Confirmar identidade", "Re-registro de MFA será exigido no próximo acesso"],
    ),
    "confirm_user_compromised": (
        "identity", "HIGH", True,
        "Marca o usuário como 'confirmedCompromised' no Identity Protection — dispara CA baseada em risco.",
        "confirm_user_safe",
        ["Evidência de comprometimento documentada"],
    ),
    "confirm_user_safe": (
        "identity", "MEDIUM", True,
        "Descarta o risco do usuário — remove a aplicação de CA baseada em risco.",
        "confirm_user_compromised",
        ["Investigação concluída"],
    ),
    "contain_compromised_user": (
        "identity", "CRITICAL", True,
        "Cadeia completa de contenção: revoke sessions + disable account + reset password (+ isolar device).",
        "enable_ad_account (sessões/senha NÃO revertem automaticamente)",
        ["Confirmar comprometimento", "Plano de recuperação do usuário", "Validar que não é conta privilegiada"],
    ),

    # ── Endpoint response (Defender for Endpoint) ────────────────────────
    "isolate_device": (
        "endpoint", "CRITICAL", True,
        "Corta todo o acesso de rede do device exceto ao serviço do Defender.",
        "unisolate_device",
        ["Verificar se não é servidor crítico", "Confirmar com o dono do device"],
    ),
    "unisolate_device": (
        "endpoint", "MEDIUM", True,
        "Libera o device do isolamento de rede.",
        "isolate_device",
        ["Confirmar que a ameaça foi remediada"],
    ),
    "isolate_multiple_devices": (
        "endpoint", "CRITICAL", True,
        "Isolamento de rede em lote — afeta vários hosts simultaneamente.",
        "unisolate_device (por device)",
        ["Garantir que nenhum é produção", "Confirmar o escopo com o SOC lead"],
    ),
    "run_antivirus_scan": (
        "endpoint", "LOW", True,
        "Scan AV (quick/full) — read-only, sem efeito colateral salvo se achar ameaça.",
        None,
        [],
    ),
    "stop_and_quarantine_file": (
        "endpoint", "HIGH", False,
        "Mata o processo e coloca o binário em quarentena — pode quebrar uma aplicação.",
        None,
        ["Confirmar que o hash é malicioso", "Verificar se o arquivo é crítico"],
    ),
    "restrict_code_execution": (
        "endpoint", "HIGH", True,
        "Só binários assinados pela Microsoft podem rodar — bloqueia apps customizados.",
        "remove_code_restriction",
        ["Verificar o papel do device", "Checar apps de linha de negócio em execução"],
    ),
    "remove_code_restriction": (
        "endpoint", "MEDIUM", True,
        "Remove a restrição de execução de código do device.",
        "restrict_code_execution",
        [],
    ),
    "collect_investigation_package": (
        "endpoint", "LOW", True,
        "Coleta pacote forense — read-only no device.",
        None,
        [],
    ),
    "live_response": (
        "endpoint", "HIGH", False,
        "Sessão interativa de Live Response no endpoint — comandos arbitrários.",
        None,
        ["Registrar todos os comandos executados", "Confirmar com SOC lead"],
    ),

    # ── Cloud App (Defender for Cloud Apps) ──────────────────────────────
    "resolve_alert": (
        "cloudapp", "MEDIUM", True,
        "Resolve/descarta um alerta do MDA.",
        "reopen_alert",
        ["Confirmar triagem"],
    ),

    # ── Incident management (Sentinel / Graph) — baixo risco, reversível ─
    "update_incident_status": ("incident", "LOW", True, "Atualiza status/severidade/owner do incidente.", None, []),
    "add_incident_comment": ("incident", "LOW", True, "Adiciona um comentário ao incidente.", None, []),
    "classify_incident": ("incident", "LOW", True, "Define classificação/determinação do incidente.", None, []),
    "assign_incident": ("incident", "LOW", True, "Atribui o incidente a um analista.", None, []),
    "add_incident_tags": ("incident", "LOW", True, "Adiciona tags ao incidente.", None, []),

    # ── Notification — baixo risco, mas não reversível (já enviado) ──────
    "send_email_report": ("notify", "LOW", False, "Envia relatório HTML por e-mail (entrega tripla).", None, []),
    "send_teams_notification": ("notify", "LOW", False, "Posta Adaptive Card no canal do Teams.", None, []),

    # ── Purview / compliance ─────────────────────────────────────────────
    "apply_retention_label": ("purview", "MEDIUM", False, "Aplica rótulo de retenção a conteúdo.", None, ["Confirmar política de retenção"]),
    "place_hold": ("purview", "MEDIUM", True, "Coloca mailbox/site em hold (eDiscovery).", "release_hold", ["Confirmar caso de eDiscovery"]),
}


class ActionSafety:
    """Evaluates response actions for risk level and approval requirements."""

    APPROVAL_THRESHOLD = "HIGH"  # HIGH and CRITICAL require approval
    _RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    def evaluate(self, action: str, context: dict | None = None) -> SafetyEvaluation:
        """Evaluate a response action and return safety metadata."""
        entry = _ACTION_REGISTRY.get(action)
        if entry is None:
            return SafetyEvaluation(
                action=action,
                category="unknown",
                risk_level="HIGH",
                approval_required=True,
                reversible=False,
                impact_description="Ação não registrada — revisar manualmente antes de executar.",
                rollback_action=None,
                pre_checks=[],
                guardrails=[],
                warnings=["Ação fora do registro de segurança — tratar como HIGH por precaução."],
            )

        category, risk, reversible, impact, rollback, pre_checks = entry
        approval_required = self._RISK_ORDER.get(risk, 0) >= self._RISK_ORDER.get(self.APPROVAL_THRESHOLD, 2)

        guardrails: list[str] = []
        if category == "identity" and risk in ("HIGH", "CRITICAL"):
            guardrails = list(GUARDRAILS_IDENTITY)
        elif category == "endpoint" and risk in ("HIGH", "CRITICAL"):
            guardrails = list(GUARDRAILS_ENDPOINT)

        warnings: list[str] = []
        if not reversible:
            warnings.append("Esta ação NÃO é facilmente reversível.")
        if risk == "CRITICAL":
            warnings.append("Impacto CRÍTICO — confirmar com o SOC lead antes de executar.")

        # Optional context hint: caller can flag a privileged target.
        if context and context.get("target_is_privileged") and category == "identity":
            warnings.append("ALVO PRIVILEGIADO detectado — BLOQUEAR: guardrail proíbe ação contra Global Admin/break-glass.")

        return SafetyEvaluation(
            action=action,
            category=category,
            risk_level=risk,
            approval_required=approval_required,
            reversible=reversible,
            impact_description=impact,
            rollback_action=rollback,
            pre_checks=list(pre_checks),
            guardrails=guardrails,
            warnings=warnings,
        )

    def is_high_risk(self, action: str) -> bool:
        """Quick check: does this action require approval?"""
        return self.evaluate(action).approval_required

    def get_all_high_risk_actions(self) -> list[str]:
        """Return all actions that require approval."""
        return [
            action for action, (_cat, risk, *_rest) in _ACTION_REGISTRY.items()
            if self._RISK_ORDER.get(risk, 0) >= self._RISK_ORDER.get(self.APPROVAL_THRESHOLD, 2)
        ]

    def list_actions(self) -> list[SafetyEvaluation]:
        """Evaluate every registered action (for catalog/listing)."""
        return [self.evaluate(a) for a in _ACTION_REGISTRY]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_RISK_EMOJI = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}


def _cmd_list(safety: ActionSafety) -> int:
    rows = sorted(safety.list_actions(), key=lambda e: (-ActionSafety._RISK_ORDER[e.risk_level], e.category, e.action))
    print(f"{'AÇÃO':<28} {'CATEGORIA':<10} {'RISCO':<10} {'APROVAÇÃO':<10} {'REVERSÍVEL':<11} ROLLBACK")
    print("-" * 92)
    for e in rows:
        appr = "SIM" if e.approval_required else "—"
        rev = "sim" if e.reversible else "NÃO"
        print(f"{e.action:<28} {e.category:<10} {_RISK_EMOJI[e.risk_level]} {e.risk_level:<7} "
              f"{appr:<10} {rev:<11} {e.rollback_action or '—'}")
    print(f"\n{len(rows)} ações · {len(safety.get_all_high_risk_actions())} exigem aprovação (HIGH/CRITICAL).")
    return 0


def _cmd_evaluate(safety: ActionSafety, action: str, target: str | None) -> int:
    ctx = {"target": target} if target else None
    ev = safety.evaluate(action, ctx)
    out = asdict(ev)
    if target:
        out["target"] = target
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def _cmd_gate(safety: ActionSafety, action: str) -> int:
    """Print a verdict and return an exit code the agent can branch on."""
    ev = safety.evaluate(action)
    emoji = _RISK_EMOJI.get(ev.risk_level, "⚪")
    if ev.approval_required:
        print(f"{emoji} {action}: {ev.risk_level} — APROVAÇÃO NECESSÁRIA antes de executar.")
        print(f"   Impacto: {ev.impact_description}")
        if ev.rollback_action:
            print(f"   Rollback: {ev.rollback_action}")
        for g in ev.guardrails:
            print(f"   ⛔ {g}")
        return 2  # needs approval
    print(f"{emoji} {action}: {ev.risk_level} — pode prosseguir (sem gate).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Action Safety Framework — risk gate for response actions.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="Lista todas as ações registradas com risco/aprovação.")
    p_eval = sub.add_parser("evaluate", help="Veredito completo (JSON) de uma ação.")
    p_eval.add_argument("action")
    p_eval.add_argument("--target", default=None, help="Alvo opcional (UPN/host) — registrado no veredito.")
    p_gate = sub.add_parser("gate", help="Veredito curto + código de saída (0=prossegue, 2=precisa aprovação).")
    p_gate.add_argument("action")
    args = parser.parse_args(argv)

    safety = ActionSafety()
    if args.command == "list":
        return _cmd_list(safety)
    if args.command == "evaluate":
        return _cmd_evaluate(safety, args.action, args.target)
    if args.command == "gate":
        return _cmd_gate(safety, args.action)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

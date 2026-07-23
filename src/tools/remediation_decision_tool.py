"""
RemediationDecisionTool

Decides the appropriate remediation strategy for a given CVE based on
severity, component type, and environment, and simulates applying that fix.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.core.config_loader import load_config


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RemediationDecisionTool:
    def __init__(self) -> None:
        try:
            self.config = load_config()
        except Exception as err:  # noqa: BLE001
            print(f"[RemediationDecisionTool] Failed to load config, proceeding with defaults: {err}")
            self.config = {}

    async def execute(self, request: Dict[str, Any]) -> Dict[str, Any]:
        operation = request.get("operation")
        params = request.get("params") or {}

        try:
            if operation == "selectStrategy":
                return await self._select_strategy(params)
            if operation == "applyFix":
                return await self._apply_fix(params)

            return {
                "error": f"Unknown operation '{operation}'",
                "supported_operations": ["selectStrategy", "applyFix"],
            }
        except Exception as err:  # noqa: BLE001
            print(f"[RemediationDecisionTool] Error executing '{operation}': {err}")
            return {
                "error": True,
                "message": str(err) or "Unknown error in RemediationDecisionTool",
                "operation": operation,
                "fallback": True,
            }

    async def _select_strategy(self, params: Dict[str, Any]) -> Dict[str, Any]:
        cve_id: Optional[str] = params.get("cve_id")
        cvss_score: Optional[float] = params.get("cvss_score")
        component_type: Optional[str] = params.get("component_type")
        environment: Optional[str] = params.get("environment")

        if cve_id is None or cvss_score is None or component_type is None or environment is None:
            raise ValueError("selectStrategy requires cve_id, cvss_score, component_type, and environment")

        if cvss_score >= 9.0 and environment == "production":
            strategy = "rollback"
            requires_approval = True
            rationale = (
                f"CVSS {cvss_score} is critical and target environment is production; "
                "rolling back is the safest immediate mitigation and requires human sign-off."
            )
        elif cvss_score >= 7.0 and environment == "production":
            strategy = "upgrade"
            requires_approval = True
            rationale = (
                f"CVSS {cvss_score} is high severity in production; an upgrade is recommended "
                "but requires approval before deployment."
            )
        elif cvss_score >= 7.0 and component_type == "dependency":
            strategy = "upgrade"
            requires_approval = False
            rationale = (
                f"CVSS {cvss_score} is high severity on a dependency component; automated upgrade "
                "can proceed without manual approval."
            )
        elif cvss_score >= 4.0 and component_type == "container":
            strategy = "rebuild"
            requires_approval = False
            rationale = (
                f"CVSS {cvss_score} is moderate severity on a container component; a rebuild "
                "resolves the vulnerable layer without approval."
            )
        elif component_type == "os_package":
            strategy = "os_upgrade"
            requires_approval = False
            rationale = "Component is an OS package; standard OS-level package upgrade applies automatically."
        else:
            strategy = "manual"
            requires_approval = True
            rationale = (
                f"No automated strategy matched the given CVSS score ({cvss_score}), component type "
                f"({component_type}), and environment ({environment}); manual review is required."
            )

        return {
            "cve_id": cve_id,
            "strategy": strategy,
            "requires_approval": requires_approval,
            "rationale": rationale,
            "timestamp": _now_iso(),
        }

    async def _apply_fix(self, params: Dict[str, Any]) -> Dict[str, Any]:
        strategy: Optional[str] = params.get("strategy")
        target: Optional[str] = params.get("target")
        patch_version: Optional[str] = params.get("patch_version")

        if not strategy or not target:
            raise ValueError("applyFix requires strategy and target")

        approval_required_strategies = {"rollback"}
        status = "pending_approval" if strategy in approval_required_strategies else "applied"

        return {
            "status": status,
            "strategy": strategy,
            "target": target,
            "patch_version": patch_version or "latest",
            "applied_at": _now_iso(),
        }

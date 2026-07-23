"""
Registers all tools from across the AVRC project so they can be looked up
by name at runtime (e.g. by an orchestrator or agent loop).
"""

from typing import Any, Dict

from src.tools.remediation_decision_tool import RemediationDecisionTool
from src.tools.git_ops_tool import GitOpsTool
from src.tools.os_pkg_upgrade_tool import OsPkgUpgradeTool


class NotImplementedTool:
    """
    Lightweight placeholder for tools referenced elsewhere in the AVRC
    project but not yet built. Registered so that `get_tool()` calls
    against their names fail gracefully with a clear "not implemented"
    message instead of a missing-registry-entry error. Replace each
    placeholder with a real import once the corresponding tool module
    exists in src/tools/.
    """

    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name

    async def execute(self, _request: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "error": True,
            "message": f"Tool '{self.tool_name}' is registered but not yet implemented.",
            "mock": True,
        }


# Placeholders for tools referenced elsewhere in the AVRC project but not
# yet built. Swap these for real imports as each tool is completed:
#   from src.tools.defect_dojo_api_tool import DefectDojoApiTool
#   from src.tools.cve_lookup_tool import CveLookupTool
#   from src.tools.pipeline_lint_tool import PipelineLintTool
#   from src.tools.dependency_patch_tool import DependencyPatchTool
#   from src.tools.container_scan_tool import ContainerScanTool
#   from src.tools.dynamic_software_scan_tool import DynamicSoftwareScanTool
#   from src.tools.audit_logger_tool import AuditLoggerTool
#   from src.tools.verification_scan_tool import VerificationScanTool
#   from src.tools.notification_tool import NotificationTool

tool_registry: Dict[str, Any] = {
    "remediation_decision_tool": RemediationDecisionTool(),
    "git_ops_tool": GitOpsTool(),
    "os_pkg_upgrade_tool": OsPkgUpgradeTool(),
    # Placeholders - replace with real tool instances as they're implemented.
    "defect_dojo_api_tool": NotImplementedTool("defect_dojo_api_tool"),
    "cve_lookup_tool": NotImplementedTool("cve_lookup_tool"),
    "pipeline_lint_tool": NotImplementedTool("pipeline_lint_tool"),
    "dependency_patch_tool": NotImplementedTool("dependency_patch_tool"),
    "container_scan_tool": NotImplementedTool("container_scan_tool"),
    "dynamic_software_scan_tool": NotImplementedTool("dynamic_software_scan_tool"),
    "audit_logger_tool": NotImplementedTool("audit_logger_tool"),
    "verification_scan_tool": NotImplementedTool("verification_scan_tool"),
    "notification_tool": NotImplementedTool("notification_tool"),
}


def get_tool(name: str) -> Any:
    tool = tool_registry.get(name)
    if tool is None:
        raise KeyError(f"Tool '{name}' not found in registry")
    return tool

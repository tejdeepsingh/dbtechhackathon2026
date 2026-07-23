import { BaseTool } from './base_tool.js';
import {
  AuditLoggerTool,
  ContainerScanTool,
  CveLookupTool,
  DefectDojoApiTool,
  DependencyPatchTool,
  DynamicSoftwareScanTool,
  GitOpsTool,
  NotificationTool,
  OsPkgUpgradeTool,
  PipelineLintTool,
  RemediationDecisionTool,
  ReportGeneratorTool,
  Tool1,
  VerificationScanTool,
} from './mock_tools.js';

const registry = new Map<string, BaseTool>([
  ['tool_1', new Tool1()],
  ['defectdojo_api_tool', new DefectDojoApiTool()],
  ['pipeline_lint_tool', new PipelineLintTool()],
  ['container_scan_tool', new ContainerScanTool()],
  ['dependency_patch_tool', new DependencyPatchTool()],
  ['os_pkg_upgrade_tool', new OsPkgUpgradeTool()],
  ['dynamic_software_scan_tool', new DynamicSoftwareScanTool()],
  ['remediation_decision_tool', new RemediationDecisionTool()],
  ['audit_logger_tool', new AuditLoggerTool()],
  ['cve_lookup_tool', new CveLookupTool()],
  ['git_ops_tool', new GitOpsTool()],
  ['verification_scan_tool', new VerificationScanTool()],
  ['notification_tool', new NotificationTool()],
  ['report_generator_tool', new ReportGeneratorTool()],
  ['report_generator_tool_shared', new ReportGeneratorTool()],
]);

export function getTool(name: string): BaseTool {
  const tool = registry.get(name);
  if (!tool) {
    throw new Error(`Tool not registered: ${name}`);
  }
  return tool;
}

export function listTools(): string[] {
  return [...registry.keys()];
}

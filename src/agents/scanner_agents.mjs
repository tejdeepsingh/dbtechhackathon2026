export class ScannerAgent {
  constructor({ name, scanner, primaryTool, domains, remediationTool = null }) {
    this.name = name;
    this.scanner = scanner;
    this.primaryTool = primaryTool;
    this.remediationTool = remediationTool;
    this.domains = domains;
  }

  describe() {
    return {
      name: this.name,
      scanner: this.scanner,
      primaryTool: this.primaryTool,
      remediationTool: this.remediationTool,
      domains: this.domains,
    };
  }
}

export const scannerAgents = [
  new ScannerAgent({
    name: 'trivy_agent',
    scanner: 'Trivy',
    primaryTool: 'trivy_scan_tool',
    domains: ['repo', 'filesystem', 'container_image', 'kubernetes_config', 'sbom'],
  }),
  new ScannerAgent({
    name: 'renovate_agent',
    scanner: 'Renovate CLI',
    primaryTool: 'renovate_fix_tool',
    domains: ['dependency_updates', 'repo_autoremediation'],
  }),
  new ScannerAgent({
    name: 'copacetic_agent',
    scanner: 'Copacetic',
    primaryTool: 'copacetic_patch_tool',
    domains: ['container_image_autoremediation'],
  }),
  new ScannerAgent({
    name: 'kubescape_agent',
    scanner: 'Kubescape',
    primaryTool: 'kubescape_scan_tool',
    domains: ['kubernetes_posture', 'deployed_workload', 'compliance'],
  }),
  new ScannerAgent({
    name: 'wazuh_agent',
    scanner: 'Wazuh',
    primaryTool: 'wazuh_vulnerability_tool',
    domains: ['on_prem_host', 'endpoint', 'hybrid_workload'],
  }),
  new ScannerAgent({
    name: 'greenbone_agent',
    scanner: 'Greenbone Community / OpenVAS',
    primaryTool: 'greenbone_scan_tool',
    domains: ['network', 'on_prem_infra', 'authenticated_host_scan'],
  }),
  new ScannerAgent({
    name: 'zap_agent',
    scanner: 'OWASP ZAP',
    primaryTool: 'zap_dast_tool',
    domains: ['runtime_app', 'dast', 'web_endpoint'],
  }),
  new ScannerAgent({
    name: 'semgrep_agent',
    scanner: 'Semgrep OSS',
    primaryTool: 'semgrep_scan_tool',
    domains: ['sast', 'source_code', 'rule_autofix'],
  }),
  new ScannerAgent({
    name: 'openrewrite_agent',
    scanner: 'OpenRewrite',
    primaryTool: 'openrewrite_remediation_tool',
    domains: ['code_remediation', 'java', 'framework_upgrade'],
  }),
  new ScannerAgent({
    name: 'osv_agent',
    scanner: 'OSV.dev',
    primaryTool: 'osv_lookup_tool',
    domains: ['cve_database', 'package_advisory', 'vulnerability_enrichment'],
  }),
  new ScannerAgent({
    name: 'nvd_agent',
    scanner: 'NVD',
    primaryTool: 'nvd_lookup_tool',
    domains: ['cve_database', 'cvss', 'vulnerability_enrichment'],
  }),
];

export function scannerAgentForTool(toolName) {
  return scannerAgents.find((agent) => agent.primaryTool === toolName) ?? null;
}

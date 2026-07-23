import { AgentRequest, AgentStep } from '../types.js';
import { BaseAgent } from './base_agent.js';

export class DefectDojoApiAgent extends BaseAgent {
  constructor() {
    super('defectdojo_api_agent');
  }

  async handle(): Promise<AgentStep[]> {
    return [(await this.runTool('defectdojo_api_tool', 'listFindings')).step];
  }
}

export class CiCdPipelineAgent extends BaseAgent {
  constructor() {
    super('ci_cd_pipeline_agent');
  }

  async handle(): Promise<AgentStep[]> {
    return [(await this.runTool('pipeline_lint_tool', 'lintPipeline')).step];
  }
}

export class ContainerImageAgent extends BaseAgent {
  constructor() {
    super('container_image_agent');
  }

  async handle(request: AgentRequest): Promise<AgentStep[]> {
    return [
      (await this.runTool('container_scan_tool', 'scanImage', {
        image: request.target ?? 'node:18',
      })).step,
    ];
  }
}

export class DependencyAgent extends BaseAgent {
  constructor() {
    super('dependency_agent');
  }

  async handle(): Promise<AgentStep[]> {
    return [(await this.runTool('dependency_patch_tool', 'scanAndPatch')).step];
  }
}

export class OsVulnerabilityAgent extends BaseAgent {
  constructor() {
    super('os_vulnerability_agent');
  }

  async handle(): Promise<AgentStep[]> {
    return [(await this.runTool('os_pkg_upgrade_tool', 'upgradePackage')).step];
  }
}

export class RuntimeAgent extends BaseAgent {
  constructor() {
    super('runtime_agent');
  }

  async handle(request: AgentRequest): Promise<AgentStep[]> {
    return [
      (await this.runTool('dynamic_software_scan_tool', 'scanTarget', {
        target: request.target,
      })).step,
    ];
  }
}

export class CveIntelligenceAgent extends BaseAgent {
  constructor() {
    super('cve_intelligence_agent');
  }

  async handle(): Promise<AgentStep[]> {
    return [(await this.runTool('cve_lookup_tool', 'lookup', { cve: 'CVE-2024-12345' })).step];
  }
}

export class DecisionRemediationAgent extends BaseAgent {
  constructor() {
    super('decision_remediation_agent');
  }

  async handle(): Promise<AgentStep[]> {
    return [
      (await this.runTool('remediation_decision_tool', 'selectStrategy')).step,
      (await this.runTool('git_ops_tool', 'openPullRequest')).step,
      (await this.runTool('audit_logger_tool', 'writeAuditEvent', { event: 'remediation_decision' })).step,
    ];
  }
}

export class VerificationAgent extends BaseAgent {
  constructor() {
    super('verification_agent');
  }

  async handle(): Promise<AgentStep[]> {
    return [(await this.runTool('verification_scan_tool', 'verifyFix')).step];
  }
}

export class NotificationReportingAgent extends BaseAgent {
  constructor() {
    super('notification_reporting_agent');
  }

  async handle(): Promise<AgentStep[]> {
    return [
      (await this.runTool('notification_tool', 'sendDigest')).step,
      (await this.runTool('report_generator_tool', 'generateExecutiveSummary')).step,
    ];
  }
}

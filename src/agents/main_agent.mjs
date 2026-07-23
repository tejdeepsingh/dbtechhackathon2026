import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

export class MainAgent {
  constructor({ config, rootDir }) {
    this.config = config;
    this.rootDir = rootDir;
  }

  async handle(request) {
    const promptPolicy = this.validatePrompt(request.prompt);
    if (!promptPolicy.allowed) {
      return {
        status: 'blocked',
        route: ['main_agent', 'policy_enforcer'],
        steps: [
          {
            agent: 'policy_enforcer',
            status: 'blocked',
            summary: promptPolicy.reason,
          },
        ],
        message: 'Request blocked by policy.',
      };
    }

    if (this.requiresApproval(request)) {
      return {
        status: 'needs_approval',
        route: ['main_agent', 'policy_enforcer'],
        steps: [
          {
            agent: 'policy_enforcer',
            status: 'needs_approval',
            summary: 'High or critical production remediation requires human approval.',
          },
        ],
        message: 'Approval required before remediation can continue.',
      };
    }

    const routePlan = this.createRoutePlan(request.prompt);
    const auditResult = await this.writeAuditEvent({
      event: 'mock_remediation_flow',
      prompt: request.prompt,
      route: routePlan.route,
    });

    return {
      status: 'success',
      route: routePlan.route,
      steps: [
        {
          agent: 'main_agent',
          status: 'success',
          summary: `Classified request as ${routePlan.kind} and routed to ${routePlan.firstAgent}.`,
          data: {
            kind: routePlan.kind,
            firstTool: routePlan.firstTool,
          },
        },
        this.mockScanStep(routePlan, request),
        {
          agent: 'cve_intelligence_agent',
          tool: 'cve_lookup_tool',
          status: 'success',
          summary: 'cve_lookup_tool.lookup completed.',
          data: {
            cve: 'CVE-2024-12345',
            cvss: 8.1,
            severity: request.severity ?? 'high',
            exploitKnown: false,
            advisory: 'Mock advisory recommends upgrading the affected package.',
          },
        },
        {
          agent: 'decision_remediation_agent',
          tool: 'remediation_decision_tool',
          status: 'success',
          summary: 'Selected upgrade strategy and simulated PR creation.',
          data: {
            strategy: 'upgrade',
            branch: 'avrc/remediate-demo-cve',
            pullRequestUrl: 'https://example.invalid/avrc/mock-pr',
          },
        },
        {
          agent: 'decision_remediation_agent',
          tool: 'audit_logger_tool',
          status: 'success',
          summary: 'Audit event written.',
          data: auditResult,
        },
        {
          agent: 'verification_agent',
          tool: 'verification_scan_tool',
          status: 'success',
          summary: 'Targeted verification scan passed.',
          data: {
            verified: true,
            remainingFindings: 0,
          },
        },
        {
          agent: 'notification_reporting_agent',
          tool: 'notification_tool',
          status: 'success',
          summary: 'Mock security digest sent and report generated.',
          data: {
            channels: ['slack', 'email'],
            reportPath: 'output/reports/avrc-executive-summary.html',
          },
        },
      ],
      message: 'Mock AVRC agentic remediation flow completed.',
    };
  }

  validatePrompt(prompt) {
    const policy = this.config.policies.preventHarmfulContent;
    if (!policy.enabled) {
      return { allowed: true };
    }

    const blocked = policy.blockedKeywords.find((keyword) =>
      prompt.toLowerCase().includes(keyword.toLowerCase()),
    );

    return blocked
      ? { allowed: false, reason: `Prompt contains blocked keyword: ${blocked}` }
      : { allowed: true };
  }

  requiresApproval(request) {
    const policy = this.config.policies.remediationApprovalGate;
    if (!policy.enabled) {
      return false;
    }

    return (
      policy.requiresApprovalForSeverities.includes(String(request.severity ?? '').toLowerCase()) &&
      policy.requiresApprovalInEnvironments.includes(String(request.environment ?? '').toLowerCase()) &&
      !request.approved
    );
  }

  createRoutePlan(prompt) {
    const lower = prompt.toLowerCase();

    if (lower.includes('defectdojo')) {
      return this.buildRoute('defectdojo', 'defectdojo_api_agent', 'defectdojo_api_tool');
    }
    if (lower.includes('pipeline') || lower.includes('github actions') || /\bci\b/.test(lower)) {
      return this.buildRoute('pipeline', 'ci_cd_pipeline_agent', 'pipeline_lint_tool');
    }
    if (lower.includes('container') || lower.includes('docker') || lower.includes('image')) {
      return this.buildRoute('container', 'container_image_agent', 'container_scan_tool');
    }
    if (lower.includes('os') || lower.includes('apt') || lower.includes('yum') || lower.includes('apk')) {
      return this.buildRoute('os', 'os_vulnerability_agent', 'os_pkg_upgrade_tool');
    }
    if (lower.includes('runtime') || lower.includes('dast') || lower.includes('zap')) {
      return this.buildRoute('runtime', 'runtime_agent', 'dynamic_software_scan_tool');
    }

    return this.buildRoute('dependency', 'dependency_agent', 'dependency_patch_tool');
  }

  buildRoute(kind, firstAgent, firstTool) {
    return {
      kind,
      firstAgent,
      firstTool,
      route: [
        'main_agent',
        firstAgent,
        'cve_intelligence_agent',
        'decision_remediation_agent',
        'verification_agent',
        'notification_reporting_agent',
      ],
    };
  }

  mockScanStep(routePlan, request) {
    return {
      agent: routePlan.firstAgent,
      tool: routePlan.firstTool,
      status: 'success',
      summary: `${routePlan.firstTool}.scan completed.`,
      data: {
        target: request.target ?? this.defaultTargetFor(routePlan.kind),
        findings: [
          {
            cve: 'CVE-2024-12345',
            severity: request.severity ?? 'high',
            package: routePlan.kind === 'dependency' ? 'demo-lib' : undefined,
          },
        ],
      },
    };
  }

  defaultTargetFor(kind) {
    const targets = {
      defectdojo: 'AVRC Demo Product',
      pipeline: '.github/workflows',
      container: 'node:18',
      dependency: 'package-lock.json',
      os: 'ubuntu:22.04',
      runtime: 'http://localhost:3000',
    };
    return targets[kind] ?? 'local-project';
  }

  async writeAuditEvent(event) {
    const serialized = JSON.stringify(
      {
        timestamp: new Date().toISOString(),
        ...event,
      },
      null,
      2,
    );
    const hash = createHash('sha256').update(serialized).digest('hex');
    const auditPath = resolve(this.rootDir, 'output', 'audit', `${Date.now()}-${hash.slice(0, 8)}.json`);

    await mkdir(dirname(auditPath), { recursive: true });
    await writeFile(auditPath, JSON.stringify({ ...event, hash }, null, 2), 'utf-8');

    return { auditPath, hash };
  }
}

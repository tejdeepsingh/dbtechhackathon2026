import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { BaseTool } from './base_tool.js';
import { getRootDir } from '../core/config_loader.js';

export class Tool1 extends BaseTool {
  constructor() {
    super('tool_1');
  }

  protected async run(operation: string, params: Record<string, unknown>) {
    return { operation, echo: params, message: 'Mock utility tool is reachable.' };
  }
}

export class DefectDojoApiTool extends BaseTool {
  constructor() {
    super('defectdojo_api_tool');
  }

  protected async run(operation: string) {
    return {
      operation,
      product: 'AVRC Demo Product',
      findings: [{ id: 101, cve: 'CVE-2024-12345', severity: 'high' }],
    };
  }
}

export class PipelineLintTool extends BaseTool {
  constructor() {
    super('pipeline_lint_tool');
  }

  protected async run() {
    return {
      issues: [
        {
          file: '.github/workflows/build.yml',
          rule: 'unpinned-action',
          recommendation: 'Pin actions by full commit SHA.',
        },
      ],
    };
  }
}

export class ContainerScanTool extends BaseTool {
  constructor() {
    super('container_scan_tool');
  }

  protected async run(_operation: string, params: Record<string, unknown>) {
    return {
      image: params.image ?? 'node:18',
      scanner: 'mock-trivy',
      vulnerabilities: [{ id: 'CVE-2024-12345', package: 'openssl', severity: 'high' }],
    };
  }
}

export class DependencyPatchTool extends BaseTool {
  constructor() {
    super('dependency_patch_tool');
  }

  protected async run() {
    return {
      ecosystem: 'npm',
      vulnerablePackage: 'demo-lib',
      currentVersion: '1.0.0',
      patchedVersion: '1.0.1',
      patchApplied: true,
    };
  }
}

export class OsPkgUpgradeTool extends BaseTool {
  constructor() {
    super('os_pkg_upgrade_tool');
  }

  protected async run() {
    return {
      packageManager: 'apt',
      package: 'openssl',
      action: 'upgrade-simulated',
      patchedVersion: '3.0.13',
    };
  }
}

export class DynamicSoftwareScanTool extends BaseTool {
  constructor() {
    super('dynamic_software_scan_tool');
  }

  protected async run(_operation: string, params: Record<string, unknown>) {
    return {
      target: params.target ?? 'http://localhost:3000',
      scanner: 'mock-zap-baseline',
      findings: [{ type: 'missing-security-header', severity: 'medium' }],
    };
  }
}

export class RemediationDecisionTool extends BaseTool {
  constructor() {
    super('remediation_decision_tool');
  }

  protected async run(_operation: string, params: Record<string, unknown>) {
    return {
      strategy: params.strategy ?? 'upgrade',
      rationale: 'Mock decision selected the lowest-risk available patch path.',
      nextAction: 'apply_patch_and_open_pr',
    };
  }
}

export class AuditLoggerTool extends BaseTool {
  constructor() {
    super('audit_logger_tool');
  }

  protected async run(_operation: string, params: Record<string, unknown>) {
    const payload = {
      timestamp: new Date().toISOString(),
      event: params.event ?? 'agent_step',
      params,
    };
    const serialized = JSON.stringify(payload, null, 2);
    const hash = createHash('sha256').update(serialized).digest('hex');
    const outputPath = resolve(getRootDir(), 'output', 'audit', `${Date.now()}-${hash.slice(0, 8)}.json`);

    await mkdir(dirname(outputPath), { recursive: true });
    await writeFile(outputPath, JSON.stringify({ ...payload, hash }, null, 2), 'utf-8');

    return { auditPath: outputPath, hash };
  }
}

export class CveLookupTool extends BaseTool {
  constructor() {
    super('cve_lookup_tool');
  }

  protected async run(_operation: string, params: Record<string, unknown>) {
    return {
      cve: params.cve ?? 'CVE-2024-12345',
      cvss: 8.1,
      severity: 'high',
      exploitKnown: false,
      advisory: 'Mock advisory: upgrade affected package to patched version.',
    };
  }
}

export class GitOpsTool extends BaseTool {
  constructor() {
    super('git_ops_tool');
  }

  protected async run() {
    return {
      branch: 'avrc/remediate-demo-cve',
      commit: 'mock-commit-sha',
      pullRequestUrl: 'https://example.invalid/mock-pr',
    };
  }
}

export class VerificationScanTool extends BaseTool {
  constructor() {
    super('verification_scan_tool');
  }

  protected async run() {
    return {
      verified: true,
      remainingFindings: 0,
      message: 'Targeted mock re-scan confirms vulnerability is resolved.',
    };
  }
}

export class NotificationTool extends BaseTool {
  constructor() {
    super('notification_tool');
  }

  protected async run() {
    return {
      channels: ['slack', 'email'],
      delivered: true,
      messageId: `mock-${Date.now()}`,
    };
  }
}

export class ReportGeneratorTool extends BaseTool {
  constructor() {
    super('report_generator_tool');
  }

  protected async run() {
    return {
      reportPath: 'output/reports/avrc-executive-summary.html',
      format: 'html',
      generated: true,
    };
  }
}

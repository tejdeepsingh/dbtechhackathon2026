import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { BaseTool } from './base_tool.js';
import { getRootDir } from '../core/config_loader.js';

async function callService(url: string, body: unknown, timeoutMs = 8000): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

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
  private readonly serviceUrl = (process.env.SEMGREP_SERVICE_URL ?? 'http://semgrep-scan-tool:8080').replace(/\/$/, '');

  constructor() {
    super('pipeline_lint_tool');
  }

  protected async run(_operation: string, params: Record<string, unknown>) {
    try {
      return await callService(`${this.serviceUrl}/semgrep/scan`, params);
    } catch (err) {
      console.warn(`[PipelineLintTool] semgrep-scan-tool unavailable, using mock: ${err}`);
      return {
        status: 'success',
        tool: 'semgrep_scan_tool',
        scanner: 'semgrep',
        mock: true,
        totalFindings: 1,
        findings: [
          {
            file: '.github/workflows/build.yml',
            rule: 'unpinned-action',
            severity: 'warning',
            recommendation: 'Pin actions by full commit SHA.',
          },
        ],
        data: { findings: [] },
      };
    }
  }
}

export class ContainerScanTool extends BaseTool {
  private readonly serviceUrl = (process.env.TRIVY_SERVICE_URL ?? 'http://trivy-scan-tool:8080').replace(/\/$/, '');

  constructor() {
    super('container_scan_tool');
  }

  protected async run(_operation: string, params: Record<string, unknown>) {
    try {
      return await callService(`${this.serviceUrl}/scan`, params);
    } catch (err) {
      console.warn(`[ContainerScanTool] trivy-scan-tool unavailable, using mock: ${err}`);
      return {
        status: 'success',
        tool: 'container_scan_tool',
        scanner: 'trivy',
        mock: true,
        image: params.image ?? 'node:18',
        totalFindings: 1,
        findings: [{ id: 'CVE-2024-12345', package: 'openssl', severity: 'high' }],
        data: { findings: [] },
      };
    }
  }
}

export class DependencyPatchTool extends BaseTool {
  private readonly serviceUrl = (process.env.RENOVATE_SERVICE_URL ?? 'http://renovate-fix-tool:8080').replace(/\/$/, '');

  constructor() {
    super('dependency_patch_tool');
  }

  protected async run(_operation: string, params: Record<string, unknown>) {
    try {
      return await callService(`${this.serviceUrl}/renovate/scan`, params);
    } catch (err) {
      console.warn(`[DependencyPatchTool] renovate-fix-tool unavailable, using mock: ${err}`);
      return {
        status: 'success',
        tool: 'dependency_patch_tool',
        scanner: 'renovate',
        mock: true,
        ecosystem: 'npm',
        vulnerablePackage: params.package ?? 'demo-lib',
        currentVersion: '1.0.0',
        patchedVersion: '1.0.1',
        patchApplied: true,
        data: { findings: [] },
      };
    }
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
  private readonly serviceUrl = (process.env.OSV_SERVICE_URL ?? 'http://osv-lookup-tool:8080').replace(/\/$/, '');

  constructor() {
    super('cve_lookup_tool');
  }

  protected async run(_operation: string, params: Record<string, unknown>) {
    try {
      return await callService(`${this.serviceUrl}/osv/lookup`, params);
    } catch (err) {
      console.warn(`[CveLookupTool] osv-lookup-tool unavailable, using mock: ${err}`);
      return {
        status: 'success',
        tool: 'cve_lookup_tool',
        scanner: 'osv.dev',
        mock: true,
        cve: params.cve ?? 'CVE-2024-12345',
        cvss: 8.1,
        severity: 'high',
        exploitKnown: false,
        advisory: 'Mock advisory: upgrade affected package to patched version.',
        findings: [],
        data: { findings: [] },
      };
    }
  }
}

const GIT_OPS_ENDPOINT: Record<string, string> = {
  createBranch: '/git/branch',
  commitPatch: '/git/commit',
  openPR: '/git/pull-request',
  openPullRequest: '/git/pull-request',
};

export class GitOpsTool extends BaseTool {
  private readonly serviceUrl = (process.env.GIT_OPS_SERVICE_URL ?? 'http://git-ops-tool:8080').replace(/\/$/, '');

  constructor() {
    super('git_ops_tool');
  }

  protected async run(operation: string, params: Record<string, unknown>) {
    const endpoint = GIT_OPS_ENDPOINT[operation] ?? '/git/pull-request';
    try {
      return await callService(`${this.serviceUrl}${endpoint}`, params);
    } catch (err) {
      console.warn(`[GitOpsTool] git-ops-tool unavailable, using mock: ${err}`);
      return {
        status: 'needs_configuration',
        provider: 'forgejo',
        operation,
        mock: true,
        branch: params.branch ?? params.newBranch ?? 'avrc/remediate-demo-cve',
        commit: 'mock-commit-sha',
        pullRequestUrl: 'https://example.invalid/mock-pr',
      };
    }
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

import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

export class MainAgent {
  constructor({ config, rootDir }) {
    this.config = config;
    this.rootDir = rootDir;
  }

  async handle(request, options = {}) {
    const onProgress = options.onProgress ?? (() => {});
    const emit = (event) =>
      onProgress({
        timestamp: new Date().toISOString(),
        ...event,
      });

    emit({
      type: 'progress',
      agent: 'main_agent',
      status: 'running',
      message: 'Received request and checking policy gates.',
    });

    const promptPolicy = this.validatePrompt(request.prompt);
    if (!promptPolicy.allowed) {
      emit({
        type: 'progress',
        agent: 'policy_enforcer',
        status: 'blocked',
        message: promptPolicy.reason,
      });

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
      emit({
        type: 'progress',
        agent: 'policy_enforcer',
        status: 'needs_approval',
        message: 'High or critical production remediation requires human approval.',
      });

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
    emit({
      type: 'route',
      agent: 'main_agent',
      status: 'success',
      message: `Classified request as ${routePlan.kind}.`,
      route: routePlan.route,
      details: {
        firstAgent: routePlan.firstAgent,
        firstTool: routePlan.firstTool,
      },
    });

    const scanResult = await this.executeTool(routePlan.firstTool, 'scan', {
      target: request.target ?? this.defaultTargetFor(routePlan.kind),
      prompt: request.prompt,
      routeKind: routePlan.kind,
    }, emit);
    const cveResult = await this.executeTool('cve_lookup_tool', 'lookup', {
      cve: 'CVE-2024-12345',
      severity: request.severity ?? 'high',
    }, emit);
    const remediationResult = await this.executeTool('remediation_decision_tool', 'selectStrategy', {
      finding: cveResult.data,
      environment: request.environment ?? 'development',
    }, emit);
    const auditResult = await this.executeTool('audit_logger_tool', 'writeAuditEvent', {
      event: 'mock_remediation_flow',
      prompt: request.prompt,
      route: routePlan.route,
    }, emit);
    const verificationResult = await this.executeTool('verification_scan_tool', 'verifyFix', {
      routeKind: routePlan.kind,
      remediation: remediationResult.data,
    }, emit);
    const notificationResult = await this.executeTool('notification_tool', 'sendDigest', {
      route: routePlan.route,
      verification: verificationResult.data,
    }, emit);

    const result = {
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
        this.toolStep(routePlan.firstAgent, routePlan.firstTool, 'scan', scanResult),
        {
          agent: 'cve_intelligence_agent',
          tool: 'cve_lookup_tool',
          status: cveResult.status,
          summary: 'cve_lookup_tool.lookup completed.',
          data: cveResult.data,
        },
        {
          agent: 'decision_remediation_agent',
          tool: 'remediation_decision_tool',
          status: remediationResult.status,
          summary: 'Selected upgrade strategy and simulated PR creation.',
          data: remediationResult.data,
        },
        {
          agent: 'decision_remediation_agent',
          tool: 'audit_logger_tool',
          status: auditResult.status,
          summary: 'Audit event written.',
          data: auditResult.data,
        },
        {
          agent: 'verification_agent',
          tool: 'verification_scan_tool',
          status: verificationResult.status,
          summary: 'Targeted verification scan passed.',
          data: verificationResult.data,
        },
        {
          agent: 'notification_reporting_agent',
          tool: 'notification_tool',
          status: notificationResult.status,
          summary: 'Mock security digest sent and report generated.',
          data: notificationResult.data,
        },
      ],
      message: 'Mock AVRC agentic remediation flow completed.',
    };

    emit({
      type: 'complete',
      agent: 'main_agent',
      status: result.status,
      message: result.message,
      route: result.route,
    });

    return result;
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

  toolStep(agent, tool, operation, result) {
    return {
      agent,
      tool,
      status: result.status,
      summary: `${tool}.${operation} completed.`,
      data: result.data,
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

  async executeTool(toolName, operation, payload, emit = () => {}) {
    const tool = this.config.tools.find((entry) => entry.name === toolName);
    if (!tool || tool.type !== 'api') {
      emit({
        type: 'tool',
        agent: this.agentForTool(toolName),
        tool: toolName,
        operation,
        status: 'mock-fallback',
        message: `${toolName}.${operation} is not configured as an API service. Using fallback.`,
      });
      return this.mockToolResult(toolName, operation, payload, 'Tool is not configured as an API service.');
    }

    const endpoint = tool.endpoints?.[operation] ?? tool.endpoints?.scan ?? '/';
    const url = `${tool.baseUrl}${endpoint}`;
    const timeoutMs = tool.timeoutMs ?? 30000;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      emit({
        type: 'tool',
        agent: this.agentForTool(toolName),
        tool: toolName,
        operation,
        status: 'running',
        message: `Calling ${toolName}.${operation}.`,
        details: { url },
      });

      const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ operation, params: payload }),
        signal: controller.signal,
      });

      const data = await response.json();
      if (!response.ok) {
        emit({
          type: 'tool',
          agent: this.agentForTool(toolName),
          tool: toolName,
          operation,
          status: 'error',
          message: `${toolName}.${operation} returned HTTP ${response.status}.`,
          details: { url },
        });

        return {
          status: 'error',
          data: {
            tool: toolName,
            operation,
            url,
            error: data,
          },
        };
      }

      emit({
        type: 'tool',
        agent: this.agentForTool(toolName),
        tool: toolName,
        operation,
        status: data.status ?? 'success',
        message: `${toolName}.${operation} completed.`,
        details: { url },
      });

      return {
        status: data.status ?? 'success',
        data: {
          source: url,
          ...data,
        },
      };
    } catch (error) {
      if (toolName === 'audit_logger_tool') {
        const localAudit = await this.writeAuditEvent(payload);
        emit({
          type: 'tool',
          agent: this.agentForTool(toolName),
          tool: toolName,
          operation,
          status: 'local-fallback',
          message: `${toolName}.${operation} failed remotely; wrote local audit event.`,
          details: {
            reason: error instanceof Error ? error.message : 'Unknown API error',
          },
        });

        return {
          status: 'success',
          data: {
            source: 'local-fallback',
            reason: error instanceof Error ? error.message : 'Unknown API error',
            ...localAudit,
          },
        };
      }

      emit({
        type: 'tool',
        agent: this.agentForTool(toolName),
        tool: toolName,
        operation,
        status: 'mock-fallback',
        message: `${toolName}.${operation} failed remotely; using mock fallback.`,
        details: {
          reason: error instanceof Error ? error.message : 'Unknown API error',
        },
      });

      return this.mockToolResult(
        toolName,
        operation,
        payload,
        error instanceof Error ? error.message : 'Unknown API error',
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  mockToolResult(toolName, operation, payload, reason) {
    return {
      status: 'success',
      data: {
        source: 'mock-fallback',
        reason,
        tool: toolName,
        operation,
        received: payload,
        data: {
          findings: [
            {
              cve: 'CVE-2024-12345',
              severity: payload?.severity ?? 'high',
              package: 'demo-package',
            },
          ],
        },
      },
    };
  }

  agentForTool(toolName) {
    const mapping = {
      defectdojo_api_tool: 'defectdojo_api_agent',
      pipeline_lint_tool: 'ci_cd_pipeline_agent',
      container_scan_tool: 'container_image_agent',
      dependency_patch_tool: 'dependency_agent',
      os_pkg_upgrade_tool: 'os_vulnerability_agent',
      dynamic_software_scan_tool: 'runtime_agent',
      cve_lookup_tool: 'cve_intelligence_agent',
      remediation_decision_tool: 'decision_remediation_agent',
      audit_logger_tool: 'decision_remediation_agent',
      git_ops_tool: 'decision_remediation_agent',
      verification_scan_tool: 'verification_agent',
      notification_tool: 'notification_reporting_agent',
      report_generator_tool: 'notification_reporting_agent',
      report_generator_tool_shared: 'notification_reporting_agent',
    };

    return mapping[toolName] ?? 'main_agent';
  }
}

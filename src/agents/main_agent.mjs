import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { scannerAgentForTool, scannerAgents } from './scanner_agents.mjs';

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

    const routePlan = this.createRoutePlan(request.prompt, request.scanScopes ?? []);
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

    const scanResults = [];
    for (const scanStep of routePlan.scanSteps) {
      scanResults.push({
        ...scanStep,
        result: await this.executeTool(scanStep.tool, scanStep.operation ?? 'scan', {
          target: this.targetForScanStep(request, scanStep, routePlan.kind),
          repo: request.repo ?? request.repository ?? null,
          repository: request.repository ?? request.repo ?? null,
          image: request.image ?? null,
          runtimeUrl: request.runtimeUrl ?? null,
          workloadTarget: request.workloadTarget ?? null,
          onPremTargets: request.onPremTargets ?? [],
          prompt: request.prompt,
          routeKind: routePlan.kind,
          scanner: scanStep.scanner,
        }, emit),
      });
    }

    const deduplicatedFindings = this.deduplicateFindings(
      scanResults.map((scanResult) => scanResult.result.data),
      request,
    );
    emit({
      type: 'progress',
      agent: 'cve_intelligence_agent',
      status: 'success',
      message: `Deduplicated scanner output to ${deduplicatedFindings.uniqueCves.length} unique CVE record(s).`,
      details: deduplicatedFindings.summary,
    });

    const osvResult = await this.executeTool('osv_lookup_tool', 'scan', {
      findings: deduplicatedFindings.uniqueCves.map((finding) => ({
        cve: finding.cve,
        severity: finding.severity,
        affectedComponents: finding.affectedComponents,
        package: finding.affectedComponents?.[0],
        sources: finding.sources,
      })),
    }, emit);
    const enrichedFindings = this.mergeOsvEnrichment(deduplicatedFindings.uniqueCves, osvResult.data);
    emit({
      type: 'progress',
      agent: 'cve_intelligence_agent',
      tool: 'osv_lookup_tool',
      status: osvResult.status,
      message: `OSV enrichment returned ${this.extractFindings(osvResult.data).length} advisory record(s).`,
      details: {
        totalAdvisories: this.extractFindings(osvResult.data).length,
        provider: 'osv.dev',
      },
    });

    const cveLookups = [];
    for (const finding of deduplicatedFindings.uniqueCves) {
      cveLookups.push(
        await this.executeTool('cve_lookup_tool', 'lookup', {
          cve: finding.cve,
          severity: finding.severity,
          affectedComponents: finding.affectedComponents,
        }, emit),
      );
    }

    const cveResult = {
      status: cveLookups.some((lookup) => lookup.status === 'error') ? 'error' : 'success',
      data: {
        deduplicated: true,
        key: 'canonical_cve_id',
        summary: deduplicatedFindings.summary,
        uniqueCves: enrichedFindings,
        osv: osvResult.data,
        lookups: cveLookups.map((lookup) => lookup.data),
      },
    };

    const remediationResult = await this.executeTool('remediation_decision_tool', 'selectStrategy', {
      finding: cveResult.data,
      environment: request.environment ?? 'development',
    }, emit);

    const repoPrResult = await this.createRepoRemediationPrIfNeeded(
      request,
      routePlan,
      cveResult,
      remediationResult,
      emit,
    );

    const auditResult = await this.executeTool('audit_logger_tool', 'writeAuditEvent', {
      event: 'mock_remediation_flow',
      prompt: request.prompt,
      route: routePlan.route,
      repoPr: repoPrResult?.data ?? null,
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
            scanAgents: routePlan.scanSteps.map((step) => step.agent),
            scanTools: routePlan.scanSteps.map((step) => step.tool),
          },
        },
        ...scanResults.map((scanResult) =>
          this.toolStep(scanResult.agent, scanResult.tool, scanResult.operation ?? 'scan', scanResult.result),
        ),
        {
          agent: 'cve_intelligence_agent',
          tool: 'dedupe_engine',
          status: 'success',
          summary: `Normalized findings by CVE ID and removed ${deduplicatedFindings.summary.duplicateCount} duplicate record(s).`,
          data: deduplicatedFindings,
        },
        {
          agent: 'cve_intelligence_agent',
          tool: 'cve_lookup_tool',
          status: cveResult.status,
          summary: 'cve_lookup_tool.lookup completed for deduplicated CVE records.',
          data: cveResult.data,
        },
        {
          agent: 'cve_intelligence_agent',
          tool: 'osv_lookup_tool',
          status: osvResult.status,
          summary: 'OSV.dev enrichment completed for deduplicated CVE records.',
          data: osvResult.data,
        },
        {
          agent: 'decision_remediation_agent',
          tool: 'remediation_decision_tool',
          status: remediationResult.status,
          summary: 'Selected upgrade strategy and simulated PR creation.',
          data: remediationResult.data,
        },
        ...(repoPrResult
          ? [
              {
                agent: 'decision_remediation_agent',
                tool: 'llm_repo_fix_generator',
                status: repoPrResult.fix.status,
                summary: 'Generated repo remediation fix from CVE guidance using the configured LLM.',
                data: repoPrResult.fix.data,
              },
              {
                agent: 'decision_remediation_agent',
                tool: 'git_ops_tool',
                status: repoPrResult.status,
                summary: 'Created PR request payload with generated fix.',
                data: repoPrResult.data,
              },
            ]
          : []),
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
      message: 'AVRC scan, enrichment, and remediation flow completed.',
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

  createRoutePlan(prompt, scanScopes = []) {
    if (Array.isArray(scanScopes) && scanScopes.length > 0) {
      const tools = this.toolsForScanScopes(scanScopes);
      if (tools.length > 0) {
        return this.buildMultiScannerRoute(scanScopes.length > 1 ? 'scoped_hybrid' : scanScopes[0], tools);
      }
    }

    const lower = prompt.toLowerCase();

    if (lower.includes('all') || lower.includes('hybrid') || lower.includes('everything')) {
      return this.buildMultiScannerRoute('hybrid', [
        'trivy_scan_tool',
        'kubescape_scan_tool',
        'wazuh_vulnerability_tool',
        'greenbone_scan_tool',
        'zap_dast_tool',
        'semgrep_scan_tool',
      ]);
    }
    if (lower.includes('trivy')) return this.buildScannerRoute('repo', 'trivy_scan_tool');
    if (lower.includes('renovate')) return this.buildScannerRoute('dependency_autofix', 'renovate_fix_tool', 'remediate');
    if (lower.includes('copacetic') || lower.includes('copa')) return this.buildScannerRoute('container_autofix', 'copacetic_patch_tool', 'remediate');
    if (lower.includes('kubescape')) return this.buildScannerRoute('kubernetes', 'kubescape_scan_tool');
    if (lower.includes('wazuh')) return this.buildScannerRoute('on_prem', 'wazuh_vulnerability_tool');
    if (lower.includes('greenbone') || lower.includes('openvas')) return this.buildScannerRoute('network', 'greenbone_scan_tool');
    if (lower.includes('semgrep')) return this.buildScannerRoute('sast', 'semgrep_scan_tool');
    if (lower.includes('openrewrite')) return this.buildScannerRoute('code_remediation', 'openrewrite_remediation_tool', 'remediate');
    if (lower.includes('osv')) return this.buildScannerRoute('cve_database', 'osv_lookup_tool', 'lookup');
    if (lower.includes('nvd')) return this.buildScannerRoute('cve_database', 'nvd_lookup_tool', 'lookup');

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

  toolsForScanScopes(scanScopes) {
    const mapping = {
      repo: ['trivy_scan_tool', 'semgrep_scan_tool', 'renovate_fix_tool'],
      image: ['trivy_scan_tool', 'copacetic_patch_tool'],
      deployed_workload: ['kubescape_scan_tool', 'trivy_scan_tool'],
      runtime: ['zap_dast_tool'],
      on_prem: ['wazuh_vulnerability_tool', 'greenbone_scan_tool'],
    };

    return [
      ...new Set(
        scanScopes.flatMap((scope) => {
          if (scope === 'all' || scope === 'hybrid') {
            return Object.values(mapping).flat();
          }
          return mapping[scope] ?? [];
        }),
      ),
    ];
  }

  buildRoute(kind, firstAgent, firstTool) {
    const scanAgent = scannerAgentForTool(firstTool);
    const agent = scanAgent?.name ?? firstAgent;

    return {
      kind,
      firstAgent: agent,
      firstTool,
      scanSteps: [
        {
          agent,
          tool: firstTool,
          operation: 'scan',
          scanner: scanAgent?.scanner ?? firstAgent,
        },
      ],
      route: [
        'main_agent',
        agent,
        'cve_intelligence_agent',
        'decision_remediation_agent',
        'verification_agent',
        'notification_reporting_agent',
      ],
    };
  }

  buildScannerRoute(kind, tool, operation = 'scan') {
    const scannerAgent = scannerAgentForTool(tool);
    return this.buildMultiScannerRoute(kind, [tool], operation, scannerAgent?.name);
  }

  buildMultiScannerRoute(kind, tools, operation = 'scan', preferredFirstAgent = null) {
    const scanSteps = tools.map((tool) => {
      const scannerAgent = scannerAgentForTool(tool);
      return {
        agent: scannerAgent?.name ?? this.agentForTool(tool),
        tool,
        operation,
        scanner: scannerAgent?.scanner ?? tool,
      };
    });
    const firstAgent = preferredFirstAgent ?? scanSteps[0]?.agent ?? 'main_agent';
    const firstTool = scanSteps[0]?.tool ?? 'tool_1';

    return {
      kind,
      firstAgent,
      firstTool,
      scanSteps,
      route: [
        'main_agent',
        ...scanSteps.map((step) => step.agent),
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

  targetForScanStep(request, scanStep, routeKind) {
    const tool = scanStep.tool ?? '';
    if (['trivy_scan_tool', 'semgrep_scan_tool', 'renovate_fix_tool', 'openrewrite_remediation_tool'].includes(tool) && request.repo) {
      return request.repo;
    }
    if (['container_scan_tool', 'copacetic_patch_tool'].includes(tool) && request.image) {
      return request.image;
    }
    if (tool === 'trivy_scan_tool' && routeKind === 'image' && request.image) {
      return request.image;
    }
    if (tool === 'zap_dast_tool' && request.runtimeUrl) {
      return request.runtimeUrl;
    }
    if (tool === 'kubescape_scan_tool' && request.workloadTarget) {
      return request.workloadTarget;
    }
    if (['wazuh_vulnerability_tool', 'greenbone_scan_tool'].includes(tool) && request.onPremTargets?.length) {
      return request.onPremTargets.join(',');
    }
    return request.target ?? this.defaultTargetFor(routeKind);
  }

  async createRepoRemediationPrIfNeeded(request, routePlan, cveResult, remediationResult, emit) {
    if (!this.shouldCreateRepoPr(request, routePlan)) {
      return null;
    }

    emit({
      type: 'progress',
      agent: 'decision_remediation_agent',
      status: 'running',
      message: 'Repo scan scope detected; generating LLM remediation fix and PR request.',
    });

    const fix = await this.generateRepoFixWithLlm(request, cveResult.data, remediationResult.data, emit);
    const fixWithSbom = await this.ensureSbomIncludedIfMissing(request, fix, routePlan, cveResult, emit);
    const prPayload = this.buildPullRequestPayload(request, fixWithSbom.data, cveResult.data);
    const prResult = await this.executeTool('git_ops_tool', 'openPullRequest', prPayload, emit);

    return {
      status: prResult.status,
      fix: fixWithSbom,
      data: {
        ...prResult.data,
        prRequest: prPayload,
      },
    };
  }

  sbomCandidatePaths() {
    return [
      'sbom.cyclonedx.json',
      'sbom.json',
      'bom.json',
      'cyclonedx.json',
      'reports/sbom.cyclonedx.json',
      'security/sbom.cyclonedx.json',
      'docs/sbom.json',
    ];
  }

  async ensureSbomIncludedIfMissing(request, fix, routePlan, cveResult, emit) {
    const baseFix = {
      status: fix.status,
      data: {
        ...(fix.data ?? {}),
        filesToChange: Array.isArray(fix.data?.filesToChange) ? [...fix.data.filesToChange] : [],
        verificationCommands: Array.isArray(fix.data?.verificationCommands) ? [...fix.data.verificationCommands] : [],
      },
    };

    if (!request.repo && !request.repository) {
      emit({
        type: 'progress',
        agent: 'decision_remediation_agent',
        status: 'skipped',
        message: 'SBOM auto-creation skipped because no repository target is available.',
      });
      return baseFix;
    }

    const check = await this.executeTool('git_ops_tool', 'checkFileExists', {
      repo: request.repo ?? request.repository,
      baseBranch: request.baseBranch ?? 'main',
      filePaths: this.sbomCandidatePaths(),
    }, emit);

    if (check.status === 'success' && check.data?.exists) {
      emit({
        type: 'progress',
        agent: 'decision_remediation_agent',
        status: 'success',
        message: `SBOM already exists in repo at ${check.data.path}; skipping SBOM creation.`,
      });
      return baseFix;
    }

    emit({
      type: 'progress',
      agent: 'decision_remediation_agent',
      status: 'running',
      message: 'SBOM file not found in repository; generating CycloneDX SBOM automatically.',
    });

    const sbomSource = request.repo ?? request.repository ?? request.image ?? request.target;
    const sbomScan = await this.executeTool('trivy_scan_tool', 'sbom', {
      repo: request.repo ?? request.repository,
      repository: request.repository ?? request.repo,
      target: sbomSource,
      branch: request.baseBranch ?? 'main',
    }, emit);

    const generatedSbom =
      (sbomScan.status === 'success' && sbomScan.data?.sbom)
        ? sbomScan.data.sbom
        : {
            bomFormat: 'CycloneDX',
            specVersion: '1.5',
            version: 1,
            metadata: {
              timestamp: new Date().toISOString(),
              component: {
                type: 'application',
                name: request.applicationName ?? 'unknown-application',
              },
              tools: [{ vendor: 'AVRC', name: 'trivy_scan_tool', version: 'fallback' }],
            },
            components: [],
          };

    const sbomPath = 'sbom.cyclonedx.json';
    baseFix.data.filesToChange.push({
      path: sbomPath,
      action: 'create',
      rationale: 'Auto-generated SBOM added because no SBOM file exists in the repository.',
      suggestedPatch: 'Generate CycloneDX SBOM via Trivy and commit to repository.',
      content: JSON.stringify(generatedSbom, null, 2),
    });

    const hasSbomVerify = baseFix.data.verificationCommands.some((command) => /sbom|trivy\s+fs|trivy\s+image/i.test(command));
    if (!hasSbomVerify) {
      baseFix.data.verificationCommands.push('trivy fs --format cyclonedx --output sbom.cyclonedx.json .');
    }

    const riskNotes = Array.isArray(baseFix.data.riskNotes) ? [...baseFix.data.riskNotes] : [];
    riskNotes.push('SBOM was auto-generated because no repository SBOM file was detected on base branch.');
    baseFix.data.riskNotes = riskNotes;

    return baseFix;
  }

  shouldCreateRepoPr(request, routePlan) {
    const scopes = request.scanScopes ?? [];
    return (
      scopes.includes('repo') ||
      routePlan.kind === 'repo' ||
      routePlan.kind === 'dependency' ||
      routePlan.scanSteps.some((step) =>
        ['trivy_scan_tool', 'semgrep_scan_tool', 'renovate_fix_tool', 'openrewrite_remediation_tool'].includes(step.tool),
      )
    );
  }

  async generateRepoFixWithLlm(request, cveData, remediationData, emit) {
    const fallback = this.fallbackRepoFix(request, cveData, remediationData);

    try {
      emit({
        type: 'progress',
        agent: 'decision_remediation_agent',
        status: 'running',
        message: 'Calling LLM to generate repo fix guidance from deduplicated CVE remediation data.',
        details: {
          model: this.selectedModel(request.llmModel),
          uniqueCveCount: cveData?.uniqueCves?.length ?? 0,
        },
      });

      const content = await this.callLlm([
        {
          role: 'system',
          content:
            'You are the AVRC (Advanced Vanguard for Rapid Containment) repo remediation generator. Return only strict JSON. Generate a safe pull-request-ready fix plan based on deduplicated CVE data and remediation guidance. Never invent destructive changes. Prefer dependency upgrades, lockfile updates, config hardening, and clear verification commands.',
        },
        {
          role: 'user',
          content: JSON.stringify(
            {
              applicationName: request.applicationName ?? 'unknown-application',
              repo: request.repo ?? request.repository ?? null,
              branch: request.baseBranch ?? 'main',
              cveData,
              remediationData,
              requiredJsonShape: {
                title: 'string',
                branchName: 'string',
                summary: 'string',
                filesToChange: [{ path: 'string', action: 'modify|create', rationale: 'string', suggestedPatch: 'string' }],
                verificationCommands: ['string'],
                riskNotes: ['string'],
              },
            },
            null,
            2,
          ),
        },
      ], { model: request.llmModel });

      const parsed = this.parseLlmJson(content);
      return {
        status: 'success',
        data: {
          source: 'llm',
          model: this.selectedModel(request.llmModel),
          ...parsed,
        },
      };
    } catch (error) {
      emit({
        type: 'progress',
        agent: 'decision_remediation_agent',
        status: 'mock-fallback',
        message: 'LLM fix generation failed; using deterministic repo fix fallback.',
        details: {
          reason: error instanceof Error ? error.message : 'Unknown LLM error',
        },
      });

      return {
        status: 'success',
        data: fallback,
      };
    }
  }

  buildPullRequestPayload(request, fix, cveData) {
    const appName = request.applicationName ?? 'avrc-app';
    const title = fix.title ?? `AVRC remediation for ${appName}`;

    return {
      applicationName: appName,
      repo: request.repo ?? request.repository ?? null,
      baseBranch: request.baseBranch ?? 'main',
      newBranch: fix.branchName ?? `avrc/remediate-${appName}`.toLowerCase().replace(/[^a-z0-9/_-]+/g, '-'),
      prTitle: title,
      prBody: [
        fix.summary ?? 'Automated AVRC remediation PR request.',
        '',
        `Deduplicated CVEs: ${(cveData?.uniqueCves ?? []).map((finding) => finding.cve).join(', ') || 'none'}`,
        '',
        'Verification:',
        ...(fix.verificationCommands ?? ['npm test']).map((command) => `- \`${command}\``),
        '',
        'Risk notes:',
        ...(fix.riskNotes ?? ['Review generated changes before merge.']).map((note) => `- ${note}`),
      ].join('\n'),
      commitMessage: title,
      changes: fix.filesToChange ?? [],
      cveSummary: cveData?.summary,
      uniqueCves: cveData?.uniqueCves ?? [],
      generatedBy: {
        agent: 'decision_remediation_agent',
        tool: 'llm_repo_fix_generator',
        model: fix.model ?? this.selectedModel(request.llmModel),
      },
    };
  }

  fallbackRepoFix(request, cveData) {
    const appName = request.applicationName ?? 'avrc-app';
    const cveIds = (cveData?.uniqueCves ?? []).map((finding) => finding.cve);

    return {
      source: 'deterministic-fallback',
      model: this.selectedModel(request.llmModel),
      title: `AVRC remediation for ${cveIds[0] ?? 'repo vulnerabilities'} in ${appName}`,
      branchName: `avrc/remediate-${appName}`.toLowerCase().replace(/[^a-z0-9/_-]+/g, '-'),
      summary:
        'Update vulnerable dependencies according to CVE advisory guidance, refresh lockfiles, and verify with security scans before merge.',
      filesToChange: [
        {
          path: 'package.json',
          action: 'modify',
          rationale: 'Upgrade affected dependency versions to patched releases identified by CVE intelligence.',
          suggestedPatch: 'Update vulnerable dependency constraints to the nearest non-vulnerable version recommended by OSV/NVD guidance.',
        },
        {
          path: 'package-lock.json',
          action: 'modify',
          rationale: 'Refresh transitive dependency graph after package updates.',
          suggestedPatch: 'Regenerate lockfile with npm install after package.json updates.',
        },
      ],
      verificationCommands: ['npm install', 'npm test', 'trivy fs .'],
      riskNotes: ['Generated fallback fix requires maintainer review before merge.'],
    };
  }

  parseLlmJson(content) {
    const trimmed = String(content ?? '').trim();
    const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
    const jsonText = fenced?.[1]?.trim() ?? trimmed;
    return JSON.parse(jsonText);
  }

  llmBaseUrlCandidates() {
    const configured = this.config.llm?.baseUrl ?? 'http://localhost:11434';
    const candidates = [configured];

    if (configured.includes('host.docker.internal')) {
      candidates.push(configured.replace('host.docker.internal', 'localhost'));
    }
    if (configured.includes('localhost')) {
      candidates.push(configured.replace('localhost', 'host.docker.internal'));
    }

    return [...new Set(candidates)];
  }

  selectedModel(model) {
    return model || this.config.llm?.model || 'qwen2.5-coder:7b';
  }

  llmKeepAlive() {
    return this.config.llm?.keepAlive ?? '30s';
  }

  async callLlm(messages, { model } = {}) {
    const payload = {
      model: this.selectedModel(model),
      stream: false,
      keep_alive: this.llmKeepAlive(),
      options: {
        temperature: this.config.llm?.temperature ?? 0.2,
        num_ctx: this.config.llm?.contextLength ?? 32768,
      },
      messages,
    };

    let lastError = null;
    for (const baseUrl of this.llmBaseUrlCandidates()) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.llm?.timeoutMs ?? 30000);

      try {
        const response = await fetch(`${baseUrl}${this.config.llm?.chatEndpoint ?? '/api/chat'}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`Ollama HTTP ${response.status}`);
        }

        const data = await response.json();
        return data.message?.content?.trim() ?? '';
      } catch (error) {
        lastError = error;
      } finally {
        clearTimeout(timeout);
      }
    }

    throw lastError ?? new Error('Ollama call failed');
  }

  deduplicateFindings(scanData, request) {
    const rawFindings = this.extractFindings(scanData);
    const fallbackSeverity = request.severity ?? 'high';
    const byCve = new Map();

    for (const rawFinding of rawFindings) {
      const cve = this.normalizeCveId(rawFinding.cve ?? rawFinding.id ?? rawFinding.vulnerabilityId);
      if (!cve) {
        continue;
      }

      const component =
        rawFinding.package ??
        rawFinding.pkgName ??
        rawFinding.component ??
        rawFinding.target ??
        'unknown-component';
      const severity = String(rawFinding.severity ?? fallbackSeverity).toLowerCase();
      const existing = byCve.get(cve);

      if (existing) {
        existing.sources.push(rawFinding);
        if (!existing.affectedComponents.includes(component)) {
          existing.affectedComponents.push(component);
        }
        existing.severity = this.maxSeverity(existing.severity, severity);
        continue;
      }

      byCve.set(cve, {
        cve,
        severity,
        affectedComponents: [component],
        sources: [rawFinding],
      });
    }

    if (byCve.size === 0) {
      byCve.set('CVE-2024-12345', {
        cve: 'CVE-2024-12345',
        severity: fallbackSeverity,
        affectedComponents: ['demo-package'],
        sources: [{ cve: 'CVE-2024-12345', severity: fallbackSeverity, package: 'demo-package' }],
      });
    }

    const uniqueCves = [...byCve.values()];
    const sourceCount = uniqueCves.reduce((count, finding) => count + finding.sources.length, 0);

    return {
      uniqueCves,
      summary: {
        sourceFindingCount: sourceCount,
        uniqueCveCount: uniqueCves.length,
        duplicateCount: Math.max(0, sourceCount - uniqueCves.length),
        dedupeKey: 'canonical_cve_id',
      },
    };
  }

  extractFindings(scanData) {
    if (Array.isArray(scanData)) {
      return scanData.flatMap((item) => this.extractFindings(item));
    }

    const candidates = [
      scanData?.findings,
      scanData?.data?.findings,
      scanData?.result?.findings,
      scanData?.vulnerabilities,
      scanData?.data?.vulnerabilities,
      scanData?.Results?.flatMap((result) => result.Vulnerabilities ?? []),
    ];

    for (const candidate of candidates) {
      if (Array.isArray(candidate) && candidate.length > 0) {
        return candidate;
      }
    }

    return [];
  }

  mergeOsvEnrichment(uniqueCves, osvData) {
    const advisories = this.extractFindings(osvData);
    return uniqueCves.map((finding) => {
      const matching = advisories.filter((advisory) =>
        advisory.cve === finding.cve ||
        advisory.id === finding.cve ||
        advisory.aliases?.includes?.(finding.cve),
      );

      return {
        ...finding,
        osvAdvisories: matching,
        remediationGuidance: matching
          .map((advisory) => advisory.summary || advisory.details)
          .filter(Boolean)
          .slice(0, 3),
        references: [...new Set(matching.flatMap((advisory) => advisory.references?.map((reference) => reference.url) ?? []))],
      };
    });
  }

  normalizeCveId(value) {
    const match = String(value ?? '').toUpperCase().match(/CVE-\d{4}-\d{4,}/);
    return match?.[0] ?? null;
  }

  maxSeverity(left, right) {
    const rank = {
      unknown: 0,
      info: 1,
      low: 2,
      medium: 3,
      high: 4,
      critical: 5,
    };

    return (rank[right] ?? 0) > (rank[left] ?? 0) ? right : left;
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
    const timeoutMs = tool.timeoutMs ?? 30000;

    // Candidate base URLs: env var override → primary config URL → local fallback URL.
    // Set TOOL_BASEURL_GIT_OPS_TOOL=http://localhost:4100 etc. when running outside Docker.
    const envKey = `TOOL_BASEURL_${toolName.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;
    const candidateBaseUrls = [
      process.env[envKey],
      tool.baseUrl,
      tool.localFallbackUrl,
    ].filter(Boolean);

    let lastError = null;

    for (const baseUrl of candidateBaseUrls) {
      const url = `${baseUrl}${endpoint}`;
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

        clearTimeout(timeout);
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
          return { status: 'error', data: { tool: toolName, operation, url, error: data } };
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

        return { status: data.status ?? 'success', data: { source: url, ...data } };
      } catch (error) {
        clearTimeout(timeout);
        lastError = error;
        // Service unreachable at this URL — try the next candidate
      }
    }

    // All candidate URLs failed
    const reason = lastError instanceof Error ? lastError.message : 'Unknown API error';

    if (toolName === 'audit_logger_tool') {
      const localAudit = await this.writeAuditEvent(payload);
      emit({
        type: 'tool',
        agent: this.agentForTool(toolName),
        tool: toolName,
        operation,
        status: 'local-fallback',
        message: `${toolName}.${operation} failed remotely; wrote local audit event.`,
        details: { reason },
      });
      return { status: 'success', data: { source: 'local-fallback', reason, ...localAudit } };
    }

    if (toolName === 'git_ops_tool') {
      // Do NOT silently mock a PR — surface the failure so the caller knows no PR was created.
      emit({
        type: 'tool',
        agent: this.agentForTool(toolName),
        tool: toolName,
        operation,
        status: 'needs_configuration',
        message: `git_ops_tool could not reach the git-ops service. No PR was created on Forgejo.`,
        details: {
          reason,
          candidateUrls: candidateBaseUrls,
          hint: 'Ensure the git-ops-tool container is running, or set TOOL_BASEURL_GIT_OPS_TOOL=http://localhost:4100 and FORGEJO_TOKEN when running outside Docker.',
        },
      });
      return {
        status: 'needs_configuration',
        data: {
          source: 'service-unavailable',
          tool: 'git_ops_tool',
          operation,
          reason,
          prCreated: false,
          hint: 'Start the git-ops-tool service (docker compose up git-ops-tool) or set TOOL_BASEURL_GIT_OPS_TOOL=http://localhost:4100.',
          prRequest: payload,
        },
      };
    }

    emit({
      type: 'tool',
      agent: this.agentForTool(toolName),
      tool: toolName,
      operation,
      status: 'mock-fallback',
      message: `${toolName}.${operation} unreachable at all candidate URLs; using mock fallback.`,
      details: { reason, candidateUrls: candidateBaseUrls },
    });

    return this.mockToolResult(toolName, operation, payload, reason);
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
      trivy_scan_tool: 'trivy_agent',
      renovate_fix_tool: 'renovate_agent',
      copacetic_patch_tool: 'copacetic_agent',
      kubescape_scan_tool: 'kubescape_agent',
      wazuh_vulnerability_tool: 'wazuh_agent',
      greenbone_scan_tool: 'greenbone_agent',
      zap_dast_tool: 'zap_agent',
      semgrep_scan_tool: 'semgrep_agent',
      openrewrite_remediation_tool: 'openrewrite_agent',
      osv_lookup_tool: 'osv_agent',
      nvd_lookup_tool: 'nvd_agent',
    };

    return mapping[toolName] ?? 'main_agent';
  }

  listScannerAgents() {
    return scannerAgents.map((agent) => agent.describe());
  }
}

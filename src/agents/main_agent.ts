import { PolicyEnforcer } from '../core/policy_enforcer.js';
import { AgentRequest, AgentResult, AgentStep } from '../types.js';
import {
  CiCdPipelineAgent,
  ContainerImageAgent,
  CveIntelligenceAgent,
  DecisionRemediationAgent,
  DefectDojoApiAgent,
  DependencyAgent,
  NotificationReportingAgent,
  OsVulnerabilityAgent,
  RuntimeAgent,
  VerificationAgent,
} from './specialized_agents.js';

type RouteKind = 'defectdojo' | 'pipeline' | 'container' | 'dependency' | 'os' | 'runtime';

export class MainAgent {
  constructor(private readonly policyEnforcer: PolicyEnforcer) {}

  async handle(request: AgentRequest): Promise<AgentResult> {
    if (this.policyEnforcer.requiresApproval(request)) {
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

    const routeKind = this.classify(request.prompt);
    const route = ['main_agent'];
    const steps: AgentStep[] = [
      {
        agent: 'main_agent',
        status: 'success',
        summary: `Classified request as ${routeKind}.`,
      },
    ];

    const firstAgent = this.agentFor(routeKind);
    route.push(firstAgent.name);
    steps.push(...(await firstAgent.handle(request)));

    const chain = [
      new CveIntelligenceAgent(),
      new DecisionRemediationAgent(),
      new VerificationAgent(),
      new NotificationReportingAgent(),
    ];

    for (const agent of chain) {
      route.push(agent.name);
      steps.push(...(await agent.handle(request)));
    }

    return {
      status: 'success',
      route,
      steps,
      message: 'Mock AVRC agentic remediation flow completed.',
    };
  }

  private classify(prompt: string): RouteKind {
    const lower = prompt.toLowerCase();
    if (lower.includes('defectdojo')) return 'defectdojo';
    if (lower.includes('pipeline') || lower.includes('github actions') || /\bci\b/.test(lower)) return 'pipeline';
    if (lower.includes('container') || lower.includes('docker') || lower.includes('image')) return 'container';
    if (lower.includes('os') || lower.includes('apt') || lower.includes('yum') || lower.includes('apk')) return 'os';
    if (lower.includes('runtime') || lower.includes('dast') || lower.includes('zap')) return 'runtime';
    return 'dependency';
  }

  private agentFor(routeKind: RouteKind) {
    switch (routeKind) {
      case 'defectdojo':
        return new DefectDojoApiAgent();
      case 'pipeline':
        return new CiCdPipelineAgent();
      case 'container':
        return new ContainerImageAgent();
      case 'os':
        return new OsVulnerabilityAgent();
      case 'runtime':
        return new RuntimeAgent();
      case 'dependency':
        return new DependencyAgent();
    }
  }
}

import { MainAgent } from '../agents/main_agent.js';
import { AgentRequest, AgentResult } from '../types.js';
import { PolicyEnforcer } from './policy_enforcer.js';

export class AgentRunner {
  private readonly policyEnforcer = new PolicyEnforcer();
  private readonly mainAgent = new MainAgent(this.policyEnforcer);

  async run(request: AgentRequest): Promise<AgentResult> {
    const promptPolicy = this.policyEnforcer.validatePrompt(request.prompt);
    if (!promptPolicy.allowed) {
      return {
        status: 'blocked',
        route: ['policy_enforcer'],
        steps: [
          {
            agent: 'policy_enforcer',
            status: 'blocked',
            summary: promptPolicy.reason ?? 'Prompt blocked by policy.',
          },
        ],
        message: 'Request blocked by policy.',
      };
    }

    return this.mainAgent.handle(request);
  }
}

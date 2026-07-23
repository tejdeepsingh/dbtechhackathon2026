import { resolve, sep } from 'node:path';
import { AgentRequest } from '../types.js';
import { getRootDir, loadConfig } from './config_loader.js';

export class PolicyEnforcer {
  private readonly config = loadConfig();

  validatePrompt(prompt: string): { allowed: boolean; reason?: string } {
    const policy = this.config.policies.preventHarmfulContent;
    if (!policy.enabled) {
      return { allowed: true };
    }

    const lowerPrompt = prompt.toLowerCase();
    const blocked = policy.blockedKeywords.find((keyword) =>
      lowerPrompt.includes(keyword.toLowerCase()),
    );

    return blocked
      ? { allowed: false, reason: `Prompt contains blocked keyword: ${blocked}` }
      : { allowed: true };
  }

  validateWritePath(path: string): { allowed: boolean; reason?: string } {
    const policy = this.config.policies.restrictFileSystemWrite;
    if (!policy.enabled) {
      return { allowed: true };
    }

    const root = resolve(getRootDir(), policy.allowedRoot);
    const target = resolve(getRootDir(), path);
    const insideAllowedRoot = target === root || target.startsWith(`${root}${sep}`);

    return insideAllowedRoot
      ? { allowed: true }
      : { allowed: false, reason: `Writes are restricted to ${policy.allowedRoot}/` };
  }

  requiresApproval(request: AgentRequest): boolean {
    const policy = this.config.policies.remediationApprovalGate;
    if (!policy.enabled) {
      return false;
    }

    const severity = request.severity?.toLowerCase();
    const environment = request.environment?.toLowerCase();

    return Boolean(
      severity &&
        environment &&
        policy.requiresApprovalForSeverities.includes(severity) &&
        policy.requiresApprovalInEnvironments.includes(environment) &&
        !request.approved,
    );
  }
}

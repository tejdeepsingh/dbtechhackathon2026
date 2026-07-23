import { AgentStep, ToolResult } from '../types.js';
import { getTool } from '../tools/tool_registry.js';

export abstract class BaseAgent {
  constructor(public readonly name: string) {}

  protected async runTool(
    toolName: string,
    operation: string,
    params: Record<string, unknown> = {},
  ): Promise<{ result: ToolResult; step: AgentStep }> {
    const result = await getTool(toolName).execute({ operation, params });

    return {
      result,
      step: {
        agent: this.name,
        tool: toolName,
        status: result.status,
        summary:
          result.status === 'success'
            ? `${toolName}.${operation} completed`
            : result.error ?? `${toolName}.${operation} failed`,
        data: result.data,
      },
    };
  }
}

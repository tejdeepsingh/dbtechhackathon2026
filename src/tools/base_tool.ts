import { ToolRequest, ToolResult } from '../types.js';

export abstract class BaseTool {
  constructor(public readonly name: string) {}

  async execute(request: ToolRequest): Promise<ToolResult> {
    try {
      const data = await this.run(request.operation, request.params ?? {});
      return {
        status: 'success',
        tool: this.name,
        operation: request.operation,
        data,
      };
    } catch (error) {
      return {
        status: 'error',
        tool: this.name,
        operation: request.operation,
        error: error instanceof Error ? error.message : 'Unknown tool error',
      };
    }
  }

  protected abstract run(
    operation: string,
    params: Record<string, unknown>,
  ): Promise<unknown>;
}

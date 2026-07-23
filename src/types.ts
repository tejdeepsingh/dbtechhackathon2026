export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface ToolRequest {
  operation: string;
  params?: Record<string, unknown>;
}

export interface ToolResult {
  status: 'success' | 'blocked' | 'needs_approval' | 'error';
  tool: string;
  operation: string;
  data?: unknown;
  error?: string;
}

export interface AgentRequest {
  prompt: string;
  target?: string;
  environment?: string;
  severity?: Severity;
  approved?: boolean;
}

export interface AgentStep {
  agent: string;
  tool?: string;
  status: string;
  summary: string;
  data?: unknown;
}

export interface AgentResult {
  status: 'success' | 'blocked' | 'needs_approval' | 'error';
  route: string[];
  steps: AgentStep[];
  message: string;
}

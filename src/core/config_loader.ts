import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

export interface AppConfig {
  app: {
    name: string;
    port: number;
    outputDir: string;
  };
  policies: {
    restrictFileSystemWrite: {
      enabled: boolean;
      allowedRoot: string;
    };
    preventHarmfulContent: {
      enabled: boolean;
      blockedKeywords: string[];
    };
    remediationApprovalGate: {
      enabled: boolean;
      requiresApprovalForSeverities: string[];
      requiresApprovalInEnvironments: string[];
    };
  };
  agents: Array<{ name: string; class: string }>;
  tools: Array<{ name: string; class: string }>;
}

export function getRootDir(): string {
  return rootDir;
}

export function loadConfig(): AppConfig {
  const configPath = resolve(rootDir, 'config', 'config.json');
  return JSON.parse(readFileSync(configPath, 'utf-8')) as AppConfig;
}

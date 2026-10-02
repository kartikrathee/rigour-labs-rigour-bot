import fs from 'fs-extra';
import path from 'path';
import os from 'os';
import { spawn } from 'child_process';
import { config, type RigourDeepMode } from '../config.js';
import { GitHubService } from './github.js';

interface AnalyzeInput {
  repository: string;
  branch: string;
  baseBranch: string;
  commit: string;
  diff: string;
  files: Array<{
    filename: string;
    status: string;
    additions: number;
    deletions: number;
    patch?: string;
  }>;
  installationId: number;
}

interface RigourFinding {
  id: string;
  gate: string;
  severity: 'error' | 'warning' | 'info';
  message: string;
  file?: string;
  line?: number;
  endLine?: number;
  suggestion?: string;
  provenance?: string;
  category?: string;
}

interface AnalyzeResult {
  passed: boolean;
  summary: string;
  findings: RigourFinding[];
  annotations: Array<{
    path: string;
    start_line: number;
    end_line: number;
    annotation_level: 'notice' | 'warning' | 'failure';
    message: string;
    title?: string;
  }>;
  reviewBody: string;
  engine: 'cli' | 'mcp' | 'degraded';
  fallbackReason?: string;
}

interface RigourAPIFailure {
  id: string;
  gate?: string;
  severity?: string;
  message?: string;
  details?: string;
  title?: string;
  file?: string;
  files?: string[];
  line?: number;
  endLine?: number;
  suggestion?: string;
  hint?: string;
  provenance?: string;
  category?: string;
}

interface CliReport {
  status?: string;
  failures?: RigourAPIFailure[];
  summary?: Record<string, unknown>;
  stats?: Record<string, unknown>;
}

interface RunnerResult {
  result: AnalyzeResult;
}

interface DeepExecutionPlan {
  enabled: boolean;
  mode: RigourDeepMode;
  reason?: string;
}

interface ProcessResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

class AsyncSemaphore {
  private active = 0;
  private queue: Array<() => void> = [];

  constructor(private readonly max: number) {}

  async acquire(): Promise<void> {
    if (this.active < this.max) {
      this.active += 1;
      return;
    }

    await new Promise<void>((resolve) => {
      this.queue.push(() => {
        this.active += 1;
        resolve();
      });
    });
  }

  release(): void {
    this.active = Math.max(0, this.active - 1);
    const next = this.queue.shift();
    if (next) next();
  }
}

class DegradedPatternRunner {
  run(input: AnalyzeInput, fallbackReason: string): RunnerResult {
    const findings: RigourFinding[] = [];

    for (const file of input.files) {
      if (!file.patch) continue;
      findings.push(...checkFilePatchPatterns(file.filename, file.patch));
    }

    const passed = !findings.some((f) => f.severity === 'error');
    const engine: AnalyzeResult['engine'] = 'degraded';
    const summary = findings.length === 0
      ? 'No drift detected (degraded mode).'
      : `Degraded analysis found ${findings.length} issue(s)`;

    return {
      result: {
        passed,
        summary,
        findings,
        annotations: findingsToAnnotations(findings),
        reviewBody: generateReviewBody(findings, input, engine, fallbackReason, undefined),
        engine,
        fallbackReason,
      },
    };
  }
}

class McpRigourRunner {
  async run(input: AnalyzeInput, tempDir: string, deep: DeepExecutionPlan): Promise<RunnerResult> {
    const resultText = await this.callTool('rigour_review', {
      cwd: tempDir,
      repository: input.repository,
      branch: input.branch,
      diff: input.diff,
      files: input.files.map((f) => f.filename),
      deep: deep.enabled,
      pro: deep.mode === 'pro',
      provider: config.rigourProvider || undefined,
      apiKey: config.rigourApiKey || undefined,
    });

    const parsed = parseMcpToolResult(resultText);
    const findings = mapFailuresToFindings(parsed.failures || []);
    const passed = parsed.status === 'PASS' || !findings.some((f) => f.severity === 'error');

    return {
      result: {
        passed,
        summary: generateSummary(findings),
        findings,
        annotations: findingsToAnnotations(findings),
        reviewBody: generateReviewBody(findings, input, 'mcp', undefined, parsed.fixPacket),
        engine: 'mcp',
      },
    };
  }

  async runSecurityAudit(tempDir: string): Promise<string | null> {
    try {
      return await this.callTool('rigour_security_audit', { cwd: tempDir });
    } catch {
      return null;
    }
  }

  private async callTool(name: string, args: Record<string, unknown>): Promise<string> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.rigourTimeoutMs);

    try {
      const response = await fetch(`${config.rigourApiUrl}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: `rigour-${Date.now()}`,
          method: 'tools/call',
          params: {
            name,
            arguments: args,
          },
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`MCP tool ${name} failed with HTTP ${response.status}`);
      }

      const data = (await response.json()) as { result?: { content?: Array<{ text?: string }> } };
      const text = data.result?.content?.[0]?.text;
      if (!text) {
        throw new Error(`MCP tool ${name} returned empty result`);
      }

      return text;
    } finally {
      clearTimeout(timeout);
    }
  }
}

class CliRigourRunner {
  async run(input: AnalyzeInput, tempDir: string, deep: DeepExecutionPlan): Promise<RunnerResult> {
    const hasRigourConfig = await fs.pathExists(path.join(tempDir, 'rigour.yml'));
    const command = await resolveRigourCommand();
    const changedPaths = input.files
      .filter((f) => f.status !== 'removed')
      .map((f) => f.filename);

    const baseArgs = [hasRigourConfig ? 'check' : 'scan', '--json', ...changedPaths];
    const deepArgs = buildDeepArgs(deep);
    const args = [...baseArgs, ...deepArgs];

    const processResult = await runProcess(command, args, {
      cwd: tempDir,
      timeoutMs: config.rigourTimeoutMs,
      env: buildCliEnv(),
    });

    if (processResult.timedOut) {
      throw new Error(`CLI timed out after ${config.rigourTimeoutMs}ms`);
    }

    if (processResult.code !== 0 && processResult.code !== 1) {
      throw new Error(`CLI failed with code ${processResult.code}: ${safeLog(processResult.stderr || processResult.stdout)}`);
    }

    const report = parseCliReport(processResult.stdout);
    const findings = mapFailuresToFindings(report.failures || []);

    let securityNote: string | undefined;
    if (config.rigourSecurityAuditEnabled) {
      securityNote = 'Security audit requested, but CLI security audit is not directly available. Use MCP tool rigour_security_audit as secondary step.';
    }

    const fixPacket = await readFixPacketIfPresent(tempDir);
    const passed = report.status === 'PASS' || !findings.some((f) => f.severity === 'error');

    return {
      result: {
        passed,
        summary: generateSummary(findings),
        findings,
        annotations: findingsToAnnotations(findings),
        reviewBody: generateReviewBody(findings, input, 'cli', securityNote, fixPacket),
        engine: 'cli',
      },
    };
  }
}

const GLOBAL_SEMAPHORE = new AsyncSemaphore(config.rigourMaxConcurrency);

export function getExecutionChain(mode: typeof config.rigourExecMode, fallbackToMcp: boolean): Array<'cli' | 'mcp' | 'degraded'> {
  if (mode === 'mcp_only') return ['mcp', 'degraded'];
  if (mode === 'cli_only') return ['cli', 'degraded'];
  return fallbackToMcp ? ['cli', 'mcp', 'degraded'] : ['cli', 'degraded'];
}

export function mapSeverity(severity?: string): RigourFinding['severity'] {
  const value = (severity || '').toLowerCase();
  if (value === 'critical' || value === 'high' || value === 'fail' || value === 'error') return 'error';
  if (value === 'medium' || value === 'warning' || value === 'warn') return 'warning';
  return 'info';
}

export function resolveDeepExecutionPlan(input: AnalyzeInput): DeepExecutionPlan {
  if (!config.rigourDeepEnabled || config.rigourDeepMode === 'off') {
    return { enabled: false, mode: 'off', reason: 'deep_disabled' };
  }

  const [org] = input.repository.split('/');
  if (config.rigourDeepAllowedRepos.length > 0 && !config.rigourDeepAllowedRepos.includes(input.repository)) {
    return { enabled: false, mode: 'off', reason: 'repo_not_allowlisted' };
  }
  if (config.rigourDeepAllowedOrgs.length > 0 && !config.rigourDeepAllowedOrgs.includes(org)) {
    return { enabled: false, mode: 'off', reason: 'org_not_allowlisted' };
  }

  const changedLoc = input.files.reduce((sum, f) => sum + f.additions + f.deletions, 0);
  if (changedLoc > config.rigourMaxChangedLocForDeep) {
    return {
      enabled: false,
      mode: 'off',
      reason: `changed_loc_exceeded_${config.rigourMaxChangedLocForDeep}`,
    };
  }

  return { enabled: true, mode: config.rigourDeepMode };
}

export function safeLog(text: string): string {
  let sanitized = text;
  const secrets = [
    config.privateKey,
    config.webhookSecret,
    config.rigourApiKey,
    process.env.GITHUB_PRIVATE_KEY || '',
    process.env.GITHUB_WEBHOOK_SECRET || '',
    process.env.RIGOUR_API_KEY || '',
  ].filter(Boolean);

  for (const secret of secrets) {
    const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    sanitized = sanitized.replace(new RegExp(escaped, 'g'), '[REDACTED]');
  }

  sanitized = sanitized.replace(/(Bearer\s+)[A-Za-z0-9._-]+/g, '$1[REDACTED]');
  return sanitized;
}

export async function getRigourRuntimeReadiness(): Promise<{ cli_ready: boolean; mcp_ready: boolean }> {
  let cliReady = false;
  try {
    const command = await resolveRigourCommand();
    const result = await runProcess(command, ['--version'], {
      cwd: process.cwd(),
      timeoutMs: 2500,
      env: buildCliEnv(),
    });
    cliReady = result.code === 0;
  } catch {
    cliReady = false;
  }

  return {
    cli_ready: cliReady,
    mcp_ready: Boolean(config.rigourApiUrl),
  };
}

export class RigourService {
  private readonly cliRunner = new CliRigourRunner();
  private readonly mcpRunner = new McpRigourRunner();
  private readonly degradedRunner = new DegradedPatternRunner();

  async analyze(input: AnalyzeInput): Promise<AnalyzeResult> {
    await GLOBAL_SEMAPHORE.acquire();

    const tempDir = path.join(os.tmpdir(), `rigour-${input.commit}-${Date.now()}`);
    const github = new GitHubService(input.installationId);
    const deepPlan = resolveDeepExecutionPlan(input);

    try {
      await fs.ensureDir(tempDir);
      await this.fetchSparseWorkspace(input, github, tempDir);

      const chain = getExecutionChain(config.rigourExecMode, config.rigourFallbackToMcp);
      let lastError = 'no_analysis_attempts';

      for (const engine of chain) {
        if (engine === 'cli') {
          try {
            return (await this.cliRunner.run(input, tempDir, deepPlan)).result;
          } catch (error) {
            lastError = `cli_error: ${safeLog(error instanceof Error ? error.message : String(error))}`;
            continue;
          }
        }

        if (engine === 'mcp') {
          try {
            const result = (await this.mcpRunner.run(input, tempDir, deepPlan)).result;
            if (lastError !== 'no_analysis_attempts') {
              result.fallbackReason = lastError;
            }
            return result;
          } catch (error) {
            lastError = `${lastError} | mcp_error: ${safeLog(error instanceof Error ? error.message : String(error))}`;
            continue;
          }
        }
      }

      return this.degradedRunner.run(input, lastError).result;
    } catch (error) {
      const reason = `analysis_pipeline_error: ${safeLog(error instanceof Error ? error.message : String(error))}`;
      console.error('Rigour analysis failed:', reason);
      return this.degradedRunner.run(input, reason).result;
    } finally {
      try {

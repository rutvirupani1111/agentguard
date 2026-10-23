import { scan } from './scan';
import type { Finding, InputType, ScanResult, Severity } from './types';
import { SEVERITIES } from './util';
import { wrapUntrusted } from './wrap';

export interface CliIO {
  readFile(path: string): Promise<string>;
  fetchUrl(url: string): Promise<{ body: string; contentType: string }>;
  readStdin(): Promise<string>;
  out(text: string): void;
  err(text: string): void;
  color: boolean;
}

const VERSION = '0.1.0';

const HELP = `agentguard ${VERSION} - prompt-injection firewall for AI agents

Usage
  agentguard scan <file|url|->      scan content and report findings
  agentguard sanitize <file|url|->  print the sanitized content
  agentguard wrap <file|url|->      print LLM-ready wrapped content

Options
  --type <auto|html|markdown|text>  content type (default: auto)
  --json                            machine-readable output
  --fail-on <severity|score>        exit 1 when severity >= level (info|low|medium|high|critical)
                                    or risk >= score (0-100)
  --quiet                           only print the summary line
  -h, --help                        show this help
  -v, --version                     print the version

Examples
  npx agentguard scan page.html
  npx agentguard scan https://example.com --fail-on high
  cat email.txt | npx agentguard scan - --json
`;

const PAINT: Record<Severity | 'none', string> = {
  critical: '\x1b[41;97;1m',
  high: '\x1b[31;1m',
  medium: '\x1b[33;1m',
  low: '\x1b[36m',
  info: '\x1b[90m',
  none: '\x1b[32;1m',
};

function paint(io: CliIO, sev: Severity | 'none', text: string): string {
  return io.color ? `${PAINT[sev]}${text}\x1b[0m` : text;
}

function dim(io: CliIO, text: string): string {
  return io.color ? `\x1b[2m${text}\x1b[0m` : text;
}

export function formatPretty(result: ScanResult, label: string, io: CliIO, quiet = false): string {
  const width = 20;
  const filled = Math.round((result.risk / 100) * width);
  const bar = '█'.repeat(filled) + '░'.repeat(width - filled);
  const head = `${label}  ${paint(io, result.severity, ` ${result.severity.toUpperCase()} `)}  risk ${result.risk}/100 ${bar}  ${result.findings.length} finding${result.findings.length === 1 ? '' : 's'} (${result.stats.type})`;
  if (quiet || result.findings.length === 0) return head;
  const lines = [head, ''];
  for (const f of result.findings as Finding[]) {
    lines.push(`  ${paint(io, f.severity, f.severity.toUpperCase().padEnd(8))} ${f.id}  ${dim(io, `${f.location.line}:${f.location.column}`)}`);
    lines.push(`           ${f.message}`);
    if (f.excerpt) lines.push(`           ${dim(io, `"${f.excerpt}"`)}`);
  }
  return lines.join('\n');
}

function shouldFail(result: ScanResult, failOn: string | undefined): boolean {
  if (!failOn) return false;
  if (/^\d+$/.test(failOn)) return result.risk >= Number(failOn);
  const idx = SEVERITIES.indexOf(failOn as Severity);
  if (idx < 0) throw new Error(`--fail-on expects a severity (${SEVERITIES.join('|')}) or a 0-100 score, got "${failOn}"`);
  return result.severity !== 'none' && SEVERITIES.indexOf(result.severity) >= idx;
}

/** Run the CLI. Returns the process exit code. */
export async function runCli(argv: string[], io: CliIO): Promise<number> {
  const args = [...argv];
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];
  while (args.length) {
    const a = args.shift() as string;
    if (a === '-h' || a === '--help') flags.help = true;
    else if (a === '-v' || a === '--version') flags.version = true;
    else if (a === '--json' || a === '--quiet') flags[a.slice(2)] = true;
    else if (a === '--type' || a === '--fail-on' || a === '--source') {
      const v = args.shift();
      if (v === undefined) {
        io.err(`agentguard: ${a} needs a value`);
        return 2;
      }
      flags[a.slice(2)] = v;
    } else if (a.startsWith('--') && a.includes('=')) {
      const [k, v] = a.slice(2).split(/=(.*)/s);
      flags[k as string] = v ?? '';
    } else positional.push(a);
  }
  if (flags.version) {
    io.out(VERSION);
    return 0;
  }
  const command = positional[0];
  if (flags.help || !command) {
    io.out(HELP);
    return flags.help ? 0 : 2;
  }
  if (!['scan', 'sanitize', 'wrap'].includes(command)) {
    io.err(`agentguard: unknown command "${command}"\n\n${HELP}`);
    return 2;
  }
  const target = positional[1] ?? '-';
  const type = String(flags.type ?? 'auto') as InputType;
  if (!['auto', 'html', 'markdown', 'text'].includes(type)) {
    io.err(`agentguard: --type must be auto, html, markdown or text`);
    return 2;
  }

  let content: string;
  let detected: InputType = type;
  try {
    if (/^https?:\/\//i.test(target)) {
      const res = await io.fetchUrl(target);
      content = res.body;
      if (type === 'auto' && /html/i.test(res.contentType)) detected = 'html';
      if (type === 'auto' && /markdown/i.test(res.contentType)) detected = 'markdown';
    } else if (target === '-') {
      content = await io.readStdin();
    } else {
      content = await io.readFile(target);
      if (type === 'auto' && /\.(?:html?|xhtml)$/i.test(target)) detected = 'html';
      if (type === 'auto' && /\.(?:md|markdown|mdx)$/i.test(target)) detected = 'markdown';
    }
  } catch (e) {
    io.err(`agentguard: cannot read ${target}: ${(e as Error).message}`);
    return 2;
  }

  const result = scan(content, { type: detected });
  if (command === 'sanitize') {
    io.out(result.sanitized);
  } else if (command === 'wrap') {
    io.out(wrapUntrusted(content, { result, source: typeof flags.source === 'string' ? flags.source : target === '-' ? undefined : target }));
  } else if (flags.json) {
    io.out(JSON.stringify({ target, ...result }, null, 2));
  } else {
    io.out(formatPretty(result, target === '-' ? 'stdin' : target, io, Boolean(flags.quiet)));
  }

  try {
    return shouldFail(result, typeof flags['fail-on'] === 'string' ? flags['fail-on'] : undefined) ? 1 : 0;
  } catch (e) {
    io.err(`agentguard: ${(e as Error).message}`);
    return 2;
  }
}

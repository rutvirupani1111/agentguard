import { detectInstructions } from './detectors/instructions';
import { detectUnicode } from './detectors/unicode';
import type { ContentType, InputType, ScanOptions, ScanResult, Severity } from './types';
import {
  applyEdits,
  createCtx,
  emptyByCategory,
  emptyBySeverity,
  plainView,
  rank,
  type TextView,
} from './util';

const WEIGHT: Record<Severity, number> = { info: 0, low: 10, medium: 40, high: 70, critical: 95 };

/** Guess whether the input is HTML, Markdown or plain text. */
export function detectType(input: string): ContentType {
  const head = input.slice(0, 20000);
  if (/<!doctype\s+html|<html[\s>]|<body[\s>]|<head[\s>]/i.test(head)) return 'html';
  const tags = head.match(/<\/?(?:div|span|p|a|img|br|table|tr|td|ul|ol|li|section|article|style|script|meta|link|h[1-6]|strong|em|b|i|font|noscript|iframe|form|input|button)\b[^>]*>/gi);
  const md = /^#{1,6}\s+\S|^\s*[-*+]\s+\S|^\s*\d+\.\s+\S|\]\([^)]*\)|^```|^>\s|\*\*[^*]+\*\*/m.test(head);
  if (tags && tags.length >= 3 && !md) return 'html';
  if (md) return 'markdown';
  if (tags && tags.length > 0) return 'html';
  return 'text';
}

function now(): number {
  return typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : Date.now();
}

/** Hook used by the HTML/Markdown analyser (registered in index.ts to keep this module small). */
export type StructuredAnalyzer = (ctx: ReturnType<typeof createCtx>) => TextView;
export type UrlAnalyzer = (ctx: ReturnType<typeof createCtx>) => void;

let structured: StructuredAnalyzer | null = null;
let urlAnalyzer: UrlAnalyzer | null = null;

export function registerStructuredAnalyzer(fn: StructuredAnalyzer): void {
  structured = fn;
}

export function registerUrlAnalyzer(fn: UrlAnalyzer): void {
  urlAnalyzer = fn;
}

/**
 * Scan untrusted content before it reaches an LLM.
 *
 * ```ts
 * const result = scan(html, { type: 'html' });
 * if (result.risk >= 50) refuse(); else feed(result.sanitized);
 * ```
 */
export function scan(input: string, options: ScanOptions = {}): ScanResult {
  const t0 = now();
  const text = typeof input === 'string' ? input : String(input ?? '');
  const requested: InputType = options.type ?? 'auto';
  const type: ContentType = requested === 'auto' ? detectType(text) : requested;
  const ctx = createCtx(text, type, Math.max(20, options.maxExcerpt ?? 160));

  const views: TextView[] = [];
  if ((type === 'html' || type === 'markdown') && structured) views.push(structured(ctx));
  else views.push(plainView(text));
  views.push(...detectUnicode(ctx));
  for (const v of views) detectInstructions(ctx, v);
  if (urlAnalyzer) urlAnalyzer(ctx);

  const findings = ctx.findings.sort(
    (a, b) => rank(b.severity) - rank(a.severity) || a.location.start - b.location.start,
  );

  let maxW = 0;
  let sumW = 0;
  let severity: Severity | 'none' = 'none';
  const bySeverity = emptyBySeverity();
  const byCategory = emptyByCategory();
  for (const f of findings) {
    const w = WEIGHT[f.severity];
    maxW = Math.max(maxW, w);
    sumW += w;
    bySeverity[f.severity]++;
    byCategory[f.category]++;
    if (severity === 'none' || rank(f.severity) > rank(severity)) severity = f.severity;
  }
  const risk = findings.length === 0 ? 0 : Math.min(100, Math.round(maxW + 0.15 * (sumW - maxW)));

  return {
    risk,
    severity,
    findings,
    sanitized: applyEdits(text, ctx.edits),
    stats: {
      type,
      length: text.length,
      findings: findings.length,
      bySeverity,
      byCategory,
      hiddenRegions: ctx.hiddenRegions,
      invisibleChars: ctx.invisibleChars,
      urls: ctx.urls,
      durationMs: Math.round((now() - t0) * 100) / 100,
    },
  };
}

/** The input with hidden content, invisible characters, injected instructions and exfiltration URLs removed. */
export function sanitize(input: string, options: ScanOptions = {}): string {
  return scan(input, options).sanitized;
}

/** `true` when the scan's risk score is below `threshold` (default 50: anything rated high or critical fails). */
export function isSafe(input: string, threshold = 50, options: ScanOptions = {}): boolean {
  return scan(input, options).risk < threshold;
}

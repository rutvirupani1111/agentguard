import type { Category, ContentType, Finding, Severity } from './types';

export const SEVERITIES: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

/** Hidden reasons that do not hide text from sighted users on their own (escalate to high, not critical). */
export const WEAK_HIDDEN: ReadonlySet<string> = new Set(['aria-hidden="true"', 'clipped to 1px (screen-reader-only)', '<template>']);

export function rank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return rank(a) >= rank(b) ? a : b;
}

/** Maps offsets to 1-based line/column. */
export class LineIndex {
  private readonly starts: number[] = [0];
  constructor(text: string) {
    for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) this.starts.push(i + 1);
  }
  at(offset: number): { line: number; column: number } {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((this.starts[mid] as number) <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - (this.starts[lo] as number) + 1 };
  }
}

/**
 * A piece of text to run pattern detectors over, with a map back to the original input.
 * `offsets === null` means identity; `hidden === null` means everything is visible.
 */
export interface TextView {
  text: string;
  offsets: number[] | null;
  hidden: (string | null)[] | null;
}

export function offsetAt(view: TextView, i: number): number {
  if (!view.offsets) return i;
  if (view.offsets.length === 0) return 0;
  return view.offsets[Math.min(i, view.offsets.length - 1)] as number;
}

export function hiddenAt(view: TextView, i: number): string | null {
  return view.hidden ? (view.hidden[i] ?? null) : null;
}

export class ViewBuilder {
  private readonly parts: string[] = [];
  private readonly offsets: number[] = [];
  private readonly hidden: (string | null)[] = [];

  /** Append `str` whose chars start at original offset `start` (consecutive). */
  push(str: string, start: number, hidden: string | null = null): void {
    for (let i = 0; i < str.length; i++) {
      this.offsets.push(start + i);
      this.hidden.push(hidden);
    }
    this.parts.push(str);
  }

  /** Append `str` with every char mapped to the same original offset. */
  pushAt(str: string, offset: number, hidden: string | null = null): void {
    for (let i = 0; i < str.length; i++) {
      this.offsets.push(offset);
      this.hidden.push(hidden);
    }
    this.parts.push(str);
  }

  /** Append `str` with an explicit per-char offset map. */
  pushMapped(str: string, map: number[], hidden: string | null = null): void {
    for (let i = 0; i < str.length; i++) {
      this.offsets.push(map[i] ?? map[map.length - 1] ?? 0);
      this.hidden.push(hidden);
    }
    this.parts.push(str);
  }

  get length(): number {
    return this.offsets.length;
  }

  build(): TextView {
    return { text: this.parts.join(''), offsets: this.offsets, hidden: this.hidden };
  }
}

export function plainView(text: string): TextView {
  return { text, offsets: null, hidden: null };
}

/** Latin look-alikes from Cyrillic, Greek and a few IPA letters. */
export const CONFUSABLES: Readonly<Record<string, string>> = {
  // Cyrillic lower
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ј: 'j', ѕ: 's', ԁ: 'd',
  һ: 'h', ӏ: 'l', ԛ: 'q', ԝ: 'w', ү: 'y', к: 'k', ё: 'e',
  // Cyrillic upper
  А: 'A', В: 'B', Е: 'E', К: 'K', М: 'M', Н: 'H', О: 'O', Р: 'P', С: 'C', Т: 'T', Х: 'X',
  У: 'Y', І: 'I', Ј: 'J', Ѕ: 'S', Ԁ: 'D', Ӏ: 'I',
  // Greek lower
  α: 'a', ο: 'o', ρ: 'p', ν: 'v', ι: 'i', κ: 'k', τ: 't', υ: 'u', χ: 'x',
  // Greek upper
  Α: 'A', Β: 'B', Ε: 'E', Ζ: 'Z', Η: 'H', Ι: 'I', Κ: 'K', Μ: 'M', Ν: 'N', Ο: 'O', Ρ: 'P',
  Τ: 'T', Υ: 'Y', Χ: 'X',
  // Latin extensions / IPA
  ı: 'i', ɑ: 'a', ɡ: 'g', ʏ: 'y', ɪ: 'i', ᴏ: 'o',
};

/** Characters that render as nothing (or nearly nothing) and are stripped before matching. */
export const INVISIBLE_RE =
  /[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ]/;

/** Fold one code point to a plain-ASCII equivalent when it is a compatibility or accented form. */
const PUNCT: Readonly<Record<string, string>> = {
  '‘': "'", '’': "'", '‛': "'", '′': "'", 'ʼ': "'",
  '“': '"', '”': '"', ' ': ' ', '–': '-', '—': '-',
};

export function foldCompat(ch: string): string {
  if (ch.charCodeAt(0) < 0x80) return ch;
  const p = PUNCT[ch];
  if (p !== undefined) return p;
  const d = ch.normalize('NFKD');
  if (d !== ch) {
    const stripped = d.replace(/[̀-ͯ]/g, '');
    if (/^[\x20-\x7e]+$/.test(stripped)) return stripped;
  }
  return ch;
}

/** Skeleton of a word: compatibility forms folded, look-alike letters mapped to Latin. */
export function skeleton(word: string): string {
  let out = '';
  for (const ch of word) {
    const f = foldCompat(ch);
    out += CONFUSABLES[f] ?? f;
  }
  return out;
}

/**
 * Normalise a view for pattern matching: drop invisible characters, fold fullwidth /
 * mathematical / accented letters to ASCII, and map Cyrillic/Greek look-alikes to Latin
 * inside words that are (partly) Latin. Offsets and hidden flags are carried through.
 */
export function normalizeView(view: TextView): TextView {
  const src = view.text;
  if (!/[^\x00-\x7f]/.test(src)) return view;

  const fold = new Uint8Array(src.length);
  for (const m of src.matchAll(/[\p{L}\p{M}]+/gu)) {
    const w = m[0];
    const idx = m.index ?? 0;
    const hasAscii = /[A-Za-z]/.test(w);
    let allMappable = true;
    for (const ch of w) {
      if (!/[A-Za-z]/.test(ch) && CONFUSABLES[ch] === undefined) {
        allMappable = false;
        break;
      }
    }
    if (hasAscii || allMappable) fold.fill(1, idx, idx + w.length);
  }

  const b = new ViewBuilder();
  let i = 0;
  while (i < src.length) {
    const cp = src.codePointAt(i) as number;
    const len = cp > 0xffff ? 2 : 1;
    const ch = src.slice(i, i + len);
    const o = offsetAt(view, i);
    const h = hiddenAt(view, i);
    const wasFold = fold[i] === 1;
    i += len;
    if (INVISIBLE_RE.test(ch) || (cp >= 0xe0000 && cp <= 0xe01ef)) continue;
    let out = ch;
    if (cp > 0x7f) {
      out = foldCompat(ch);
      if (wasFold && CONFUSABLES[out] !== undefined) out = CONFUSABLES[out] as string;
    }
    b.pushAt(out, o, h);
  }
  return b.build();
}

/** Collapse whitespace and truncate. */
export function clip(text: string, max: number): string {
  const t = text.replace(/\s+/g, ' ').trim();
  return t.length > max ? t.slice(0, Math.max(1, max - 1)) + '…' : t;
}

/** A readable excerpt of `text[s, e)` with a little context. */
export function excerptAround(text: string, s: number, e: number, max: number): string {
  const core = text.slice(s, e);
  if (core.length >= max) return clip(core, max);
  const before = text.slice(Math.max(0, s - 30), s);
  const after = text.slice(e, e + 80);
  const full = (s > 30 ? '…' : '') + before + core + after;
  return clip(full, max);
}

export interface Edit {
  start: number;
  end: number;
  replacement: string;
}

export type NewFinding = Omit<Finding, 'location'> & { start: number; end: number };

/** Shared state passed to every detector. */
export interface Ctx {
  readonly input: string;
  readonly type: ContentType;
  readonly maxExcerpt: number;
  readonly lines: LineIndex;
  readonly findings: Finding[];
  readonly edits: Edit[];
  hiddenRegions: number;
  invisibleChars: number;
  urls: number;
  add(f: NewFinding): Finding;
}

export function createCtx(input: string, type: ContentType, maxExcerpt: number): Ctx {
  const lines = new LineIndex(input);
  const findings: Finding[] = [];
  return {
    input,
    type,
    maxExcerpt,
    lines,
    findings,
    edits: [],
    hiddenRegions: 0,
    invisibleChars: 0,
    urls: 0,
    add(f: NewFinding): Finding {
      const { start, end, ...rest } = f;
      const pos = lines.at(start);
      const finding: Finding = { ...rest, location: { start, end, line: pos.line, column: pos.column } };
      if (finding.hidden === undefined) delete finding.hidden;
      if (finding.decoded === undefined) delete finding.decoded;
      if (finding.url === undefined) delete finding.url;
      findings.push(finding);
      return finding;
    },
  };
}

/** Apply non-overlapping edits (earliest, then longest wins). */
export function applyEdits(input: string, edits: Edit[]): string {
  const sorted = [...edits].sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  let out = '';
  let pos = 0;
  for (const e of sorted) {
    if (e.start < pos) continue;
    out += input.slice(pos, e.start) + e.replacement;
    pos = e.end;
  }
  return out + input.slice(pos);
}

export function emptyByCategory(): Record<Category, number> {
  return { 'hidden-text': 0, unicode: 0, instruction: 0, exfiltration: 0 };
}

export function emptyBySeverity(): Record<Severity, number> {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

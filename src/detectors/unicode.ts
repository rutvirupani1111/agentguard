import { clip, skeleton, ViewBuilder, type Ctx, type TextView } from '../util';

const KEYWORDS = new Set([
  'ignore', 'disregard', 'forget', 'previous', 'prior', 'instruction', 'instructions', 'system',
  'prompt', 'assistant', 'override', 'bypass', 'jailbreak', 'password', 'passwords', 'secret',
  'secrets', 'token', 'tokens', 'credential', 'credentials', 'admin', 'execute', 'exfiltrate',
  'confidential', 'apikey', 'email', 'send', 'http', 'https', 'delete', 'transfer', 'wallet',
  'bitcoin', 'payment', 'login', 'user', 'developer', 'unrestricted', 'reveal', 'command',
]);

const EMOJI_RE = /\p{Extended_Pictographic}|️|⃣/u;
const NON_LATIN_LETTER_RE = /[\p{L}\p{M}]/u;

function codePointBefore(s: string, i: number): string {
  if (i <= 0) return '';
  const lo = s.charCodeAt(i - 1);
  if (lo >= 0xdc00 && lo <= 0xdfff && i >= 2) return s.slice(i - 2, i);
  return s.slice(i - 1, i);
}

function codePointAfter(s: string, i: number): string {
  if (i >= s.length) return '';
  const cp = s.codePointAt(i) as number;
  return s.slice(i, i + (cp > 0xffff ? 2 : 1));
}

/** ZWJ/ZWNJ have legitimate uses: emoji sequences and joining behaviour in non-Latin scripts. */
function isBenignJoiner(s: string, start: number, run: string): boolean {
  if (run !== '‍' && run !== '‌') return false;
  const prev = codePointBefore(s, start);
  const next = codePointAfter(s, start + run.length);
  if (EMOJI_RE.test(prev) && EMOJI_RE.test(next)) return true;
  const nonLatin = (c: string) => c !== '' && NON_LATIN_LETTER_RE.test(c) && !/[A-Za-zÀ-ɏ]/.test(c);
  return nonLatin(prev) || nonLatin(next);
}

/**
 * Unicode smuggling: tag characters, variation-selector payloads, zero-width characters,
 * bidi controls and homoglyph-obfuscated keywords. Returns decoded hidden payloads as views
 * so the instruction detector can inspect them too.
 */
export function detectUnicode(ctx: Ctx): TextView[] {
  const s = ctx.input;
  const views: TextView[] = [];
  if (!/[^\x00-\x7f]/.test(s)) return views;

  // 1. Unicode tag characters (U+E0000-U+E007F): invisible, but tokenized by LLMs as ASCII.
  const tagRuns = [...s.matchAll(/(?:\uDB40[\uDC00-\uDC7F])+/g)];
  if (tagRuns.length > 0) {
    const all = new ViewBuilder();
    const decodeRun = (raw: string, start: number): string => {
      let decoded = '';
      for (let k = 0; k + 1 < raw.length; k += 2) {
        const v = raw.charCodeAt(k + 1) - 0xdc00;
        if (v >= 0x20 && v <= 0x7e) {
          const c = String.fromCharCode(v);
          decoded += c;
          all.pushAt(c, start + k, 'unicode tag characters');
        }
      }
      return decoded;
    };
    const decodedRuns = tagRuns.map((m) => ({ start: m.index ?? 0, raw: m[0], decoded: decodeRun(m[0], m.index ?? 0) }));
    for (const r of decodedRuns) {
      ctx.edits.push({ start: r.start, end: r.start + r.raw.length, replacement: '' });
      ctx.invisibleChars += r.raw.length / 2;
    }
    const report = decodedRuns.length <= 3 ? decodedRuns : [decodedRuns[0]!];
    for (const r of report) {
      const decoded = report.length === 1 && decodedRuns.length > 1 ? decodedRuns.map((d) => d.decoded).join('') : r.decoded;
      const count = report.length === 1 && decodedRuns.length > 1 ? decodedRuns.reduce((n, d) => n + d.raw.length / 2, 0) : r.raw.length / 2;
      ctx.add({
        id: 'unicode/tag-characters',
        category: 'unicode',
        severity: 'high',
        message: `${count} invisible Unicode tag character${count === 1 ? '' : 's'} (U+E0000-U+E007F) smuggle hidden ASCII text that humans cannot see but LLMs read${decoded ? `: "${clip(decoded, 80)}"` : ''}.`,
        excerpt: decoded ? clip(decoded, ctx.maxExcerpt) : '(no printable payload)',
        start: r.start,
        end: r.start + r.raw.length,
        hidden: 'unicode tag characters',
        decoded,
      });
    }
    if (all.length > 0) views.push(all.build());
  }

  // 2. Variation-selector smuggling: arbitrary bytes encoded as VS1-VS256 after a visible char.
  for (const m of s.matchAll(/(?:[︀-️]|\uDB40[\uDD00-\uDDEF]){2,}/g)) {
    const start = m.index ?? 0;
    const bytes: number[] = [];
    for (const ch of m[0]) {
      const cp = ch.codePointAt(0) as number;
      bytes.push(cp <= 0xfe0f ? cp - 0xfe00 : cp - 0xe0100 + 16);
    }
    let decoded = '';
    try {
      decoded = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes)).replace(/�/g, '');
    } catch {
      decoded = '';
    }
    ctx.invisibleChars += bytes.length;
    ctx.edits.push({ start, end: start + m[0].length, replacement: '' });
    ctx.add({
      id: 'unicode/variation-selectors',
      category: 'unicode',
      severity: 'high',
      message: `${bytes.length} consecutive variation selectors encode a hidden byte payload${decoded ? `: "${clip(decoded, 80)}"` : ''}.`,
      excerpt: decoded ? clip(decoded, ctx.maxExcerpt) : `(${bytes.length} bytes)`,
      start,
      end: start + m[0].length,
      hidden: 'variation selectors',
      decoded,
    });
    if (decoded) {
      const b = new ViewBuilder();
      b.pushAt(decoded, start, 'variation selectors');
      views.push(b.build());
    }
  }

  // 3. Zero-width characters.
  let zwTotal = 0;
  let zwRuns = 0;
  let zwMaxRun = 0;
  let zwInWord = false;
  let zwFirst = -1;
  let zwFirstEnd = -1;
  for (const m of s.matchAll(/[​-‍⁠-⁤᠎﻿]+/g)) {
    const start = m.index ?? 0;
    const run = m[0];
    if (start === 0 && run === '﻿') continue; // byte-order mark
    if (isBenignJoiner(s, start, run)) continue;
    zwTotal += run.length;
    zwRuns++;
    zwMaxRun = Math.max(zwMaxRun, run.length);
    if (/[A-Za-z0-9]/.test(s[start - 1] ?? '') && /[A-Za-z0-9]/.test(s[start + run.length] ?? '')) zwInWord = true;
    if (zwFirst < 0) {
      zwFirst = start;
      zwFirstEnd = start + run.length;
    }
    ctx.edits.push({ start, end: start + run.length, replacement: '' });
  }
  if (zwTotal > 0) {
    ctx.invisibleChars += zwTotal;
    const stego = zwMaxRun >= 8;
    const severity = stego ? 'high' : zwInWord ? 'medium' : 'low';
    const ctxText = s.slice(Math.max(0, zwFirst - 20), zwFirstEnd + 20).replace(/[​-‍⁠-⁤᠎﻿]/g, '·');
    ctx.add({
      id: 'unicode/zero-width',
      category: 'unicode',
      severity,
      message: stego
        ? `${zwTotal} zero-width characters (longest run ${zwMaxRun}) look like a steganographic payload hidden in the text.`
        : zwInWord
          ? `${zwTotal} zero-width character${zwTotal === 1 ? '' : 's'} split words, a common trick to sneak keywords past filters.`
          : `${zwTotal} zero-width character${zwTotal === 1 ? '' : 's'} in ${zwRuns} place${zwRuns === 1 ? '' : 's'}.`,
      excerpt: clip(ctxText, ctx.maxExcerpt),
      start: zwFirst,
      end: zwFirstEnd,
      hidden: 'zero-width characters',
    });
  }

  // 4. Bidirectional controls (Trojan Source style reordering).
  let bidiCount = 0;
  let bidiOverride = false;
  let bidiFirst = -1;
  for (const m of s.matchAll(/[‪-‮⁦-⁩]/g)) {
    const start = m.index ?? 0;
    bidiCount++;
    if (m[0] === '‭' || m[0] === '‮') bidiOverride = true;
    if (bidiFirst < 0) bidiFirst = start;
    ctx.edits.push({ start, end: start + 1, replacement: '' });
  }
  if (bidiCount > 0) {
    ctx.invisibleChars += bidiCount;
    ctx.add({
      id: 'unicode/bidi-control',
      category: 'unicode',
      severity: bidiOverride ? 'high' : 'low',
      message: bidiOverride
        ? `${bidiCount} bidirectional control character${bidiCount === 1 ? '' : 's'} including a direction override (U+202D/U+202E): what a human sees is not the order the model reads.`
        : `${bidiCount} bidirectional embedding/isolate character${bidiCount === 1 ? '' : 's'}.`,
      excerpt: clip(s.slice(bidiFirst, bidiFirst + 60).replace(/[‪-‮⁦-⁩]/g, '⟨bidi⟩'), ctx.maxExcerpt),
      start: bidiFirst,
      end: bidiFirst + 1,
      hidden: 'bidi reordering',
    });
  }

  // 5. Homoglyph-obfuscated keywords and mixed-script words.
  let mixedReported = 0;
  for (const m of s.matchAll(/[\p{L}\p{M}\p{N}]+/gu)) {
    const word = m[0];
    if (!/[^\x00-\x7f]/.test(word)) continue;
    const skel = skeleton(word);
    if (skel === word || !/^[A-Za-z0-9]+$/.test(skel)) continue;
    const start = m.index ?? 0;
    const lower = skel.toLowerCase();
    if (KEYWORDS.has(lower)) {
      ctx.add({
        id: 'unicode/homoglyph-keyword',
        category: 'unicode',
        severity: 'high',
        message: `Look-alike characters disguise the keyword "${lower}" ("${word}"), a common way to evade keyword filters.`,
        excerpt: clip(s.slice(Math.max(0, start - 20), start + word.length + 40), ctx.maxExcerpt),
        start,
        end: start + word.length,
        decoded: skel,
      });
    } else if (/[A-Za-z]/.test(word) && /[Ͱ-ϿЀ-ԯ]/.test(word) && mixedReported < 20) {
      mixedReported++;
      ctx.add({
        id: 'unicode/mixed-script',
        category: 'unicode',
        severity: 'low',
        message: `The word "${word}" mixes Latin with Cyrillic/Greek look-alike letters (reads as "${skel}").`,
        excerpt: clip(word, ctx.maxExcerpt),
        start,
        end: start + word.length,
        decoded: skel,
      });
    }
  }

  return views;
}

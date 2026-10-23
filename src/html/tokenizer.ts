/**
 * A small, forgiving, dependency-free HTML tokenizer. It does not build a DOM; it yields
 * tokens with exact source offsets so findings can point back into the original input.
 */

export interface Attr {
  name: string;
  /** Raw (still entity-encoded) value. */
  raw: string;
  /** Offset of the first char of the raw value in the input. */
  valueStart: number;
}

export type Token =
  | { type: 'text'; start: number; end: number }
  | { type: 'comment'; start: number; end: number; contentStart: number; contentEnd: number }
  | { type: 'open'; name: string; attrs: Attr[]; selfClosing: boolean; start: number; end: number }
  | { type: 'close'; name: string; start: number; end: number }
  | { type: 'raw'; name: string; start: number; end: number }
  | { type: 'other'; start: number; end: number };

export type OpenToken = Extract<Token, { type: 'open' }>;

const RAWTEXT = new Set(['script', 'style', 'xmp', 'iframe', 'noembed', 'noframes']);
const RCDATA = new Set(['textarea', 'title']);
const CLOSE_RE = /<\/([A-Za-z][^\s/>]*)[^>]*>/y;
const NAME_RE = /[A-Za-z][^\s/>]*/y;
const isSpace = (c: string | undefined) => c === ' ' || c === '\n' || c === '\t' || c === '\r' || c === '\f';

function findClose(html: string, name: string, from: number): number {
  const re = new RegExp(`</${name}(?=[\\s/>])`, 'gi');
  re.lastIndex = from;
  const m = re.exec(html);
  return m ? m.index : html.length;
}

function parseOpen(html: string, lt: number): OpenToken | null {
  NAME_RE.lastIndex = lt + 1;
  const nm = NAME_RE.exec(html);
  if (!nm) return null;
  const name = nm[0].toLowerCase();
  const n = html.length;
  const attrs: Attr[] = [];
  let j = lt + 1 + nm[0].length;
  while (j < n) {
    while (j < n && isSpace(html[j])) j++;
    if (j >= n) return null;
    const ch = html[j];
    if (ch === '>') return { type: 'open', name, attrs, selfClosing: false, start: lt, end: j + 1 };
    if (ch === '/') {
      if (html[j + 1] === '>') return { type: 'open', name, attrs, selfClosing: true, start: lt, end: j + 2 };
      j++;
      continue;
    }
    const ns = j;
    while (j < n && !isSpace(html[j]) && html[j] !== '=' && html[j] !== '>' && !(html[j] === '/' && html[j + 1] === '>')) j++;
    const attrName = html.slice(ns, j).toLowerCase();
    let k = j;
    while (k < n && isSpace(html[k])) k++;
    if (html[k] === '=') {
      k++;
      while (k < n && isSpace(html[k])) k++;
      const q = html[k];
      if (q === '"' || q === "'") {
        const close = html.indexOf(q, k + 1);
        if (close < 0) return null;
        attrs.push({ name: attrName, raw: html.slice(k + 1, close), valueStart: k + 1 });
        j = close + 1;
      } else {
        const vs = k;
        while (k < n && !isSpace(html[k]) && html[k] !== '>') k++;
        attrs.push({ name: attrName, raw: html.slice(vs, k), valueStart: vs });
        j = k;
      }
    } else if (attrName) {
      attrs.push({ name: attrName, raw: '', valueStart: j });
    }
    if (j === ns) j++;
  }
  return null;
}

export function tokenize(html: string): Token[] {
  const tokens: Token[] = [];
  const n = html.length;
  let i = 0;
  let textStart = 0;
  const flushText = (end: number) => {
    if (end > textStart) tokens.push({ type: 'text', start: textStart, end });
  };
  while (i < n) {
    const lt = html.indexOf('<', i);
    if (lt < 0) break;
    const c = html[lt + 1];
    if (html.startsWith('<!--', lt)) {
      flushText(lt);
      const close = html.indexOf('-->', lt + 4);
      const contentEnd = close < 0 ? n : close;
      const end = close < 0 ? n : close + 3;
      tokens.push({ type: 'comment', start: lt, end, contentStart: lt + 4, contentEnd });
      i = textStart = end;
      continue;
    }
    if (c === '!' || c === '?') {
      flushText(lt);
      const gt = html.indexOf('>', lt);
      const end = gt < 0 ? n : gt + 1;
      tokens.push({ type: 'other', start: lt, end });
      i = textStart = end;
      continue;
    }
    if (c === '/') {
      CLOSE_RE.lastIndex = lt;
      const m = CLOSE_RE.exec(html);
      if (m) {
        flushText(lt);
        tokens.push({ type: 'close', name: (m[1] as string).toLowerCase(), start: lt, end: lt + m[0].length });
        i = textStart = lt + m[0].length;
        continue;
      }
      i = lt + 1;
      continue;
    }
    if (c !== undefined && /[A-Za-z]/.test(c)) {
      const tag = parseOpen(html, lt);
      if (tag) {
        flushText(lt);
        tokens.push(tag);
        i = textStart = tag.end;
        if (!tag.selfClosing && (RAWTEXT.has(tag.name) || RCDATA.has(tag.name))) {
          const closeIdx = findClose(html, tag.name, tag.end);
          if (closeIdx > tag.end) {
            tokens.push(RAWTEXT.has(tag.name) ? { type: 'raw', name: tag.name, start: tag.end, end: closeIdx } : { type: 'text', start: tag.end, end: closeIdx });
          }
          i = textStart = closeIdx;
        }
        continue;
      }
    }
    i = lt + 1;
  }
  flushText(n);
  return tokens;
}

const NAMED: Readonly<Record<string, string>> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '©', reg: '®', trade: '™',
  hellip: '…', mdash: '—', ndash: '–', lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', bull: '•',
  middot: '·', euro: '€', pound: '£', yen: '¥', cent: '¢', deg: '°', times: '×', divide: '÷',
  laquo: '«', raquo: '»', zwj: '‍', zwnj: '‌', shy: '­', lrm: '‎', rlm: '‏',
  ensp: ' ', emsp: ' ', thinsp: ' ', sect: '§', para: '¶', iexcl: '¡', iquest: '¿',
};

const ENTITY_RE = /&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([A-Za-z][A-Za-z0-9]{1,31}));?/y;

function fromCodePoint(cp: number): string | undefined {
  if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return undefined;
  return String.fromCodePoint(cp);
}

/** Decode HTML entities, returning the decoded text and, for each decoded char, its source offset. */
export function decodeEntities(raw: string, base = 0): { text: string; map: number[] | null } {
  if (raw.indexOf('&') < 0) return { text: raw, map: null };
  let text = '';
  const map: number[] = [];
  let i = 0;
  while (i < raw.length) {
    if (raw[i] === '&') {
      ENTITY_RE.lastIndex = i;
      const m = ENTITY_RE.exec(raw);
      if (m) {
        const out = m[1] ? fromCodePoint(parseInt(m[1], 10)) : m[2] ? fromCodePoint(parseInt(m[2], 16)) : NAMED[(m[3] as string).toLowerCase()];
        if (out !== undefined) {
          text += out;
          for (let k = 0; k < out.length; k++) map.push(base + i);
          i += m[0].length;
          continue;
        }
      }
    }
    text += raw[i];
    map.push(base + i);
    i++;
  }
  return { text, map };
}

import {
  backgroundColor,
  contrast,
  formatColor,
  over,
  parseColor,
  parseSheet,
  parseStyle,
  styleHiding,
  type HideInfo,
  type RGBA,
  type SheetRule,
} from '../html/style';
import { decodeEntities, tokenize } from '../html/tokenizer';
import type { Severity } from '../types';
import { clip, ViewBuilder, type Ctx, type Edit, type TextView } from '../util';

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr', 'keygen']);
const BLOCK = new Set([
  'p', 'div', 'br', 'li', 'ul', 'ol', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'tr', 'td', 'th', 'table', 'section',
  'article', 'header', 'footer', 'nav', 'aside', 'main', 'blockquote', 'pre', 'hr', 'dd', 'dt', 'dl', 'form',
  'fieldset', 'figure', 'figcaption', 'details', 'summary', 'body', 'html', 'head', 'title', 'option', 'select',
  'textarea', 'noscript', 'address', 'center', 'template',
]);
const AUTO_CLOSE = new Set(['p', 'li', 'option', 'dt', 'dd', 'tr', 'td', 'th']);
const TEXT_ATTRS = new Set(['alt', 'title', 'aria-label', 'aria-description', 'placeholder', 'summary', 'label', 'content']);
const VISUAL_TRICKS = new Set(['low-contrast', 'font-size-zero', 'opacity-zero', 'off-screen', 'transparent-text', 'zero-size']);

interface Block {
  info: HideInfo;
  start: number;
  end: number;
  text: string;
  comment?: boolean;
  natural?: boolean;
}

interface Frame {
  name: string;
  hide: HideInfo | null;
  color: RGBA;
  bg: RGBA;
  bgAssumed: boolean;
  block: Block | null;
}

export interface StructuredResult {
  view: TextView;
  /** Runs after instruction detection: rates hidden blocks and removes weakly hidden ones that carry instructions. */
  post: () => void;
}

const looksNatural = (text: string) => {
  const t = text.trim();
  return t.length >= 40 && t.split(/\s+/).filter((w) => /\p{L}{2,}/u.test(w)).length >= 6;
};

/**
 * Walk HTML (or Markdown with embedded HTML) and build a text view of everything an LLM
 * would read, flagging the parts a human would not see.
 */
export function analyzeStructured(ctx: Ctx): StructuredResult {
  const html = ctx.input;
  const tokens = tokenize(html);

  const rules: SheetRule[] = [];
  let pageBg: RGBA | null = null;
  let pageColor: RGBA | null = null;
  for (const t of tokens) {
    if (t.type === 'raw' && t.name === 'style') {
      const s = parseSheet(html.slice(t.start, t.end));
      rules.push(...s.rules);
      pageBg = s.pageBg ?? pageBg;
      pageColor = s.pageColor ?? pageColor;
    }
  }

  const b = new ViewBuilder();
  const blocks: Block[] = [];
  const weak: Array<{ start: number; end: number; edit: Edit }> = [];
  const root: Frame = { name: '#root', hide: null, color: pageColor ?? [0, 0, 0, 1], bg: pageBg ?? [255, 255, 255, 1], bgAssumed: !pageBg, block: null };
  const stack: Frame[] = [root];
  let scriptStart = -1;

  const finalize = (blk: Block) => {
    if (blk.info.weak) weak.push({ start: blk.start, end: blk.end, edit: { start: blk.start, end: blk.end, replacement: '' } });
    else blocks.push(blk);
  };
  const popTo = (idx: number, matchedEnd: number, innerEnd: number) => {
    while (stack.length > idx) {
      const f = stack.pop() as Frame;
      if (f.block) {
        f.block.end = stack.length === idx ? matchedEnd : innerEnd;
        finalize(f.block);
      }
    }
  };

  for (const t of tokens) {
    for (const f of stack) if (f.block) f.block.end = Math.max(f.block.end, t.end);
    const cur = stack[stack.length - 1] as Frame;
    if (t.type === 'text') {
      const { text, map } = decodeEntities(html.slice(t.start, t.end), t.start);
      const reason = cur.hide?.reason ?? null;
      if (map) b.pushMapped(text, map, reason);
      else b.push(text, t.start, reason);
      for (const f of stack) if (f.block) f.block.text += text;
    } else if (t.type === 'comment') {
      ctx.edits.push({ start: t.start, end: t.end, replacement: '' });
      const content = html.slice(t.contentStart, t.contentEnd);
      if (/^\s*\[if\b|^\s*<!\[endif|^\s*\[endif/i.test(content)) continue;
      const { text, map } = decodeEntities(content, t.contentStart);
      b.pushAt('\n', t.start);
      if (map) b.pushMapped(text, map, 'HTML comment');
      else b.push(text, t.contentStart, 'HTML comment');
      b.pushAt('\n', t.end - 1);
      blocks.push({ info: { id: 'html-comment', reason: 'HTML comment' }, start: t.start, end: t.end, text, comment: true, natural: looksNatural(text) });
    } else if (t.type === 'open') {
      const name = t.name;
      if (AUTO_CLOSE.has(name) && cur.name === name) popTo(stack.length - 1, t.start, t.start);
      const parent = stack[stack.length - 1] as Frame;
      const attrs = new Map(t.attrs.map((a) => [a.name, a]));
      const attrVal = (n: string) => {
        const a = attrs.get(n);
        return a ? decodeEntities(a.raw).text : undefined;
      };

      const st = new Map<string, string>();
      if (rules.length) {
        const classes = (attrVal('class') ?? '').toLowerCase().split(/\s+/).filter(Boolean);
        const id = (attrVal('id') ?? '').toLowerCase();
        for (const r of rules) {
          if (r.tag && r.tag !== name) continue;
          if (r.cls && !classes.includes(r.cls)) continue;
          if (r.id && r.id !== id) continue;
          if (!r.cls && !r.id) continue;
          for (const [k, v] of r.decls) st.set(k, v);
        }
      }
      const inline = attrVal('style');
      if (inline) for (const [k, v] of parseStyle(inline)) st.set(k, v);

      let own: HideInfo | null = null;
      if (attrs.has('hidden')) own = { id: 'hidden-attribute', reason: 'hidden attribute' };
      else if (name === 'noscript') own = { id: 'noscript', reason: '<noscript>' };
      else if (name === 'template') own = { id: 'template', reason: '<template>', weak: true };
      if (!own) own = styleHiding(st);

      const ownColor = parseColor(st.get('color'));
      const ownBg = backgroundColor(st);
      const hasBg = !!ownBg && ownBg[3] > 0.1;
      const bg = hasBg ? over(ownBg as RGBA, parent.bg) : parent.bg;
      const bgAssumed = hasBg ? false : parent.bgAssumed;
      const color = ownColor ?? parent.color;
      if ((!own || own.weak) && (ownColor || hasBg) && color[3] > 0.1) {
        const ratio = contrast(over(color, bg), bg);
        if (ratio < 1.25) {
          own = {
            id: 'low-contrast',
            reason: `text colour ${formatColor(color)} on background ${formatColor(bg)}${bgAssumed ? ' (default page background)' : ''}`,
          };
        }
      }
      if (!own && attrVal('aria-hidden') === 'true') own = { id: 'aria-hidden', reason: 'aria-hidden="true"', weak: true };

      let hide = parent.hide;
      let block: Block | null = null;
      if (own && (!hide || (hide.weak && !own.weak))) {
        hide = own;
        block = { info: own, start: t.start, end: t.end, text: '' };
      }

      if (BLOCK.has(name)) b.pushAt('\n', t.start);
      const type = (attrVal('type') ?? '').toLowerCase();
      for (const a of t.attrs) {
        const isText =
          TEXT_ATTRS.has(a.name) ||
          (a.name === 'value' && type === 'hidden') ||
          (a.name.startsWith('data-') && a.raw.length >= 40);
        if (!isText || !a.raw.trim()) continue;
        if (a.name === 'content' && name !== 'meta') continue;
        const { text, map } = decodeEntities(a.raw, a.valueStart);
        const reason = hide && !hide.weak ? hide.reason : `${a.name} attribute`;
        b.pushAt('\n', t.start);
        if (map) b.pushMapped(text, map, reason);
        else b.push(text, a.valueStart, reason);
        b.pushAt('\n', t.start);
        weak.push({ start: a.valueStart, end: a.valueStart + a.raw.length, edit: { start: a.valueStart, end: a.valueStart + a.raw.length, replacement: '' } });
        if (block) block.text += ` ${text}`;
      }

      if (name === 'script' && !t.selfClosing) scriptStart = t.start;
      if (VOID.has(name) || t.selfClosing) {
        if (block) {
          block.end = t.end;
          finalize(block);
        }
        continue;
      }
      stack.push({ name, hide, color, bg, bgAssumed, block });
    } else if (t.type === 'close') {
      if (t.name === 'script' && scriptStart >= 0) {
        ctx.edits.push({ start: scriptStart, end: t.end, replacement: '' });
        scriptStart = -1;
      }
      let idx = -1;
      for (let k = stack.length - 1; k >= 1; k--) {
        if ((stack[k] as Frame).name === t.name) {
          idx = k;
          break;
        }
      }
      if (idx > 0) popTo(idx, t.end, t.start);
      if (BLOCK.has(t.name)) b.pushAt('\n', t.start);
    }
  }
  while (stack.length > 1) {
    const f = stack.pop() as Frame;
    if (f.block) finalize(f.block);
  }

  const view = b.build();

  // Markdown comments: [//]: # (hidden text)
  const mdBlocks: Block[] = [];
  if (ctx.type === 'markdown') {
    for (const m of html.matchAll(/^[ \t]{0,3}\[[^\]\n]*\]:[ \t]*(?:#|<>)[ \t]*(?:\((.*)\)|"(.*)"|'(.*)')[ \t]*$/gm)) {
      const start = m.index ?? 0;
      const end = start + m[0].length;
      mdBlocks.push({ info: { id: 'markdown-comment', reason: 'Markdown comment' }, start, end, text: m[1] ?? m[2] ?? m[3] ?? '', comment: true, natural: looksNatural(m[1] ?? m[2] ?? m[3] ?? '') });
      ctx.edits.push({ start, end, replacement: '' });
    }
    if (mdBlocks.length && view.offsets && view.hidden) {
      for (let i = 0; i < view.text.length; i++) {
        const o = view.offsets[i] as number;
        if (mdBlocks.some((mb) => o >= mb.start && o < mb.end)) view.hidden[i] = 'Markdown comment';
      }
    }
    blocks.push(...mdBlocks);
  }

  const post = () => {
    const instr = ctx.findings.filter((f) => f.category === 'instruction');
    const hasInstr = (s: number, e: number) => instr.some((f) => f.location.start >= s && f.location.start < e);
    for (const blk of blocks) {
      const text = clip(blk.text, 100000);
      const has = hasInstr(blk.start, blk.end);
      if (blk.comment) {
        ctx.hiddenRegions++;
        if (!has && !blk.natural) continue;
      } else {
        ctx.edits.push({ start: blk.start, end: blk.end, replacement: '' });
        if (!text && !has) continue;
        ctx.hiddenRegions++;
      }
      const len = text.length;
      let severity: Severity;
      if (has) severity = 'high';
      else if (blk.comment) severity = 'info';
      else if (VISUAL_TRICKS.has(blk.info.id)) severity = len >= 20 ? 'medium' : 'low';
      else severity = len >= 40 ? 'low' : 'info';
      ctx.add({
        id: `hidden-text/${blk.info.id}`,
        category: 'hidden-text',
        severity,
        message: has
          ? `Text hidden from human readers (${blk.info.reason}) contains instructions aimed at AI.`
          : `${len} character${len === 1 ? '' : 's'} of text hidden from human readers (${blk.info.reason}).`,
        excerpt: clip(text, ctx.maxExcerpt),
        start: blk.start,
        end: blk.end,
        hidden: blk.info.reason,
      });
    }
    for (const w of weak) if (hasInstr(w.start, w.end)) ctx.edits.push(w.edit);
  };

  return { view, post };
}

/** Inline-style / tiny-stylesheet helpers: declarations, lengths, colours and contrast. */

export type RGBA = [number, number, number, number];

export function parseStyle(style: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const decl of style.split(';')) {
    const c = decl.indexOf(':');
    if (c < 0) continue;
    const prop = decl.slice(0, c).trim().toLowerCase();
    const val = decl.slice(c + 1).replace(/!\s*important/i, '').trim().toLowerCase();
    if (prop) out.set(prop, val);
  }
  return out;
}

/** Length in px (em/rem assume 16px, % of 16px). `null` if not a plain length. */
export function lengthPx(v: string | undefined): number | null {
  if (v === undefined) return null;
  const m = /^(-?\d*\.?\d+)\s*(px|em|rem|pt|%|vw|vh|ch|ex)?$/.exec(v.trim());
  if (!m) return null;
  const n = parseFloat(m[1] as string);
  switch (m[2]) {
    case 'em':
    case 'rem':
      return n * 16;
    case 'pt':
      return (n * 4) / 3;
    case '%':
      return (n / 100) * 16;
    case 'vw':
    case 'vh':
      return n * 10;
    case 'ch':
    case 'ex':
      return n * 8;
    default:
      return n;
  }
}

const NAMED: Readonly<Record<string, RGBA>> = {
  white: [255, 255, 255, 1], black: [0, 0, 0, 1], red: [255, 0, 0, 1], green: [0, 128, 0, 1],
  blue: [0, 0, 255, 1], gray: [128, 128, 128, 1], grey: [128, 128, 128, 1], silver: [192, 192, 192, 1],
  yellow: [255, 255, 0, 1], orange: [255, 165, 0, 1], purple: [128, 0, 128, 1], navy: [0, 0, 128, 1],
  maroon: [128, 0, 0, 1], teal: [0, 128, 128, 1], olive: [128, 128, 0, 1], lime: [0, 255, 0, 1],
  aqua: [0, 255, 255, 1], cyan: [0, 255, 255, 1], fuchsia: [255, 0, 255, 1], magenta: [255, 0, 255, 1],
  whitesmoke: [245, 245, 245, 1], snow: [255, 250, 250, 1], ivory: [255, 255, 240, 1],
  ghostwhite: [248, 248, 255, 1], floralwhite: [255, 250, 240, 1], azure: [240, 255, 255, 1],
  mintcream: [245, 255, 250, 1], aliceblue: [240, 248, 255, 1], seashell: [255, 245, 238, 1],
  linen: [250, 240, 230, 1], beige: [245, 245, 220, 1], lightgray: [211, 211, 211, 1],
  lightgrey: [211, 211, 211, 1], gainsboro: [220, 220, 220, 1], darkgray: [169, 169, 169, 1],
  dimgray: [105, 105, 105, 1], transparent: [0, 0, 0, 0],
};

function hslToRgb(h: number, s: number, l: number): [number, number, number] {
  const k = (n: number) => (n + h / 30) % 12;
  const a = s * Math.min(l, 1 - l);
  const f = (n: number) => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
  return [Math.round(f(0) * 255), Math.round(f(8) * 255), Math.round(f(4) * 255)];
}

export function parseColor(v: string | undefined): RGBA | null {
  if (!v) return null;
  const s = v.trim().toLowerCase();
  if (NAMED[s]) return [...NAMED[s]] as RGBA;
  let m = /^#([0-9a-f]{3,8})$/.exec(s);
  if (m) {
    const h = m[1] as string;
    if (h.length === 3 || h.length === 4) {
      const p = [...h].map((c) => parseInt(c + c, 16));
      return [p[0] as number, p[1] as number, p[2] as number, h.length === 4 ? (p[3] as number) / 255 : 1];
    }
    if (h.length === 6 || h.length === 8) {
      const p = [0, 2, 4, 6].map((i) => parseInt(h.slice(i, i + 2), 16));
      return [p[0] as number, p[1] as number, p[2] as number, h.length === 8 ? (p[3] as number) / 255 : 1];
    }
    return null;
  }
  m = /^(rgba?|hsla?)\(([^)]*)\)$/.exec(s);
  if (m) {
    const parts = (m[2] as string).split(/[\s,/]+/).filter(Boolean);
    const num = (x: string | undefined, scale: number) => {
      if (x === undefined) return NaN;
      return x.endsWith('%') ? (parseFloat(x) / 100) * scale : parseFloat(x);
    };
    const alpha = parts[3] !== undefined ? num(parts[3], 1) : 1;
    if ((m[1] as string).startsWith('rgb')) {
      const rgb = [num(parts[0], 255), num(parts[1], 255), num(parts[2], 255)];
      if (rgb.some((x) => Number.isNaN(x))) return null;
      return [rgb[0] as number, rgb[1] as number, rgb[2] as number, Number.isNaN(alpha) ? 1 : alpha];
    }
    const h = parseFloat(parts[0] ?? '');
    const sat = num(parts[1], 1);
    const l = num(parts[2], 1);
    if ([h, sat, l].some((x) => Number.isNaN(x))) return null;
    const [r, g, b] = hslToRgb(((h % 360) + 360) % 360, sat, l);
    return [r, g, b, Number.isNaN(alpha) ? 1 : alpha];
  }
  return null;
}

/** First colour token in a `background` shorthand. */
export function backgroundColor(st: Map<string, string>): RGBA | null {
  const direct = parseColor(st.get('background-color'));
  if (direct) return direct;
  const bg = st.get('background');
  if (!bg) return null;
  const whole = parseColor(bg);
  if (whole) return whole;
  for (const tok of bg.match(/#[0-9a-f]{3,8}\b|(?:rgba?|hsla?)\([^)]*\)|\b[a-z]+\b/gi) ?? []) {
    const c = parseColor(tok);
    if (c) return c;
  }
  return null;
}

function luminance([r, g, b]: RGBA): number {
  const ch = (v: number) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b);
}

/** WCAG contrast ratio between two opaque colours (1 = identical, 21 = black on white). */
export function contrast(a: RGBA, b: RGBA): number {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** Composite a possibly translucent colour over an opaque background. */
export function over(fg: RGBA, bg: RGBA): RGBA {
  const a = fg[3];
  return [fg[0] * a + bg[0] * (1 - a), fg[1] * a + bg[1] * (1 - a), fg[2] * a + bg[2] * (1 - a), 1];
}

export function formatColor(c: RGBA): string {
  const hex = (n: number) => Math.round(n).toString(16).padStart(2, '0');
  return `#${hex(c[0])}${hex(c[1])}${hex(c[2])}${c[3] < 1 ? hex(c[3] * 255) : ''}`;
}

export interface HideInfo {
  id: string;
  reason: string;
  /** Weak hiding (aria-hidden, screen-reader-only): only reported when it contains instructions. */
  weak?: boolean;
}

/** Hiding techniques that do not depend on inherited colours. */
export function styleHiding(st: Map<string, string>): HideInfo | null {
  const display = st.get('display');
  if (display === 'none') return { id: 'display-none', reason: 'display:none' };
  const vis = st.get('visibility');
  if (vis === 'hidden' || vis === 'collapse') return { id: 'visibility-hidden', reason: `visibility:${vis}` };
  const op = st.get('opacity');
  if (op !== undefined) {
    const n = op.endsWith('%') ? parseFloat(op) / 100 : parseFloat(op);
    if (!Number.isNaN(n) && n <= 0.05) return { id: 'opacity-zero', reason: `opacity:${op}` };
  }
  const fs = lengthPx(st.get('font-size'));
  if (fs !== null && fs <= 1.5) return { id: 'font-size-zero', reason: `font-size:${st.get('font-size')}` };
  const color = parseColor(st.get('color'));
  if (color && color[3] <= 0.1) return { id: 'transparent-text', reason: `color:${st.get('color')}` };
  const ti = lengthPx(st.get('text-indent'));
  if (ti !== null && ti <= -500) return { id: 'off-screen', reason: `text-indent:${st.get('text-indent')}` };
  const pos = st.get('position');
  if (pos === 'absolute' || pos === 'fixed') {
    for (const p of ['left', 'top', 'right', 'bottom']) {
      const v = lengthPx(st.get(p));
      if (v !== null && v <= -500) return { id: 'off-screen', reason: `position:${pos}; ${p}:${st.get(p)}` };
    }
  }
  const tr = st.get('transform');
  if (tr) {
    if (/scale\(\s*0(?:\.0+)?\s*(?:,\s*0(?:\.0+)?\s*)?\)/.test(tr)) return { id: 'zero-size', reason: `transform:${tr}` };
    const t = /translate(?:x|y|3d)?\(\s*(-?\d+(?:\.\d+)?)(px|%|em|rem)/.exec(tr);
    if (t && parseFloat(t[1] as string) <= -500 && t[2] === 'px') return { id: 'off-screen', reason: `transform:${tr}` };
  }
  const overflowHidden = /hidden|clip/.test(st.get('overflow') ?? '');
  const h = lengthPx(st.get('height')) ?? lengthPx(st.get('max-height'));
  const w = lengthPx(st.get('width')) ?? lengthPx(st.get('max-width'));
  const clip = st.get('clip') ?? '';
  const clipPath = st.get('clip-path') ?? '';
  const srOnly =
    /rect\(\s*0(?:px)?[\s,]+0(?:px)?[\s,]+0(?:px)?[\s,]+0(?:px)?\s*\)/.test(clip) ||
    /inset\(\s*(?:50|100)%\s*\)|circle\(\s*0/.test(clipPath) ||
    (overflowHidden && h !== null && h <= 1 && w !== null && w <= 1 && h > 0);
  if (srOnly) return { id: 'clipped', reason: 'clipped to 1px (screen-reader-only)', weak: true };
  if (overflowHidden && ((h !== null && h <= 0) || (w !== null && w <= 0))) return { id: 'zero-size', reason: 'zero-size box with overflow:hidden' };
  return null;
}

export interface SheetRule {
  tag?: string;
  cls?: string;
  id?: string;
  decls: Map<string, string>;
}

/** Parse simple `.class`, `#id`, `tag.class` and `body/html` rules out of a stylesheet. */
export function parseSheet(css: string): { rules: SheetRule[]; pageBg: RGBA | null; pageColor: RGBA | null } {
  const rules: SheetRule[] = [];
  let pageBg: RGBA | null = null;
  let pageColor: RGBA | null = null;
  const clean = css.replace(/\/\*[\s\S]*?\*\//g, '');
  for (const m of clean.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const decls = parseStyle(m[2] as string);
    for (const raw of (m[1] as string).split(',')) {
      const sel = raw.trim().toLowerCase();
      if (sel === 'body' || sel === 'html' || sel === ':root') {
        pageBg = backgroundColor(decls) ?? pageBg;
        pageColor = parseColor(decls.get('color')) ?? pageColor;
        continue;
      }
      const sm = /^([a-z][a-z0-9-]*)?(?:\.([\w-]+)|#([\w-]+))$/.exec(sel);
      if (sm) rules.push({ tag: sm[1], cls: sm[2], id: sm[3], decls });
    }
  }
  return { rules, pageBg, pageColor };
}

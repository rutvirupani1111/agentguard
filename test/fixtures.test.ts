import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scan } from '../src/index';

const fixture = (name: string) => readFileSync(join(__dirname, 'fixtures', name), 'utf8');

describe('fixture: product page with white-on-white injection', () => {
  const r = scan(fixture('product-page.html'));

  it('is detected as HTML and rated critical', () => {
    expect(r.stats.type).toBe('html');
    expect(r.severity).toBe('critical');
    expect(r.risk).toBeGreaterThanOrEqual(95);
  });

  it('explains the hiding technique and the instructions', () => {
    const hidden = r.findings.find((f) => f.id === 'hidden-text/low-contrast');
    expect(hidden?.severity).toBe('high');
    expect(hidden?.hidden).toContain('#ffffff');
    const ids = r.findings.filter((f) => f.severity === 'critical').map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(['instruction/override', 'instruction/exfiltration', 'instruction/concealment']));
  });

  it('points at the right line', () => {
    const f = r.findings.find((x) => x.id === 'instruction/override')!;
    expect(f.location.line).toBe(24);
  });

  it('sanitizes the attack but keeps the product content', () => {
    expect(r.sanitized).not.toMatch(/cart-recovery|ignore all previous/i);
    expect(r.sanitized).toContain('Add to cart');
    expect(r.sanitized).toContain('Trailblazer 40L Hiking Backpack');
    expect(r.sanitized).not.toContain('<script>window.dataLayer');
  });

  it('does not over-report the benign parts of the page', () => {
    const benign = r.findings.filter((f) => !['instruction', 'hidden-text'].includes(f.category) || f.id === 'hidden-text/display-none');
    expect(benign.every((f) => f.severity === 'info' || f.severity === 'low')).toBe(true);
  });
});

describe('fixture: GitHub issue with an HTML comment injection', () => {
  const r = scan(fixture('github-issue.md'));

  it('is treated as Markdown and rated critical', () => {
    expect(r.stats.type).toBe('markdown');
    expect(r.severity).toBe('critical');
  });

  it('finds the hidden instructions inside the comment', () => {
    const critical = r.findings.filter((f) => f.severity === 'critical');
    expect(critical.length).toBeGreaterThanOrEqual(2);
    expect(critical.every((f) => f.hidden === 'HTML comment')).toBe(true);
    expect(r.findings.find((f) => f.id === 'hidden-text/html-comment')?.severity).toBe('high');
  });

  it('removes the comment and keeps the bug report', () => {
    expect(r.sanitized).not.toContain('npmrc');
    expect(r.sanitized).toContain('parseConfig');
    expect(r.sanitized).toContain('Expected:');
  });
});

describe('fixture: README with an exfiltration image', () => {
  const r = scan(fixture('readme-exfil.md'));

  it('flags the templated webhook image as critical', () => {
    const f = r.findings.find((x) => x.id === 'exfiltration/templated-url');
    expect(f?.severity).toBe('critical');
    expect(f?.url).toContain('webhook.site');
    expect(f?.message).toMatch(/webhook\.site/);
  });

  it('finds the instruction hidden in the Markdown comment', () => {
    const f = r.findings.find((x) => x.category === 'instruction' && x.hidden === 'Markdown comment');
    expect(f?.severity).toBe('critical');
  });

  it('leaves the npm badge alone', () => {
    expect(r.findings.some((f) => f.url?.includes('shields.io'))).toBe(false);
  });

  it('sanitizes the image and comment', () => {
    expect(r.sanitized).not.toContain('webhook.site');
    expect(r.sanitized).not.toContain('[//]: #');
    expect(r.sanitized).toContain('[image removed by agentguard]');
    expect(r.sanitized).toContain('A tiny, fast CSV parser');
  });
});

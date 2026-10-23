#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { runCli } from './cli-core';

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  return Buffer.concat(chunks).toString('utf8');
}

runCli(process.argv.slice(2), {
  readFile: (p) => readFile(p, 'utf8'),
  readStdin,
  async fetchUrl(url) {
    const res = await fetch(url, { headers: { 'user-agent': 'agentguard (+https://github.com/rutvirupani1111/agentguard)' }, redirect: 'follow' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { body: await res.text(), contentType: res.headers.get('content-type') ?? '' };
  },
  out: (t) => process.stdout.write(`${t}\n`),
  err: (t) => process.stderr.write(`${t}\n`),
  color: Boolean(process.stdout.isTTY) && !process.env.NO_COLOR,
}).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    process.stderr.write(`agentguard: ${(e as Error)?.stack ?? String(e)}\n`);
    process.exitCode = 2;
  },
);

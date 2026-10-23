# Status

_Last updated: 2026-10-23 · version 0.1.0 (unpublished)_

## Done

| Area | What ships |
| --- | --- |
| Core API | `scan()`, `sanitize()`, `isSafe()`, `wrapUntrusted()`, `detectType()`; ESM + CJS + `.d.ts` via tsup; zero runtime dependencies |
| Unicode | Tag characters (decoded), variation-selector byte payloads (decoded), zero-width runs (emoji ZWJ, BOM and non-Latin joiners exempt), bidi overrides/isolates, homoglyph keywords, mixed-script words, fullwidth / mathematical alphanumerics |
| Instructions | ~20 rule families: override, forget, prompt extraction, chat-template tokens, fake system headers, new instructions, role reassignment, AI-addressed text, concealment, exfiltration requests, render-image-with-data, tool invocation, jailbreak markers, boundary spoofing; es/fr/de/pt/it/zh/ja/ru override variants. Matched on normalised text (invisible chars dropped, look-alikes folded). Hidden + imperative escalates to critical |
| HTML | Own tokenizer with source offsets and entity decoding; inline styles plus simple `.class`/`#id` stylesheet rules; display/visibility/opacity/font-size/transparent/low-contrast (WCAG ratio vs inherited background)/off-screen/text-indent/zero-size/hidden attribute/noscript/comments/aria-hidden/screen-reader-only/alt-title-aria-label-meta attributes |
| Markdown | Same pipeline (embedded HTML + comments) plus `[//]: # (...)` comments, image/link/reference URLs |
| Exfiltration | Templated URLs, request catchers and tunnels (webhook.site, requestbin, pipedream, ngrok, trycloudflare, OAST, Discord/Telegram/Slack/Teams webhooks), `data:` and `javascript:` URLs, long base64/hex query payloads (signature params ignored) |
| Sanitizer | Removes hidden blocks, comments, scripts, invisible characters, injected instructions in visible text, instruction-bearing attributes; neutralises exfiltration URLs |
| CLI | `agentguard scan|sanitize|wrap <file|url|->`, `--json`, `--fail-on <severity|score>`, `--type`, `--quiet`, colour output |
| Tests | 169 vitest cases including three realistic fixtures |

## Known limitations

- Pattern matching is English-first. Other languages only cover the classic "ignore previous instructions" phrasing.
- CSS support is intentionally tiny: inline styles plus single-class / single-id selectors. Descendant selectors, media queries, external stylesheets and computed layout are not evaluated.
- Low-contrast detection assumes a white page when no background is declared inline or in a `body`/`html` rule.
- Markdown code blocks are not special-cased: HTML samples inside fenced code are analysed like live markup.
- Invisible characters that arrive via HTML entities (`&#8203;`, `&#xE0049;`) are normalised away for matching but not reported as Unicode findings.
- Instructions that span two block elements are only matched within one block.
- A deterministic scanner cannot catch paraphrased or novel injections. Pair it with least-privilege tools and human confirmation for side effects.

## Next

1. Benchmark against public injection datasets (BIPIA, Tensor Trust, HackAPrompt) and publish precision/recall.
2. Rule packs per language and a plugin API for custom rules.
3. PDF/DOCX text extraction adapters (hidden text in white fonts, tiny fonts, off-page objects).
4. Streaming mode for very large documents.
5. `npm publish` once the API is reviewed.

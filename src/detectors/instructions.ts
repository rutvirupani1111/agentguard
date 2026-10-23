import type { Severity } from '../types';
import { excerptAround, hiddenAt, maxSeverity, normalizeView, offsetAt, rank, WEAK_HIDDEN, type Ctx, type TextView } from '../util';

export interface InstructionRule {
  id: string;
  severity: Severity;
  message: string;
  re: RegExp;
}

const AI_NOUN =
  '(?:ai|a\\.i\\.|llms?|large\\s+language\\s+models?|language\\s+models?|ai\\s+(?:assistants?|agents?|models?|systems?)|assistants?|chatbots?|agents?|bots?|gpts?|claude|chatgpt|gemini|copilot|crawlers?|summari[sz]ers?)';

const SENSITIVE =
  "(?:conversation|chat|history|transcript|context|system\\s+prompt|credentials?|passwords?|api[\\s_-]?keys?|secrets?|tokens?|cookies?|session|ssn|social\\s+security|credit\\s+card|card\\s+numbers?|bank|personal|private|user'?s|users'|their|contents?|cart|inbox|emails|files|documents|memory|everything|all\\s+(?:data|information|messages))";

const DEST =
  "(?:https?:\\/\\/\\S+|www\\.\\S+|[\\w.+-]+@[\\w-]+(?:\\.[\\w-]+)+|(?:this|the\\s+following|the\\s+attacker'?s?|my|our)\\s+(?:url|link|address|endpoint|webhook|server|email|inbox|site|website|domain))";

/** English plus a few common variants and languages. Matched against normalised text. */
export const INSTRUCTION_RULES: InstructionRule[] = [
  {
    id: 'instruction/override',
    severity: 'high',
    message: "Tries to override the model's existing instructions",
    re: /\b(?:ignore|disregard|forget|skip|override|bypass|neglect|abandon)\b[^.!?\n]{0,40}?\b(?:previous|prior|above|earlier|preceding|foregoing|former|all|any|every|your|the|those|these|system|original|initial|existing|old)\b[^.!?\n]{0,30}?\b(?:instructions?|prompts?|directions?|directives?|rules|guidelines|guidance|context|commands?|constraints|guardrails|polic(?:y|ies)|programming)\b/gi,
  },
  {
    id: 'instruction/override',
    severity: 'high',
    message: "Tries to override the model's existing instructions (non-English)",
    re: /(?:\b(?:ignora|ignore|olvida|omite|descarta)\s+(?:todas?\s+)?(?:las?\s+|tus\s+)?(?:instrucciones|indicaciones|ordenes|reglas)\s+(?:anteriores|previas)|\b(?:ignorez|ignorer|ignore|oubliez|oublie)\s+(?:toutes?\s+)?(?:les\s+|vos\s+|tes\s+)?(?:instructions|consignes|directives|regles)\s+(?:precedentes|anterieures)|\b(?:ignoriere|ignorieren\s+sie|vergiss|vergessen\s+sie|missachte)\s+(?:alle\s+)?(?:vorherigen|bisherigen|vorigen|obigen|fruheren)\s+(?:anweisungen|instruktionen|befehle|regeln)|\b(?:ignore|ignora|esqueca|desconsidere)\s+(?:todas\s+)?(?:as\s+)?(?:instrucoes|ordens|regras)\s+(?:anteriores|previas)|\b(?:ignora|dimentica)\s+(?:tutte\s+)?(?:le\s+)?(?:istruzioni|regole)\s+(?:precedenti|anteriori)|(?:忽略|无视|忘记|忽视)(?:之前|以上|先前|上面|前面|所有)(?:的)?(?:所有)?(?:的)?(?:指令|指示|说明|提示|规则)|(?:以前|前|上記|これまで)の(?:すべての)?(?:指示|命令|指令|ルール)を(?:すべて)?(?:無視|忘れ)|(?:игнорируй|игнорировать|забудь|проигнорируй)\s+(?:все\s+)?(?:предыдущие|прежние|предшествующие)\s+(?:инструкции|указания|команды))/gi,
  },
  {
    id: 'instruction/override',
    severity: 'medium',
    message: 'Asks the model to forget what it was told',
    re: /\b(?:forget|disregard|ignore)\s+(?:everything|all)\s+(?:(?:you(?:'ve|\s+have|\s+were)?\s+(?:been\s+)?(?:told|instructed|given|programmed|taught))|above|before|prior|previously|so\s+far)\b/gi,
  },
  {
    id: 'instruction/prompt-extraction',
    severity: 'high',
    message: 'Asks the model to reveal its system prompt or hidden instructions',
    re: /\b(?:reveal|print|show|display|output|repeat|leak|disclose|dump|share|recite|tell\s+me|give\s+me|write\s+out)\b[^.!?\n]{0,30}?\b(?:system\s+(?:prompt|message|instructions?)|initial\s+(?:prompt|instructions?)|developer\s+(?:prompt|message|instructions?)|hidden\s+(?:prompt|instructions?)|your\s+(?:instructions|prompt|rules|guidelines|configuration))\b/gi,
  },
  {
    id: 'instruction/chat-template',
    severity: 'high',
    message: 'Contains chat-template control tokens used to forge system/assistant turns',
    re: /<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id|eot_id|begin_of_text)\|>|\[\/?INST\]|<<\/?SYS>>|\[\/?SYSTEM\]|<\/?(?:system|assistant)>/gi,
  },
  {
    id: 'instruction/chat-template',
    severity: 'medium',
    message: 'Fake system/instruction header',
    re: /^[ \t]*(?:#{1,4}|\*\*|\[)?[ \t]*(?:system|system\s+prompt|instructions?\s+for\s+(?:the\s+)?(?:ai|assistant|model|agent)|ai\s+instructions?)[ \t]*(?:\*\*|\])?[ \t]*:/gim,
  },
  {
    id: 'instruction/new-instructions',
    severity: 'medium',
    message: 'Announces new or replacement instructions',
    re: /\b(?:new|updated|real|actual|true|revised|additional|secret|hidden)\s+(?:system\s+)?(?:instructions?|directives?|orders)\s*(?::|-|are\b|follow\b)|\byour\s+(?:new|real|actual|true|only|primary)\s+(?:task|goal|objective|purpose|instructions?|role|job|mission)\s+(?:is|are|will\s+be|now)\b/gi,
  },
  {
    id: 'instruction/role-reassignment',
    severity: 'medium',
    message: 'Tries to reassign the model a new identity or role',
    re: /\byou\s+are\s+(?:now\s+(?!(?:subscribed|unsubscribed|registered|logged|signed|connected|enrolled|ready|able|eligible|part|a\s+member|a\s+subscriber|following|verified|set|all\s+set|booked|confirmed|checked|on\s+the|in\s+the|leaving|viewing|being|using|done|redirected)\b)|no\s+longer\s+(?:an?\s+)?(?:ai|assistant|bound|restricted|chatbot|claude|chatgpt)|not\s+(?:an?\s+)?(?:ai|assistant|chatbot|language\s+model)\b)|\bfrom\s+now\s+on,?\s+(?:you|act|respond|answer|reply|behave|ignore|only)\b|\bpretend\s+(?:to\s+be|you\s+are|that\s+you\s+are)\b|\b(?:act|behave|respond)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|evil|rogue|dan)\b|\broleplay\s+as\b|\byou\s+will\s+now\s+(?:act|behave|respond|answer|be)\b/gi,
  },
  {
    id: 'instruction/ai-addressed',
    severity: 'medium',
    message: 'Text addresses AI systems directly, which is how indirect prompt injections speak to agents',
    re: new RegExp(
      [
        `\\bas\\s+an?\\s+(?:ai|llm|language\\s+model|large\\s+language\\s+model)(?:\\s+(?:assistant|agent|model|system|chatbot))?\\s*,?\\s+you\\s+(?:must|should|shall|need\\s+to|are\\s+(?:required|instructed|expected)\\s+to|have\\s+to|will|cannot|can't|may\\s+not)\\b`,
        `\\b(?:when|if|whenever|once)\\s+(?:an?\\s+|the\\s+|any\\s+)?${AI_NOUN}\\s+(?:[\\w'-]+\\s+){0,6}?(?:it|they|you)\\s+(?:must|should|shall|needs?\\s+to|has\\s+to|have\\s+to|will\\s+need\\s+to)\\b`,
        `\\b(?:if|when)\\s+you\\s+are\\s+an?\\s+(?:ai|llm|large\\s+language\\s+model|language\\s+model|ai\\s+(?:assistant|agent|model)|assistant|chatbot|bot|agent|automated\\s+(?:system|agent|tool)|crawler|scraper|summari[sz]er)\\b`,
        `\\b(?:attention|note|message|instructions?|important(?:\\s+note)?|reminder|notice)\\s+(?:to|for)\\s+(?:the\\s+|any\\s+|all\\s+)?${AI_NOUN}\\b`,
        `\\b(?:dear|hey|attention|attn)\\s*,?\\s+(?:ai|a\\.i\\.|llm|assistant|chatbot|ai\\s+agent|ai\\s+assistant|language\\s+model|chatgpt|gpt)\\b`,
        `\\b(?:ai|llm|assistant|chatbot|agent|chatgpt|gpt|copilot)s?\\s*[,:]\\s*(?:you\\s+)?(?:must|should|please|now|ignore|do\\s+not|don't|never|always|immediately)\\b`,
      ].join('|'),
      'gi',
    ),
  },
  {
    id: 'instruction/concealment',
    severity: 'high',
    message: 'Asks the model to hide something from the user',
    re: /\b(?:do\s+not|don't|dont|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|reveal(?:ing)?|alert(?:ing)?|notify(?:ing)?|warn(?:ing)?|show(?:ing)?|disclos(?:e|ing)|let(?:ting)?)\s+(?:this\s+to\s+)?(?:the\s+|your\s+|any\s+)?(?:user|users|human|humans|customer|reader|operator|owner)\b|\b(?:do\s+not|don't|never)\s+(?:mention|reveal|disclose|acknowledge|reference|repeat|discuss|admit)\s+(?:this|these|that|the|any)\s+(?:instructions?|message|prompt|note|request|command|directive)s?\b|\b(?:keep|hide)\s+(?:this|these|it)\s+(?:secret|hidden|confidential|private)\s+from\s+(?:the\s+)?(?:user|human)|\b(?:the\s+)?(?:user|human)\s+(?:must|should|will|need)\s+(?:not|never)\s+(?:know|see|find\s+out|be\s+(?:told|informed|aware))\b/gi,
  },
  {
    id: 'instruction/exfiltration',
    severity: 'high',
    message: 'Asks the model to send user data or conversation contents somewhere',
    re: new RegExp(
      `\\b(?:send|email|e-mail|forward|post|upload|transmit|leak|exfiltrate|submit|copy|append|attach|deliver|report|share)\\b[^.!?\\n]{0,50}?\\b${SENSITIVE}[^.!?\\n]{0,50}?\\b(?:to|at|into|via)\\s+${DEST}`,
      'gi',
    ),
  },
  {
    id: 'instruction/exfiltration',
    severity: 'high',
    message: 'Asks the model to visit a URL carrying user or conversation data',
    re: /\b(?:visit|open|load|fetch|navigate\s+to|go\s+to|browse\s+to|request|call|curl|wget|ping)\b[^.!?\n]{0,40}?(?:https?:\/\/\S+|this\s+(?:url|link|endpoint|page)|the\s+following\s+(?:url|link|endpoint|page))[^.!?\n]{0,60}?\b(?:with|including|containing|appending|append|adding|add|and\s+(?:include|append|add))\b[^.!?\n]{0,40}?\b(?:user|their|conversation|chat|history|data|info|information|details|email|name|address|password|credentials?|token|key|cookie|session|contents?)\b/gi,
  },
  {
    id: 'instruction/exfiltration',
    severity: 'high',
    message: "Asks the model to include the user's private data in its output",
    re: /\binclude\s+(?:the\s+)?(?:user'?s?|users'|their|customer'?s?|your\s+user'?s?)\s+(?:[\w-]+\s+){0,2}?(?:email|e-mail|name|address|phone|password|credentials?|data|details|information|history|messages?|conversation|location|account|card|ssn|token|session|cookies?)\b/gi,
  },
  {
    id: 'instruction/exfiltration',
    severity: 'high',
    message: 'Asks the model to render an image or link that carries conversation data',
    re: /\b(?:render|display|show|output|print|include|add|append|embed|insert)\b[^.!?\n]{0,60}?\b(?:image|badge|img|pixel|link|url)\b[^.!?\n]{0,60}?\b(?:with|containing|including|carrying|that\s+includes)\b[^.!?\n]{0,30}?\b(?:conversation|chat|history|transcript|context|user'?s?|their|previous\s+messages|messages|secrets?)\b/gi,
  },
  {
    id: 'instruction/tool-invocation',
    severity: 'medium',
    message: 'Tells the model to invoke a tool or function',
    re: /\b(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?[\w.-]*(?:send_?email|send_?message|http_?request|web_?request|fetch_?url|browser|execute_?command|run_?shell|shell|terminal|run_?code|python|write_?file|delete_?file|transfer_?funds|make_?payment|purchase)[\w.-]*\s+(?:tool|function|plugin|action)\b/gi,
  },
  {
    id: 'instruction/jailbreak',
    severity: 'high',
    message: 'Contains a known jailbreak / safety-bypass phrase',
    re: /\b(?:do\s+anything\s+now|dan\s+mode|developer\s+mode\s+(?:enabled|on|activated|output)|jailbr(?:eak|oken)\s+mode|(?:enable|activate|enter|switch\s+to)\s+(?:developer|god|admin|sudo|debug|unrestricted|jailbreak|dan)\s+mode|you\s+(?:have|are\s+under)\s+no\s+(?:restrictions|limitations|rules|filters|guidelines|content\s+polic(?:y|ies))|(?:respond|answer|reply|act|operate|speak|write)\s+without\s+(?:any\s+)?(?:ethical\s+|moral\s+|safety\s+)?(?:restrictions|limitations|filters|censorship|guardrails)|(?:ignore|bypass|disable|turn\s+off)\s+(?:your\s+|all\s+|the\s+)?(?:safety|content|ethical|moral)\s+(?:filters?|guidelines|rules|policies|restrictions|protocols|training))\b/gi,
  },
  {
    id: 'instruction/jailbreak',
    severity: 'medium',
    message: 'Role-play jailbreak marker',
    re: /\bstay\s+in\s+character\b|\b(?:evil|unfiltered|uncensored|amoral|unrestricted)\s+(?:ai|assistant|chatbot|mode|version|model|persona)\b/gi,
  },
  {
    id: 'instruction/boundary-spoof',
    severity: 'medium',
    message: 'Fakes the end of the untrusted content to smuggle text into the trusted context',
    re: /(?:^|\n)[ \t]*(?:-{3,}|={3,}|\*{3,}|#{2,}|\[)?[ \t]*(?:end|begin|start)\s+(?:of\s+)?(?:the\s+)?(?:user(?:'s)?\s+(?:input|message|query|request)|document|context|untrusted\s+(?:content|data|input)|web\s*page|email|search\s+results?|tool\s+(?:output|result))\b|<\/?(?:user|context|document|untrusted[\w-]*|tool_(?:output|result)|function_results?|search_results?)\b[^>]{0,80}>/gi,
  },
];

const SORTED_RULES = [...INSTRUCTION_RULES].sort((a, b) => rank(b.severity) - rank(a.severity));

export const REMOVED_INSTRUCTION = '[agentguard: removed suspected prompt injection]';

/**
 * Pattern-match AI-directed instructions in a view. Matches inside hidden text
 * (display:none, comments, tag characters, ...) are escalated: hidden + imperative = critical.
 */
export function detectInstructions(ctx: Ctx, view: TextView): number {
  const norm = normalizeView(view);
  const text = norm.text;
  const taken: Array<{ s: number; e: number; r: number }> = [];
  let count = 0;
  for (const rule of SORTED_RULES) {
    for (const m of text.matchAll(rule.re)) {
      let s = m.index ?? 0;
      let e = s + m[0].length;
      // trim leading newline/space captured by anchored alternatives
      while (s < e && /\s/.test(text[s] as string)) s++;
      while (e > s && /\s/.test(text[e - 1] as string)) e--;
      if (e <= s) continue;
      const r = rank(rule.severity);
      if (taken.some((t) => t.s < e && s < t.e && t.r >= r)) continue;
      taken.push({ s, e, r });

      let hidden: string | null = null;
      for (let k = s; k < e; k++) {
        const h = hiddenAt(norm, k);
        if (h) {
          hidden = h;
          break;
        }
      }
      const severity: Severity = !hidden
        ? rule.severity
        : WEAK_HIDDEN.has(hidden)
          ? maxSeverity(rule.severity, 'high')
          : r >= rank('medium')
            ? 'critical'
            : 'medium';
      const start = offsetAt(norm, s);
      const end = Math.max(start + 1, offsetAt(norm, e - 1) + 1);
      ctx.add({
        id: rule.id,
        category: 'instruction',
        severity,
        message: hidden ? `${rule.message}, hidden from human readers (${hidden}).` : `${rule.message}.`,
        excerpt: excerptAround(text, s, e, ctx.maxExcerpt),
        start,
        end,
        hidden: hidden ?? undefined,
      });
      count++;
      if (!hidden && rank(severity) >= rank('high')) {
        ctx.edits.push({ start, end, replacement: REMOVED_INSTRUCTION });
      }
    }
  }
  return count;
}

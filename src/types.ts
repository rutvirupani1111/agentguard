/** How bad a single finding (or a whole scan) is. Ordered from least to most severe. */
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** Concrete content types the scanner understands. */
export type ContentType = 'html' | 'markdown' | 'text';

/** Content type passed to `scan()`. `auto` sniffs the input. */
export type InputType = ContentType | 'auto';

/** Detector families. */
export type Category = 'hidden-text' | 'unicode' | 'instruction' | 'exfiltration';

export interface FindingLocation {
  /** Start offset (UTF-16 code units) in the original input. */
  start: number;
  /** End offset (exclusive) in the original input. */
  end: number;
  /** 1-based line of `start`. */
  line: number;
  /** 1-based column of `start`. */
  column: number;
}

export interface Finding {
  /** Stable detector id, e.g. `instruction/override` or `hidden-text/display-none`. */
  id: string;
  category: Category;
  severity: Severity;
  /** Human-readable explanation of what was found and why it matters. */
  message: string;
  /** Short, whitespace-collapsed snippet of the offending content. */
  excerpt: string;
  location: FindingLocation;
  /** Why the content is invisible to a human reader, if it is (e.g. `display:none`). */
  hidden?: string;
  /** Decoded payload, e.g. the ASCII hidden in Unicode tag characters. */
  decoded?: string;
  /** Offending URL for exfiltration findings. */
  url?: string;
}

export interface ScanOptions {
  /** Content type of the input. Defaults to `auto`. */
  type?: InputType;
  /** Maximum length of each finding's excerpt. Defaults to 160. */
  maxExcerpt?: number;
}

export interface ScanStats {
  type: ContentType;
  /** Input length in UTF-16 code units. */
  length: number;
  findings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<Category, number>;
  /** Hidden HTML/Markdown regions (comments, display:none blocks, ...). */
  hiddenRegions: number;
  /** Invisible / format characters (zero-width, bidi, tag characters, ...). */
  invisibleChars: number;
  /** URLs inspected by the exfiltration detector. */
  urls: number;
  durationMs: number;
}

export interface ScanResult {
  /** 0 (nothing found) to 100 (almost certainly an attack). */
  risk: number;
  /** Highest finding severity, or `none`. */
  severity: Severity | 'none';
  /** Findings, most severe first. */
  findings: Finding[];
  /** The input with hidden content, invisible characters, injected instructions and exfiltration URLs removed. */
  sanitized: string;
  stats: ScanStats;
}

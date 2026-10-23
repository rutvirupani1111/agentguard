export { scan, sanitize, isSafe, detectType } from './scan';
export { wrapUntrusted, type WrapOptions } from './wrap';
export { INSTRUCTION_RULES, type InstructionRule } from './detectors/instructions';
export { tokenize, decodeEntities, type Token, type Attr } from './html/tokenizer';
export type {
  Category,
  ContentType,
  Finding,
  FindingLocation,
  InputType,
  ScanOptions,
  ScanResult,
  ScanStats,
  Severity,
} from './types';

export const VERSION = '0.1.0';

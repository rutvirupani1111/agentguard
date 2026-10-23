export { scan, sanitize, isSafe, detectType } from './scan';
export { INSTRUCTION_RULES } from './detectors/instructions';
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

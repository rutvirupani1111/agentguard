import { describe, expect, it } from 'vitest';
import { VERSION } from '../src/index';

describe('package', () => {
  it('exposes a version', () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

import { describe, expect, it } from 'vitest';
import { formatAgo, formatBytes, formatDuration, percent } from './format';

describe('format', () => {
  it('bytes', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(2 * 1024 ** 3)).toBe('2.0 GB');
  });
  it('duration', () => {
    expect(formatDuration(59)).toBe('0m');
    expect(formatDuration(3700)).toBe('1h 1m');
    expect(formatDuration(90000)).toBe('1d 1h');
  });
  it('ago', () => {
    expect(formatAgo(100, 103)).toBe('just now');
    expect(formatAgo(0, 120)).toBe('2 minutes ago');
    expect(formatAgo(0, 3600)).toBe('1 hour ago');
  });
  it('percent', () => {
    expect(percent(1, 4)).toBe(25);
    expect(percent(1, 0)).toBe(0);
  });
});

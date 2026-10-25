import { describe, expect, it } from 'vitest';
import { filterCommands, isPaletteShortcut } from './commands';

const ctx = {
  servers: [
    { id: 's1', name: 'edge-1' },
    { id: 's2', name: 'batch-box' }
  ]
};

describe('filterCommands', () => {
  it('filterCommands_matches_server_by_partial_name', () => {
    const out = filterCommands('edg', ctx);
    expect(out.map((c) => c.label)).toEqual(['Go to edge-1']);
    expect(out[0].action).toEqual({ kind: 'goto', path: '/servers/s1' });
  });

  it('lists every command for an empty query, add server first', () => {
    const labels = filterCommands('', ctx).map((c) => c.label);
    expect(labels).toEqual(['Add server', 'Go to fleet board', 'Go to edge-1', 'Go to batch-box']);
  });

  it('matches fuzzy subsequences and ranks substrings first', () => {
    expect(filterCommands('abx', ctx).map((c) => c.label)).toEqual(['Go to batch-box']);
    expect(filterCommands('add', ctx)[0].label).toBe('Add server');
    expect(filterCommands('zzz', ctx)).toEqual([]);
  });
});

describe('isPaletteShortcut', () => {
  const key = (init: KeyboardEventInit) => new KeyboardEvent('keydown', { key: 'k', ...init });
  it('uses Ctrl+K off macOS and Cmd+K on macOS', () => {
    expect(isPaletteShortcut(key({ ctrlKey: true }), false)).toBe(true);
    expect(isPaletteShortcut(key({ metaKey: true }), false)).toBe(false);
    expect(isPaletteShortcut(key({ metaKey: true }), true)).toBe(true);
    expect(isPaletteShortcut(key({ ctrlKey: true }), true)).toBe(false);
    expect(isPaletteShortcut(key({}), false)).toBe(false);
    expect(isPaletteShortcut(key({ ctrlKey: true, key: 'j' }), false)).toBe(false);
  });
});

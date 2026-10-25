import { describe, expect, it } from 'vitest';
import { rowState, sortRows, STATE_LABEL, summaryLine } from './status';
import type { AppState, AppView, Reachability, ServerView } from './types';

const server = (reachability: Reachability = 'online', id = 's1'): ServerView => ({
  id,
  name: id,
  host: `${id}.example.com`,
  reachability,
  last_seen: null,
  status: null
});

const app = (name: string, state: AppState, s: ServerView = server()): AppView => ({
  server_id: s.id,
  server_name: s.name,
  app: { id: 1, name, project_id: null, state }
});

describe('status', () => {
  it('sortRows_problems_first', () => {
    const off = server('unreachable', 'off');
    const on = server();
    const rows = [
      { app: app('zeta', 'live', on), server: on },
      { app: app('beta', 'degraded', on), server: on },
      { app: app('alpha', 'live', on), server: on },
      { app: app('gamma', 'building', on), server: on },
      { app: app('omega', 'live', off), server: off },
      { app: app('delta', 'down', on), server: on }
    ];
    expect(sortRows(rows).map((r) => r.app.app.name)).toEqual([
      'delta',
      'omega',
      'gamma',
      'beta',
      'alpha',
      'zeta'
    ]);
  });

  it('unreachable_server_marks_apps_unreachable_not_down', () => {
    for (const r of ['unreachable', 'untrusted'] as const) {
      const s = server(r);
      expect(rowState(app('web', 'live', s), s)).toBe('unreachable');
      expect(rowState(app('web', 'down', s), s)).toBe('unreachable');
    }
    const ok = server();
    expect(rowState(app('web', 'down', ok), ok)).toBe('down');
    expect(STATE_LABEL.unreachable).toBe('Server unreachable');
  });

  it('connecting_servers_sort_between_degraded_and_live', () => {
    const c = server('connecting', 'c');
    const on = server();
    expect(rowState(app('web', 'down', c), c)).toBe('connecting');
    const rows = [
      { app: app('a', 'live', on), server: on },
      { app: app('b', 'live', c), server: c },
      { app: app('c', 'degraded', on), server: on }
    ];
    expect(sortRows(rows).map((r) => r.app.app.name)).toEqual(['c', 'b', 'a']);
  });

  it('summaryLine_counts', () => {
    const on = server();
    const rows = [
      { app: app('a', 'down', on), server: on },
      { app: app('b', 'live', on), server: on }
    ];
    expect(summaryLine(rows, 2)).toBe('2 apps on 2 servers · 1 down');
    expect(summaryLine([], 1)).toBe('0 apps on 1 server');
  });
});

describe('serverBadge', () => {
  it('labels every reachability in words', async () => {
    const { serverBadge } = await import('./status');
    expect(serverBadge(server('online'))).toEqual({ state: 'live', label: 'Online' });
    expect(serverBadge(server('connecting'))).toEqual({ state: 'connecting', label: 'Connecting' });
    expect(serverBadge(server('unreachable'))).toEqual({ state: 'unreachable', label: 'Unreachable' });
    expect(serverBadge(server('untrusted'))).toEqual({
      state: 'untrusted',
      label: 'Identity changed'
    });
  });

  it('gives identity changed its own icon, distinct from unreachable', async () => {
    const { STATE_ICON } = await import('./status');
    const IconShieldX = (await import('@tabler/icons-svelte/icons/shield-x')).default;
    expect(STATE_ICON.untrusted).toBe(IconShieldX);
    expect(STATE_ICON.untrusted).not.toBe(STATE_ICON.unreachable);
  });
});

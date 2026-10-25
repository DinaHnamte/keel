import { beforeEach, describe, expect, it, vi } from 'vitest';

const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...a: unknown[]) => invoke(...a) }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));

import { APPS_NOTICE, fleet, refreshApps } from './fleet.svelte';

const app = { server_id: 's1', server_name: 'a', app: { id: 1, name: 'web', project_id: null, state: 'live' } };

beforeEach(() => {
  invoke.mockReset();
  fleet.apps = [];
  fleet.appsNotice = '';
  fleet.error = '';
});

describe('refreshApps', () => {
  it('failure sets a plain notice, keeps last apps, and does not touch the board error', async () => {
    invoke.mockResolvedValueOnce([app]);
    expect(await refreshApps()).toBe(true);
    invoke.mockRejectedValueOnce('raw backend error');
    expect(await refreshApps()).toBe(false);
    expect(fleet.appsNotice).toBe(APPS_NOTICE);
    expect(fleet.appsNotice).not.toContain('raw');
    expect(fleet.error).toBe('');
    expect(fleet.apps).toHaveLength(1);
  });

  it('success clears the notice', async () => {
    invoke.mockRejectedValueOnce('x');
    await refreshApps();
    expect(fleet.appsNotice).not.toBe('');
    invoke.mockResolvedValueOnce([app]);
    await refreshApps();
    expect(fleet.appsNotice).toBe('');
  });
});

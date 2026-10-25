import { render, screen, waitFor } from '@testing-library/svelte';
import { tick } from 'svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...a: unknown[]) => invoke(...a) }));

import { fleet } from '$lib/fleet.svelte';
import type { ServerView } from '$lib/types';
import Page from './+page.svelte';

const status = {
  hostname: 'h', os_pretty_name: 'Ubuntu', arch: 'x86_64', uptime_secs: 1, load_1m: 0.1,
  mem_total_bytes: 100, mem_used_bytes: 10, disk_total_bytes: 100, disk_used_bytes: 10, agent_rss_bytes: 1
};
const view = (load: number): ServerView => ({
  id: 's1', name: 'edge-1', host: 'h:7443', reachability: 'online', last_seen: 1,
  status: { ...status, load_1m: load }
});

beforeEach(() => {
  invoke.mockReset();
  invoke.mockResolvedValue([
    { id: 1, display_name: 'Dinah', role: 'owner', key_fingerprint: 'SHA256:x' }
  ]);
  fleet.loaded = true;
  fleet.servers = [view(0.1)];
});

describe('server page', () => {
  it('loads users once across poll updates and shows roles in sentence case', async () => {
    render(Page);
    await waitFor(() => expect(screen.getByText('Dinah')).toBeInTheDocument());
    expect(screen.getByText('Owner')).toBeInTheDocument();
    for (const load of [0.2, 0.3, 0.4]) {
      fleet.servers = [view(load)];
      await tick();
    }
    expect(screen.getByText('Dinah')).toBeInTheDocument();
    expect(screen.queryByText('Loading users…')).toBeNull();
    expect(invoke.mock.calls.filter((c) => c[0] === 'list_users')).toHaveLength(1);
  });
});

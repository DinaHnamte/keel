import { render, screen } from '@testing-library/svelte';
import { createRawSnippet } from 'svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...a: unknown[]) => invoke(...a) }));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));

import Layout from './+layout.svelte';

const KEYCHAIN =
  "Keel couldn't open your system keychain. Unlock it or install a keychain service, then restart Keel.";
const children = createRawSnippet(() => ({ render: () => '<p>fleet board</p>' }));
let status: { fatal: string | null; notice: string | null };

beforeEach(() => {
  invoke.mockReset();
  status = { fatal: null, notice: null };
  invoke.mockImplementation(async (cmd: string) => {
    if (cmd === 'startup_status') return status;
    if (cmd === 'list_servers' || cmd === 'list_apps') return [];
    return null;
  });
});

describe('layout startup', () => {
  it('shows only the keychain message when the keychain is unavailable', async () => {
    status = { fatal: KEYCHAIN, notice: null };
    render(Layout, { children });
    expect(await screen.findByText(KEYCHAIN)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: "Keel can't start" })).toBeInTheDocument();
    expect(screen.queryByText('fleet board')).toBeNull();
    expect(screen.queryByRole('button', { name: /Add server/ })).toBeNull();
    expect(invoke.mock.calls.map((c) => c[0])).not.toContain('list_servers');
  });

  it('shows the board and a one-time notice when the server list was reset', async () => {
    const notice =
      "Keel couldn't read your saved servers, so it started fresh. The old file was kept as servers.json.corrupt-42.";
    status = { fatal: null, notice };
    render(Layout, { children });
    expect(await screen.findByText(notice)).toBeInTheDocument();
    expect(screen.getByText('fleet board')).toBeInTheDocument();
    expect(invoke.mock.calls.map((c) => c[0])).toContain('list_servers');
    screen.getByRole('button', { name: 'Dismiss' }).click();
    await vi.waitFor(() => expect(screen.queryByText(notice)).toBeNull());
  });

  it('shows the board with no notice on a normal start', async () => {
    render(Layout, { children });
    expect(await screen.findByText('fleet board')).toBeInTheDocument();
    await vi.waitFor(() => expect(invoke.mock.calls.map((c) => c[0])).toContain('list_servers'));
    expect(screen.queryByRole('alert')).toBeNull();
  });
});

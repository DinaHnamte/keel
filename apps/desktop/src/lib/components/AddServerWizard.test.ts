import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const invoke = vi.fn();
let handler: ((e: { payload: unknown }) => void) | undefined;
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...a: unknown[]) => invoke(...a) }));
vi.mock('@tauri-apps/api/event', () => ({
  listen: async (_name: string, h: (e: { payload: unknown }) => void) => {
    handler = h;
    return () => {};
  }
}));

import AddServerWizard from './AddServerWizard.svelte';

const KEY = 'ssh-ed25519 AAAAC3Nza keel';
const emit = async (type: string, data?: unknown) => {
  handler!({ payload: data === undefined ? { type } : { type, data } });
  await Promise.resolve();
};
const calls = (name: string) => invoke.mock.calls.filter((c) => c[0] === name);

beforeEach(() => {
  invoke.mockReset();
  handler = undefined;
  invoke.mockImplementation(async (cmd: string) => {
    if (cmd === 'generate_ssh_key') return KEY;
    return null;
  });
});

async function fillConnection() {
  await screen.findByDisplayValue(KEY);
  await fireEvent.input(screen.getByLabelText('Name'), { target: { value: 'edge-1' } });
  await fireEvent.input(screen.getByLabelText('Host'), { target: { value: '203.0.113.5' } });
}
async function toProgress() {
  await fillConnection();
  await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  await fireEvent.click(screen.getByRole('button', { name: 'Add server' }));
  await waitFor(() => expect(calls('start_onboarding')).toHaveLength(1));
}

describe('AddServerWizard', () => {
  it('shows the key, defaults and the authorized_keys instruction on step 1', async () => {
    render(AddServerWizard, { onclose: vi.fn() });
    expect(await screen.findByDisplayValue(KEY)).toHaveAttribute('readonly');
    expect(screen.getByLabelText('SSH port')).toHaveValue(22);
    expect(screen.getByLabelText('User')).toHaveValue('root');
    expect(screen.getByLabelText('Generate a key for Keel (recommended)')).toBeChecked();
    expect(
      screen.getByText('Add this line to ~/.ssh/authorized_keys for root on the server, then continue.')
    ).toBeInTheDocument();
  });

  it('copies the key and says Copied', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    render(AddServerWizard, { onclose: vi.fn() });
    await screen.findByDisplayValue(KEY);
    await fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
    expect(writeText).toHaveBeenCalledWith(KEY);
    expect(await screen.findByRole('button', { name: 'Copied' })).toBeInTheDocument();
  });

  it('sends the request with the generated key and the chosen options', async () => {
    render(AddServerWizard, { onclose: vi.fn() });
    await toProgress();
    expect(calls('start_onboarding')[0][1]).toEqual({
      req: {
        name: 'edge-1',
        host: '203.0.113.5',
        port: 22,
        user: 'root',
        auth: { kind: 'generated_key' },
        options: {
          enable_firewall: true,
          auto_security_updates: true,
          disable_ssh_passwords: false,
          keep_ssh_credentials: false
        }
      }
    });
  });

  it('shows keep-credentials checked and disabled when passwords are turned off', async () => {
    render(AddServerWizard, { onclose: vi.fn() });
    await fillConnection();
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    const keep = screen.getByLabelText('Keep SSH sign-in details');
    expect(keep).not.toBeChecked();
    expect(keep).toBeEnabled();
    await fireEvent.click(screen.getByLabelText('Turn off password sign-in for SSH'));
    expect(keep).toBeChecked();
    expect(keep).toBeDisabled();
    expect(
      screen.getByText("Keel will keep this server's SSH key in your system keychain so you can't be locked out.")
    ).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Add server' }));
    await waitFor(() => expect(calls('start_onboarding')).toHaveLength(1));
    expect(calls('start_onboarding')[0][1].req.options.keep_ssh_credentials).toBe(true);
  });

  it('wizard_blocks_install_on_blocker_finding', async () => {
    render(AddServerWizard, { onclose: vi.fn() });
    await toProgress();
    await emit('Findings', [{ severity: 'Blocker', message: 'Ports 80 and 443 are in use.' }]);
    expect(await screen.findByText('Ports 80 and 443 are in use.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /continue/i })).toBeNull();
  });

  it('shows warnings inline without pausing', async () => {
    render(AddServerWizard, { onclose: vi.fn() });
    await toProgress();
    await emit('Findings', [{ severity: 'Warning', message: 'AlmaLinux is best-effort.' }]);
    await emit('Installing', 'Uploading the agent');
    expect(await screen.findByText('AlmaLinux is best-effort.')).toBeInTheDocument();
    expect(screen.getByText('Uploading the agent')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /continue/i })).toBeNull();
  });

  it('shows the server fingerprint with its hint', async () => {
    render(AddServerWizard, { onclose: vi.fn() });
    await toProgress();
    await emit('HostKey', 'SHA256:abc123');
    expect(await screen.findByText('Server fingerprint')).toBeInTheDocument();
    expect(screen.getByText('SHA256:abc123')).toHaveClass('mono');
    expect(
      screen.getByText('It should match the fingerprint your hosting provider shows for this server.')
    ).toBeInTheDocument();
  });

  it('wizard_shows_plain_error_on_failed_event', async () => {
    render(AddServerWizard, { onclose: vi.fn() });
    await toProgress();
    await emit('Failed', "Couldn't sign in. Check the key was added for root.");
    expect(await screen.findByRole('alert')).toHaveTextContent(
      "Couldn't sign in. Check the key was added for root."
    );
    expect(screen.getByRole('button', { name: 'Back' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });

  it('keeps entered values and the generated key on Back and on Try again', async () => {
    render(AddServerWizard, { onclose: vi.fn() });
    await toProgress();
    await emit('Failed', 'Nope.');
    await fireEvent.click(await screen.findByRole('button', { name: 'Back' }));
    expect(screen.getByLabelText('Name')).toHaveValue('edge-1');
    expect(screen.getByLabelText('Host')).toHaveValue('203.0.113.5');
    expect(screen.getByDisplayValue(KEY)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Add server' }));
    await waitFor(() => expect(calls('start_onboarding')).toHaveLength(2));
    await emit('Failed', 'Nope again.');
    await fireEvent.click(await screen.findByRole('button', { name: 'Try again' }));
    await waitFor(() => expect(calls('start_onboarding')).toHaveLength(3));
    expect(calls('generate_ssh_key')).toHaveLength(1);
  });

  it('generates a new key only on request', async () => {
    render(AddServerWizard, { onclose: vi.fn() });
    await screen.findByDisplayValue(KEY);
    invoke.mockImplementation(async () => 'ssh-ed25519 NEWKEY keel');
    await fireEvent.click(screen.getByRole('button', { name: 'Generate a new key' }));
    expect(await screen.findByDisplayValue('ssh-ed25519 NEWKEY keel')).toBeInTheDocument();
  });

  it('ignores Escape while installing but closes after a failure', async () => {
    const onclose = vi.fn();
    render(AddServerWizard, { onclose });
    await toProgress();
    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(onclose).not.toHaveBeenCalled();
    await emit('Failed', 'Nope.');
    await screen.findByRole('alert');
    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(onclose).toHaveBeenCalledOnce();
  });

  it('fills in steps from events and ends with a link to the server page', async () => {
    const onclose = vi.fn();
    render(AddServerWizard, { onclose });
    await toProgress();
    await emit('Connecting');
    await emit('Checking');
    await emit('Installing', 'Uploading the agent');
    await emit('Pairing');
    await emit('Done', { id: 's9', name: 'edge-1', host: '203.0.113.5', port: 7443, fingerprint: 'x', ssh_saved: false });
    expect(await screen.findByText('Server added')).toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'Open server page' });
    expect(link).toHaveAttribute('href', '/servers/s9');
    await fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onclose).toHaveBeenCalled();
  });

  it('sends a private key and passphrase when chosen', async () => {
    render(AddServerWizard, { onclose: vi.fn() });
    await fillConnection();
    await fireEvent.click(screen.getByLabelText('Use my own private key'));
    await fireEvent.input(screen.getByLabelText('Private key'), { target: { value: 'PEMDATA' } });
    await fireEvent.input(screen.getByLabelText('Passphrase (optional)'), { target: { value: 'pp' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Add server' }));
    await waitFor(() => expect(calls('start_onboarding')).toHaveLength(1));
    expect(calls('start_onboarding')[0][1].req.auth).toEqual({
      kind: 'private_key',
      pem: 'PEMDATA',
      passphrase: 'pp'
    });
  });

  it('pairs with a code', async () => {
    const onclose = vi.fn();
    render(AddServerWizard, { onclose });
    await screen.findByDisplayValue(KEY);
    await fireEvent.click(screen.getByRole('button', { name: 'I have a pairing code' }));
    invoke.mockImplementation(async (cmd: string) =>
      cmd === 'pair_with_code' ? { id: 's7', name: 'box' } : null
    );
    await fireEvent.input(screen.getByLabelText('Pairing code'), { target: { value: 'keel-pair://x' } });
    await fireEvent.input(screen.getByLabelText('Name'), { target: { value: 'box' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Pair' }));
    await screen.findByText('Server added');
    expect(calls('pair_with_code')[0][1]).toEqual({ code: 'keel-pair://x', name: 'box' });
    expect(screen.getByRole('link', { name: 'Open server page' })).toHaveAttribute('href', '/servers/s7');
  });
});

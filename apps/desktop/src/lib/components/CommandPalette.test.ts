import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const goto = vi.fn();
vi.mock('$app/navigation', () => ({ goto: (...a: unknown[]) => goto(...a) }));

import { fleet } from '$lib/fleet.svelte';
import { ui } from '$lib/ui.svelte';
import CommandPalette from './CommandPalette.svelte';

beforeEach(() => {
  goto.mockReset();
  ui.addServerOpen = false;
  fleet.servers = [
    { id: 's1', name: 'edge-1', host: 'h', reachability: 'online', last_seen: 1, status: null }
  ];
});

describe('CommandPalette', () => {
  it('filters as you type and runs the selected command with Enter', async () => {
    const onclose = vi.fn();
    render(CommandPalette, { onclose });
    const input = screen.getByRole('combobox');
    expect(input).toHaveFocus();
    await fireEvent.input(input, { target: { value: 'edg' } });
    expect(screen.getAllByRole('option')).toHaveLength(1);
    await fireEvent.keyDown(input, { key: 'Enter' });
    expect(goto).toHaveBeenCalledWith('/servers/s1');
    expect(onclose).toHaveBeenCalled();
  });

  it('moves with arrow keys, opens the wizard for Add server, and closes on Escape', async () => {
    const onclose = vi.fn();
    render(CommandPalette, { onclose });
    const input = screen.getByRole('combobox');
    await fireEvent.keyDown(input, { key: 'ArrowDown' });
    await fireEvent.keyDown(input, { key: 'ArrowUp' });
    await fireEvent.keyDown(input, { key: 'Enter' });
    expect(ui.addServerOpen).toBe(true);
    onclose.mockClear();
    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(onclose).toHaveBeenCalledOnce();
  });

  it('says so when nothing matches', async () => {
    render(CommandPalette, { onclose: vi.fn() });
    await fireEvent.input(screen.getByRole('combobox'), { target: { value: 'zzzz' } });
    expect(screen.getByText('No matching commands')).toBeInTheDocument();
  });
});

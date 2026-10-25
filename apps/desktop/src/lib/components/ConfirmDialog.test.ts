import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import ConfirmDialog from './ConfirmDialog.svelte';

const props = () => ({
  title: 'Remove edge-1?',
  body: 'Body',
  confirmLabel: 'Remove edge-1',
  onconfirm: vi.fn(),
  oncancel: vi.fn()
});

describe('ConfirmDialog', () => {
  it('traps Tab inside the dialog', async () => {
    render(ConfirmDialog, props());
    const cancel = screen.getByRole('button', { name: 'Cancel' });
    const confirm = screen.getByRole('button', { name: 'Remove edge-1' });
    expect(cancel).toHaveFocus();
    confirm.focus();
    await fireEvent.keyDown(window, { key: 'Tab' });
    expect(cancel).toHaveFocus();
    await fireEvent.keyDown(window, { key: 'Tab', shiftKey: true });
    expect(confirm).toHaveFocus();
  });

  it('only the topmost overlay handles Escape', async () => {
    const lower = props();
    const upper = props();
    render(ConfirmDialog, lower);
    render(ConfirmDialog, upper);
    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(upper.oncancel).toHaveBeenCalledOnce();
    expect(lower.oncancel).not.toHaveBeenCalled();
  });
});

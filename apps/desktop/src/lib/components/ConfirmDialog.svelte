<script lang="ts">
  import { onMount } from 'svelte';
  import { registerOverlay } from '../ui.svelte';

  let {
    title,
    body,
    confirmLabel,
    busy = false,
    error = '',
    onconfirm,
    oncancel
  }: {
    title: string;
    body: string;
    confirmLabel: string;
    busy?: boolean;
    error?: string;
    onconfirm: () => void;
    oncancel: () => void;
  } = $props();

  let cancelButton: HTMLButtonElement;
  let dialog: HTMLDivElement;
  const overlay = registerOverlay();
  onMount(() => {
    const opener = document.activeElement as HTMLElement | null;
    cancelButton.focus();
    return () => {
      overlay.release();
      opener?.focus?.();
    };
  });

  function onkeydown(e: KeyboardEvent) {
    if (!overlay.isTop()) return;
    if (e.key === 'Escape') {
      if (!busy) oncancel();
      return;
    }
    if (e.key !== 'Tab') return;
    const items = Array.from(dialog.querySelectorAll<HTMLElement>('button:not([disabled])'));
    if (items.length === 0) {
      e.preventDefault();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || !dialog.contains(active))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (active === last || !dialog.contains(active))) {
      e.preventDefault();
      first.focus();
    }
  }
</script>

<svelte:window {onkeydown} />

<div class="scrim">
  <div class="dialog" bind:this={dialog} role="alertdialog" aria-modal="true" aria-labelledby="dlg-title" aria-describedby="dlg-body">
    <h2 id="dlg-title">{title}</h2>
    <p id="dlg-body">{body}</p>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <div class="actions">
      <button class="btn" bind:this={cancelButton} onclick={oncancel} disabled={busy}>Cancel</button>
      <button class="btn danger" onclick={onconfirm} disabled={busy}>{confirmLabel}</button>
    </div>
  </div>
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    display: grid;
    place-items: center;
    background: color-mix(in srgb, var(--canvas) 70%, transparent);
    z-index: 20;
  }
  .dialog {
    width: min(420px, calc(100vw - 32px));
    background: var(--panel);
    border: 1px solid var(--ink-2);
    border-radius: var(--radius);
    padding: 20px;
  }
  h2 {
    font-size: 16px;
  }
  p {
    margin: 8px 0 0;
    color: var(--ink-2);
  }
  .error {
    color: var(--down);
    font-weight: 500;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 20px;
  }
</style>

<script lang="ts">
  import { onMount } from 'svelte';

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
  onMount(() => cancelButton.focus());
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && !busy && oncancel()} />

<div class="scrim">
  <div class="dialog" role="alertdialog" aria-modal="true" aria-labelledby="dlg-title" aria-describedby="dlg-body">
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

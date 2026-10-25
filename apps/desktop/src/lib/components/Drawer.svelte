<script lang="ts">
  import IconX from '@tabler/icons-svelte/icons/x';
  import { rowState } from '../status';
  import type { AppView, ServerView } from '../types';
  import StatusBadge from './StatusBadge.svelte';

  let {
    app,
    server,
    onclose
  }: { app: AppView; server: ServerView; onclose: () => void } = $props();
  const state = $derived(rowState(app, server));
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && onclose()} />

<aside class="drawer" aria-label="App details">
  <header>
    <h2>{app.app.name}</h2>
    <button class="close" onclick={onclose} aria-label="Close details"><IconX size={18} /></button>
  </header>
  <dl>
    <dt>State</dt>
    <dd><StatusBadge {state} /></dd>
    <dt>Server</dt>
    <dd><a href="/servers/{server.id}">{server.name}</a></dd>
  </dl>
  {#if state === 'unreachable'}
    <p class="muted note">
      Keel can't reach {server.name}, so it can't tell whether {app.app.name} is running.
    </p>
  {/if}
</aside>

<style>
  .drawer {
    width: 320px;
    flex: none;
    background: var(--panel);
    border-left: 1px solid var(--rule);
    padding: 16px;
    overflow-y: auto;
    animation: slide-in 140ms ease-out;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    margin-bottom: 16px;
  }
  h2 {
    font-size: 16px;
    overflow-wrap: anywhere;
  }
  .close {
    display: inline-flex;
    padding: 4px;
    border: 0;
    background: none;
    border-radius: var(--radius);
    cursor: pointer;
    color: var(--ink-2);
  }
  .close:hover {
    color: var(--ink);
    background: var(--hover);
  }
  dl {
    display: grid;
    grid-template-columns: 70px 1fr;
    row-gap: 10px;
    margin: 0;
  }
  dt {
    color: var(--ink-2);
  }
  dd {
    margin: 0;
  }
  .note {
    margin: 16px 0 0;
  }
  @keyframes slide-in {
    from {
      transform: translateX(12px);
      opacity: 0;
    }
  }
</style>

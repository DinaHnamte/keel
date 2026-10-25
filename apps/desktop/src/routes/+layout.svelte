<script lang="ts">
  import '@fontsource/instrument-sans/400.css';
  import '@fontsource/instrument-sans/500.css';
  import '@fontsource/instrument-sans/600.css';
  import '@fontsource/jetbrains-mono/400.css';
  import '../lib/tokens.css';
  import IconPlus from '@tabler/icons-svelte/icons/plus';
  import IconLock from '@tabler/icons-svelte/icons/lock';
  import IconInfoCircle from '@tabler/icons-svelte/icons/info-circle';
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import AddServerWizard from '../lib/components/AddServerWizard.svelte';
  import CommandPalette from '../lib/components/CommandPalette.svelte';
  import { isPaletteShortcut, shortcutLabel } from '../lib/commands';
  import { startFleet } from '../lib/fleet.svelte';
  import { ui } from '../lib/ui.svelte';

  type StartupStatus = { fatal: string | null; notice: string | null };

  let { children } = $props();
  let started = $state(false);
  let fatal = $state('');
  let notice = $state('');

  onMount(() => {
    let stop: (() => void) | undefined;
    let disposed = false;
    (async () => {
      try {
        const s = await invoke<StartupStatus>('startup_status');
        fatal = s.fatal ?? '';
        notice = s.notice ?? '';
      } catch (e) {
        console.error(e);
      }
      started = true;
      if (!fatal && !disposed) stop = startFleet();
    })();
    return () => {
      disposed = true;
      stop?.();
    };
  });

  function onkeydown(e: KeyboardEvent) {
    if (fatal || !isPaletteShortcut(e)) return;
    e.preventDefault();
    ui.paletteOpen = !ui.paletteOpen;
  }
</script>

<svelte:window {onkeydown} />

{#if fatal}
  <main class="fatal">
    <IconLock size={32} stroke={1.5} aria-hidden="true" />
    <h1>Keel can't start</h1>
    <p role="alert">{fatal}</p>
  </main>
{:else if started}
<div class="shell">
  <header class="bar">
    <a class="brand" href="/">Keel</a>
    <div class="actions">
      <button class="btn" onclick={() => (ui.paletteOpen = true)} aria-keyshortcuts={shortcutLabel()}>
        Commands <span class="keys mono muted">{shortcutLabel()}</span>
      </button>
      <button class="btn primary" onclick={() => (ui.addServerOpen = true)}>
        <IconPlus size={16} stroke={2} aria-hidden="true" /> Add server
      </button>
    </div>
  </header>
  {#if notice}
    <div class="startup-notice" role="alert">
      <IconInfoCircle size={16} stroke={2} aria-hidden="true" />
      <span>{notice}</span>
      <button class="btn" onclick={() => (notice = '')}>Dismiss</button>
    </div>
  {/if}
  <div class="content">
    {@render children()}
  </div>
</div>
{/if}

{#if !fatal && ui.addServerOpen}
  <AddServerWizard onclose={() => (ui.addServerOpen = false)} />
{/if}
{#if !fatal && ui.paletteOpen}
  <CommandPalette onclose={() => (ui.paletteOpen = false)} />
{/if}

<style>
  .shell {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }
  .bar {
    flex: none;
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 48px;
    padding: 0 16px;
    background: var(--panel);
    border-bottom: 1px solid var(--rule);
  }
  .actions {
    display: flex;
    gap: 8px;
  }
  .brand {
    font-weight: 600;
    font-size: 16px;
    text-decoration: none;
  }
  .fatal {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 12px;
    height: 100vh;
    padding: 0 24px;
    text-align: center;
    color: var(--ink);
  }
  .fatal h1 {
    font-size: 20px;
    font-weight: 600;
    margin: 0;
  }
  .fatal p {
    max-width: 480px;
    margin: 0;
    color: var(--ink-2);
  }
  .startup-notice {
    flex: none;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 16px;
    background: var(--panel);
    border-bottom: 1px solid var(--rule);
  }
  .startup-notice span {
    flex: 1;
  }
  .content {
    flex: 1;
    min-height: 0;
    display: flex;
  }
</style>

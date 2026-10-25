<script lang="ts">
  import '@fontsource/instrument-sans/400.css';
  import '@fontsource/instrument-sans/500.css';
  import '@fontsource/instrument-sans/600.css';
  import '@fontsource/jetbrains-mono/400.css';
  import '../lib/tokens.css';
  import IconPlus from '@tabler/icons-svelte/icons/plus';
  import { onMount } from 'svelte';
  import AddServerWizard from '../lib/components/AddServerWizard.svelte';
  import CommandPalette from '../lib/components/CommandPalette.svelte';
  import { isPaletteShortcut, shortcutLabel } from '../lib/commands';
  import { startFleet } from '../lib/fleet.svelte';
  import { ui } from '../lib/ui.svelte';

  let { children } = $props();
  onMount(() => startFleet());

  function onkeydown(e: KeyboardEvent) {
    if (!isPaletteShortcut(e)) return;
    e.preventDefault();
    ui.paletteOpen = !ui.paletteOpen;
  }
</script>

<svelte:window {onkeydown} />

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
  <div class="content">
    {@render children()}
  </div>
</div>

{#if ui.addServerOpen}
  <AddServerWizard onclose={() => (ui.addServerOpen = false)} />
{/if}
{#if ui.paletteOpen}
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
  .content {
    flex: 1;
    min-height: 0;
    display: flex;
  }
</style>

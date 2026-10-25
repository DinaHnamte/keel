<script lang="ts">
  import '@fontsource/instrument-sans/400.css';
  import '@fontsource/instrument-sans/500.css';
  import '@fontsource/instrument-sans/600.css';
  import '@fontsource/jetbrains-mono/400.css';
  import '../lib/tokens.css';
  import IconPlus from '@tabler/icons-svelte/icons/plus';
  import { onMount } from 'svelte';
  import { startFleet } from '../lib/fleet.svelte';
  import { ui } from '../lib/ui.svelte';

  let { children } = $props();
  onMount(() => startFleet());
</script>

<div class="shell">
  <header class="bar">
    <a class="brand" href="/">Keel</a>
    <button class="btn primary" onclick={() => (ui.addServerOpen = true)}>
      <IconPlus size={16} stroke={2} aria-hidden="true" /> Add server
    </button>
  </header>
  <div class="content">
    {@render children()}
  </div>
</div>

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

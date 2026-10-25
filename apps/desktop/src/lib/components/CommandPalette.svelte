<script lang="ts">
  import { goto } from '$app/navigation';
  import IconLayoutDashboard from '@tabler/icons-svelte/icons/layout-dashboard';
  import IconPlus from '@tabler/icons-svelte/icons/plus';
  import IconServer from '@tabler/icons-svelte/icons/server';
  import { onMount } from 'svelte';
  import { filterCommands, type Command } from '../commands';
  import { fleet } from '../fleet.svelte';
  import { registerOverlay, ui } from '../ui.svelte';

  let { onclose }: { onclose: () => void } = $props();

  let query = $state('');
  let active = $state(0);
  let input: HTMLInputElement;
  const overlay = registerOverlay();

  const results = $derived(filterCommands(query, { servers: fleet.servers }));
  $effect(() => {
    if (active >= results.length) active = Math.max(0, results.length - 1);
  });

  onMount(() => {
    const opener = document.activeElement as HTMLElement | null;
    input.focus();
    return () => {
      overlay.release();
      opener?.focus?.();
    };
  });

  function run(c: Command) {
    onclose();
    if (c.action.kind === 'add-server') ui.addServerOpen = true;
    else void goto(c.action.path);
  }

  function onwindowkeydown(e: KeyboardEvent) {
    if (!overlay.isTop()) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      onclose();
    } else if (e.key === 'Tab') {
      // The input is the only stop; keep focus here.
      e.preventDefault();
      input.focus();
    }
  }

  function oninputkeydown(e: KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (results.length) active = (active + 1) % results.length;
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (results.length) active = (active - 1 + results.length) % results.length;
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const c = results[active];
      if (c) run(c);
    }
  }
</script>

<svelte:window onkeydown={onwindowkeydown} />

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<div class="scrim" onmousedown={(e) => e.target === e.currentTarget && onclose()}>
  <div class="palette" role="dialog" aria-modal="true" aria-label="Command palette">
    <input
      bind:this={input}
      bind:value={query}
      oninput={() => (active = 0)}
      onkeydown={oninputkeydown}
      role="combobox"
      aria-expanded="true"
      aria-controls="palette-list"
      aria-activedescendant={results[active] ? `cmd-${results[active].id}` : undefined}
      aria-label="Type a command"
      placeholder="Type a command or a server name"
      autocomplete="off"
      spellcheck="false"
    />
    {#if results.length === 0}
      <p class="empty muted" role="status">No matching commands</p>
    {/if}
    <ul id="palette-list" role="listbox" aria-label="Commands">
      {#each results as c, i (c.id)}
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <li
          id="cmd-{c.id}"
          role="option"
          aria-selected={i === active}
          class:active={i === active}
          onmousemove={() => (active = i)}
          onclick={() => run(c)}
        >
          {#if c.action.kind === 'add-server'}
            <IconPlus size={16} stroke={2} aria-hidden="true" />
          {:else if c.id === 'fleet'}
            <IconLayoutDashboard size={16} stroke={2} aria-hidden="true" />
          {:else}
            <IconServer size={16} stroke={2} aria-hidden="true" />
          {/if}
          <span>{c.label}</span>
        </li>
      {/each}
    </ul>
  </div>
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    display: flex;
    justify-content: center;
    align-items: flex-start;
    padding-top: 14vh;
    background: color-mix(in srgb, var(--canvas) 70%, transparent);
    z-index: 30;
  }
  .palette {
    width: min(520px, calc(100vw - 32px));
    background: var(--panel);
    border: 1px solid var(--ink-2);
    border-radius: var(--radius);
    overflow: hidden;
  }
  input {
    width: 100%;
    height: 40px;
    padding: 0 12px;
    border: 0;
    border-bottom: 1px solid var(--rule);
    background: transparent;
    outline-offset: -2px;
  }
  input::placeholder {
    color: var(--ink-2);
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 4px;
    max-height: 320px;
    overflow: auto;
  }
  li {
    display: flex;
    align-items: center;
    gap: 8px;
    height: var(--row-h);
    padding: 0 8px;
    border-radius: var(--radius);
    cursor: pointer;
  }
  li.active {
    background: var(--selected);
    box-shadow: inset 2px 0 0 var(--ink);
  }
  .empty {
    margin: 0;
    padding: 12px;
  }
</style>

<script lang="ts">
  import { rowState } from '../status';
  import type { AppView, ServerView } from '../types';
  import StatusBadge from './StatusBadge.svelte';

  let {
    app,
    server,
    selected,
    onselect
  }: { app: AppView; server: ServerView; selected: boolean; onselect: () => void } = $props();

  const state = $derived(rowState(app, server));
</script>

<button
  class="row {state}"
  class:selected
  aria-pressed={selected}
  onclick={onselect}
>
  <span class="status"><StatusBadge {state} /></span>
  <span class="name">{app.app.name}</span>
  <span class="server muted">{app.server_name}</span>
  <!-- Uptime strip arrives with monitoring in a later milestone; no placeholder bars. -->
</button>

<style>
  .row {
    display: grid;
    grid-template-columns: 170px minmax(0, 1.4fr) minmax(0, 1fr);
    align-items: center;
    column-gap: 16px;
    width: 100%;
    min-height: var(--row-h);
    padding: 0 12px 0 9px;
    border: 0;
    border-left: 3px solid transparent;
    border-bottom: 1px solid var(--rule);
    background: var(--panel);
    text-align: left;
    cursor: pointer;
  }
  .row:hover {
    background: var(--hover);
  }
  .row.selected {
    background: var(--selected);
  }
  .row.down,
  .row.unreachable {
    border-left-color: var(--down);
    background: var(--down-tint);
  }
  .row.down:hover,
  .row.unreachable:hover,
  .row.down.selected,
  .row.unreachable.selected {
    background: color-mix(in srgb, var(--down) 14%, var(--panel));
  }
  .row:focus-visible {
    outline-offset: -2px;
  }
  .status {
    display: flex;
  }
  .row.selected:not(.down):not(.unreachable) {
    border-left-color: var(--ink);
  }
  .name {
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .server {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>

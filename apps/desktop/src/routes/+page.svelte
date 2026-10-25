<script lang="ts">
  import Drawer from '$lib/components/Drawer.svelte';
  import FleetRow from '$lib/components/FleetRow.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import { fleet } from '$lib/fleet.svelte';
  import { serverBadge, sortRows, summaryLine } from '$lib/status';
  import { ui } from '$lib/ui.svelte';
  import type { Row } from '$lib/status';

  const rows = $derived(
    sortRows(
      fleet.apps.flatMap((app) => {
        const server = fleet.servers.find((s) => s.id === app.server_id);
        return server ? [{ app, server }] : [];
      })
    )
  );
  const key = (r: Row) => `${r.app.server_id}:${r.app.app.id}`;
  let selectedKey = $state<string | null>(null);
  const selected = $derived(rows.find((r) => key(r) === selectedKey) ?? null);
</script>

<svelte:head><title>Keel</title></svelte:head>

<div class="board">
  <main>
    {#if !fleet.loaded}
      <p class="muted pad" role="status">Loading your servers…</p>
    {:else if fleet.error}
      <p class="pad error" role="alert">{fleet.error}</p>
    {:else if fleet.servers.length === 0}
      <section class="empty">
        <h1>Add your first server</h1>
        <p class="muted">
          Keel connects over SSH once, installs a small agent, and pairs this device with it. After
          that you manage the server from here.
        </p>
        <button class="btn primary" onclick={() => (ui.addServerOpen = true)}>Add server</button>
      </section>
    {:else}
      {#if fleet.appsNotice}
        <p class="notice" role="status">{fleet.appsNotice}</p>
      {/if}
      <h1 class="summary num">{summaryLine(rows, fleet.servers.length)}</h1>

      {#if rows.length === 0}
        <section class="note">
          <h2>Your servers are ready</h2>
          <p class="muted">Deploying apps arrives in the next version.</p>
        </section>
      {:else}
        <ul class="list" aria-label="Apps">
          {#each rows as r (key(r))}
            <li>
              <FleetRow
                app={r.app}
                server={r.server}
                selected={key(r) === selectedKey}
                onselect={() => (selectedKey = key(r) === selectedKey ? null : key(r))}
              />
            </li>
          {/each}
        </ul>
      {/if}

      <h2 class="section">Servers</h2>
      <ul class="list" aria-label="Servers">
        {#each fleet.servers as s (s.id)}
          {@const b = serverBadge(s)}
          <li>
            <a class="srv" href="/servers/{s.id}">
              <StatusBadge state={b.state} label={b.label} />
              <span class="name">{s.name}</span>
              <span class="mono muted">{s.host}</span>
            </a>
          </li>
        {/each}
      </ul>
    {/if}
  </main>
  {#if selected}
    <Drawer app={selected.app} server={selected.server} onclose={() => (selectedKey = null)} />
  {/if}
</div>

<style>
  .board {
    display: flex;
    flex: 1;
    min-width: 0;
  }
  main {
    flex: 1;
    min-width: 0;
    overflow-y: auto;
    padding: 16px;
  }
  .pad {
    padding: 8px 0;
  }
  .error {
    color: var(--down);
  }
  .summary {
    font-size: 14px;
    font-weight: 500;
    color: var(--ink-2);
    margin-bottom: 10px;
  }
  .notice {
    margin: 0 0 10px;
    padding: 8px 12px;
    border: 1px solid var(--warn);
    border-left-width: 3px;
    border-radius: var(--radius);
    background: var(--panel);
  }
  .section {
    font-size: 14px;
    color: var(--ink-2);
    margin: 24px 0 10px;
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--rule);
    border-bottom: 0;
    border-radius: var(--radius);
    overflow: hidden;
    background: var(--panel);
  }
  .srv {
    display: grid;
    grid-template-columns: 170px minmax(0, 1.4fr) minmax(0, 1fr);
    align-items: center;
    column-gap: 16px;
    min-height: var(--row-h);
    padding: 0 12px;
    border-bottom: 1px solid var(--rule);
    text-decoration: none;
  }
  .srv:hover {
    background: var(--hover);
  }
  .srv .name {
    font-weight: 500;
  }
  .empty {
    max-width: 440px;
    margin: 12vh auto 0;
    padding: 24px;
    background: var(--panel);
    border: 1px solid var(--rule);
    border-radius: var(--radius);
  }
  .empty h1 {
    font-size: 20px;
  }
  .empty p {
    margin: 8px 0 20px;
  }
  .note {
    padding: 14px 12px;
    background: var(--panel);
    border: 1px solid var(--rule);
    border-radius: var(--radius);
  }
  .note h2 {
    font-size: 14px;
  }
  .note p {
    margin: 4px 0 0;
  }
</style>

<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import IconArrowLeft from '@tabler/icons-svelte/icons/arrow-left';
  import { invoke } from '@tauri-apps/api/core';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import { fleet } from '$lib/fleet.svelte';
  import { formatAgo, formatBytes, formatDuration, percent } from '$lib/format';
  import { serverBadge } from '$lib/status';
  import type { UserInfo } from '$lib/types';

  const server = $derived(fleet.servers.find((s) => s.id === page.params.id) ?? null);
  const status = $derived(server?.status ?? null);

  let users = $state<UserInfo[] | null>(null);
  let usersState = $state<'idle' | 'loading' | 'forbidden' | 'failed' | 'ready'>('idle');
  let confirming = $state(false);
  let removing = $state(false);
  let removeError = $state('');

  $effect(() => {
    const id = page.params.id;
    if (!id || server?.reachability !== 'online') {
      return;
    }
    let stale = false;
    usersState = 'loading';
    invoke<UserInfo[] | null>('list_users', { id })
      .then((list) => {
        if (stale) return;
        users = list;
        usersState = list === null ? 'forbidden' : 'ready';
      })
      .catch(() => {
        if (!stale) usersState = 'failed';
      });
    return () => {
      stale = true;
    };
  });

  async function remove() {
    if (!server) return;
    removing = true;
    removeError = '';
    try {
      await invoke('remove_server', { id: server.id });
      await goto('/');
    } catch (e) {
      removeError = String(e);
      removing = false;
    }
  }

  const meters = $derived(
    status
      ? [
          { label: 'Memory', used: status.mem_used_bytes, total: status.mem_total_bytes },
          { label: 'Disk', used: status.disk_used_bytes, total: status.disk_total_bytes }
        ]
      : []
  );
</script>

<svelte:head><title>{server?.name ?? 'Server'} · Keel</title></svelte:head>

<main>
  <a class="back muted" href="/"><IconArrowLeft size={16} aria-hidden="true" /> Fleet board</a>

  {#if !fleet.loaded}
    <p class="muted" role="status">Loading…</p>
  {:else if !server}
    <h1>Server not found</h1>
    <p class="muted">This server isn't in your list any more. Go back to the fleet board.</p>
  {:else}
    {@const b = serverBadge(server)}
    <header>
      <h1>{server.name}</h1>
      <StatusBadge state={b.state} label={b.label} />
    </header>

    {#if server.reachability === 'untrusted'}
      <p class="alert" role="alert">
        This server's identity no longer matches the one Keel trusted when you added it. Keel has
        stopped talking to it. If you didn't reinstall the server, treat this as a warning, then
        remove it and add it again once you've checked.
      </p>
    {:else if server.reachability === 'unreachable'}
      <p class="alert" role="alert">
        Keel can't reach this server. Check that it's powered on and that the agent's port is open, then wait a few seconds. Keel keeps trying.
      </p>
    {/if}

    <dl class="facts">
      <dt>Host</dt>
      <dd class="mono">{server.host}</dd>
      <dt>Last seen</dt>
      <dd class="num">
        {server.reachability === 'online'
          ? 'Now'
          : server.last_seen
            ? formatAgo(server.last_seen)
            : 'Not yet'}
      </dd>
      {#if status}
        <dt>System</dt>
        <dd>{status.os_pretty_name} · {status.arch}</dd>
        <dt>Uptime</dt>
        <dd class="num">{formatDuration(status.uptime_secs)}</dd>
        <dt>CPU load</dt>
        <dd class="num">{status.load_1m.toFixed(2)} <span class="muted">(1 minute)</span></dd>
      {/if}
    </dl>

    {#if status}
      <h2>Resources</h2>
      <div class="meters">
        {#each meters as m (m.label)}
          {@const pct = percent(m.used, m.total)}
          <div class="meter-row">
            <span>{m.label}</span>
            <div
              class="meter"
              role="meter"
              aria-label={m.label}
              aria-valuemin="0"
              aria-valuemax="100"
              aria-valuenow={pct}
            >
              <div class="fill" style="width: {pct}%"></div>
            </div>
            <span class="num">{formatBytes(m.used)} of {formatBytes(m.total)} · {pct}%</span>
          </div>
        {/each}
        <div class="meter-row">
          <span>Agent memory</span>
          <span></span>
          <span class="num">{formatBytes(status.agent_rss_bytes)}</span>
        </div>
      </div>
    {:else if server.reachability === 'connecting'}
      <p class="muted">Connecting to the server…</p>
    {/if}

    <h2>Users</h2>
    {#if usersState === 'ready' && users}
      <ul class="users">
        {#each users as u (u.id)}
          <li>
            <span class="name">{u.display_name}</span>
            <span class="muted">{u.role}</span>
            <span class="mono muted">{u.key_fingerprint}</span>
          </li>
        {/each}
      </ul>
    {:else if usersState === 'forbidden'}
      <p class="muted">Your role on this server can't see its users.</p>
    {:else if usersState === 'failed'}
      <p class="muted">Couldn't load the users. Try again in a moment.</p>
    {:else if usersState === 'loading'}
      <p class="muted" role="status">Loading users…</p>
    {:else}
      <p class="muted">Users show when the server is online.</p>
    {/if}

    <div class="danger-zone">
      <button class="btn danger" onclick={() => (confirming = true)}>Remove server</button>
    </div>

    {#if confirming}
      <ConfirmDialog
        title="Remove {server.name}?"
        body="Keel will forget this server and its saved sign-in on this device. Apps and data on the server aren't touched, and the Keel agent keeps running there."
        confirmLabel="Remove {server.name}"
        busy={removing}
        error={removeError}
        onconfirm={remove}
        oncancel={() => {
          confirming = false;
          removeError = '';
        }}
      />
    {/if}
  {/if}
</main>

<style>
  main {
    flex: 1;
    min-width: 0;
    overflow-y: auto;
    padding: 16px;
    max-width: 820px;
  }
  .back {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    text-decoration: none;
    margin-bottom: 12px;
  }
  .back:hover {
    color: var(--ink);
  }
  header {
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 16px;
  }
  h1 {
    font-size: 20px;
  }
  h2 {
    font-size: 14px;
    color: var(--ink-2);
    margin: 24px 0 8px;
  }
  .alert {
    margin: 0 0 16px;
    padding: 10px 12px;
    border: 1px solid var(--down);
    border-left-width: 3px;
    border-radius: var(--radius);
    background: var(--down-tint);
  }
  .facts {
    display: grid;
    grid-template-columns: 110px 1fr;
    row-gap: 8px;
    margin: 0;
    padding: 12px;
    background: var(--panel);
    border: 1px solid var(--rule);
    border-radius: var(--radius);
  }
  .facts dt {
    color: var(--ink-2);
  }
  .facts dd {
    margin: 0;
  }
  .meters {
    display: grid;
    gap: 10px;
    padding: 12px;
    background: var(--panel);
    border: 1px solid var(--rule);
    border-radius: var(--radius);
  }
  .meter-row {
    display: grid;
    grid-template-columns: 110px minmax(80px, 1fr) minmax(0, 220px);
    align-items: center;
    column-gap: 12px;
  }
  .meter {
    height: 8px;
    background: var(--canvas);
    border: 1px solid var(--rule);
    border-radius: 4px;
    overflow: hidden;
  }
  .fill {
    height: 100%;
    background: var(--ink-2);
    transition: width 300ms ease-out;
  }
  .users {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--rule);
    border-bottom: 0;
    border-radius: var(--radius);
    overflow: hidden;
    background: var(--panel);
  }
  .users li {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 90px minmax(0, 1.4fr);
    column-gap: 16px;
    align-items: center;
    min-height: var(--row-h);
    padding: 0 12px;
    border-bottom: 1px solid var(--rule);
  }
  .users .name {
    font-weight: 500;
  }
  .users .mono {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .danger-zone {
    margin-top: 32px;
    padding-top: 16px;
    border-top: 1px solid var(--rule);
  }
</style>

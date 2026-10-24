<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';

  type ServerView = {
    id: string;
    name: string;
    host: string;
    reachability: 'online' | 'unreachable' | 'untrusted';
    last_seen: number | null;
  };

  let servers = $state<ServerView[]>([]);
  let error = $state('');

  onMount(() => {
    let unlisten: (() => void) | undefined;
    let disposed = false;
    invoke<ServerView[]>('list_servers')
      .then((list) => (servers = list))
      .catch((e) => (error = String(e)));
    listen<ServerView[]>('servers://changed', (e) => (servers = e.payload)).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  });
</script>

<h1>Keel</h1>
{#if error}<p>{error}</p>{/if}
<ul>
  {#each servers as s (s.id)}
    <li>{s.name} ({s.host}): {s.reachability}</li>
  {:else}
    <li>No servers yet.</li>
  {/each}
</ul>

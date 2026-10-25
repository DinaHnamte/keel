import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { AppView, ServerView } from './types';

/** Live view of every server and app, kept fresh by `servers://changed`. */
export const fleet = $state({
  servers: [] as ServerView[],
  apps: [] as AppView[],
  loaded: false,
  error: ''
});

async function refreshApps() {
  try {
    fleet.apps = await invoke<AppView[]>('list_apps');
  } catch (e) {
    fleet.error = String(e);
  }
}

/** Start listening. Returns a cleanup function. */
export function startFleet(): () => void {
  let disposed = false;
  let unlisten: (() => void) | undefined;
  (async () => {
    try {
      fleet.servers = await invoke<ServerView[]>('list_servers');
      await refreshApps();
      fleet.error = '';
    } catch (e) {
      fleet.error = "Couldn't load your servers. Restart Keel and try again.";
      console.error(e);
    }
    fleet.loaded = true;
  })();
  listen<ServerView[]>('servers://changed', (e) => {
    fleet.servers = e.payload;
    void refreshApps();
  }).then((fn) => {
    if (disposed) fn();
    else unlisten = fn;
  });
  return () => {
    disposed = true;
    unlisten?.();
  };
}

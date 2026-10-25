import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { AppView, ServerView } from './types';

/** Live view of every server and app, kept fresh by `servers://changed`. */
export const fleet = $state({
  servers: [] as ServerView[],
  apps: [] as AppView[],
  loaded: false,
  /** The server list could not be loaded at all: replaces the board. */
  error: '',
  /** Apps could not be refreshed: shown inline above the list, last known apps stay. */
  appsNotice: ''
});

export const APPS_NOTICE = "Couldn't load your apps. Keel will keep trying.";

/** Returns true on success. Clears the notice on success, sets it on failure. */
export async function refreshApps(): Promise<boolean> {
  try {
    fleet.apps = await invoke<AppView[]>('list_apps');
    fleet.appsNotice = '';
    return true;
  } catch (e) {
    console.error(e);
    fleet.appsNotice = APPS_NOTICE;
    return false;
  }
}

/** Start listening. Returns a cleanup function. */
export function startFleet(): () => void {
  let disposed = false;
  let unlisten: (() => void) | undefined;
  (async () => {
    try {
      fleet.servers = await invoke<ServerView[]>('list_servers');
      fleet.error = '';
    } catch (e) {
      fleet.error = "Couldn't load your servers. Restart Keel and try again.";
      console.error(e);
    }
    await refreshApps();
    fleet.loaded = true;
  })();
  listen<ServerView[]>('servers://changed', (e) => {
    fleet.servers = e.payload;
    fleet.error = '';
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

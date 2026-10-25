import IconCircleCheck from '@tabler/icons-svelte/icons/circle-check';
import IconAlertTriangle from '@tabler/icons-svelte/icons/alert-triangle';
import IconCircleX from '@tabler/icons-svelte/icons/circle-x';
import IconHammer from '@tabler/icons-svelte/icons/hammer';
import IconCloudOff from '@tabler/icons-svelte/icons/cloud-off';
import IconLoader from '@tabler/icons-svelte/icons/loader-2';
import IconShieldX from '@tabler/icons-svelte/icons/shield-x';
import type { AppView, ServerView } from './types';

export type RowState = 'down' | 'unreachable' | 'building' | 'degraded' | 'connecting' | 'live';

/** Problems first; a server we have not heard from yet sits between degraded and live. */
const ORDER: RowState[] = ['down', 'unreachable', 'building', 'degraded', 'connecting', 'live'];

/** Badge states: every row state, plus a server whose identity changed. */
export type BadgeState = RowState | 'untrusted';

export const STATE_LABEL: Record<BadgeState, string> = {
  untrusted: 'Identity changed',
  down: 'Down',
  unreachable: 'Server unreachable',
  building: 'Building',
  degraded: 'Degraded',
  connecting: 'Connecting',
  live: 'Live'
};

// The Tabler Svelte icons are typed as legacy class components.
export const STATE_ICON: Record<BadgeState, typeof IconCircleCheck> = {
  untrusted: IconShieldX,
  down: IconCircleX,
  unreachable: IconCloudOff,
  building: IconHammer,
  degraded: IconAlertTriangle,
  connecting: IconLoader,
  live: IconCircleCheck
};

export function rowState(app: AppView, server: ServerView): RowState {
  if (server.reachability === 'connecting') return 'connecting';
  if (server.reachability !== 'online') return 'unreachable';
  return app.app.state;
}

export type Row = { app: AppView; server: ServerView };

export function sortRows<T extends { app: AppView; server: ServerView }>(rows: T[]): T[] {
  return [...rows].sort(
    (a, b) =>
      ORDER.indexOf(rowState(a.app, a.server)) - ORDER.indexOf(rowState(b.app, b.server)) ||
      a.app.app.name.localeCompare(b.app.app.name)
  );
}

/** "4 apps on 2 servers · 1 down" */
export function summaryLine(rows: Row[], serverCount: number): string {
  const plural = (n: number, one: string, many = one + 's') => `${n} ${n === 1 ? one : many}`;
  const parts = [`${plural(rows.length, 'app')} on ${plural(serverCount, 'server')}`];
  const counts: Partial<Record<RowState, number>> = {};
  for (const r of rows) {
    const s = rowState(r.app, r.server);
    counts[s] = (counts[s] ?? 0) + 1;
  }
  if (counts.down) parts.push(`${counts.down} down`);
  if (counts.unreachable) parts.push(`${counts.unreachable} on unreachable servers`);
  if (counts.building) parts.push(`${counts.building} building`);
  if (counts.degraded) parts.push(`${counts.degraded} degraded`);
  return parts.join(' · ');
}

/** How a server itself is shown: same icons and colors as app states, server wording. */
export function serverBadge(server: ServerView): { state: BadgeState; label: string } {
  switch (server.reachability) {
    case 'online':
      return { state: 'live', label: 'Online' };
    case 'connecting':
      return { state: 'connecting', label: 'Connecting' };
    case 'untrusted':
      return { state: 'untrusted', label: 'Identity changed' };
    default:
      return { state: 'unreachable', label: 'Unreachable' };
  }
}

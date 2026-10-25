export type CommandAction = { kind: 'add-server' } | { kind: 'goto'; path: string };

export type Command = {
  id: string;
  label: string;
  action: CommandAction;
};

export type CommandContext = { servers: { id: string; name: string }[] };

export function allCommands(ctx: CommandContext): Command[] {
  return [
    { id: 'add-server', label: 'Add server', action: { kind: 'add-server' } },
    { id: 'fleet', label: 'Go to fleet board', action: { kind: 'goto', path: '/' } },
    ...ctx.servers.map(
      (s): Command => ({
        id: `server:${s.id}`,
        label: `Go to ${s.name}`,
        action: { kind: 'goto', path: `/servers/${s.id}` }
      })
    )
  ];
}

/** Lower is better; null means no match. Substring beats scattered letters. */
function score(label: string, query: string): number | null {
  const l = label.toLowerCase();
  const at = l.indexOf(query);
  if (at >= 0) return at;
  let from = 0;
  let gaps = 0;
  for (const ch of query) {
    const i = l.indexOf(ch, from);
    if (i < 0) return null;
    gaps += i - from;
    from = i + 1;
  }
  return 1000 + gaps;
}

export function filterCommands(query: string, ctx: CommandContext): Command[] {
  const all = allCommands(ctx);
  const q = query.trim().toLowerCase().replace(/\s+/g, '');
  if (!q) return all;
  return all
    .map((command, order) => ({ command, order, s: score(command.label.replace(/\s+/g, ''), q) }))
    .filter((x): x is { command: Command; order: number; s: number } => x.s !== null)
    .sort((a, b) => a.s - b.s || a.order - b.order)
    .map((x) => x.command);
}

export function isMac(): boolean {
  if (typeof navigator === 'undefined') return false;
  return /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent);
}

/** Ctrl+K on Linux and Windows, Cmd+K on macOS. */
export function isPaletteShortcut(e: KeyboardEvent, mac: boolean = isMac()): boolean {
  if (e.key.toLowerCase() !== 'k' || e.altKey || e.shiftKey) return false;
  return mac ? e.metaKey && !e.ctrlKey : e.ctrlKey && !e.metaKey;
}

export const shortcutLabel = (mac: boolean = isMac()) => (mac ? '⌘K' : 'Ctrl+K');

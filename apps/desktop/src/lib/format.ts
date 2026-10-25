export function formatBytes(n: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 || v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

export function formatDuration(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/** "just now", "3 minutes ago", "2 hours ago", "5 days ago" */
export function formatAgo(unixSecs: number, nowSecs = Date.now() / 1000): string {
  const diff = Math.max(0, Math.round(nowSecs - unixSecs));
  if (diff < 10) return 'just now';
  const unit = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'} ago`;
  if (diff < 60) return unit(diff, 'second');
  if (diff < 3600) return unit(Math.floor(diff / 60), 'minute');
  if (diff < 86400) return unit(Math.floor(diff / 3600), 'hour');
  return unit(Math.floor(diff / 86400), 'day');
}

export function percent(used: number, total: number): number {
  return total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0;
}

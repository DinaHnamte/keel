export type Reachability = 'connecting' | 'online' | 'unreachable' | 'untrusted';
export type AppState = 'live' | 'building' | 'degraded' | 'down';

export type ServerStatus = {
  hostname: string;
  os_pretty_name: string;
  arch: string;
  uptime_secs: number;
  load_1m: number;
  mem_total_bytes: number;
  mem_used_bytes: number;
  disk_total_bytes: number;
  disk_used_bytes: number;
  agent_rss_bytes: number;
};

export type ServerView = {
  id: string;
  name: string;
  host: string;
  reachability: Reachability;
  last_seen: number | null;
  status: ServerStatus | null;
};

export type AppSummary = {
  id: number;
  name: string;
  project_id: unknown;
  state: AppState;
};

export type AppView = {
  server_id: string;
  server_name: string;
  app: AppSummary;
};

export type UserInfo = {
  id: number;
  display_name: string;
  role: 'owner' | 'admin' | 'developer' | 'viewer';
  key_fingerprint: string;
};

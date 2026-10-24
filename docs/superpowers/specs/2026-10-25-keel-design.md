# Keel — design spec

Date: 2026-10-25
Status: draft for review
Working name: Keel (may change before public release)

## 1. Purpose

Keel is a self-hosted tool for deploying and running web apps on your own VPS servers. A desktop app on your computer is the interface; a small agent on each server does the work. After the first connection, you never need to SSH into the server by hand.

### Audience

- **Now:** a single developer managing their own projects.
- **Later:** released publicly (open source or sold), used by individuals and small teams or agencies.

Because of the later release, install experience, documentation and broad compatibility are requirements from the first version, not afterthoughts.

### Success criteria

1. A user with a fresh Ubuntu or Debian VPS can go from "add server" to a live HTTPS site from a Git repo without opening a terminal.
2. The agent's idle memory stays under 25 MB (enforced in CI). A 1 GB VPS can run the agent, a database and several small apps.
3. Deploys are zero-downtime, and rollback takes seconds with no rebuild.
4. When a whole server goes down, the user is alerted even though that server can't report it.
5. A stolen teammate key with the Developer role cannot get a shell on the server.

### Differentiator

Existing self-hosted panels (Coolify, Dokploy, CapRover) run their dashboard on the server and need roughly 1–2 GB of RAM before any app runs. Keel moves the interface to the user's machine and keeps the server-side footprint as small as possible.

### Non-goals for the first release

- Hosted SaaS or multi-tenant service.
- A web UI served by the agent (the design leaves room to add one later).
- Kubernetes, clusters, or load balancing one app across servers.
- Team definitions synced across servers (users are per server).
- Windows or macOS servers.

## 2. Architecture overview

```
 Your computer                                Each VPS
 ┌──────────────────────────┐   mutual TLS   ┌──────────────────────────────────┐
 │ Keel desktop app (Tauri) │◄──────────────►│ keel-agent (Rust, systemd)       │
 │  - UI (fleet board)      │   pinned cert  │  - API + permission checks       │
 │  - local builds          │                │  - reconcile loop (desired state)│
 │  - keys in OS keychain   │                │  - deploy engine, monitors       │
 └──────────────────────────┘                │  - SQLite (WAL)                  │
                                             │                                  │
                         internet :80/:443 ─►│ Caddy (separate process)         │
                                             │   ├─► app services (systemd)     │
                                             │   ├─► PHP-FPM pools              │
                                             │   └─► Podman containers          │
                                             │ Postgres / MariaDB / Valkey      │
                                             └──────────────────────────────────┘
```

### Components

| Unit | Responsibility | Depends on |
|---|---|---|
| `keel-proto` (shared crate) | Message types, versioning, role/permission definitions, stack detection logic | — |
| `keel-agent` | Runs on each VPS. Owns server state, applies it, runs deploys and checks, enforces permissions | `keel-proto`, systemd, Caddy, SQLite |
| `keel-desktop` | Tauri app. UI, onboarding over SSH, local builds, holds user keys | `keel-proto`, OS keychain |
| Proxy adapter (inside agent) | Interface the agent uses to manage routes and TLS. Caddy is the only implementation in v1 | Caddy admin API |
| Runtime adapters (inside agent) | Start, stop and health-check an app: native systemd service, PHP-FPM pool, or Podman container | systemd, Podman |

Each unit communicates only through `keel-proto` types or its own narrow interface, so internals can change without touching callers.

### Tech stack

- Agent: Rust, single static binary (musl), targets x86-64 and ARM64.
- Desktop: Tauri (system WebView), UI in SvelteKit, Rust backend shared with the agent via `keel-proto`.
- Agent storage: SQLite in WAL mode.
- Proxy: Caddy, controlled through its local admin API (bound to a Unix socket, not a TCP port).

## 3. Server onboarding

1. **Add server.** The user enters host, port and user, and then either:
   - lets Keel generate a fresh key pair and shows a one-line command to add the public key on the server (recommended), or
   - pastes an existing private key or password.
2. **Preflight over SSH.** Keel checks OS and version, CPU architecture, systemd, free disk, and whether ports 80 and 443 are free. Any blocker is shown in plain language before anything is changed.
3. **Install.** Keel uploads the agent binary (signature verified), creates a `keel` system user and a systemd unit, installs Caddy, and configures the firewall (80, 443, SSH, agent port).
4. **Pair.** The agent generates its own TLS key and certificate. The desktop app pins the certificate fingerprint and registers the user's public key as Owner.
5. **Optional hardening.** Offer automatic security updates and disabling SSH password login.
6. **SSH credentials.** The user can delete them, or keep them encrypted in the OS keychain for repair actions (for example, reinstalling a broken agent). Day-to-day traffic never uses SSH.

A headless install path also exists: a one-line script with checksum verification, which prints a pairing code to enter in the desktop app.

## 4. Running apps

### Stack detection

| Found in repo | Runtime | Notes |
|---|---|---|
| `composer.json` | PHP-FPM pool | Laravel, Symfony, WordPress detected for defaults |
| `package.json` | Native Node service | Framework read from dependencies (Next.js, Nuxt, SvelteKit, Express, NestJS…) |
| `Cargo.toml` | Native binary service | Axum, Actix, Rocket |
| Static files or static build output | Served by Caddy | No process |
| `Dockerfile` | Podman (rootless) | Any other stack |

Detection is shown to the user before the first deploy and can be overridden. An optional `keel.toml` in the repo pins runtime versions, build command, start command, health check path and memory limit. When present, it wins over detection.

### Runtimes

The agent installs language versions on demand into `/opt/keel/runtimes/` (for example Node 20 and 22 side by side, PHP 8.2 and 8.3), verified against official checksums. Each app pins its version. Unused versions are removed.

### Filesystem layout

```
/srv/apps/<app>/
  releases/<n>/   one folder per release
  shared/         .env, uploads, storage; linked into each release
```

### Process isolation

Every app runs as its own Linux user, as a systemd service with:
- memory and CPU limits (cgroups v2); exceeding memory kills and restarts only that app
- `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`, and a restricted set of writable paths
- a localhost port or Unix socket only; Caddy is the only public entry point

Podman containers run rootless under the app's user with the same limits.

## 5. Builds and deploys

### Where builds run

1. **Deploy clicked in the desktop app:** built locally on the user's computer.
2. **Git webhook (push or merge):** received by the agent, which delegates the build to any connected desktop app whose user has deploy permission on that project.
3. **No desktop app online:** the agent builds on the server under a memory cap, unless server builds are disabled for that app, in which case the deploy is queued until a desktop app connects.

An optional tray process lets the desktop app accept delegated builds while its window is closed. It is off by default.

### Reproducible local builds

Local builds run inside a Linux build environment on the user's computer (Podman machine or WSL2), using the same pinned toolchain versions as the server. This avoids native-module and OS mismatches (Node native addons, Rust targets). Rust cross-compiles for the server's architecture.

### Upload

Release artifacts are uploaded as content-addressed chunks; only chunks the server doesn't already have are sent. Later deploys of the same app typically transfer only changed files.

### Deploy state machine

```
queued → fetching → building → uploading → starting → health_checking → switching → draining → live
                                                         │
                                                         └─ fail → previous release stays live, deploy marked failed
```

- Each step is persisted before it starts. After an agent crash or reboot, the deploy resumes or rolls back; an app is never left half-switched.
- Health check: the new release must return HTTP 200 on its health path (default `/`) within a configurable timeout (default 60 seconds).
- Switching: Caddy route is updated atomically to the new upstream.
- Draining: the old release keeps serving in-flight requests for a grace period, then stops.
- Rollback: the same switch, pointed at a kept release. No rebuild.
- Retention: last 5 releases per app (configurable). Build caches are pruned. A deploy is refused if it would fill the disk.

## 6. Domains and HTTPS

1. User adds a domain to an app.
2. Keel shows the exact A and AAAA records needed.
3. Keel polls DNS until it resolves to the server, then issues a Let's Encrypt certificate through Caddy. Renewal is automatic.
4. Optional DNS provider token (Cloudflare first, others later): Keel creates records itself and can issue wildcard certificates.

The agent talks to the proxy only through the proxy adapter interface (add/remove route, set upstream, list certificate status). Caddy is the v1 implementation; a hardened Rust proxy can replace it later without changes elsewhere.

## 7. Databases and backups

- One-click PostgreSQL, MariaDB and Valkey (Redis-compatible), installed natively as systemd services.
- Configurations tuned for small servers (target idle: Postgres 30–50 MB, MariaDB 80–120 MB, Valkey ~5 MB).
- Creating a database for an app generates credentials and injects them into the app's environment (`DATABASE_URL`, plus Laravel-style `DB_*` variables for PHP apps).
- Databases listen on localhost or a Unix socket only. The desktop app can open a temporary tunnel for local GUI tools.
- Scheduled backups of databases and an app's `shared/` folder to S3-compatible storage or another Keel server. Backups are encrypted before upload. One-click restore.

## 8. Monitoring and alerts

### On each server (agent)

- Process and HTTP health checks every few seconds per app.
- Auto-restart crashed apps with exponential backoff.
- CPU, memory, disk and per-app usage stored in SQLite; raw samples rolled up to hourly and daily aggregates.
- Early warnings: disk over 90%, certificate renewal failing, an app repeatedly hitting its memory limit.

### Whole-server failure

- **Peer checks:** with two or more servers, agents check each other's heartbeats and public sites. When one goes dark, a peer sends the alert. An Owner enables peering in the desktop app, which gives each agent the other's address and pinned certificate; peers authenticate with mutual TLS and can only exchange heartbeats, not call any other API.
- **Dead-man's switch:** each agent pings an external heartbeat URL (for example healthchecks.io or a self-hosted equivalent) every minute. Offered during setup for single-server users.
- **Desktop app:** shows live reachability while open. This is a visible indicator only, not monitoring.

### Alert channels

Email, Telegram, Discord, Slack, generic webhook, and ntfy for phone push.

## 9. Users, roles and security

### Identity

- Each desktop app install generates a key pair. The private key stays in the OS keychain; opening the app can require OS unlock (Touch ID, Windows Hello) or a passphrase.
- The agent identifies users only by public key. There is no password login on the server.

### Invites

1. An Owner or Admin creates an invite: role, projects, expiry (default 24 h). It produces a one-time code containing the server address and certificate fingerprint.
2. The invitee enters the code in their desktop app, which registers their public key. The code is then invalid.
3. "Grant on these servers" writes the same invite to several servers in one action. Users are stored per server; there is no cross-server sync in v1.

Revoking a user removes their key and drops their open connections immediately.

### Roles

| Role | Permissions |
|---|---|
| Owner | Everything, including server settings, users and agent upgrades |
| Admin | All projects; can invite users other than Owners |
| Developer | On assigned projects: deploy, roll back, view logs, edit env vars |
| Viewer | On assigned projects: view status, metrics and logs; secrets masked |

The user/role/project data model and permission checks exist from the first milestone, even before the invite UI ships.

### Safeguards

- Audit log of every action: user, action, target, time, device.
- Secrets (env values, database passwords, DNS tokens, backup keys) encrypted at rest with a key held by the agent; masked in the UI unless the role permits reading.
- The agent API exposes only fixed, typed operations. There is no arbitrary command execution.
- The agent listens on one port, mutual TLS only, with connection rate limiting.

## 10. Desktop app UI

### Layout: fleet board

- Main screen is one list of all apps across all servers. Problems sort to the top: down, then degraded or building, then healthy.
- Each row: status, app name, server, recent uptime strip.
- Selecting an app opens a detail drawer on the right (overview, deploys, logs, environment, domains, databases). The list stays visible.
- Servers have their own page: resources, installed runtimes, users, agent version and settings.
- Ctrl/Cmd+K command palette available everywhere (deploy, roll back, open logs, jump to app or server).

### Visual direction

An instrument panel: mostly quiet greys, with **color reserved for state**, so a down app is impossible to miss.

| Role | Light | Dark |
|---|---|---|
| Canvas | `#EEF1F4` | `#12171D` |
| Panel | `#FFFFFF` | `#1A2129` |
| Ink (text, primary buttons) | `#18212B` | `#E6EBF0` |
| Secondary text | `#5A6675` | `#93A0AE` |
| Rules and borders | `#D6DCE2` | `#2A333D` |
| Live | `#1E9E6A` | `#3DBE88` |
| Building or degraded | `#D4930F` | `#E8AE3A` |
| Down | `#D2412F` | `#EF6B5A` |

- No brand accent color; primary buttons are ink-filled.
- Type: Instrument Sans for interface text, with tabular figures for metrics. JetBrains Mono only for code-like content (logs, commit hashes, env values). Sentence case; no all-caps labels.
- Density: compact bordered rows (~32 px), not card grids.
- Motion only when something changes (uptime cell filling in, deploy progress).
- Status is never conveyed by color alone; each state also has an icon and text label.

## 11. Distribution and updates

### Desktop app

Signed installers: Windows (.msi), macOS (.dmg, notarized), Linux (AppImage, .deb). Signed auto-updates.

### Agent

- Static binaries for x86-64 and ARM64.
- Supported: Ubuntu 22.04 and 24.04, Debian 12 and 13 (fully tested). AlmaLinux and Rocky 9 best-effort at launch.
- Releases are signed (Ed25519); the agent rejects unsigned updates.
- Update flow: download → verify signature → start new binary → self-check → hand over. On failure, the previous binary is restored.
- Apps and Caddy run independently of the agent; an agent restart or crash never takes sites offline.
- Protocol is versioned. The desktop app supports the current and previous agent version.

## 12. Reliability model

- **Desired state:** the agent database records what should exist (apps, releases, routes, certificates, databases, schedules).
- **Reconcile loop:** on startup and periodically, the agent compares desired state with reality (systemd units, Caddy routes, files) and converges. All operations are idempotent.
- **Resumable deploys:** see section 5.
- **Agent's own data:** the SQLite database is included in scheduled backups.

## 13. Error handling

- Every failure shown to the user states what happened and what to do next, in plain language (for example, "Build ran out of memory at 512 MB. Raise the limit or build locally.").
- Deploy failures keep the previous release live and attach full build and start logs to the failed deploy.
- Unreachable server: the fleet board marks all its apps as "server unreachable" (distinct from "app down") and shows when it was last seen.
- Onboarding preflight failures are reported before any change is made to the server.
- Raw errors are logged for diagnosis but never shown as the primary message.

## 14. Testing

- **Unit:** stack detection, deploy state machine transitions (including crash at each step), permission checks per role, reconcile logic.
- **Integration:** agent running on each supported distro in CI (VMs), exercising install, pair, deploy, rollback, upgrade, and reboot recovery.
- **End-to-end sample matrix:** Laravel, WordPress, Next.js, Nuxt, SvelteKit, Express, Axum, a static site and a Dockerfile app, each deployed, health-checked, rolled back.
- **Memory budget:** CI fails if agent idle RSS exceeds 25 MB.
- **Fuzzing:** the agent's protocol parser and any input from the network.
- **Desktop:** UI component tests and a scripted onboarding test against a disposable VM.

## 15. Delivery plan

Each milestone gets its own implementation plan and is shippable on its own.

1. **Foundation:** `keel-proto`, agent core (API, mTLS, SQLite, reconcile loop skeleton, user/role model and permission checks), onboarding over SSH, desktop shell with fleet board and server page.
2. **Deploy engine:** detection, runtimes, local and server builds, delegation, chunked upload, zero-downtime switch, rollback.
3. **Domains and HTTPS:** proxy adapter, Caddy integration, DNS guidance, Cloudflare token support.
4. **Monitoring and alerts:** health checks, auto-restart, metrics, peer checks, dead-man's switch, alert channels.
5. **Databases and backups.**
6. **Team features:** invites, multi-server grants, role management UI, audit log viewer.

## 16. Open questions

- Final product name (Keel is a working name).
- License (open source, source-available, or commercial) — decide before public release.

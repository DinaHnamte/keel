# Keel milestone 1: foundation — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A user can add a fresh Ubuntu or Debian VPS in the desktop app, have the agent installed and paired over SSH without touching a terminal, and see the server's live status on the fleet board and server page.

**Architecture:** A Cargo workspace with three Rust crates (`keel-proto` shared types, `keel-agent` server binary, `keel-client` desktop-side logic) and a Tauri 2 app whose UI is SvelteKit. The desktop talks to the agent over mutual TLS with a pinned agent certificate; users are identified by their client certificate's public key. SSH is used only during onboarding.

**Tech Stack:** Rust (edition 2024), tokio (current-thread runtime in the agent), rustls 0.23 + tokio-rustls, rcgen, rusqlite (bundled SQLite, WAL), serde + serde_json, clap 4, ed25519-dalek 2, sha2, russh, keyring 3, Tauri 2, SvelteKit 2 with Svelte 5, Vitest + @testing-library/svelte, @fontsource for Instrument Sans and JetBrains Mono.

**Spec:** `docs/superpowers/specs/2026-10-25-keel-design.md` (sections 2, 3, 9, 10, 12, 13, 14 apply to this milestone).

## Global Constraints

- Agent idle RSS must stay under 25 MB (spec §1, §14). Enforced by a test in Task 7.
- Agent: single static musl binary, targets `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.
- Supported servers: Ubuntu 22.04 and 24.04, Debian 12 and 13 (fully supported); AlmaLinux and Rocky 9 (best-effort: allowed with a warning). Anything else is refused at preflight.
- The agent listens on one port only, default `7443`, mutual TLS only. No other listener in this milestone.
- The agent API exposes only fixed, typed operations. No arbitrary command execution, ever.
- No password login on the agent. Users are identified only by client-certificate public key.
- Desktop private keys and any kept SSH credentials live in the OS keychain, never in plain files.
- Agent paths: binary `/usr/local/bin/keel-agent`, config `/etc/keel/agent.toml`, data `/var/lib/keel/` (mode `0700`, owner `keel`), database `/var/lib/keel/keel.db`, TLS `/var/lib/keel/tls/`.
- The agent runs as the `keel` system user in this milestone. Privileged operations (creating app users, systemd units) arrive in milestone 2 and are out of scope here.
- Caddy installation, agent self-update and desktop auto-update are out of scope for this milestone. Preflight still checks that ports 80 and 443 are free.
- UI copy: sentence case, no all-caps labels, plain language, errors say what happened and what to do next. Status is never shown by color alone: every state has an icon and a text label.
- UI color tokens are exactly the table in spec §10. No other accent color.
- Commit messages end with the trailer block configured for this session (Co-Authored-By and Claude-Session lines).

## Review Focus

1. **SSH on a non-standard port.** Enabling the firewall during onboarding must keep the port the installer is connected on open, or the user is locked out. Test in Task 9.
2. **Re-running onboarding on a half-installed server.** A second install must be idempotent: no duplicate Owner, no reuse of a burned pairing token, existing TLS key kept. Tests in Tasks 5 and 10.
3. **Agent restarts while the desktop is open.** The desktop must show "Server unreachable", then recover on its own when the agent returns, with no user action. Test in Task 11.
4. **Agent certificate changes** (reinstall or interception). The desktop must refuse to connect and explain, never silently re-pin. Test in Task 8.
5. **Pairing replay.** A pairing token used once, or expired (older than 24 h), must be rejected with a plain message. Test in Task 6.

---

## File structure

```
Cargo.toml                         workspace
crates/keel-proto/src/
  lib.rs                           re-exports
  roles.rs                         Role, Permission, Scope, authorize()
  messages.rs                      Request, Response, ErrorCode, data types
  version.rs                       protocol version constants and compat check
  codec.rs                         length-prefixed frame encode/decode
  pairing.rs                       PairingCode encode/parse
  fuzz/fuzz_targets/decode.rs      cargo-fuzz target
crates/keel-agent/src/
  main.rs                          clap entry: `init`, `run`
  config.rs                        AgentConfig load/defaults
  store/mod.rs                     Store: open, migrations
  store/users.rs                   users, projects, memberships
  store/pairing.rs                 pairing tokens
  store/audit.rs                   audit log writes
  tls.rs                           agent cert load/create, client identity
  init.rs                          `keel-agent init`
  server.rs                        accept loop, limits, connection handling
  handlers.rs                      Request -> Response dispatch with authorize
  sysinfo.rs                       /proc and statvfs readers
  reconcile.rs                     Reconciler trait and loop
  dist/keel-agent.service          systemd unit
crates/keel-agent/tests/           integration tests (spawn agent on localhost)
crates/keel-client/src/
  lib.rs
  identity.rs                      key pair, client cert, Keychain trait
  servers.rs                       ServerRecord store (JSON in app data dir)
  connection.rs                    mTLS client with pinning, request/response
  onboarding/mod.rs                OnboardingPlan, run_onboarding()
  onboarding/preflight.rs          pure parsing and checks
  onboarding/ssh.rs                russh session wrapper
  onboarding/install.rs            install steps
  onboarding/artifact.rs           agent binary signature verification
apps/desktop/src-tauri/src/
  main.rs, commands.rs, poller.rs  Tauri bridge and status polling
apps/desktop/src/
  lib/tokens.css                   design tokens
  lib/status.ts                    status model and sort order
  lib/components/*.svelte          FleetRow, Drawer, StatusBadge, CommandPalette, AddServerWizard
  routes/+page.svelte              fleet board
  routes/servers/[id]/+page.svelte server page
scripts/install.sh                 headless install
.github/workflows/ci.yml           unit, integration matrix, memory budget, fuzz smoke
```

---

### Task 1: Workspace, roles and permissions

**Files:**
- Create: `Cargo.toml`, `crates/keel-proto/Cargo.toml`, `crates/keel-proto/src/lib.rs`, `crates/keel-proto/src/roles.rs`, `rust-toolchain.toml`, `.gitignore`
- Test: `crates/keel-proto/src/roles.rs` (unit tests module)

**Interfaces:**
- Produces:
  - `enum Role { Owner, Admin, Developer, Viewer }` (serde, lowercase)
  - `enum Permission { ViewStatus, ViewLogs, ReadSecrets, EditEnv, Deploy, Rollback, ManageProjects, ManageUsers, InviteOwner, ManageServer, UpgradeAgent }`
  - `struct ProjectId(pub i64)`
  - `struct Principal { pub role: Role, pub projects: Vec<ProjectId> }`
  - `fn authorize(p: &Principal, perm: Permission, project: Option<ProjectId>) -> Result<(), Denied>`
  - `struct Denied { pub perm: Permission }` implementing `Display` as plain language ("Your role can't do this.")

- [ ] **Step 1: Create workspace** with members `crates/*` and `apps/desktop/src-tauri`, `rust-toolchain.toml` pinning stable with the two musl targets, and `.gitignore` for `target/`, `node_modules/`, `.svelte-kit/`.

- [ ] **Step 2: Write the failing table test** `authorize_matrix` covering every role × permission, using spec §9:
  - Owner: all permissions, any project or none.
  - Admin: all except `InviteOwner`, `ManageServer`, `UpgradeAgent`.
  - Developer: `ViewStatus, ViewLogs, ReadSecrets, EditEnv, Deploy, Rollback` only when `project` is `Some` and in `projects`; denied on `None` for everything except `ViewStatus`.
  - Viewer: `ViewStatus, ViewLogs` on assigned projects; `ViewStatus` with `None`; `ReadSecrets` and `EditEnv` always denied.
  - Assert `authorize(dev_on_p1, Deploy, Some(p2))` is `Err`.

- [ ] **Step 3: Run** `cargo test -p keel-proto authorize_matrix`. Expected: FAIL (not defined).

- [ ] **Step 4: Implement** `authorize` in `roles.rs` as an explicit match on role, then a project-membership check for Developer and Viewer.

- [ ] **Step 5: Run** the test. Expected: PASS.

- [ ] **Step 6: Commit** `feat(proto): roles and permission checks`.

---

### Task 2: Protocol messages, versioning and codec

**Files:**
- Create: `crates/keel-proto/src/messages.rs`, `version.rs`, `codec.rs`, `pairing.rs`, `crates/keel-proto/fuzz/` (cargo-fuzz scaffold, target `decode`)
- Test: unit tests in each file

**Interfaces:**
- Consumes: `Role`, `ProjectId` (Task 1)
- Produces:
  - `const PROTOCOL_VERSION: u16 = 1; const MIN_PROTOCOL_VERSION: u16 = 1;`
  - `fn negotiate(client: u16) -> Result<u16, ErrorCode>`: accepts `MIN..=PROTOCOL_VERSION`.
  - `enum Request { Hello { protocol: u16, client_version: String }, Pair { token: String, display_name: String }, WhoAmI, ServerStatus, ListApps, ListUsers }` (serde, `tag = "type"`)
  - `enum Response { HelloOk { protocol: u16, agent_version: String, server_id: String }, Paired { user_id: i64, role: Role }, Me(UserInfo), Status(ServerStatus), Apps(Vec<AppSummary>), Users(Vec<UserInfo>), Error { code: ErrorCode, message: String } }`
  - `struct ServerStatus { hostname, os_pretty_name, arch: String, uptime_secs: u64, load_1m: f32, mem_total_bytes, mem_used_bytes, disk_total_bytes, disk_used_bytes: u64, agent_rss_bytes: u64 }`
  - `struct AppSummary { id: i64, name: String, project_id: ProjectId, state: AppState }`, `enum AppState { Live, Building, Degraded, Down }`
  - `struct UserInfo { id: i64, display_name: String, role: Role, key_fingerprint: String }`
  - `enum ErrorCode { UnsupportedProtocol, NotPaired, Forbidden, BadToken, TokenExpired, TooLarge, Malformed, Internal }`
  - `const MAX_FRAME: usize = 1_048_576;`
  - `async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()>` and `async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T, FrameError>`; frame = u32 big-endian length + JSON body.
  - `fn decode_frame_bytes(buf: &[u8]) -> Result<Request, FrameError>` (sync, used by fuzzing)
  - `struct PairingCode { host: String, port: u16, fingerprint: String, token: String }` with `fn encode(&self) -> String` (`"keel1:"` + base64url-no-pad of JSON) and `fn parse(s: &str) -> Result<PairingCode, PairingCodeError>`

- [ ] **Step 1: Write failing tests:**
  - `negotiate_accepts_current_and_rejects_newer`: `negotiate(1) == Ok(1)`, `negotiate(2)` is `Err(UnsupportedProtocol)`, `negotiate(0)` is `Err(UnsupportedProtocol)`.
  - `frame_roundtrip` for each `Request` variant.
  - `frame_rejects_oversize`: a header declaring `MAX_FRAME + 1` returns `FrameError::TooLarge` without allocating the body.
  - `frame_rejects_truncated` and `frame_rejects_bad_json` return `FrameError::Malformed`.
  - `pairing_code_roundtrip`, and `pairing_code_rejects_wrong_prefix` (`"keel2:..."`) and trailing whitespace is trimmed (pasted codes).
- [ ] **Step 2: Run** `cargo test -p keel-proto`. Expected: FAIL.
- [ ] **Step 3: Implement** the types and functions above.
- [ ] **Step 4: Run** tests. Expected: PASS.
- [ ] **Step 5: Add fuzz target** `decode` calling `decode_frame_bytes` and `PairingCode::parse` on arbitrary input; run `cargo +nightly fuzz run decode -- -max_total_time=60`. Expected: no crashes.
- [ ] **Step 6: Commit** `feat(proto): messages, versioning, framing, pairing codes`.

---

### Task 3: Agent config and store

**Files:**
- Create: `crates/keel-agent/Cargo.toml`, `src/main.rs` (stub), `src/config.rs`, `src/store/mod.rs`, `src/store/users.rs`, `src/store/pairing.rs`, `src/store/audit.rs`
- Test: unit tests using `Store::open_in_memory()`

**Interfaces:**
- Consumes: `Role`, `ProjectId`, `UserInfo`, `AppSummary` (Tasks 1–2)
- Produces:
  - `struct AgentConfig { listen: SocketAddr /* default 0.0.0.0:7443 */, data_dir: PathBuf /* /var/lib/keel */ }`, `fn AgentConfig::load(path: &Path) -> Result<AgentConfig>` (missing file → defaults)
  - `struct Store` with `fn open(path: &Path) -> Result<Store>` (WAL, `foreign_keys=ON`, runs migrations) and `fn open_in_memory() -> Result<Store>`
  - Schema (migration 1): `meta(key PK, value)` holding `server_id`; `users(id, display_name, key_fingerprint UNIQUE, role, created_at)`; `projects(id, name UNIQUE)`; `project_members(user_id, project_id, PK both)`; `apps(id, name UNIQUE, project_id, state)`; `pairing_tokens(id, token_hash UNIQUE, role, expires_at, used_at NULL)`; `audit_log(id, at, user_id NULL, action, target, device)`.
  - `fn server_id(&self) -> Result<String>` (creates a random UUID v4 once)
  - `fn find_user_by_fingerprint(&self, fp: &str) -> Result<Option<(UserInfo, Vec<ProjectId>)>>`
  - `fn list_users(&self) -> Result<Vec<UserInfo>>`, `fn list_apps(&self) -> Result<Vec<AppSummary>>`
  - `fn create_pairing_token(&self, token_hash: &[u8; 32], role: Role, expires_at: i64) -> Result<()>`
  - `fn redeem_pairing_token(&self, token_hash: &[u8; 32], fp: &str, display_name: &str, now: i64) -> Result<UserInfo, RedeemError>` — in one transaction: token must exist, be unused, unexpired; marks used; inserts user (or returns `RedeemError::AlreadyPaired` if fingerprint exists). `enum RedeemError { Unknown, Used, Expired, AlreadyPaired }`
  - `fn audit(&self, user_id: Option<i64>, action: &str, target: &str, device: &str) -> Result<()>`

- [ ] **Step 1: Write failing tests:** `migrations_idempotent` (open twice on same file, schema version 1), `server_id_stable`, `redeem_happy_path` (returns Owner user), `redeem_twice_fails_used`, `redeem_expired_fails`, `redeem_same_fingerprint_twice_already_paired` (second token, same key), `audit_row_written`.
- [ ] **Step 2: Run** `cargo test -p keel-agent store`. Expected: FAIL.
- [ ] **Step 3: Implement** with `rusqlite` and a `user_version` pragma for migrations.
- [ ] **Step 4: Run** tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): config and SQLite store`.

---

### Task 4: Agent TLS identity

**Files:**
- Create: `crates/keel-agent/src/tls.rs`
- Test: unit tests in `tls.rs`

**Interfaces:**
- Produces:
  - `fn load_or_create_identity(dir: &Path) -> Result<AgentIdentity>`: reads `agent.key`/`agent.crt`, or creates an ECDSA P-256 self-signed cert (rcgen, CN `keel-agent`, 10-year validity) with key file mode `0600`.
  - `struct AgentIdentity { pub cert_der: Vec<u8>, pub fingerprint: String /* hex SHA-256 of SubjectPublicKeyInfo */ }`
  - `fn spki_fingerprint(cert_der: &[u8]) -> Result<String>` (shared definition; `keel-client` uses the same function, so put it in `keel-proto::pairing` and re-export)
  - `fn server_config(id: &AgentIdentity, key_der: ...) -> Arc<rustls::ServerConfig>` requiring a client certificate but accepting any self-signed one (custom `ClientCertVerifier` that checks the handshake signature only); authorization happens later by fingerprint.
  - `fn peer_fingerprint(conn: &rustls::ServerConnection) -> Option<String>`

- [ ] **Step 1: Write failing tests:** `identity_created_then_reloaded_same_fingerprint`, `key_file_mode_0600`, `fingerprint_matches_known_vector` (fixed DER fixture → known hex).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** Move `spki_fingerprint` into `keel-proto` (parse SPKI with `x509-parser`).
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): TLS identity and client fingerprinting`.

---

### Task 5: `keel-agent init`

**Files:**
- Create: `crates/keel-agent/src/init.rs`; modify `src/main.rs` (clap subcommands `init`, `run`)
- Test: `crates/keel-agent/tests/init.rs`

**Interfaces:**
- Consumes: `AgentConfig`, `Store`, `load_or_create_identity`, `PairingCode`
- Produces:
  - CLI `keel-agent init --host <public host> [--config PATH] [--data-dir PATH]` prints exactly two lines to stdout: `fingerprint=<hex>` and `pairing_code=<keel1:...>`. A new Owner pairing token (32 random bytes, base64url) is created on every run, expiring in 24 hours; the token itself is never stored, only its SHA-256.
  - `fn init(cfg: &AgentConfig, host: &str, now: i64) -> Result<InitOutput>`, `struct InitOutput { fingerprint: String, pairing_code: PairingCode }`

- [ ] **Step 1: Write failing tests:**
  - `init_creates_data_dir_cert_db_and_prints_code`.
  - `init_twice_keeps_same_fingerprint` (Review Focus 2).
  - `init_twice_old_token_still_single_use`: redeem the first token, run init again, the first token stays rejected as `Used`, the new one works.
  - `init_after_owner_exists_issues_owner_token` (repair path: a user who lost their key can re-pair through SSH).
- [ ] **Step 2: Run** `cargo test -p keel-agent --test init`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): init command with pairing code`.

---

### Task 6: Agent server and handlers

**Files:**
- Create: `crates/keel-agent/src/server.rs`, `handlers.rs`, `sysinfo.rs`
- Test: `crates/keel-agent/tests/api.rs` (spawns `run` on `127.0.0.1:0` with a temp data dir; a test client built from rustls with a fresh self-signed client cert)

**Interfaces:**
- Consumes: Tasks 1–5
- Produces:
  - `type Clock = Arc<dyn Fn() -> i64 + Send + Sync>` (Unix seconds; production uses system time, tests pass a fixed or advancing value).
  - `async fn run(cfg: AgentConfig, clock: Clock, shutdown: impl Future<Output = ()>) -> Result<()>` on a tokio current-thread runtime.
  - Limits: max 64 concurrent connections; max 30 new connections per minute per source IP (over the limit: close immediately); TLS handshake and first frame must complete within 10 seconds; frames capped by `MAX_FRAME`.
  - Connection flow: first frame must be `Hello` (else `Error{Malformed}` and close); reply `HelloOk` or `Error{UnsupportedProtocol}` and close. Then:
    - Unknown fingerprint: only `Pair` is accepted; anything else returns `Error{NotPaired, "This device isn't paired with the server yet."}`.
    - `Pair`: SHA-256 the token, `redeem_pairing_token`, map errors to `BadToken` ("That pairing code isn't valid."), `TokenExpired` ("That pairing code has expired. Create a new one."), used → `BadToken`; success → `Paired`.
    - Known user: `WhoAmI` → `Me`; `ServerStatus` needs `ViewStatus` (no project); `ListApps` returns only apps the principal may `ViewStatus` on; `ListUsers` needs `ManageUsers`.
    - Every request handled writes an audit row (`action` = request type, `device` = peer IP).
  - `fn read_status(data_dir: &Path) -> io::Result<ServerStatus>` reading `/proc/meminfo` (`MemTotal - MemAvailable`), `/proc/loadavg`, `/proc/uptime`, `/etc/os-release` `PRETTY_NAME`, `statvfs` on the data dir, `/proc/self/status` `VmRSS`. Parsers are pure functions over `&str` so they test on any OS.

- [ ] **Step 1: Write failing tests:**
  - `hello_then_pair_then_whoami_is_owner`.
  - `unpaired_client_gets_not_paired`.
  - `pair_token_replay_rejected` and `pair_token_expired_rejected` (Review Focus 5; the test's `Clock` jumps 24 h + 1 s past token creation).
  - `newer_protocol_rejected_cleanly`.
  - `first_frame_not_hello_closes`.
  - `oversize_frame_closes_without_crash`.
  - `rate_limit_drops_31st_connection_in_a_minute`.
  - `viewer_cannot_list_users` (insert a Viewer directly through the store).
  - `parse_meminfo`, `parse_loadavg`, `parse_os_release` against fixture strings.
- [ ] **Step 2: Run** `cargo test -p keel-agent --test api`. Expected: FAIL.
- [ ] **Step 3: Implement** `server.rs` (accept, limits, TLS, per-connection task), `handlers.rs` (`fn handle(store: &Store, who: Option<&Principal>, req: Request, peer: IpAddr) -> Response`), `sysinfo.rs`.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): mTLS API with pairing, status and permissions`.

---

### Task 7: Reconcile loop, systemd unit and memory budget

**Files:**
- Create: `crates/keel-agent/src/reconcile.rs`, `crates/keel-agent/dist/keel-agent.service`, `crates/keel-agent/tests/memory.rs`
- Modify: `src/main.rs` (`run` starts the reconcile loop alongside the server)

**Interfaces:**
- Produces:
  - `trait Reconciler { fn name(&self) -> &'static str; fn reconcile(&self, store: &Store) -> Result<Report>; }`, `struct Report { pub changed: Vec<String> }`
  - `fn spawn_reconcile_loop(store: Store, reconcilers: Vec<Box<dyn Reconciler>>, interval: Duration /* 60s */)`: runs once at start, then every interval; a failing reconciler is logged and does not stop the others.
  - `DataDirReconciler`: ensures `data_dir` and `data_dir/tls` exist with mode `0700`, and key files `0600`.
  - Unit: `Type=simple`, `User=keel`, `ExecStart=/usr/local/bin/keel-agent run`, `Restart=always`, `RestartSec=2`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/keel`, `PrivateTmp=yes`, `ProtectHome=yes`, `MemoryMax=64M`.

- [ ] **Step 1: Write failing tests:**
  - `data_dir_reconciler_fixes_modes` (chmod to 0755, reconcile, back to 0700; report lists the change).
  - `failing_reconciler_does_not_block_others`.
  - `idle_rss_under_25mb` in `tests/memory.rs` (Linux only, `#[cfg(target_os = "linux")]`): build in release, start `run`, connect one paired client, wait 10 seconds, read `VmRSS` of the child; assert `< 25 * 1024 * 1024`.
- [ ] **Step 2: Run** `cargo test -p keel-agent reconcile` and `cargo test -p keel-agent --release --test memory`. Expected: FAIL.
- [ ] **Step 3: Implement.** If the memory test fails after implementation, reduce before moving on: current-thread runtime, `rusqlite` with `cache_size` capped, no TLS session cache, jemalloc not used.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): reconcile loop, systemd unit, memory budget test`.

---

### Task 8: Desktop client core

**Files:**
- Create: `crates/keel-client/Cargo.toml`, `src/lib.rs`, `src/identity.rs`, `src/servers.rs`, `src/connection.rs`
- Test: unit tests plus `crates/keel-client/tests/connect.rs` (runs the agent from Task 6 in-process)

**Interfaces:**
- Consumes: `keel-proto` (all), `keel-agent` as a dev-dependency for tests
- Produces:
  - `trait Keychain { fn get(&self, key: &str) -> Result<Option<Vec<u8>>>; fn set(&self, key: &str, value: &[u8]) -> Result<()>; fn delete(&self, key: &str) -> Result<()>; }` with `OsKeychain` (keyring crate, service `"keel"`) and `MemoryKeychain` for tests.
  - `struct DeviceIdentity { cert_der, key_der, fingerprint }`, `fn DeviceIdentity::load_or_create(kc: &dyn Keychain) -> Result<DeviceIdentity>` (ECDSA P-256, keychain key `"device-identity"`).
  - `struct ServerRecord { id: String /* agent server_id */, name: String, host: String, port: u16, fingerprint: String, ssh_saved: bool }`; `struct ServerStore` with `load(dir)`, `upsert`, `remove`, `list`; JSON file `servers.json`, written atomically (temp file + rename).
  - `struct Connection`; `async fn Connection::open(rec: &ServerRecord, id: &DeviceIdentity) -> Result<(Connection, HelloInfo), ConnectError>`; `async fn request(&mut self, req: Request) -> Result<Response, ConnectError>`.
  - `enum ConnectError { Unreachable(String), FingerprintMismatch { expected: String, got: String }, UnsupportedProtocol, NotPaired, Io(String) }` with `Display` in plain language, e.g. FingerprintMismatch: "This server's identity has changed since you added it. If you reinstalled the agent, remove and re-add the server. Otherwise someone may be intercepting the connection."
  - `async fn pair(host, port, fingerprint, token, display_name, id) -> Result<ServerRecord, ConnectError>`

- [ ] **Step 1: Write failing tests:**
  - `identity_persists_in_keychain` (MemoryKeychain, load twice, same fingerprint).
  - `server_store_atomic_roundtrip`.
  - `connect_pinned_ok_then_status`.
  - `connect_with_wrong_pin_refuses` (Review Focus 4): `FingerprintMismatch`, and the record in `ServerStore` is unchanged.
  - `connect_to_closed_port_is_unreachable`.
- [ ] **Step 2: Run** `cargo test -p keel-client`. Expected: FAIL.
- [ ] **Step 3: Implement.** Pinning: a custom `ServerCertVerifier` that accepts only when `spki_fingerprint(cert) == expected`, ignoring hostname and CA.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(client): device identity, server store, pinned mTLS connection`.

---

### Task 9: Onboarding preflight and install plan

**Files:**
- Create: `crates/keel-client/src/onboarding/mod.rs`, `preflight.rs`
- Test: unit tests in `preflight.rs` with fixture command outputs

**Interfaces:**
- Produces:
  - `struct HostFacts { os_id: String, os_version: String, arch: String, has_systemd: bool, free_disk_bytes: u64, ports_in_use: Vec<u16>, ssh_port: u16, is_root: bool, has_sudo: bool, firewall: FirewallKind }`, `enum FirewallKind { Ufw, Firewalld, None }`
  - `fn parse_facts(os_release: &str, uname_m: &str, systemctl_ok: bool, df_out: &str, ss_out: &str, ssh_port: u16, id_u: &str, sudo_ok: bool, fw: FirewallKind) -> HostFacts`
  - `enum Support { Full, BestEffort(String), Unsupported(String) }`, `fn support(f: &HostFacts) -> Support`: Full for ubuntu 22.04/24.04, debian 12/13; BestEffort for almalinux/rocky 9; else Unsupported with the OS name in the message.
  - `struct Finding { severity: Severity /* Blocker | Warning */, message: String }`, `fn preflight(f: &HostFacts, agent_port: u16) -> Vec<Finding>`. Blockers: unsupported OS, arch not `x86_64`/`aarch64`, no systemd, under 1 GiB free disk, not root and no sudo, agent port in use. Warnings: ports 80 or 443 in use ("Port 80 is in use by another program. Websites won't work until it's freed."), best-effort OS.
  - `struct InstallOptions { enable_firewall: bool /* default true */, auto_security_updates: bool /* default true */, disable_ssh_passwords: bool /* default false */, keep_ssh_credentials: bool /* default false */ }`
  - `fn firewall_rules(f: &HostFacts, agent_port: u16) -> Vec<u16>` → `[ssh_port, 80, 443, agent_port]`, deduplicated.

- [ ] **Step 1: Write failing tests:**
  - `ubuntu_2404_full`, `debian_13_full`, `rocky_9_best_effort`, `centos_7_unsupported_message_names_os`.
  - `arm64_reported_as_aarch64_supported`.
  - `port_80_busy_is_warning_not_blocker`.
  - `agent_port_busy_is_blocker`.
  - `firewall_keeps_nonstandard_ssh_port` (Review Focus 1): `ssh_port = 2222` → rules contain 2222 and not 22.
- [ ] **Step 2: Run** `cargo test -p keel-client preflight`. Expected: FAIL.
- [ ] **Step 3: Implement** as pure functions.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(client): onboarding preflight`.

---

### Task 10: Onboarding over SSH

**Files:**
- Create: `crates/keel-client/src/onboarding/ssh.rs`, `install.rs`, `artifact.rs`; modify `onboarding/mod.rs`
- Test: `crates/keel-client/tests/onboarding.rs` (ignored by default; runs in CI against a systemd container with sshd, see Task 14)

**Interfaces:**
- Consumes: Tasks 5, 8, 9
- Produces:
  - `enum SshAuth { GeneratedKey, PrivateKey { pem: String, passphrase: Option<String> }, Password(String) }`
  - `fn generate_ssh_keypair() -> (String /* private OpenSSH */, String /* public line "ssh-ed25519 ... keel@<device>" */)`
  - `struct SshTarget { host: String, port: u16, user: String, auth: SshAuth }`
  - `fn verify_agent_artifact(bin: &[u8], sig: &[u8; 64], pubkey: &[u8; 32]) -> Result<()>` (Ed25519). Release public key embedded at build time from `KEEL_RELEASE_PUBKEY` env (hex); debug builds fall back to a committed dev key in `crates/keel-client/dev-release.pub`.
  - `enum OnboardingEvent { Connecting, Checking, Findings(Vec<Finding>), Installing(&'static str), Pairing, Done(ServerRecord), Failed(String) }`
  - `async fn run_onboarding(target: SshTarget, name: String, opts: InstallOptions, agent_bin: &[u8], agent_sig: &[u8; 64], id: &DeviceIdentity, events: mpsc::Sender<OnboardingEvent>) -> Result<ServerRecord>`
  - Steps, in order, each idempotent:
    1. Connect, gather facts, `preflight`; any Blocker → `Failed` with the message and **no changes made**.
    2. Verify artifact signature locally before upload.
    3. Upload to `/usr/local/bin/keel-agent.new`, `chmod 755`, rename over `/usr/local/bin/keel-agent`.
    4. Create `keel` system user if missing; write unit file; `systemctl daemon-reload`.
    5. Run `keel-agent init --host <host>` as `keel`; parse `fingerprint=` and `pairing_code=`.
    6. `systemctl enable --now keel-agent` (or `restart` if already running).
    7. Firewall when `enable_firewall`: Ufw → `ufw allow <port>/tcp` for each rule then `ufw --force enable`; Firewalld → `firewall-cmd --permanent --add-port`, reload; None on Ubuntu/Debian → install ufw and proceed.
    8. When chosen: install `unattended-upgrades` (Debian family) or `dnf-automatic` (RHEL family); set `PasswordAuthentication no` in an `sshd_config.d/50-keel.conf` drop-in **only if** the current session authenticated with a key, then reload sshd.
    9. Pair over TLS with the fingerprint obtained over SSH; store the record; save SSH credentials to the keychain only if `keep_ssh_credentials`.
  - Every command runs through one helper that prefixes `sudo -n` when not root; a non-zero exit becomes `Failed("<step>: <plain explanation>")` with stderr attached for the log.

- [ ] **Step 1: Write failing tests:**
  - unit: `artifact_signature_valid`, `artifact_signature_tampered_rejected`.
  - integration (`#[ignore]`): `onboard_fresh_server`, `onboard_twice_is_idempotent` (Review Focus 2: one Owner per device fingerprint, same agent fingerprint, second run pairs successfully because `init` issued a fresh token), `onboard_blocked_makes_no_changes` (agent port pre-occupied by `nc -l`; assert `/usr/local/bin/keel-agent` does not exist), `onboard_ssh_2222_firewall_keeps_access` (reconnect over SSH after onboarding succeeds).
- [ ] **Step 2: Run** unit tests. Expected: FAIL.
- [ ] **Step 3: Implement** `ssh.rs` (russh client, `exec(cmd) -> (exit, stdout, stderr)`, `upload(path, bytes)` via SFTP), `artifact.rs`, `install.rs`, `run_onboarding`.
- [ ] **Step 4: Run** unit tests. Expected: PASS. Integration tests run in Task 14.
- [ ] **Step 5: Commit** `feat(client): agent install and pairing over SSH`.

---

### Task 11: Tauri shell and status polling

**Files:**
- Create: `apps/desktop/` (Tauri 2 + SvelteKit scaffold, static adapter; Rust package name `keel-desktop`), `apps/desktop/src-tauri/src/main.rs`, `commands.rs`, `poller.rs`
- Test: unit tests in `poller.rs`

**Interfaces:**
- Consumes: `keel-client` (Tasks 8–10)
- Produces (Tauri commands, all `async`, errors as plain-language strings):
  - `list_servers() -> Vec<ServerView>`
  - `server_status(id: String) -> ServerView`
  - `list_apps() -> Vec<AppView>` (all servers merged)
  - `generate_ssh_key() -> String` (public line only; private key held in memory until onboarding finishes)
  - `start_onboarding(req: OnboardRequest) -> ()` emitting `onboarding://event` with `OnboardingEvent` payloads
  - `pair_with_code(code: String, name: String) -> ServerView` (headless install path)
  - `remove_server(id: String) -> ()`
  - `struct ServerView { id, name, host, reachability: Reachability, last_seen: Option<i64>, status: Option<ServerStatus> }`, `enum Reachability { Online, Unreachable, Untrusted }` (Untrusted = fingerprint mismatch)
  - `struct AppView { server_id, server_name, app: AppSummary }`
  - Poller: one task per server, `ServerStatus` + `ListApps` every 5 seconds on a kept-open connection; two consecutive failures → `Unreachable`; reconnect attempts every 5 seconds; mismatch → `Untrusted` and stop retrying. Emits `servers://changed` on any change. Poller runs only while the window is open.

- [ ] **Step 1: Write failing tests** for the poller state machine as a pure function `fn next(state: PollState, outcome: PollOutcome, now: i64) -> PollState`:
  - `one_failure_stays_online`, `two_failures_unreachable_keeps_last_seen`.
  - `recovers_after_restart` (Review Focus 3): Online → fail → fail → Unreachable → success → Online.
  - `mismatch_is_untrusted_and_terminal`.
- [ ] **Step 2: Run** `cargo test -p keel-desktop poller`. Expected: FAIL.
- [ ] **Step 3: Implement** `poller.rs` and the commands.
- [ ] **Step 4: Run.** Expected: PASS. Also run `npm run tauri build -- --debug` once; expected: build succeeds.
- [ ] **Step 5: Commit** `feat(desktop): Tauri shell, commands, reachability polling`.

---

### Task 12: Fleet board, drawer and server page

**Files:**
- Create: `apps/desktop/src/lib/tokens.css`, `src/lib/status.ts`, `src/lib/components/StatusBadge.svelte`, `FleetRow.svelte`, `Drawer.svelte`, `src/routes/+layout.svelte`, `src/routes/+page.svelte`, `src/routes/servers/[id]/+page.svelte`
- Test: `apps/desktop/src/lib/status.test.ts`, `src/lib/components/FleetRow.test.ts`

**Interfaces:**
- Consumes: Tauri commands from Task 11
- Produces:
  - `type RowState = 'down' | 'unreachable' | 'building' | 'degraded' | 'live'`
  - `function rowState(app: AppView, server: ServerView): RowState` — any non-`Online` server → `'unreachable'` for all its apps.
  - `function sortRows(rows): rows` ordered `down, unreachable, building, degraded, live`, then by app name.
  - `const STATE_LABEL: Record<RowState, string>`: `Down`, `Server unreachable`, `Building`, `Degraded`, `Live`. `STATE_ICON` uses Tabler outline icons.
  - Tokens: CSS custom properties for every row of spec §10, light and dark via `prefers-color-scheme`. Fonts: Instrument Sans (body, `font-variant-numeric: tabular-nums` on metric elements), JetBrains Mono only for fingerprints and future logs.

- [ ] **Step 1: Write failing tests:**
  - `sortRows_problems_first`.
  - `unreachable_server_marks_apps_unreachable_not_down`.
  - `FleetRow renders label text and icon, not only color` (query by text `Server unreachable`).
- [ ] **Step 2: Run** `npm test`. Expected: FAIL.
- [ ] **Step 3: Implement:**
  - Fleet board: summary line ("4 apps on 2 servers · 1 down" style counts), compact bordered rows (~32 px): status, app name, server name, uptime strip placeholder (no data until milestone 4; render nothing rather than fake bars).
  - Empty state when there are no servers: headline "Add your first server", one line explaining what happens, button "Add server". With servers but no apps: "Your servers are ready. Deploying apps arrives in the next version." plus a server list.
  - Drawer on row select (right side, list stays visible). For this milestone it shows app name, server, state.
  - Server page: name, host, OS, reachability with last seen, CPU load, memory and disk bars with numbers, agent memory, users list (if allowed), "Remove server" (confirmation dialog naming the server).
- [ ] **Step 4: Run** `npm test`. Expected: PASS. Then launch `npm run tauri dev` with a local agent and check light and dark themes, keyboard focus visible, and a narrow 900 px window.
- [ ] **Step 5: Commit** `feat(desktop): fleet board, drawer, server page`.

---

### Task 13: Add-server wizard and command palette

**Files:**
- Create: `apps/desktop/src/lib/components/AddServerWizard.svelte`, `CommandPalette.svelte`, `src/lib/commands.ts`
- Test: `src/lib/commands.test.ts`, `AddServerWizard.test.ts`

**Interfaces:**
- Consumes: `generate_ssh_key`, `start_onboarding`, `pair_with_code`, `onboarding://event`
- Produces:
  - Wizard steps: (1) Connection: name, host, SSH port (default 22), user (default `root`), auth choice with "Generate a key for Keel (recommended)" first, showing the copyable `authorized_keys` line; (2) Options: the four `InstallOptions` with defaults from Task 9 and one-line explanations; (3) Progress: live list of steps from events, findings shown before installing, warnings require "Continue anyway"; (4) Done: link to the server page. A second entry point "I have a pairing code" calls `pair_with_code`.
  - `function filterCommands(query: string, ctx): Command[]` — fuzzy match over: "Add server", "Go to <server>", "Go to fleet board". Opened with Ctrl+K (Cmd+K on macOS) from anywhere; Esc closes; arrow keys and Enter select.

- [ ] **Step 1: Write failing tests:**
  - `filterCommands_matches_server_by_partial_name`.
  - `wizard_blocks_install_on_blocker_finding` (mock events: Findings with a Blocker → no "Continue" button, message shown).
  - `wizard_shows_plain_error_on_failed_event`.
- [ ] **Step 2: Run** `npm test`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(desktop): add-server wizard and command palette`.

---

### Task 14: Headless install script and CI

**Files:**
- Create: `scripts/install.sh`, `.github/workflows/ci.yml`, `ci/systemd-sshd/Dockerfile` (one per distro via build arg)
- Test: the workflow itself

**Interfaces:**
- Consumes: everything above
- Produces:
  - `install.sh`: POSIX sh; detects arch; downloads `keel-agent-<arch>` and `keel-agent-<arch>.sha256` from `${KEEL_DOWNLOAD_BASE:-https://github.com/<owner>/keel/releases/latest/download}`; verifies the checksum (abort with a plain message on mismatch); performs Task 10 steps 3, 4 and 6 locally; runs `keel-agent init --host "$(hostname -f)"` (overridable with `KEEL_HOST`); prints "Paste this pairing code into the Keel app:" and the code. Re-running is safe.
  - CI jobs:
    1. `lint-test`: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`, `npm ci && npm test` in `apps/desktop`.
    2. `memory`: `cargo test -p keel-agent --release --test memory`.
    3. `fuzz-smoke`: 60 seconds of the `decode` target.
    4. `onboarding-matrix`: for `ubuntu:22.04, ubuntu:24.04, debian:12, debian:13`, start a privileged systemd + sshd container, run `cargo test -p keel-client --test onboarding -- --ignored`, then `systemctl restart keel-agent` inside the container and assert the client reconnects and gets `ServerStatus` within 15 seconds (reboot-recovery stand-in).
    5. `build-agent`: musl release builds for both arches (cross), signed with the release key from CI secrets when on a tag, dev key otherwise.
    6. `build-desktop`: Tauri builds for Windows, macOS and Linux (unsigned in this milestone).

- [ ] **Step 1: Write** `install.sh` and run `shellcheck scripts/install.sh`. Expected: no warnings.
- [ ] **Step 2: Test** `install.sh` in an `ubuntu:24.04` systemd container with `KEEL_DOWNLOAD_BASE` pointing at a local HTTP server serving a CI-built binary; expected: prints a `keel1:` code, and running it again prints a new code with the same fingerprint line. Also serve a wrong checksum and expect a non-zero exit with "The download didn't match its checksum. Nothing was installed."
- [ ] **Step 3: Write** `ci.yml` and the container Dockerfile.
- [ ] **Step 4: Push to a branch and run CI.** Expected: all six jobs pass.
- [ ] **Step 5: Commit** `ci: install script, distro matrix, memory budget, fuzz smoke`.

---

## Spec coverage notes

- Covered here: §2 components and stack, §3 onboarding (except Caddy install), §9 identity, roles, permission checks, audit writes, fixed API, mTLS on one port with rate limiting, §10 fleet board, drawer, server page, Ctrl+K, visual tokens, §12 reconcile skeleton, §13 error handling for onboarding and reachability, §14 unit, distro integration, memory budget, fuzzing, desktop component tests.
- Deferred by the spec's delivery plan: deploys (M2), Caddy and domains (M3), monitoring and alerts (M4), databases and backups (M5), invites and audit viewer (M6).
- Not assigned to any milestone in the spec: agent self-update and desktop auto-update (§11). Recommend adding them as their own milestone before public release.

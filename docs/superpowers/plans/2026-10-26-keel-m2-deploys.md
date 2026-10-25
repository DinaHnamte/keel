# Keel milestone 2: deploys — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A user can create an app from a Git repo in the desktop app, press **Deploy**, and have a Node, static, Laravel or Rust app built on their computer, uploaded, started on the server with zero downtime, and reachable over HTTPS, with one-click rollback.

**Architecture:** The desktop app fetches the repo with the user's own Git, detects the stack, builds locally and uploads only changed files over the existing pinned mTLS connection. The unprivileged agent records desired state and drives each deploy through persisted steps. A small root **helper** process (same binary, separate systemd service) performs the few privileged operations through a fixed, validated set of operations on a Unix socket. Caddy serves every app. Each release runs as its own systemd template instance, so the old and new releases can run side by side during the switch.

**Tech Stack:** Rust (agent, helper, client), `toml` + serde for `keel.toml`, `chacha20poly1305` for secrets at rest, `ureq` with rustls for downloads, Caddy 2 via its admin API on a Unix socket, systemd template units, Tauri 2 + Svelte 5 for the UI.

**Spec:** `docs/superpowers/specs/2026-10-25-keel-design.md` (§4 Running apps and §5 Builds and deploys are the core; §6 for the proxy adapter; §9 for permissions, audit and secrets; §12 reconcile; §13 errors).

**Base branch:** `oracle-linux-fixes` (it carries the Oracle Linux and dnf fixes that onboarding changes in Task 11 build on). Work on branch `m2-deploys`.

## Decisions this plan makes (review these)

1. **Root helper.** The M1 agent runs as the unprivileged `keel` user with `MemoryMax=64M` (any child it spawns inherits that cap). Deploys need root for a few things: creating app users, writing systemd units, starting app services, running dependency installs under their own memory cap, and installing Caddy. A separate `keel-helper` service runs as root and accepts only the operations in Task 4. Each operation has typed, validated arguments. There is no "run this command as root" operation, and the helper renders unit files itself from structured input.
2. **Where builds happen.** Compiling and bundling run on the user's computer: `npm run build`, Vite asset builds and `cargo zigbuild`. Production dependencies for interpreted stacks are installed on the server, in the release directory, as the app's own user under a memory cap: `npm ci --omit=dev` (or the pnpm/yarn equivalent) and `composer install --no-dev`. This is the only way native Node modules and PHP extensions match the server's OS. Rust binaries are fully built locally as static musl binaries.
3. **Reaching an app before custom domains (M3).** Every app gets `https://<app>.<server-ip>.sslip.io` automatically. sslip.io resolves that name to the IP, so Caddy can get a Let's Encrypt certificate without any DNS setup. M3 adds custom domains through the same proxy adapter.
4. **Health checks go through Caddy.** Each starting release gets a private route on a localhost-only Caddy listener. The agent checks the release exactly as visitors will reach it, which works the same for Node, PHP-FPM, Rust and static sites.
5. **Out of scope for M2:** push-to-deploy webhooks, server-side builds and build delegation, Dockerfile/Podman apps, custom domains, database provisioning, project management UI (apps go into one project named `default`), and agent self-update. Instead, **Update agent** re-runs onboarding with the saved SSH credentials.

## Global Constraints

- Spec §1: agent idle RSS stays under 25 MB (enforced by `tests/memory.rs`). The helper's idle RSS must stay under 10 MB (new test in Task 15).
- Spec §2/M1: agent and helper ship as one static musl binary `keel-agent` for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.
- Spec §9: the agent API exposes only fixed, typed operations; no arbitrary command execution. User-supplied build and start commands run only as the app's own Linux user, never as `keel` or root.
- Spec §4 paths: `/srv/apps/<app>/releases/<n>/`, `/srv/apps/<app>/shared/`, runtimes in `/opt/keel/runtimes/`.
- Spec §5: health check must return HTTP 200 on the health path (default `/`) within 60 seconds; keep the last 5 releases per app; refuse a deploy that would fill the disk; a failed deploy leaves the previous release live.
- Spec §9: Developer can deploy, roll back, view logs and edit env vars on assigned projects; Viewer sees status and logs, secrets masked; every mutating action writes an audit row; secrets are encrypted at rest.
- App names match `^[a-z][a-z0-9-]{1,30}$` (they become Linux user names `keel-app-<name>`, unit names and hostnames). Both agent and helper validate them.
- Supported servers: Ubuntu 22.04/24.04, Debian 12/13 (full); AlmaLinux, Rocky Linux and Oracle Linux 9 (best-effort).
- UI copy: sentence case, plain language, errors say what happened and what to do next; color only for state, every state has icon + text; tokens from spec §10.
- Commit trailers per the session attribution reminder.
- Local commands: `cargo` works directly on the Mac; in the cloud container prefix `RUSTUP_TOOLCHAIN=stable-x86_64-unknown-linux-gnu`.

## Review Focus

1. **The app ignores `PORT` or listens on the wrong address.** The health check must fail within 60 s with "The app didn't answer on port <p>. Make sure it listens on the PORT environment variable.", and the previous release stays live. Test in Task 9.
2. **Dependency install runs out of memory on a small server** (a 500 MB Oracle instance with `npm ci`). The prepare step is capped, fails with "Installing dependencies ran out of memory (limit <n> MB). Free memory on the server or build a lighter release.", and the live release is untouched. Test in Task 9.
3. **The agent restarts mid-deploy.** On startup the deploy is marked failed ("The agent restarted during this deploy. Deploy again."), the half-started instance is stopped, and the previous release still serves. Test in Task 9.
4. **Hostile names and paths** (`../x`, `A`, `a;rm`, 40-character names, staging paths outside the staging root, symlinks in uploads). Rejected by both agent and helper with no filesystem effect. Tests in Tasks 4, 5 and 8.
5. **Two deploys of the same app at once** (two teammates, or a double click). The second is refused with "A deploy of <app> is already running." Test in Task 9.

---

## File structure

```
crates/keel-proto/src/
  apps.rs            AppSpec, Stack, Runtime pins, DeploySummary, DeployStep, Release, EnvVar types
  keeltoml.rs        keel.toml schema + parse
  detect.rs          stack detection over a FileTree trait (pure)
  messages.rs        new Request/Response variants (modify)
  version.rs         PROTOCOL_VERSION = 2 (modify)
crates/keel-agent/src/
  helper/mod.rs      HelperOp, HelperReply, validation, line protocol
  helper/server.rs   root service: Unix socket, SO_PEERCRED check, dispatch
  helper/ops.rs      op implementations over a System trait
  helper/unit.rs     app unit file rendering
  helper/client.rs   HelperClient used by the agent
  runtimes.rs        runtime catalog + verified downloader
  runtimes.toml      pinned URLs and sha256s (embedded)
  proxy/mod.rs       Proxy trait
  proxy/caddy.rs     Caddy admin-API implementation
  uploads.rs         content-addressed store, staging, manifests
  deploy/mod.rs      deploy engine (state machine)
  deploy/steps.rs    step implementations over Helper/Proxy/Runtimes traits
  secrets.rs         secret key + encrypt/decrypt
  store/apps.rs      app/release/deploy/instance/env queries
  handlers.rs        new request handling (modify; split app handlers into handlers_apps.rs)
  reconcile.rs       AppsReconciler (modify)
  dist/keel-helper.service
crates/keel-client/src/
  build/mod.rs       local build runner (fetch, detect, build, artifact)
  build/stacks.rs    per-stack build commands
  upload.rs          manifest + changed-files upload
  deploy.rs          run_deploy orchestration + DeployEvent
  onboarding/*       helper install, dirs, groups (modify); update_agent()
apps/desktop/
  src-tauri/src/apps.rs                 app/deploy Tauri commands
  src/lib/components/CreateAppDialog.svelte
  src/lib/components/AppDrawer.svelte   tabs: overview, deploys, environment, logs
  src/lib/components/DeployLog.svelte
  src/lib/apps.svelte.ts                app/deploy state
```

---

### Task 1: Protocol for apps, deploys and env vars

**Files:**
- Create: `crates/keel-proto/src/apps.rs`
- Modify: `crates/keel-proto/src/messages.rs`, `crates/keel-proto/src/version.rs`, `crates/keel-proto/src/lib.rs`
- Test: unit tests in `apps.rs` and `codec.rs`

**Interfaces:**
- Produces:
  - `pub fn valid_app_name(s: &str) -> bool` (regex from Global Constraints, implemented without the regex crate)
  - `enum Stack { Node, Static, Laravel, Rust }` (serde snake_case)
  - `enum PackageManager { Npm, Pnpm, Yarn }`
  - `struct AppSpec { name: String, project: String /* default "default" */, repo_url: String, branch: String, stack: Stack, node_version: Option<String>, php_version: Option<String>, package_manager: Option<PackageManager>, build_command: Option<String>, output_dir: Option<String>, start_command: Option<String>, release_command: Option<String>, health_path: String /* "/" */, memory_mb: u32 /* 256 */, rust_bin: Option<String> }`
  - `enum DeployStep { Receiving, Preparing, Starting, HealthChecking, Switching, Draining, Live, Failed }` (snake_case)
  - `struct DeploySummary { id: i64, app: String, release: u32, step: DeployStep, started_at: i64, finished_at: Option<i64>, commit: Option<String>, error: Option<String>, by: String }`
  - `struct ReleaseInfo { number: u32, commit: Option<String>, created_at: i64, live: bool, size_bytes: u64 }`
  - `struct AppDetail { spec: AppSpec, state: AppState, url: String, live_release: Option<u32>, releases: Vec<ReleaseInfo> }`
  - `struct FileEntry { path: String, mode: u32, sha256: String, size: u64 }`
  - `struct EnvVar { key: String, value: Option<String> /* None = masked */ }`
  - New `Request` variants: `CreateApp(AppSpec)`, `UpdateApp(AppSpec)`, `DeleteApp { app }`, `GetApp { app }`, `BeginUpload { app, commit: Option<String>, files: Vec<FileEntry> }`, `UploadChunk { upload_id: String, sha256: String, offset: u64, data_b64: String }`, `FinishUpload { upload_id }`, `GetDeploy { deploy_id, log_from: u32 }`, `ListDeploys { app, limit: u32 }`, `Rollback { app, release: u32 }`, `Restart { app }`, `GetEnv { app }`, `SetEnv { app, vars: Vec<(String, Option<String>)> /* None = delete */ }`, `AppLogs { app, lines: u32 }`
  - New `Response` variants: `App(AppDetail)`, `UploadStarted { upload_id: String, missing: Vec<String> }`, `DeployStarted { deploy_id: i64 }`, `Deploy { summary: DeploySummary, log: Vec<String>, log_next: u32 }`, `Deploys(Vec<DeploySummary>)`, `Env(Vec<EnvVar>)`, `Logs(Vec<String>)`, `Done`
  - New `ErrorCode` variants: `NotFound`, `Conflict`, `Invalid`
  - `PROTOCOL_VERSION = 2`, `MIN_PROTOCOL_VERSION = 1` (an M1 desktop can still connect; it just never sends the new requests).

- [ ] **Step 1: Write failing tests:**
  - `app_name_rules`: accepts `"api"`, `"my-app-2"`; rejects `""`, `"a"`, `"A"`, `"1app"`, `"a_b"`, `"../x"`, `"a;rm"`, a 32-character name.
  - `app_spec_defaults_roundtrip`: deserializing `{"name":"api","repo_url":"…","branch":"main","stack":"node"}` fills `project="default"`, `health_path="/"`, `memory_mb=256`.
  - `every_new_request_and_response_roundtrips` through `write_frame`/`read_frame`.
  - `upload_chunk_fits_frame`: a `UploadChunk` carrying 700 000 raw bytes base64-encoded stays under `MAX_FRAME`.
  - `negotiate(1) == Ok(1)` and `negotiate(2) == Ok(2)`.
- [ ] **Step 2: Run** `cargo test -p keel-proto`. Expected: FAIL (types missing).
- [ ] **Step 3: Implement** the types above. Keep `messages.rs` for the enums and put the payload structs in `apps.rs`.
- [ ] **Step 4: Run.** Expected: PASS. Then run `cargo build --workspace`; fix every exhaustive `match` on `Request` in the agent (`handlers.rs` `request_name`, dispatch) by returning `Error{Invalid, "This agent doesn't support that yet."}` for the new variants until Task 10.
- [ ] **Step 5: Commit** `feat(proto): app, deploy and env messages (protocol 2)`.

---

### Task 2: `keel.toml` and stack detection

**Files:**
- Create: `crates/keel-proto/src/keeltoml.rs`, `crates/keel-proto/src/detect.rs`
- Test: unit tests in both files

**Interfaces:**
- Consumes: `AppSpec`, `Stack`, `PackageManager` (Task 1)
- Produces:
  - `trait FileTree { fn exists(&self, path: &str) -> bool; fn read(&self, path: &str) -> Option<String>; }` plus `struct MemTree(BTreeMap<String,String>)` for tests and `struct DirTree(PathBuf)` (reads a real directory, rejects `..` in paths).
  - `struct KeelToml { stack: Option<Stack>, build: Option<String>, output: Option<String>, start: Option<String>, release: Option<String>, health: Option<String>, memory: Option<String> /* "256M", "1G" */, node: Option<String>, php: Option<String>, bin: Option<String> }` parsed from:
    ```toml
    stack = "node"            # node | static | laravel | rust
    node = "22"               # or php = "8.3"
    [build]
    command = "npm run build"
    output = "dist"           # static sites only
    [run]
    command = "npm start"
    release = "php artisan migrate --force"
    health = "/healthz"
    memory = "512M"
    bin = "server"            # rust: which binary
    ```
  - `fn parse_keel_toml(s: &str) -> Result<KeelToml, String>` (errors are plain sentences naming the field).
  - `fn parse_memory(s: &str) -> Result<u32 /* MB */, String>` accepting `256M`, `1G`, `512` (MB); range 64–8192.
  - `struct Detected { spec: AppSpec /* name/repo/branch empty, filled by caller */, notes: Vec<String> }` and `fn detect(tree: &dyn FileTree) -> Result<Detected, String>`.
  - Detection rules, in order: `keel.toml` `stack` wins. Otherwise `composer.json` requiring `laravel/framework` → Laravel. `Cargo.toml` → Rust. `package.json` → Node, unless it has no `start` script and has a `build` script and no server dependency (`express`, `fastify`, `koa`, `@nestjs/core`, `next`, `nuxt`, `@sveltejs/adapter-node`), in which case Static with `output_dir` from `keel.toml`, else the first of `dist`, `build`, `out` named in the build script, else `dist`. A root `index.html` with no `package.json` → Static, `output_dir="."`. Anything else → `Err("Keel couldn't tell what kind of app this is. Add a keel.toml with a stack = line.")`.
  - Defaults:
    - Node: `package_manager` from the lockfile (`pnpm-lock.yaml` → Pnpm, `yarn.lock` → Yarn, else Npm); `build_command` = `<pm> run build` if a `build` script exists; `start_command` = `<pm> start` if a `start` script exists, else `node <main or index.js>`; `node_version` from `engines.node`'s major or `"22"`.
    - Laravel: `php_version` from `require.php`'s minimum major.minor or `"8.3"`; `build_command` = `npm run build` if `package.json` has a build script; `start_command` none (PHP-FPM).
    - Rust: `rust_bin` from `[[bin]]` name or `package.name`; `start_command` = `./<rust_bin>`.
    - Static: no start command.
    - Laravel adds this note to `notes`: "Laravel needs APP_KEY. Add it under Environment before the first deploy (php artisan key:generate --show prints one)."

- [ ] **Step 1: Write failing tests:** `keeltoml_full_example_parses`, `keeltoml_unknown_stack_names_field` (`stack = "go"` → error mentions `stack`), `memory_parse_bounds` (`"32M"` err, `"1G"` = 1024), `detect_express_is_node_with_npm_start`, `detect_next_is_node`, `detect_vite_spa_is_static_dist`, `detect_plain_html_is_static_root`, `detect_laravel_with_vite_build` (also asserts the APP_KEY note), `detect_rust_bin_name` (and `start_command == "./<bin>"`), `detect_pnpm_and_yarn_lockfiles`, `detect_keel_toml_overrides`, `detect_unknown_errors_with_hint`, `dirtree_rejects_parent_paths`.
- [ ] **Step 2: Run** `cargo test -p keel-proto detect keeltoml`. Expected: FAIL.
- [ ] **Step 3: Implement** with `toml` and `serde_json` (both via workspace deps).
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(proto): keel.toml and stack detection`.

---

### Task 3: Store migration 2 and secrets at rest

**Files:**
- Create: `crates/keel-agent/src/store/apps.rs`, `crates/keel-agent/src/secrets.rs`
- Modify: `crates/keel-agent/src/store/mod.rs` (migration 2), `crates/keel-agent/src/init.rs` (create secret key), `crates/keel-agent/src/reconcile.rs` (`DataDirReconciler` checks `secret.key` mode 0600)
- Test: unit tests in `store/apps.rs`, `secrets.rs`

**Interfaces:**
- Produces:
  - Migration 2 (adds; never alters M1 tables destructively):
    - `ALTER TABLE apps ADD COLUMN spec TEXT` (JSON `AppSpec`), `ADD COLUMN live_release INTEGER`
    - `releases(app_id, number, commit, created_at, size_bytes, PRIMARY KEY(app_id, number))`
    - `deploys(id, app_id, release, step, started_at, finished_at, commit, error, by_user INTEGER)`
    - `deploy_log(deploy_id, seq, line, PRIMARY KEY(deploy_id, seq))`, capped at 2 000 lines per deploy (older lines dropped)
    - `instances(app_id, release, port, PRIMARY KEY(app_id, release))`, `UNIQUE(port)`
    - `env_vars(app_id, key, nonce BLOB, ciphertext BLOB, PRIMARY KEY(app_id, key))`
  - `Store` methods: `create_app(&AppSpec) -> Result<i64>` (creates project `default` if missing; `Conflict` on duplicate name), `update_app(&AppSpec)`, `delete_app(name)`, `get_app(name) -> Result<Option<(i64, AppSpec, AppState, Option<u32>)>>`, `set_app_state(name, AppState)`, `set_live_release(name, Option<u32>)`, `next_release_number(name) -> u32`, `add_release(name, ReleaseInfo)`, `list_releases(name) -> Vec<ReleaseInfo>`, `remove_release(name, n)`, `begin_deploy(name, release, commit, by_user) -> Result<i64, DeployConflict>` (refuses if another deploy of the app is not in `Live`/`Failed`), `set_deploy_step(id, DeployStep)`, `fail_deploy(id, msg)`, `append_deploy_log(id, line)`, `get_deploy(id, log_from) -> (DeploySummary, Vec<String>, u32)`, `list_deploys(name, limit)`, `unfinished_deploys() -> Vec<DeploySummary>`, `allocate_port(name, release) -> u16` (lowest free in 20000–29999), `release_port(name, release)`, `instance_port(name, release) -> Option<u16>`, `set_env(name, key, value: Option<&str>, &SecretBox)`, `get_env(name, &SecretBox, reveal: bool) -> Vec<EnvVar>`, `env_for_unit(name, &SecretBox) -> Vec<(String,String)>`.
  - `struct SecretBox` in `secrets.rs`: `fn load_or_create(path: &Path) -> Result<SecretBox>` (32 random bytes, file mode 0600, atomic write), `fn seal(&self, plaintext: &[u8]) -> (nonce [u8;24], Vec<u8>)`, `fn open(&self, nonce, ct) -> Result<Vec<u8>>` (XChaCha20-Poly1305). `SecretBox` has a redacting `Debug`.
  - Env keys must match `^[A-Z_][A-Z0-9_]{0,127}$`; values at most 32 KiB and with no NUL or newline (they go into a systemd `EnvironmentFile`). Violations → `Invalid` with a plain message naming the key.

- [ ] **Step 1: Write failing tests:** `migration_2_upgrades_m1_db` (open a DB created by the M1 schema with one app row, migrate, row still there, `user_version == 2`), `create_app_conflict_on_duplicate`, `second_deploy_refused_while_first_running`, `deploy_log_caps_at_2000`, `ports_lowest_free_and_unique`, `env_roundtrip_encrypted` (raw `ciphertext` column never contains the plaintext), `env_masked_unless_reveal`, `env_key_and_value_validation`, `secret_key_file_0600_and_stable`, `secret_box_rejects_tampered_ciphertext`.
- [ ] **Step 2: Run** `cargo test -p keel-agent store secrets`. Expected: FAIL.
- [ ] **Step 3: Implement.** `init` creates `<data_dir>/secret.key` via `SecretBox::load_or_create`.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): app, release, deploy and env storage`.

---

### Task 4: Root helper — protocol, socket and app-unit operations

**Files:**
- Create: `crates/keel-agent/src/helper/{mod.rs,server.rs,ops.rs,unit.rs,client.rs}`, `crates/keel-agent/dist/keel-helper.service`
- Modify: `crates/keel-agent/src/main.rs` (subcommand `helper`), `crates/keel-agent/src/lib.rs`
- Test: unit tests in each file; `crates/keel-agent/tests/helper.rs`

**Interfaces:**
- Produces:
  - Socket `/run/keel/helper.sock`, mode 0660, owner `root:keel`, directory `/run/keel` mode 0750 `root:keel` (from the unit's `RuntimeDirectory=keel`, `RuntimeDirectoryMode=0750`, with `Group=keel` only for the directory; the service itself runs as root).
  - Framing: one JSON `HelperOp` per line in, one JSON `HelperReply` per line out; a line is at most 64 KiB; one op per connection.
  - Peer check: `SO_PEERCRED` uid must equal the `keel` user's uid (looked up at start). Anything else → close without reply, and log a warning.
  - `enum HelperOp` (serde tag `op`, snake_case). This task implements:
    - `EnsureAppUser { app }` → `useradd --system --no-create-home --home-dir /srv/apps/<app> --shell /usr/sbin/nologin keel-app-<app>` if missing. Create `/srv/apps/<app>` 0750 `keel-app-<app>:keel-app-<app>` and `/srv/apps/<app>/shared` 0750 owned the same. Grant the caddy user read access with `setfacl -m u:caddy:rx` on `/srv/apps/<app>`.
    - `WriteAppUnit { app, spec: AppUnitSpec }` → render with `unit::render_app_unit`, write `/etc/systemd/system/keel-app-<app>@.service` atomically, `systemctl daemon-reload`.
    - `Systemctl { app, release: u32, action: UnitAction /* Start|Stop|Restart */ }` → only `keel-app-<app>@<release>.service`.
    - `ReadLogs { app, lines: u32 /* ≤ 1000 */ }` → `journalctl -u 'keel-app-<app>@*' -n <lines> --no-pager -o short-iso`.
    - `RemoveApp { app }` → stop and disable all instances, remove the unit file, `/srv/apps/<app>` and the user.
  - `struct AppUnitSpec { kind: UnitKind /* Process | PhpFpm */, start_command: Option<String>, runtime_bin_dirs: Vec<String> /* absolute paths under /opt/keel/runtimes */, memory_mb: u32 }`.
  - `HelperReply { ok: bool, message: Option<String>, output: Option<String> }`.
  - `trait System { fn run(&self, argv: &[&str], stdin: Option<&[u8]>) -> io::Result<(i32, String, String)>; fn write_file(&self, path: &Path, bytes: &[u8], mode: u32) -> io::Result<()>; fn exists(&self, path: &Path) -> bool; fn remove_tree(&self, path: &Path) -> io::Result<()>; }` with `RealSystem` and a recording `FakeSystem` for tests. Commands always go through argv, never through a shell built from strings, except for the app's own start command inside the rendered unit.
  - `fn render_app_unit(app: &str, spec: &AppUnitSpec) -> String`. For `Process`:
    ```
    [Unit]
    Description=Keel app <app> (release %i)
    After=network-online.target
    StartLimitIntervalSec=300
    StartLimitBurst=10
    [Service]
    User=keel-app-<app>
    Group=keel-app-<app>
    WorkingDirectory=/srv/apps/<app>/releases/%i
    EnvironmentFile=-/var/lib/keel/apps/<app>/env
    EnvironmentFile=/var/lib/keel/apps/<app>/run/%i.env
    Environment=PATH=<runtime_bin_dirs joined by :>:/usr/local/bin:/usr/bin:/bin
    ExecStart=/bin/sh -c <start_command, systemd-quoted>
    Restart=on-failure
    RestartSec=2
    MemoryMax=<memory_mb>M
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateTmp=yes
    ReadWritePaths=/srv/apps/<app>/shared /srv/apps/<app>/releases/%i
    ```
    For `PhpFpm`, `ExecStart=<php runtime>/sbin/php-fpm --nodaemonize --fpm-config /var/lib/keel/apps/<app>/run/%i.fpm.conf` (the agent writes that pool file in Task 9), plus `RuntimeDirectory=keel-apps/<app>-%i` and `RuntimeDirectoryMode=0755`. The directory is per instance, so stopping the old release never removes the new release's socket. The socket is protected by the pool's `listen.acl_users`. There is no `[Install]` section: the agent starts the instances it wants.
  - `struct HelperClient { path: PathBuf }` with `async fn call(&self, op: HelperOp) -> Result<HelperReply>` (connect, write the line, read the line, 30 s timeout; 15 min for `RunPrepare` in Task 5).
  - `keel-helper.service`: `User=root`, `ExecStart=/usr/local/bin/keel-agent helper`, `RuntimeDirectory=keel`, `RuntimeDirectoryMode=0750`, `Restart=always`, `MemoryMax=32M`, `ProtectHome=yes`, `PrivateTmp=yes`.

- [ ] **Step 1: Write failing tests:**
  - `validation_rejects_hostile_input`: every op with app `"../x"`, `"A"`, `"a;rm"` or a 32-character name → `ok=false` and zero `FakeSystem` calls (Review Focus 4).
  - `ensure_app_user_is_idempotent` (second call issues no `useradd`).
  - `render_app_unit_process_snapshot` and `render_app_unit_php_snapshot` (exact text, including the per-instance `RuntimeDirectory`).
  - `start_command_is_quoted_for_systemd`: `echo "a b" $PORT %` renders so systemd passes it to `sh -c` unchanged (`%` doubled, quotes escaped).
  - `systemctl_only_touches_app_template_instance`.
  - `read_logs_caps_lines_at_1000`.
  - Integration `peer_with_wrong_uid_is_rejected` (Linux only): run the helper server on a temp socket configured with an expected uid that isn't the test's uid; a connect + op gets no reply.
  - `oversized_line_rejected`.
- [ ] **Step 2: Run** `cargo test -p keel-agent helper`. Expected: FAIL.
- [ ] **Step 3: Implement.** Use `tokio::net::UnixListener`, `nix` or `libc` for `SO_PEERCRED`, and the existing tracing setup.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): root helper with validated app-unit operations`.

---

### Task 5: Helper — release files, dependency install and Caddy

**Files:**
- Modify: `crates/keel-agent/src/helper/{mod.rs,ops.rs}`
- Create: `crates/keel-agent/dist/caddy.service`
- Test: unit tests in `ops.rs`

**Interfaces:**
- Consumes: Task 4's `HelperOp`, `System`, validation.
- Produces (new `HelperOp` variants):
  - `Materialize { app, release: u32, staging: String }`. `staging` must canonicalize to a directory directly under `/var/lib/keel/staging/` and contain no symlinks anywhere (checked while walking). The op copies the tree to `/srv/apps/<app>/releases/<release>/` (which must not already exist), then `chown -R keel-app-<app>:keel-app-<app>`, then `chmod -R u=rwX,g=rX,o=` and `setfacl -R -m u:caddy:rX`. After success it removes the staging dir.
  - `RunPrepare { app, release: u32, argv: Vec<String>, env: Vec<(String,String)>, path_dirs: Vec<String>, memory_mb: u32, timeout_secs: u32 /* ≤ 900 */ }` runs:
    ```
    systemd-run --wait --pipe --collect --quiet \
      -p User=keel-app-<app> -p Group=keel-app-<app> \
      -p WorkingDirectory=/srv/apps/<app>/releases/<release> \
      -p MemoryMax=<memory_mb>M -p RuntimeMaxSec=<timeout_secs> \
      -p NoNewPrivileges=yes -p ProtectHome=yes -p PrivateTmp=yes \
      -p Environment=HOME=/srv/apps/<app>/shared/.home \
      -p Environment=PATH=<path_dirs>:/usr/local/bin:/usr/bin:/bin \
      [-p Environment=K=V ...] -- <argv...>
    ```
    It replies with the exit code and the last 200 lines of combined output in `output`. If the unit ended because of `MemoryMax` (detect `Result: oom-kill` from `systemctl show` on the transient unit, or exit 137 plus "oom" in the journal), it replies `message = "oom"`.
  - `RemoveRelease { app, release }` → refuses if the instance unit is active; otherwise deletes the release dir.
  - `EnsureCaddy { version: String, sha256: String, url: String }`:
    - Downloads to a temp file and verifies the sha256.
    - Installs `/usr/local/bin/caddy` with mode 0755.
    - Creates the `caddy` system user and group `keel-proxy`, adds `keel` to `keel-proxy`, and creates `/var/lib/caddy` owned by caddy.
    - Writes `caddy.service`:
      ```
      User=caddy
      Group=keel-proxy
      AmbientCapabilities=CAP_NET_BIND_SERVICE
      ExecStart=/usr/local/bin/caddy run --resume --environ
      Environment=CADDY_ADMIN=unix//run/caddy/admin.sock|0660
      RuntimeDirectory=caddy
      RuntimeDirectoryMode=0750
      Restart=always
      MemoryMax=128M
      ```
    - Enables and starts the service.
    - Idempotent: when the installed binary's sha256 already matches, it skips the download.

- [ ] **Step 1: Write failing tests:**
  - `materialize_rejects_outside_staging` (`/var/lib/keel/staging/../tls`, `/tmp/x`) and `materialize_rejects_symlink_in_tree` (Review Focus 4).
  - `materialize_refuses_existing_release`.
  - `run_prepare_builds_exact_systemd_run_argv`.
  - `run_prepare_reports_oom`: fake `systemctl show` gives `Result=oom-kill`, so the reply message is `"oom"`.
  - `run_prepare_timeout_capped_at_900`.
  - `remove_release_refuses_active_instance`.
  - `ensure_caddy_verifies_checksum`: a wrong sha gives `ok=false` and no file in `/usr/local/bin`.
  - `ensure_caddy_idempotent`.
- [ ] **Step 2: Run** `cargo test -p keel-agent helper`. Expected: FAIL.
- [ ] **Step 3: Implement.** Download with `ureq` (rustls, no default features) inside `spawn_blocking`.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): helper ops for releases, dependency installs and Caddy`.

---

### Task 6: Runtime catalog and verified downloads

**Files:**
- Create: `crates/keel-agent/src/runtimes.rs`, `crates/keel-agent/src/runtimes.toml`
- Test: unit tests in `runtimes.rs`

**Interfaces:**
- Produces:
  - `runtimes.toml` (embedded with `include_str!`). One entry per `(kind, version, arch)` with `url` and `sha256`:
    - `node` 20 and 22: latest patch at implementation time, official `node-v<ver>-linux-{x64,arm64}.tar.xz`, sha256 from the release's `SHASUMS256.txt`.
    - `php` 8.3 and 8.4: static builds of `php` (CLI) and `php-fpm` for `x86_64` and `aarch64` from static-php-cli (`https://dl.static-php.dev/static-php-cli/bulk/`). Record the sha256 you compute after downloading over HTTPS, and note the date. If a needed build isn't published, stop and report NEEDS_CONTEXT; don't substitute a distro package.
    - `composer` 2.x `composer.phar`, sha256 from `https://getcomposer.org/download/<ver>/composer.phar.sha256sum`.
    - `caddy` 2.x linux amd64/arm64 tarballs, sha256 derived from the release's checksums file.
  - `struct Catalog`, `fn catalog() -> &'static Catalog`, `fn lookup(kind: &str, version_major: &str, arch: &str) -> Option<&Entry>`. Version matching takes the newest entry whose version starts with `<major>` or `<major.minor>`.
  - `struct Runtimes { root: PathBuf /* /opt/keel/runtimes */ }` and `async fn ensure(&self, kind, version, arch) -> Result<PathBuf /* bin dir */, RuntimeError>`. It downloads to `<root>/.tmp`, verifies the sha256, extracts to `<root>/<kind>-<version>-<arch>`, and renames into place atomically, so a crash never leaves a half-installed runtime. It is idempotent.
  - `fn bin_dirs(kind, dir) -> Vec<String>`: node → `<dir>/bin`; php → `<dir>/bin` and `<dir>/sbin`; composer → `<dir>`.
  - `RuntimeError` gives plain messages, for example: "Node 18 isn't available in Keel. Use Node 20 or 22." and "The download of PHP 8.3 didn't match its checksum. Nothing was installed."
  - `fn prune_unused(&self, in_use: &[PathBuf])` removes runtime dirs that no app uses.
  - `#[async_trait] trait RuntimeProvider: Send + Sync { async fn ensure(&self, kind: &str, version: &str, arch: &str) -> Result<PathBuf, RuntimeError>; fn bin_dirs(&self, kind: &str, dir: &Path) -> Vec<String>; fn prune_unused(&self, in_use: &[PathBuf]); }`, implemented by `Runtimes`. The deploy engine (Task 9) depends only on this trait.

- [ ] **Step 1: Write failing tests:**
  - `catalog_has_required_entries` for every kind, version and arch above.
  - `lookup_major_and_minor`.
  - `unknown_version_message`.
  - `ensure_verifies_and_extracts`, using a local test HTTP server (a `tokio` listener serving a small tar.xz fixture with a known sha) through an injectable base URL.
  - `ensure_bad_checksum_leaves_nothing`.
  - `ensure_is_idempotent` (no second request).
  - `prune_keeps_in_use`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** with `ureq`, `xz2` / `tar` (or `lzma-rs` to avoid C code under musl; prefer pure Rust) and `sha2`. Fill the catalog with real values and record the commands used to obtain each sha256 in the report.
- [ ] **Step 4: Run.** Expected: PASS. Also check that `cargo test -p keel-agent --release --test memory` still passes; the agent idle RSS must stay under 25 MB.
- [ ] **Step 5: Commit** `feat(agent): pinned runtime catalog with verified installs`.

---

### Task 7: Proxy adapter and Caddy driver

**Files:**
- Create: `crates/keel-agent/src/proxy/{mod.rs,caddy.rs}`
- Test: unit tests in `caddy.rs` against a fake admin server on a temp Unix socket

**Interfaces:**
- Produces:
  - `enum Upstream { Port(u16), PhpFpm { socket: String, root: String }, Static { root: String } }`
  - `trait Proxy: Send + Sync { async fn set_public(&self, app: &str, host: &str, up: &Upstream) -> Result<()>; async fn set_preview(&self, app: &str, release: u32, up: &Upstream) -> Result<()>; async fn remove_preview(&self, app: &str, release: u32) -> Result<()>; async fn remove_app(&self, app: &str) -> Result<()>; async fn health(&self, app: &str, release: u32, path: &str) -> Result<u16 /* status */>; }`
  - `struct CaddyProxy { admin_socket: PathBuf /* /run/caddy/admin.sock */, preview_port: u16 /* 2080, 127.0.0.1 only */ }`
  - It manages two Caddy servers under `apps.http.servers`:
    - `keel_public` listens on `:443` and `:80`, with automatic HTTPS.
    - `keel_preview` listens on `127.0.0.1:2080`, with `automatic_https.disable = true`.
  - Each route has `@id` `keel-<app>` (public) or `keel-<app>-r<release>` (preview), so the driver can address it through `/id/<id>`.
  - Preview host is `r<release>.<app>.keel.internal`.
  - Route handlers:
    - `Port` → `reverse_proxy` to `127.0.0.1:<port>`.
    - `PhpFpm` → `vars root` + `php_fastcgi`-equivalent JSON (`rewrite` to `index.php` + `reverse_proxy` with `transport.protocol = "fastcgi"`, `split_path: [".php"]`, root `<root>/public`, plus `file_server` for existing files).
    - `Static` → `file_server` with root and `try_files {path} {path}/ /index.html`.
  - `set_public` is atomic: it uses `PATCH /id/keel-<app>` when the route exists and `POST` to the routes array otherwise, so traffic switches in one admin call.
  - `health` sends `GET http://127.0.0.1:2080<path>` with `Host: r<release>.<app>.keel.internal`, a 5 s timeout, and returns the status code.
  - `fn public_host(app: &str, server_ip: &str) -> String` → `"<app>.<ip>.sslip.io"`. IPv6 uses dashes in place of colons, per sslip.io.
  - The server IP comes from the address the desktop used, which onboarding already stores as `--host` in the agent config (Task 11 persists it as `public_host` in `agent.toml`).
  - All admin calls use HTTP/1.1 over the Unix socket. Requests are hand-written with `tokio` and parsed minimally; add no HTTP client crate for this. Each call times out after 10 s.

- [ ] **Step 1: Write failing tests:**
  - `first_set_public_posts_route_with_id`.
  - `second_set_public_patches_same_id` (one request, so the switch is atomic).
  - `php_route_json_snapshot`.
  - `static_route_json_snapshot`.
  - `preview_server_is_localhost_only_without_https`.
  - `remove_app_deletes_all_ids`.
  - `health_sends_preview_host_header`.
  - `public_host_ipv4_and_ipv6`.
  - `admin_error_body_becomes_plain_error`: a Caddy 400 with a JSON error gives "The web server rejected Keel's route change: <short reason>".
- [ ] **Step 2: Run** `cargo test -p keel-agent proxy`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): Caddy proxy adapter`.

---

### Task 8: Uploads: content-addressed store, staging and client uploader

**Files:**
- Create: `crates/keel-agent/src/uploads.rs`, `crates/keel-client/src/upload.rs`
- Test: unit tests in both; `crates/keel-client/tests/upload.rs` (in-process agent)

**Interfaces:**
- Produces (agent):
  - `struct Uploads { cas: PathBuf /* <data_dir>/cas */, staging: PathBuf /* <data_dir>/staging */ }`
  - `fn begin(&self, app, commit, files: &[FileEntry]) -> Result<(String /* upload_id, 128-bit random hex */, Vec<String> /* missing sha256s */), UploadError>`. Validation:
    - Paths are relative, use `/` separators, contain no `..`, no leading `/`, no NUL, at most 4 096 bytes each.
    - At most 100 000 files.
    - Total size is at most 2 GiB.
    - `mode` is either 0o644 or 0o755. Executable bit only; no setuid.
  - `fn chunk(&self, upload_id, sha256, offset, bytes) -> Result<(), UploadError>`. Writes to `cas/.partial/<sha>` at `offset`, which must equal the current partial length. When the partial reaches the declared size, the sha is verified and the file is moved to `cas/<sha[0..2]>/<sha>`; a mismatch deletes the partial and returns an error.
  - `fn finish(&self, upload_id) -> Result<PathBuf /* staging dir */, UploadError>`. All shas must now be in the CAS. It builds `staging/<upload_id>/` by copying each file from the CAS to its path with its mode; files are never symlinked.
  - Uploads expire after 30 minutes of inactivity. `fn gc(&self, keep: &HashSet<String>)` removes CAS blobs no kept release references; the agent keeps a per-release manifest file `releases/<app>/<n>.json` in `data_dir` for this.
  - Disk guard: `begin` refuses when the missing bytes × 2 + 512 MiB exceed free space on `data_dir`'s filesystem. Message: "The server doesn't have enough free disk space for this release (needs <n> MB, <m> MB free). Remove old releases or add disk space."
- Produces (client):
  - `fn manifest(dir: &Path) -> Result<Vec<FileEntry>>`. Walks the tree, skips `.git`, follows no symlinks (a symlink is an error naming the path: "Keel can't upload symlinks yet: <path>"), and sorts by path.
  - `async fn upload(conn: &mut Connection, app: &str, commit: Option<String>, dir: &Path, progress: impl Fn(u64, u64)) -> Result<i64 /* deploy_id */, ConnectError>`. Sends `BeginUpload`, then `UploadChunk` frames of 700 000 raw bytes each for the missing files, then `FinishUpload`, which returns `DeployStarted`.

- [ ] **Step 1: Write failing tests:**
  - Agent:
    - `begin_rejects_bad_paths` (`../a`, `/etc/x`, `a\0b`, a setuid mode) — Review Focus 4.
    - `chunk_must_be_contiguous`.
    - `sha_mismatch_discards_partial`.
    - `second_upload_reports_only_changed_files`.
    - `finish_builds_staging_with_modes`.
    - `disk_guard_message` (Review Focus 5; inject free-space function).
    - `expired_upload_is_gone`.
  - Client:
    - `manifest_skips_git_and_rejects_symlinks`.
    - Integration `upload_then_reupload_sends_only_diff`, with an in-process agent and the deploy engine stubbed by a test `DeployStarter`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** `finish` hands the staging dir to the deploy engine through a `trait DeployStarter { fn start(&self, app, release, staging, commit, by_user) -> Result<i64> }`, which Task 9 implements.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat: content-addressed uploads with changed-files transfer`.

---

### Task 9: Deploy engine

**Files:**
- Create: `crates/keel-agent/src/deploy/{mod.rs,steps.rs}`
- Modify: `crates/keel-agent/src/reconcile.rs` (`AppsReconciler`)
- Test: unit tests in `deploy/mod.rs` with fake `Helper`, `Proxy`, `Runtimes`, `Clock`

**Interfaces:**
- Consumes: Store (Task 3), helper ops via a `trait Helper { async fn call(&self, op: HelperOp) -> Result<HelperReply>; }` implemented by `HelperClient` (Task 4), `Proxy` (Task 7), `Runtimes` via `trait RuntimeProvider` (Task 6), `Uploads` (Task 8).
- Produces:
  - `struct DeployEngine { store, helper: Arc<dyn Helper>, proxy: Arc<dyn Proxy>, runtimes: Arc<dyn RuntimeProvider>, uploads, clock, config: EngineConfig }` with `EngineConfig { health_timeout: 60s, drain: 10s, keep_releases: 5, prepare_memory_mb: fn(server_free_mb) -> u32 /* 70% of free memory, min 128, max 2048 */ }`, implementing `DeployStarter`.
  - `fn start(...) -> Result<i64>` calls `store.begin_deploy` (on conflict: `Conflict`, "A deploy of <app> is already running.") and spawns the run on the runtime.
  - Steps, each persisted with `set_deploy_step` before it runs, each logging plain lines to `deploy_log`:
    1. `Receiving` → `Materialize`.
    2. `Preparing`:
       - Ensure the runtime for the stack.
       - Node: `RunPrepare` `<pm> ci --omit=dev` (pnpm: `pnpm install --prod --frozen-lockfile`; yarn: `yarn install --production --frozen-lockfile`). The `pnpm`/`yarn` commands run via `corepack` from the Node runtime.
       - Laravel: `["php", "<composer dir>/composer.phar", "install", "--no-dev", "--optimize-autoloader", "--no-interaction"]`, with the PHP and composer bin dirs on `path_dirs`. Then link the shared storage with `["/bin/sh","-c","mkdir -p ../../shared/storage/app ../../shared/storage/framework/cache ../../shared/storage/framework/sessions ../../shared/storage/framework/views ../../shared/storage/logs && rm -rf storage && ln -s ../../shared/storage storage"]`. Removing first matters, because `ln` onto an existing directory would create the link inside it.
       - Rust and Static: nothing.
       - Then `release_command` if set, run as `["/bin/sh","-c",cmd]`.
       - On `"oom"`: fail with Review Focus 2's message.
       - Env from `env_for_unit` is passed to each prepare command.
    3. `Starting`:
       - Write `/var/lib/keel/apps/<app>/env` from the decrypted env and `run/<release>.env` with `PORT=<allocated>`, `HOST=127.0.0.1` and `APP_URL=https://<public host>` (mode 0600, owned by keel).
       - PHP: write `run/<release>.fpm.conf`, a pool listening on `/run/keel-apps/<app>-<release>/php.sock`, owned by the app user, with `listen.acl_users = caddy`, `pm = ondemand`, `pm.max_children = 4`.
       - `WriteAppUnit`, then `Systemctl Start`.
       - Static has no process.
    4. `HealthChecking`:
       - `set_preview`.
       - Poll `proxy.health(path)` every second until it returns 200 or `health_timeout` passes.
       - On timeout, fail with Review Focus 1's message for `Port`. For PHP: "The app didn't answer at <path>. Check the deploy log and app logs." The last 30 lines of `ReadLogs` are appended to the deploy log.
    5. `Switching`: `set_public` to the new upstream, then `set_live_release`, `add_release` and app state Live.
    6. `Draining`: wait `drain`, then `Systemctl Stop` on the previous live release and release its port. The previous release's files are kept for rollback.
    7. `Live`.
    8. Prune releases beyond `keep_releases` (never the live one): `RemoveRelease`, `uploads.gc`, `runtimes.prune_unused`.
  - On any failure before `Switching`: stop the new instance if started, `remove_preview`, release its port, `fail_deploy(msg)`, and leave the app's state as it was (or `Down` if it had no live release).
  - `async fn rollback(app, release, by_user) -> Result<i64>`: a deploy record whose steps are `Starting` (reuses the existing release dir) → `HealthChecking` → `Switching` → `Draining` → `Live`.
  - `async fn restart(app, by_user)`: the same, with the live release (used after env changes).
  - `AppsReconciler` (runs at agent start and every 60 s):
    - For each `unfinished_deploys()` older than the current process start, fail it with Review Focus 3's message and stop its instance if it isn't the live one.
    - For each app with a live release, ensure the instance is active (`Systemctl Start` if not) and `set_public` matches the DB.
- [ ] **Step 1: Write failing tests (all against fakes):**
  - `happy_path_node_steps_in_order`: asserts the exact op sequence, step sequence and the final live release.
  - `health_timeout_keeps_previous_live` (Review Focus 1).
  - `prepare_oom_message_and_previous_live` (Review Focus 2).
  - `reconciler_fails_interrupted_deploy_and_stops_instance` (Review Focus 3).
  - `concurrent_deploy_conflict` (Review Focus 5).
  - `static_deploy_has_no_process_and_switches_root`.
  - `laravel_prepare_runs_composer_then_release_command_with_env`.
  - `rust_deploy_skips_prepare`.
  - `rollback_restarts_kept_release_without_prepare`.
  - `prune_keeps_five_and_never_live`.
  - `env_file_written_0600_with_port`.
- [ ] **Step 2: Run** `cargo test -p keel-agent deploy`. Expected: FAIL.
- [ ] **Step 3: Implement.** Steps live in `steps.rs` as functions over the traits; `mod.rs` sequences them and owns persistence and cleanup.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): zero-downtime deploy engine with rollback`.

---

### Task 10: App request handlers and permissions

**Files:**
- Create: `crates/keel-agent/src/handlers_apps.rs`
- Modify: `crates/keel-agent/src/handlers.rs`, `crates/keel-agent/src/server.rs` (construct engine, helper client, proxy, runtimes, uploads; pass to handlers), `crates/keel-agent/src/config.rs` (`public_host`)
- Test: `crates/keel-agent/tests/apps_api.rs` (in-process agent, fake helper/proxy injected through a `serve_with` test constructor)

**Interfaces:**
- Consumes: Tasks 1, 3, 8, 9.
- Produces — permission per request (project = the app's project):
  | Request | Permission |
  |---|---|
  | CreateApp, DeleteApp | ManageProjects (no project) |
  | UpdateApp, BeginUpload/UploadChunk/FinishUpload, Rollback, Restart | Deploy (UpdateApp: EditEnv is not enough) |
  | GetApp, ListDeploys, GetDeploy | ViewStatus |
  | AppLogs | ViewLogs |
  | GetEnv | ViewLogs; values revealed only with ReadSecrets |
  | SetEnv | EditEnv |
- Audit rows for every mutating request: `create_app`, `update_app`, `delete_app`, `deploy`, `rollback`, `restart`, `set_env` (target = app name; `set_env` lists key names, never values).
- `GetApp` returns `AppDetail.url = https://<public_host(app, cfg.public_host)>`.
- `CreateApp` runs `EnsureAppUser`, then stores the app. `DeleteApp` refuses while a deploy is running (`Conflict`), otherwise `RemoveApp` + `proxy.remove_app` + store delete.
- Handlers that call async engine/helper code become `async`; `server.rs` awaits them. The 120 s idle timeout still applies between requests, not during an upload.
- Upload frames are rate-limited per connection to 200 per second; exceeding it is `TooLarge`.

- [ ] **Step 1: Write failing tests:**
  - `developer_can_deploy_assigned_app_not_others`.
  - `viewer_gets_masked_env_and_logs_but_cannot_deploy`.
  - `admin_creates_app_in_default_project`.
  - `mutations_write_audit_rows_without_env_values`.
  - `get_app_url_uses_sslip_host`.
  - `delete_app_refused_during_deploy`.
  - `m1_client_protocol_1_still_works` (Hello with protocol 1, then ServerStatus).
- [ ] **Step 2: Run** `cargo test -p keel-agent --test apps_api`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the whole agent suite, including `--release --test memory`. Expected: PASS, idle RSS still < 25 MB.
- [ ] **Step 5: Commit** `feat(agent): app, deploy and env API with per-project permissions`.

---

### Task 11: Onboarding installs the helper; Update agent

**Files:**
- Modify: `crates/keel-client/src/onboarding/{install.rs,mod.rs}`, `crates/keel-agent/dist/keel-agent.service`, `scripts/install.sh`, `crates/keel-agent/src/config.rs`/`init.rs` (`--public-host`)
- Test: fake-Remote tests in `install.rs`; the CI onboarding script in Task 15

**Interfaces:**
- Produces:
  - Agent unit gains `ReadWritePaths=/var/lib/keel /opt/keel/runtimes` and `SupplementaryGroups=keel-proxy`.
  - Install sequence additions, all idempotent, after the binary upload and before `init`:
    - Create the groups and `/run/keel` handling.
    - `install -d -m 0755 -o root -g root /srv/apps`.
    - `install -d -m 0755 -o keel -g keel /opt/keel/runtimes`.
    - `install -d -m 0700 -o keel -g keel /var/lib/keel/{staging,cas,apps}`.
    - Install the `acl` package if `setfacl` is missing (apt or dnf).
    - Write `keel-helper.service` (embedded from `crates/keel-agent/dist/`), then `systemctl enable --now keel-helper` and restart it if already running.
    - `init` is passed `--public-host <host>`, which is stored in `agent.toml`.
  - `pub async fn update_agent(record: &ServerRecord, kc: &dyn Keychain, artifacts: &AgentArtifacts, events) -> Result<()>`. It loads `ssh:<id>` credentials and re-runs the install sequence with the saved `InstallOptions`, skipping pairing (`pair_or_confirm` confirms the existing Owner). Without saved credentials it fails with "Keel needs SSH access to update the agent. Re-add the server to save its sign-in details."
  - Fix the M1 UI mislabel: `StepFailed` carries the step name as a separate field (`StepFailed { step: &'static str, message: String }`), so `OnboardingEvent::Failed { step, message }` marks the right row in the wizard. Update `AddServerWizard.svelte` and its tests.
  - `install.sh` mirrors the new steps exactly (and its unit-file identity check covers `keel-helper.service`).
- [ ] **Step 1: Write failing tests:**
  - `full_sequence_includes_helper_and_dirs_in_order` (the helper is enabled before `init`; the acl package is installed only when `setfacl` is missing).
  - `reachability_failure_names_starting_step` (wizard event has `step = "Starting the agent"`).
  - `update_agent_requires_saved_credentials`.
  - `update_agent_skips_pairing`.
  - Svelte: `failed_event_marks_named_step`.
- [ ] **Step 2: Run** `cargo test -p keel-client onboarding` and `npm test`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS; `shellcheck scripts/install.sh` clean.
- [ ] **Step 5: Commit** `feat: install the root helper and add Update agent`.

---

### Task 12: Local build runner

**Files:**
- Create: `crates/keel-client/src/build/{mod.rs,stacks.rs}`
- Test: unit tests with a fake `Cmd` runner; `crates/keel-client/tests/build.rs` (real builds, `#[ignore]`, run in CI)

**Interfaces:**
- Consumes: `detect`, `KeelToml`, `AppSpec` (Task 2).
- Produces:
  - `trait Cmd { fn run(&self, argv: &[&str], cwd: &Path, env: &[(&str,&str)], log: &mut dyn FnMut(&str)) -> io::Result<i32>; fn which(&self, prog: &str) -> bool; }` with `RealCmd`.
  - `struct Workspace { root: PathBuf /* <app data>/builds */ }`.
  - `fn fetch(&self, cmd, app: &str, repo_url, branch, log) -> Result<(PathBuf /* checkout */, String /* commit sha */), BuildError>`:
    - First time: `git clone --depth 1 --branch <branch> <url> <root>/<app>/src`.
    - Afterwards: `git -C … fetch --depth 1 origin <branch>` then `git -C … reset --hard FETCH_HEAD`.
    - It uses the user's own git and credentials.
  - `fn build(&self, cmd, spec: &AppSpec, src: &Path, target_arch: &str /* from ServerStatus.arch */, log) -> Result<PathBuf /* artifact dir */, BuildError>`. Into a fresh `<root>/<app>/out`:
    - Node: run `<pm> install --frozen-lockfile` (npm: `npm ci`), then `build_command`. Then copy the source tree minus `node_modules`, `.git` and anything in `.keelignore` (gitignore syntax via the `ignore` crate) into out.
    - Static: optional `<pm> ci` + `build_command`, then copy `output_dir` contents into out.
    - Laravel: if `build_command` is set, `npm ci` + `npm run build`. Then copy the source minus `vendor`, `node_modules`, `.git`, `.env` and `storage/` contents (keep the empty structure).
    - Rust: `cargo zigbuild --release --target <arch>-unknown-linux-musl`, then copy `target/<triple>/release/<rust_bin>` to `out/<rust_bin>` (mode 0755), plus any `include` dirs from `keel.toml`.
  - Missing tools are checked before anything runs, each with a plain message:
    - git: "Keel needs git to fetch your code. Install it and try again."
    - npm, pnpm or yarn, as needed.
    - cargo-zigbuild: "Building Rust apps needs cargo-zigbuild and zig: brew install zig && cargo install cargo-zigbuild".
  - Build failures return `BuildError::Failed { step, code }`. The last 50 log lines are already streamed through `log`.
  - A `.env` file in the source is never copied for any stack, and a deploy-log line says it was skipped. Secrets belong in Environment.
- [ ] **Step 1: Write failing tests (fake `Cmd`):**
  - `node_npm_runs_ci_then_build_and_omits_node_modules`.
  - `pnpm_uses_frozen_lockfile`.
  - `static_copies_only_output_dir`.
  - `laravel_skips_vendor_env_and_storage_contents`.
  - `rust_targets_server_arch_musl`.
  - `missing_tool_message`.
  - `fetch_clones_then_resets_on_second_call`.
  - `keelignore_respected`.
- [ ] **Step 2: Run** `cargo test -p keel-client build`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(client): local build runner for node, static, laravel and rust`.

---

### Task 13: Deploy orchestration and Tauri commands

**Files:**
- Create: `crates/keel-client/src/deploy.rs`, `apps/desktop/src-tauri/src/apps.rs`
- Modify: `apps/desktop/src-tauri/src/{lib.rs,commands.rs}`
- Test: unit tests in `deploy.rs` (fake connection trait), Rust tests for command argument validation

**Interfaces:**
- Consumes: Tasks 8, 11, 12; the `Connection` (M1).
- Produces:
  - `enum DeployEvent { Fetching, Building, Log(String), Uploading { sent: u64, total: u64 }, Server(DeploySummary, Vec<String>), Done(DeploySummary), Failed(String) }` (Serialize).
  - `async fn run_deploy(conn, ws, cmd, app: &AppDetail, server_arch: &str, events: Sender<DeployEvent>) -> Result<DeploySummary>`. Runs fetch → build → upload → then polls `GetDeploy` every second, forwarding new log lines, until `Live` or `Failed`.
  - Tauri commands:
    - `detect_app(repo_url, branch) -> AppSpec`: fetches into a temp workspace and runs `detect` with a `DirTree`.
    - `create_app(server_id, spec) -> AppDetail`, `update_app`, `delete_app`, `get_app(server_id, app)`.
    - `deploy_app(server_id, app)`: emits `deploy://event` with `{server_id, app, event}`. Only one local deploy per app at a time; a second returns "This app is already deploying."
    - `rollback_app(server_id, app, release)`, `restart_app(server_id, app)`.
    - `get_env`, `set_env`, `app_logs`, `list_deploys`.
    - `update_agent(server_id)` emits `onboarding://event`.
  - All commands open their own `Connection` (the poller's stays dedicated to status).

- [ ] **Step 1: Write failing tests:**
  - `run_deploy_streams_server_log_until_live`.
  - `run_deploy_build_failure_never_uploads`.
  - `run_deploy_reports_server_failure_message_verbatim`.
  - `second_local_deploy_of_same_app_refused`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p keel-client deploy` and `cargo test -p keel-desktop`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(desktop): deploy orchestration and app commands`.

---

### Task 14: App UI — create, deploy, rollback, environment, logs

**Files:**
- Create: `apps/desktop/src/lib/apps.svelte.ts`, `apps/desktop/src/lib/components/{CreateAppDialog.svelte,AppDrawer.svelte,DeployLog.svelte}` and tests
- Modify: `apps/desktop/src/routes/+page.svelte` (Create app button, drawer swap), `apps/desktop/src/routes/servers/[id]/+page.svelte` (Update agent button), `apps/desktop/src/lib/commands.ts` (palette: "Deploy <app>", "Roll back <app>", "Create app")
- Test: Vitest component tests

**Interfaces:**
- Consumes: Task 13 commands and events.
- Produces UI (visual rules from Global Constraints; reuse ConfirmDialog, StatusBadge and the overlay stack):
  - **Create app** (a modal, from the fleet board header when at least one server exists):
    1. Pick a server, enter the repo URL and branch (default `main`), then **Check repo**, which calls `detect_app`.
    2. The detected stack shows with an icon and a one-line description, alongside editable name (prefilled from the repo name, validated live against the app-name rule with an inline message), versions, build command, start command, health path and memory.
    3. **Create app** creates it, opens the app drawer and offers **Deploy now**.
  - **App drawer** tabs:
    - Overview: state, URL as a link, live release, and the **Deploy** button (the one primary button). **Restart** is secondary.
    - Deploys: a list with state icon + text, release number, commit short sha, who, and when. Each kept release has **Roll back** with a confirm dialog naming the release.
    - Environment: a key/value table, values masked with **Show** if permitted, add/edit/delete, and **Save**. After saving: "Saved. Restart the app to use the new values." with a **Restart** button.
    - Logs: the last 200 lines in monospace, with **Refresh**.
  - **DeployLog**: live step list (Fetching, Building, Uploading with a progress bar, then the server steps) and a scrolling monospace log. It auto-scrolls unless the user scrolls up. The failure message shows in plain text above the log.
  - The fleet board shows real app states, with Building while a deploy runs.
  - The server page gets **Update agent** (secondary button), which reuses the wizard's progress view.

- [ ] **Step 1: Write failing tests:**
  - `create_app_validates_name_inline`.
  - `create_app_shows_detected_stack_and_submits_spec`.
  - `deploy_button_streams_events_into_log`.
  - `deploy_failure_shows_message_above_log`.
  - `rollback_confirms_release_number`.
  - `env_values_masked_without_permission`.
  - `env_save_offers_restart`.
  - `update_agent_button_on_server_page`.
  - `palette_lists_deploy_commands`.
- [ ] **Step 2: Run** `npm test`. Expected: FAIL.
- [ ] **Step 3: Implement.** Then capture screenshots in light and dark (create dialog, drawer overview, a deploy in progress, a failed deploy, environment) with the existing headless-browser harness and check them.
- [ ] **Step 4: Run** `npm test`, `npm run check` and `npm run build`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(desktop): create, deploy, roll back and manage apps`.

---

### Task 15: End-to-end deploy matrix in CI

**Files:**
- Create: `ci/samples/{static-site,express-app,laravel-app,axum-app}/` (minimal apps, each with a `/` that returns 200 and a page containing a marker string), `ci/deploy-e2e.sh`, `crates/keel-agent/tests/helper_memory.rs`
- Modify: `.github/workflows/ci.yml` (new `deploy-e2e` job on Ubuntu 24.04 and Rocky 9 systemd containers), `ci/onboarding.sh`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `ci/deploy-e2e.sh`, driven by a small Rust test binary in `crates/keel-client/tests/deploy_e2e.rs` (`#[ignore]`, env-configured like the onboarding tests). It:
    1. Onboards the container.
    2. For each sample: create app → deploy → `curl -H "Host: <app>.<ip>.sslip.io" http://<container>/` returns 200 with the marker. HTTP only in CI; the container has no public certificate.
    3. Deploys again with a changed marker and checks that a parallel `curl` loop saw no non-200 during the switch (zero-downtime check).
    4. Rolls back and sees the old marker.
    5. Deploys a sample that ignores PORT and sees the failure message, with the old release still serving.
    6. Sets an env var, restarts, and sees it in the app's output.
    7. Checks that `systemctl show keel-app-<app>@<n> -p MemoryMax` matches the spec.
  - `helper_idle_rss_under_10mb` (Linux): spawn `keel-agent helper` on a temp socket, wait 5 s, assert VmRSS < 10 MiB.
- [ ] **Step 1: Write** the samples and the e2e test; run it locally against the debootstrap Ubuntu 24.04 container (as in M1 Task 14). Expected: all steps pass. Record anything that can only run in CI.
- [ ] **Step 2: Add** the CI job; run `actionlint`. Expected: clean.
- [ ] **Step 3: Run** `cargo test -p keel-agent --release --test memory --test helper_memory`. Expected: PASS.
- [ ] **Step 4: Commit** `ci: end-to-end deploy matrix for static, node, laravel and rust`.

---

## Spec coverage notes

- **Covered:**
  - §4: detection, `keel.toml`, runtimes, layout, isolation; Podman is excluded per Decision 5.
  - §5:
    - Local builds, server-side dependency install (Decision 2), changed-files upload, the full state machine, rollback, retention, disk guard, crash recovery.
    - Webhooks and delegation are excluded per Decision 5.
  - §6: proxy adapter and Caddy, plus a default HTTPS host; custom domains stay in M3.
  - §9: per-project permissions, audit, secrets encrypted at rest and masked.
  - §12: `AppsReconciler`.
  - §13: plain-language errors throughout.
  - §14: sample deploy matrix (four stacks), memory budgets.
- **Deferred:** webhooks and server-side builds; Podman; custom domains (M3); monitoring/alerts beyond restart-on-failure (M4); databases (M5); project management and invites UI (M6); agent self-update.

<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import IconAlertOctagon from '@tabler/icons-svelte/icons/alert-octagon';
  import IconAlertTriangle from '@tabler/icons-svelte/icons/alert-triangle';
  import IconCheck from '@tabler/icons-svelte/icons/check';
  import IconCircleX from '@tabler/icons-svelte/icons/circle-x';
  import IconLoader from '@tabler/icons-svelte/icons/loader-2';
  import { onMount, tick } from 'svelte';
  import { registerOverlay } from '../ui.svelte';

  let { onclose }: { onclose: () => void } = $props();

  type Finding = { severity: 'Blocker' | 'Warning'; message: string };
  type OnboardingEvent =
    | { type: 'Connecting' | 'Checking' | 'Pairing' }
    | { type: 'HostKey' | 'Installing' | 'Failed'; data: string }
    | { type: 'Findings'; data: Finding[] }
    | { type: 'Done'; data: { id: string; name: string } };
  type Step = { label: string; state: 'running' | 'done' | 'failed' };
  type AuthKind = 'generated' | 'private' | 'password';

  const overlay = registerOverlay();

  // Step 1: connection
  let name = $state('');
  let host = $state('');
  let port = $state<number | null>(22);
  let user = $state('root');
  let authKind = $state<AuthKind>('generated');
  let pem = $state('');
  let passphrase = $state('');
  let password = $state('');
  let publicKey = $state('');
  let keyBusy = $state(false);
  let keyError = $state('');
  let copyState = $state<'idle' | 'copied' | 'failed'>('idle');
  let copyTimer: ReturnType<typeof setTimeout> | undefined;

  // Step 2: options (defaults match the backend's InstallOptions)
  let enableFirewall = $state(true);
  let autoUpdates = $state(true);
  let disablePasswords = $state(false);
  let keepCredentials = $state(false);

  // Flow
  let step = $state<'connection' | 'options' | 'progress' | 'done'>('connection');
  let mode = $state<'ssh' | 'pair'>('ssh');
  let phase = $state<'idle' | 'running' | 'failed' | 'done'>('idle');
  let steps = $state<Step[]>([]);
  let findings = $state<Finding[]>([]);
  let fingerprint = $state('');
  let failure = $state('');
  let added = $state<{ id: string; name: string } | null>(null);

  // Pairing
  let pairCode = $state('');
  let pairBusy = $state(false);
  let pairError = $state('');

  let dialog: HTMLDivElement;
  let heading: HTMLHeadingElement;
  let nameInput: HTMLInputElement | undefined = $state();

  const portValid = $derived(port !== null && Number.isInteger(port) && port >= 1 && port <= 65535);
  const connectionValid = $derived(
    name.trim() !== '' &&
      host.trim() !== '' &&
      portValid &&
      user.trim() !== '' &&
      (authKind === 'generated'
        ? publicKey !== ''
        : authKind === 'private'
          ? pem.trim() !== ''
          : password !== '')
  );
  const keepShown = $derived(keepCredentials || disablePasswords);
  const busy = $derived(phase === 'running' || pairBusy);

  async function generateKey() {
    keyBusy = true;
    keyError = '';
    try {
      publicKey = await invoke<string>('generate_ssh_key');
      copyState = 'idle';
    } catch (e) {
      console.error(e);
      keyError = "Couldn't create a key. Try again, or choose another way to sign in.";
    } finally {
      keyBusy = false;
    }
  }

  /** Show the key generated earlier (the person may already have added it), or make one. */
  async function loadOrGenerateKey() {
    keyBusy = true;
    try {
      const pending = await invoke<string | null>('pending_ssh_key');
      if (pending) {
        publicKey = pending;
        keyBusy = false;
        return;
      }
    } catch (e) {
      console.error(e);
    }
    await generateKey();
  }

  async function copyKey() {
    clearTimeout(copyTimer);
    try {
      await navigator.clipboard.writeText(publicKey);
      copyState = 'copied';
    } catch {
      copyState = 'failed';
    }
    copyTimer = setTimeout(() => (copyState = 'idle'), 2000);
  }

  // Progress events
  let unlisten: (() => void) | undefined;
  let disposed = false;
  let listening: Promise<void> = Promise.resolve();

  function beginStep(label: string) {
    const last = steps[steps.length - 1];
    if (last?.state === 'running' && last.label === label) return;
    for (const s of steps) if (s.state === 'running') s.state = 'done';
    steps.push({ label, state: 'running' });
  }

  function clearSecrets() {
    pem = '';
    passphrase = '';
    password = '';
  }

  function fail(message: string) {
    for (const s of steps) if (s.state === 'running') s.state = 'failed';
    failure = message;
    phase = 'failed';
  }

  function onEvent(ev: OnboardingEvent) {
    if (phase !== 'running') return;
    switch (ev.type) {
      case 'Connecting':
        beginStep('Connecting over SSH');
        break;
      case 'HostKey':
        fingerprint = ev.data;
        break;
      case 'Checking':
        beginStep('Checking the server');
        break;
      case 'Findings':
        findings.push(...ev.data);
        break;
      case 'Installing':
        beginStep(ev.data);
        break;
      case 'Pairing':
        beginStep('Pairing this device');
        break;
      case 'Done':
        for (const s of steps) s.state = 'done';
        clearSecrets();
        added = { id: ev.data.id, name: ev.data.name };
        phase = 'done';
        step = 'done';
        break;
      case 'Failed':
        fail(ev.data);
        break;
    }
  }

  function buildRequest() {
    const auth =
      authKind === 'generated'
        ? { kind: 'generated_key' }
        : authKind === 'private'
          ? { kind: 'private_key', pem, passphrase: passphrase || undefined }
          : { kind: 'password', password };
    return {
      name: name.trim(),
      host: host.trim(),
      port: port as number,
      user: user.trim(),
      auth,
      options: {
        enable_firewall: enableFirewall,
        auto_security_updates: autoUpdates,
        disable_ssh_passwords: disablePasswords,
        keep_ssh_credentials: keepShown
      }
    };
  }

  async function start() {
    steps = [];
    findings = [];
    fingerprint = '';
    failure = '';
    phase = 'running';
    step = 'progress';
    await listening;
    try {
      await invoke('start_onboarding', { req: buildRequest() });
    } catch (e) {
      fail(typeof e === 'string' ? e : "Couldn't start setting up the server. Try again.");
    }
  }

  async function pair() {
    pairBusy = true;
    pairError = '';
    try {
      const view = await invoke<{ id: string; name: string }>('pair_with_code', {
        code: pairCode.trim(),
        name: name.trim()
      });
      added = { id: view.id, name: view.name };
      pairCode = '';
      step = 'done';
      phase = 'done';
    } catch (e) {
      pairError =
        typeof e === 'string' ? e : "Couldn't pair with that code. Check it and try again.";
    } finally {
      pairBusy = false;
    }
  }

  function back() {
    phase = 'idle';
    step = 'connection';
  }

  onMount(() => {
    const opener = document.activeElement as HTMLElement | null;
    nameInput?.focus();
    listening = listen<OnboardingEvent>('onboarding://event', (e) => onEvent(e.payload))
      .then((fn) => {
        if (disposed) fn();
        else unlisten = fn;
      })
      .catch((e) => console.error(e));
    void loadOrGenerateKey();
    return () => {
      disposed = true;
      unlisten?.();
      clearTimeout(copyTimer);
      overlay.release();
      opener?.focus?.();
    };
  });

  // Move focus to the heading when the view changes, so keyboard and screen reader
  // users land at the top of the new content.
  let firstView = true;
  $effect(() => {
    void step;
    void mode;
    if (firstView) {
      firstView = false;
      return;
    }
    void tick().then(() => heading?.focus());
  });

  function onkeydown(e: KeyboardEvent) {
    if (!overlay.isTop()) return;
    if (e.key === 'Escape') {
      if (!busy) onclose();
      return;
    }
    if (e.key !== 'Tab') return;
    const items = Array.from(
      dialog.querySelectorAll<HTMLElement>(
        'button:not([disabled]), a[href], input:not([disabled]), textarea:not([disabled])'
      )
    );
    if (items.length === 0) {
      e.preventDefault();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === heading || !dialog.contains(active))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (active === last || !dialog.contains(active))) {
      e.preventDefault();
      first.focus();
    }
  }

  const title = $derived(
    step === 'done'
      ? 'Server added'
      : mode === 'pair'
        ? 'Add a server with a pairing code'
        : step === 'connection'
          ? 'Connect to your server'
          : step === 'options'
            ? 'Choose what Keel sets up'
            : phase === 'failed'
              ? "Couldn't finish setting up"
              : 'Setting up your server'
  );
  const stepNote = $derived(
    mode === 'pair' || step === 'done'
      ? ''
      : `Step ${step === 'connection' ? 1 : step === 'options' ? 2 : 3} of 3`
  );
</script>

<svelte:window {onkeydown} />

<div class="scrim">
  <div
    class="dialog"
    bind:this={dialog}
    role="dialog"
    aria-modal="true"
    aria-labelledby="wiz-title"
  >
    <header>
      <h2 id="wiz-title" tabindex="-1" bind:this={heading}>{title}</h2>
      {#if stepNote}<span class="muted num">{stepNote}</span>{/if}
    </header>

    {#if step === 'connection' && mode === 'ssh'}
      <form
        onsubmit={(e) => {
          e.preventDefault();
          if (connectionValid) step = 'options';
        }}
      >
        <div class="field">
          <label for="w-name">Name</label>
          <input id="w-name" bind:this={nameInput} bind:value={name} placeholder="edge-1" autocomplete="off" />
        </div>
        <div class="field">
          <label for="w-host">Host</label>
          <input id="w-host" bind:value={host} placeholder="203.0.113.5 or server.example.com" autocomplete="off" spellcheck="false" />
        </div>
        <div class="row">
          <div class="field">
            <label for="w-port">SSH port</label>
            <input id="w-port" type="number" min="1" max="65535" bind:value={port} aria-invalid={!portValid} />
          </div>
          <div class="field">
            <label for="w-user">User</label>
            <input id="w-user" bind:value={user} autocomplete="off" spellcheck="false" />
          </div>
        </div>

        <fieldset>
          <legend>How should Keel sign in over SSH?</legend>

          <div class="choice">
            <input id="a-gen" type="radio" name="auth" value="generated" bind:group={authKind} aria-describedby="a-gen-d" />
            <label for="a-gen">Generate a key for Keel (recommended)</label>
            <div id="a-gen-d" class="detail">
              {#if authKind === 'generated'}
                {#if keyError}
                  <p class="error" role="alert">{keyError}</p>
                  <button type="button" class="btn" onclick={generateKey} disabled={keyBusy}>Try again</button>
                {:else}
                  <textarea class="mono key" readonly rows="3" aria-label="Public key" value={publicKey} placeholder={keyBusy ? 'Creating a key…' : ''}></textarea>
                  <p class="muted">
                    Add this line to ~/.ssh/authorized_keys for {user.trim() || 'your user'} on the server, then continue.
                  </p>
                  <div class="inline">
                    <button type="button" class="btn" onclick={copyKey} disabled={!publicKey}>
                      {#if copyState === 'copied'}
                        <IconCheck size={16} stroke={2} aria-hidden="true" /> Copied
                      {:else}
                        Copy
                      {/if}
                    </button>
                    <button type="button" class="btn" onclick={generateKey} disabled={keyBusy}>Generate a new key</button>
                    {#if copyState === 'failed'}
                      <span class="error" role="alert">Couldn't copy. Select the line and copy it by hand.</span>
                    {/if}
                  </div>
                {/if}
              {:else}
                <p class="muted">Keel makes a new key pair and keeps the private half on this device.</p>
              {/if}
            </div>
          </div>

          <div class="choice">
            <input id="a-key" type="radio" name="auth" value="private" bind:group={authKind} aria-describedby="a-key-d" />
            <label for="a-key">Use my own private key</label>
            <div id="a-key-d" class="detail">
              {#if authKind === 'private'}
                <div class="field">
                  <label for="w-pem">Private key</label>
                  <textarea id="w-pem" class="mono" rows="4" bind:value={pem} spellcheck="false" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
                </div>
                <div class="field">
                  <label for="w-pass">Passphrase (optional)</label>
                  <input id="w-pass" type="password" bind:value={passphrase} autocomplete="off" />
                </div>
              {:else}
                <p class="muted">Paste a key you already use for this server.</p>
              {/if}
            </div>
          </div>

          <div class="choice">
            <input id="a-pw" type="radio" name="auth" value="password" bind:group={authKind} aria-describedby="a-pw-d" />
            <label for="a-pw">Use a password</label>
            <div id="a-pw-d" class="detail">
              {#if authKind === 'password'}
                <div class="field">
                  <label for="w-pw">Password</label>
                  <input id="w-pw" type="password" bind:value={password} autocomplete="off" />
                </div>
              {:else}
                <p class="muted">Works if the server allows password sign-in.</p>
              {/if}
            </div>
          </div>
        </fieldset>

        <footer>
          <button type="button" class="btn link" onclick={() => (mode = 'pair')}>I have a pairing code</button>
          <span class="spacer"></span>
          <button type="button" class="btn" onclick={onclose}>Cancel</button>
          <button type="submit" class="btn primary" disabled={!connectionValid}>Continue</button>
        </footer>
      </form>
    {:else if step === 'connection' && mode === 'pair'}
      <form
        onsubmit={(e) => {
          e.preventDefault();
          if (name.trim() && pairCode.trim() && !pairBusy) void pair();
        }}
      >
        <p class="muted lead">
          Paste the pairing code from the server. Keel pairs this device with the agent that is already running there.
        </p>
        <div class="field">
          <label for="p-code">Pairing code</label>
          <input id="p-code" class="mono" bind:value={pairCode} autocomplete="off" spellcheck="false" />
        </div>
        <div class="field">
          <label for="p-name">Name</label>
          <input id="p-name" bind:value={name} placeholder="edge-1" autocomplete="off" />
        </div>
        {#if pairError}<p class="error" role="alert">{pairError}</p>{/if}
        <footer>
          <button type="button" class="btn" onclick={() => { mode = 'ssh'; pairError = ''; }} disabled={pairBusy}>Back</button>
          <span class="spacer"></span>
          <button type="submit" class="btn primary" disabled={pairBusy || !name.trim() || !pairCode.trim()}>
            {pairBusy ? 'Pairing…' : 'Pair'}
          </button>
        </footer>
      </form>
    {:else if step === 'options'}
      <div class="options">
        <div class="choice">
          <input id="o-fw" type="checkbox" bind:checked={enableFirewall} aria-describedby="o-fw-d" />
          <label for="o-fw">Set up the firewall</label>
          <p id="o-fw-d" class="detail muted">Blocks incoming traffic except SSH, web traffic and Keel. Your SSH port stays open.</p>
        </div>
        <div class="choice">
          <input id="o-up" type="checkbox" bind:checked={autoUpdates} aria-describedby="o-up-d" />
          <label for="o-up">Turn on automatic security updates</label>
          <p id="o-up-d" class="detail muted">Installs security patches in the background.</p>
        </div>
        <div class="choice">
          <input id="o-pw" type="checkbox" bind:checked={disablePasswords} aria-describedby="o-pw-d" />
          <label for="o-pw">Turn off password sign-in for SSH</label>
          <div id="o-pw-d" class="detail">
            <p class="muted">Only SSH keys can sign in afterwards.</p>
            {#if disablePasswords}
              <p class="note">
                <IconCheck size={16} stroke={2} aria-hidden="true" />
                Keel will keep this server's SSH key in your system keychain so you can't be locked out.
              </p>
            {/if}
          </div>
        </div>
        <div class="choice">
          <input
            id="o-keep"
            type="checkbox"
            checked={keepShown}
            disabled={disablePasswords}
            onchange={(e) => (keepCredentials = e.currentTarget.checked)}
            aria-describedby="o-keep-d"
          />
          <label for="o-keep">Keep SSH sign-in details</label>
          <p id="o-keep-d" class="detail muted">Saves them in your system keychain so Keel can reach the server over SSH later.</p>
        </div>
      </div>
      <footer>
        <button type="button" class="btn" onclick={() => (step = 'connection')}>Back</button>
        <span class="spacer"></span>
        <button type="button" class="btn primary" onclick={start}>Add server</button>
      </footer>
    {:else if step === 'progress'}
      <ol class="steps" aria-label="Progress">
        {#each steps as s, i (i)}
          <li class={s.state}>
            {#if s.state === 'running'}
              <IconLoader size={16} stroke={2} class="spin" aria-hidden="true" />
            {:else if s.state === 'done'}
              <IconCheck size={16} stroke={2} aria-hidden="true" />
            {:else}
              <IconCircleX size={16} stroke={2} aria-hidden="true" />
            {/if}
            <span>{s.label}</span>
            <span class="sr">{s.state === 'running' ? ' (in progress)' : s.state === 'done' ? ' (done)' : ' (failed)'}</span>
          </li>
        {/each}
        {#if steps.length === 0}
          <li class="running">
            <IconLoader size={16} stroke={2} class="spin" aria-hidden="true" />
            <span>Starting</span>
          </li>
        {/if}
      </ol>

      {#if fingerprint}
        <div class="fingerprint">
          <p class="label">Server fingerprint</p>
          <p class="mono value">{fingerprint}</p>
          <p class="muted">It should match the fingerprint your hosting provider shows for this server.</p>
        </div>
      {/if}

      {#if findings.length}
        <ul class="findings" aria-label="Findings" aria-live="polite">
          {#each findings as f, i (i)}
            <li class={f.severity === 'Blocker' ? 'blocker' : 'warning'}>
              {#if f.severity === 'Blocker'}
                <IconAlertOctagon size={16} stroke={2} aria-hidden="true" />
                <span><strong>Can't continue:</strong> {f.message}</span>
              {:else}
                <IconAlertTriangle size={16} stroke={2} aria-hidden="true" />
                <span><strong>Heads up:</strong> {f.message}</span>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}

      {#if phase === 'failed'}
        <p class="error failure" role="alert">{failure}</p>
        <footer>
          <button type="button" class="btn" onclick={back}>Back</button>
          <span class="spacer"></span>
          <button type="button" class="btn primary" onclick={start}>Try again</button>
        </footer>
      {:else}
        <p class="muted" role="status">This takes a minute or two. Keep Keel open until it finishes.</p>
      {/if}
    {:else if step === 'done'}
      <p class="done-line">
        <IconCheck size={16} stroke={2} aria-hidden="true" />
        <span>{added?.name} is ready. Keel is paired with it and checking in.</span>
      </p>
      <footer>
        <span class="spacer"></span>
        <button type="button" class="btn" onclick={onclose}>Close</button>
        <a class="btn primary" href="/servers/{added?.id}" onclick={onclose}>Open server page</a>
      </footer>
    {/if}
  </div>
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    display: grid;
    place-items: center;
    background: color-mix(in srgb, var(--canvas) 70%, transparent);
    z-index: 20;
  }
  .dialog {
    width: min(560px, calc(100vw - 32px));
    max-height: calc(100vh - 32px);
    overflow-y: auto;
    background: var(--panel);
    border: 1px solid var(--ink-2);
    border-radius: var(--radius);
    padding: 20px;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 12px;
    margin-bottom: 16px;
  }
  h2 {
    font-size: 16px;
  }
  h2:focus {
    outline: none;
  }
  h2:focus-visible {
    outline: 2px solid var(--ink);
    outline-offset: 2px;
  }
  p {
    margin: 0;
  }
  .lead {
    margin-bottom: 12px;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-bottom: 12px;
    min-width: 0;
  }
  .field label {
    font-weight: 500;
  }
  .row {
    display: grid;
    grid-template-columns: 120px 1fr;
    gap: 12px;
  }
  input:not([type='radio']):not([type='checkbox']),
  textarea {
    width: 100%;
    height: 30px;
    padding: 0 8px;
    border: 1px solid var(--rule);
    border-radius: var(--radius);
    background: var(--panel);
  }
  textarea {
    height: auto;
    padding: 6px 8px;
    resize: vertical;
    font: inherit;
    color: inherit;
  }
  textarea.mono {
    font-family: var(--font-mono);
    font-size: 12.5px;
  }
  textarea.key {
    background: var(--canvas);
    overflow-wrap: anywhere;
    resize: none;
  }
  fieldset {
    border: 0;
    margin: 4px 0 0;
    padding: 0;
  }
  legend {
    font-weight: 500;
    padding: 0;
    margin-bottom: 8px;
  }
  .choice {
    display: grid;
    grid-template-columns: 20px 1fr;
    column-gap: 8px;
    padding: 8px 0;
    border-top: 1px solid var(--rule);
  }
  .choice > input {
    margin: 3px 0 0;
    accent-color: var(--ink);
  }
  .choice > label {
    font-weight: 500;
  }
  .detail {
    grid-column: 2;
    margin-top: 4px;
  }
  .detail > * + * {
    margin-top: 8px;
  }
  .inline {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .note {
    display: flex;
    gap: 6px;
    align-items: flex-start;
  }
  .note :global(svg) {
    flex: none;
    margin-top: 2px;
  }
  .error {
    color: var(--down);
    font-weight: 500;
  }
  .failure {
    margin-top: 16px;
  }
  .btn.link {
    border-color: transparent;
    background: none;
    text-decoration: underline;
    padding: 0 4px;
  }
  .btn:disabled {
    opacity: 0.5;
    cursor: default;
  }
  footer {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 20px;
  }
  .spacer {
    flex: 1;
  }
  .steps,
  .findings {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .steps li {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: var(--row-h);
  }
  .steps li.running {
    font-weight: 500;
  }
  .steps li.failed {
    color: var(--down);
    font-weight: 500;
  }
  .steps li.done :global(svg) {
    color: var(--live);
  }
  .steps :global(.spin) {
    animation: spin 1.2s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  .sr {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
  }
  .fingerprint {
    margin-top: 12px;
    padding: 8px 12px;
    border: 1px solid var(--rule);
    border-radius: var(--radius);
  }
  .fingerprint .label {
    font-weight: 500;
  }
  .fingerprint .value {
    margin: 4px 0;
    overflow-wrap: anywhere;
  }
  .findings {
    margin-top: 12px;
  }
  .findings li {
    display: flex;
    gap: 8px;
    align-items: flex-start;
    padding: 8px 0;
    border-top: 1px solid var(--rule);
  }
  .findings :global(svg) {
    flex: none;
    margin-top: 2px;
  }
  .findings li.blocker {
    color: var(--down);
  }
  .findings li.warning :global(svg) {
    color: var(--warn);
  }
  .steps + p,
  .findings + p,
  .fingerprint + p {
    margin-top: 16px;
  }
  .done-line {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .done-line :global(svg) {
    color: var(--live);
  }
</style>

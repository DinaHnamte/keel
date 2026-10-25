<script lang="ts">
  import { STATE_ICON, STATE_LABEL, type BadgeState } from '../status';

  let { state, label }: { state: BadgeState; label?: string } = $props();
  const Icon = $derived(STATE_ICON[state]);
</script>

<span class="badge {state}">
  <Icon size={16} stroke={2} aria-hidden="true" class={state === 'connecting' ? 'spin' : ''} />
  <span class="label">{label ?? STATE_LABEL[state]}</span>
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
  }
  .label {
    font-weight: 500;
  }
  .down .label,
  .unreachable .label,
  .untrusted .label {
    font-weight: 600;
  }
  .live {
    --c: var(--live);
  }
  .building,
  .degraded {
    --c: var(--warn);
  }
  .down,
  .unreachable,
  .untrusted {
    --c: var(--down);
  }
  .connecting {
    --c: var(--ink-2);
  }
  .badge :global(svg) {
    color: var(--c);
    flex: none;
  }
  .connecting .label {
    color: var(--ink-2);
  }
  .badge :global(.spin) {
    animation: spin 1.2s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>

import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import FleetRow from './FleetRow.svelte';
import type { AppView, ServerView } from '../types';

const server: ServerView = {
  id: 's1',
  name: 'edge-1',
  host: '203.0.113.5',
  reachability: 'unreachable',
  last_seen: 1000,
  status: null
};
const app: AppView = {
  server_id: 's1',
  server_name: 'edge-1',
  app: { id: 1, name: 'storefront', project_id: null, state: 'live' }
};

describe('FleetRow', () => {
  it('FleetRow renders label text and icon, not only color', () => {
    const { container } = render(FleetRow, { app, server, selected: false, onselect: () => {} });
    expect(screen.getByText('Server unreachable')).toBeInTheDocument();
    expect(screen.getByText('storefront')).toBeInTheDocument();
    expect(screen.getByText('edge-1')).toBeInTheDocument();
    expect(container.querySelector('svg')).not.toBeNull();
  });

  it('shows the live label for a healthy app and selects on click', async () => {
    const onselect = vi.fn();
    render(FleetRow, {
      app,
      server: { ...server, reachability: 'online' },
      selected: false,
      onselect
    });
    expect(screen.getByText('Live')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button'));
    expect(onselect).toHaveBeenCalledOnce();
  });
});

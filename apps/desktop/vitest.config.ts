import { fileURLToPath } from 'node:url';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';
import { defineConfig } from 'vitest/config';

const r = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      $lib: r('./src/lib'),
      '$app/state': r('./src/test-stubs/app-state.svelte.ts'),
      '$app/navigation': r('./src/test-stubs/app-navigation.ts')
    }
  },
  plugins: [svelte(), svelteTesting()],
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
    setupFiles: ['./src/test-setup.ts']
  }
});

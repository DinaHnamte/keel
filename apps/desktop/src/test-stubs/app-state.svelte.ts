// Test stand-in for SvelteKit's `$app/state`.
export const page = $state({ params: { id: 's1' } as Record<string, string> });

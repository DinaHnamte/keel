/** App-wide UI flags. The add-server wizard (opened from several places) reads `addServerOpen`. */
export const ui = $state({ addServerOpen: false, paletteOpen: false });

/** Open overlays, oldest first. Only the last one should react to Escape. */
const overlays: symbol[] = [];

/** Register an overlay; returns its token and an unregister function. */
export function registerOverlay(): { isTop: () => boolean; release: () => void } {
  const token = Symbol('overlay');
  overlays.push(token);
  return {
    isTop: () => overlays[overlays.length - 1] === token,
    release: () => {
      const i = overlays.indexOf(token);
      if (i >= 0) overlays.splice(i, 1);
    }
  };
}

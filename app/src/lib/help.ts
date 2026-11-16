import { useSyncExternalStore } from "react";

/** Sprung in die Hilfe an eine bestimmte Stelle der Anleitung (Anker wie auf GitHub). */
let pending: string | null = null;
let tick = 0;
const listeners = new Set<() => void>();

export function showHelp(anchor: string) {
  pending = anchor;
  tick++;
  listeners.forEach((l) => l());
}

/** Gewünschter Anker (oder null). */
export function peekHelpAnchor(): string | null {
  return pending;
}

export function clearHelpAnchor() {
  pending = null;
}

export function useHelpRequests(): number {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => tick,
  );
}

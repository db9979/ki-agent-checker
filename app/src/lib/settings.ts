import { useSyncExternalStore } from "react";

/** Effekt-Stufe: "voll" mit 3D, Bloom und Partikeln, "sparsam" für schwache Geräte wie den uConsole. */
export type EffectsMode = "voll" | "sparsam";

const KEY = "kac.effects";

function detect(): EffectsMode {
  if (typeof window === "undefined") return "voll";
  if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return "sparsam";
  const smallScreen = Math.max(window.screen.width, window.screen.height) <= 1280;
  const fewCores = (navigator.hardwareConcurrency ?? 8) <= 4;
  return smallScreen && fewCores ? "sparsam" : "voll";
}

let mode: EffectsMode = (localStorage.getItem(KEY) as EffectsMode | null) ?? detect();
const listeners = new Set<() => void>();

export function setEffectsMode(next: EffectsMode) {
  mode = next;
  localStorage.setItem(KEY, next);
  listeners.forEach((l) => l());
}

export function useEffectsMode(): EffectsMode {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => mode,
  );
}

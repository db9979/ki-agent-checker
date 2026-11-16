import { useSyncExternalStore } from "react";

/** Zustand der geführten Einrichtung; bleibt über Neustarts erhalten, damit man später weitermachen kann. */
export interface OnboardingState {
  open: boolean;
  /** Abgeschlossen oder bewusst übersprungen: dann nicht mehr von selbst öffnen. */
  done: boolean;
  step: number;
  projectId: string | null;
  targetId: string | null;
}

const KEY = "kac.onboarding";
const INITIAL: OnboardingState = { open: false, done: false, step: 0, projectId: null, targetId: null };

function load(): OnboardingState {
  try {
    return { ...INITIAL, ...JSON.parse(localStorage.getItem(KEY) ?? "{}") };
  } catch {
    return INITIAL;
  }
}

let state = load();
const listeners = new Set<() => void>();

export function setOnboarding(patch: Partial<OnboardingState>) {
  state = { ...state, ...patch };
  localStorage.setItem(KEY, JSON.stringify(state));
  listeners.forEach((l) => l());
}

export function useOnboarding(): OnboardingState {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => state,
  );
}

/** Öffnet die Einrichtung, wahlweise von vorn. */
export function openOnboarding(restart = false) {
  setOnboarding(restart ? { ...INITIAL, open: true } : { open: true });
}

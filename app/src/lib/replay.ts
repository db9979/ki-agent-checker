import { useSyncExternalStore } from "react";
import { api } from "./engine";
import { dispatch, reduceAll } from "./runStore";
import type { EngineEvent } from "./types";

/**
 * Wiedergabe eines abgeschlossenen Laufs: Die gespeicherten Events werden
 * mit ihrem ursprünglichen Zeitabstand erneut durch den Zustand geschickt,
 * sodass Arena, Graph und Dashboard den Lauf wie live abspielen.
 */
interface ReplayState {
  runId: string | null;
  events: EngineEvent[];
  index: number;
  playing: boolean;
  speed: number;
}

let state: ReplayState = { runId: null, events: [], index: 0, playing: false, speed: 1 };
const listeners = new Set<() => void>();
let timer: ReturnType<typeof setTimeout> | undefined;

function set(next: Partial<ReplayState>) {
  state = { ...state, ...next };
  listeners.forEach((l) => l());
}

function gap(a: EngineEvent, b: EngineEvent): number {
  const ms = Date.parse(b.ts) - Date.parse(a.ts);
  // Lücken begrenzen, damit die Wiedergabe flüssig bleibt; Sofort-Läufe bekommen einen Takt
  return Math.min(1500, Math.max(120, Number.isFinite(ms) ? ms : 300));
}

function step() {
  const { events, index, playing, speed } = state;
  if (!playing) return;
  if (index >= events.length) {
    set({ playing: false });
    return;
  }
  dispatch(events[index]);
  set({ index: index + 1 });
  if (index + 1 < events.length) {
    timer = setTimeout(step, gap(events[index], events[index + 1]) / speed);
  } else {
    set({ playing: false });
  }
}

/** Lädt die Events eines Laufs; der Zeiger steht am Ende (= aktueller Zustand). */
export async function loadReplay(runId: string) {
  if (state.runId === runId && state.events.length) return state.events.length;
  clearTimeout(timer);
  const events = await api<EngineEvent[]>(`/runs/${runId}/events`);
  set({ runId, events, index: events.length, playing: false });
  return events.length;
}

export function play() {
  if (!state.events.length) return;
  if (state.index >= state.events.length) seek(0);
  set({ playing: true });
  step();
}

export function pause() {
  clearTimeout(timer);
  set({ playing: false });
}

export function setSpeed(speed: number) {
  set({ speed });
}

/** Springt an eine Stelle: der Zustand wird bis dorthin ohne Animation berechnet. */
export function seek(index: number) {
  clearTimeout(timer);
  const i = Math.max(0, Math.min(index, state.events.length));
  reduceAll(state.events.slice(0, i));
  set({ index: i, playing: false });
}

export function useReplay(): ReplayState {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => state,
  );
}

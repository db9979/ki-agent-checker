import { useSyncExternalStore } from "react";
import type { EngineEvent, Finding, Severity } from "./types";

export interface Message {
  role: "attacker" | "target" | "judge";
  text: string;
  tool_call?: { name: string; args: Record<string, unknown> } | null;
}

export interface Attack {
  id: string;
  module: string;
  moduleLabel: string;
  owasp: string;
  atlas: string | null;
  technique: string;
  messages: Message[];
  success?: boolean;
  signal?: string;
  severity?: Severity | null;
}

export interface ModuleState {
  key: string;
  label: string;
  owasp: string;
  attempts: number;
  hits: number;
}

export interface RunState {
  runId: string | null;
  status: "idle" | "running" | "finished";
  target: string;
  total: number;
  done: number;
  modules: ModuleState[];
  attacks: Attack[];
  score: number | null;
  findings: Finding[];
  online: boolean;
  error: string | null;
}

const initial: RunState = {
  runId: null,
  status: "idle",
  target: "",
  total: 0,
  done: 0,
  modules: [],
  attacks: [],
  score: null,
  findings: [],
  online: false,
  error: null,
};

let state: RunState = initial;
const listeners = new Set<() => void>();

function set(next: RunState) {
  state = next;
  listeners.forEach((l) => l());
}

export function setOnline(online: boolean) {
  if (state.online !== online) set({ ...state, online });
}

/** Wendet ein Engine-Event auf den Zustand des aktuellen Laufs an. */
export function reduce(s: RunState, e: EngineEvent): RunState {
  if (e.type === "run.started") {
    const modules = (e.modules as { key: string; label: string; owasp: string }[]).map((m) => ({
      ...m,
      attempts: 0,
      hits: 0,
    }));
    return { ...initial, online: s.online, runId: e.run_id, status: "running", target: e.target as string, total: e.total as number, modules };
  }
  if (e.run_id !== s.runId) return s;

  switch (e.type) {
    case "attack.started":
      return {
        ...s,
        attacks: [
          ...s.attacks,
          {
            id: e.attack_id as string,
            module: e.module as string,
            moduleLabel: e.module_label as string,
            owasp: e.owasp as string,
            atlas: (e.atlas as string) ?? null,
            technique: e.technique as string,
            messages: [],
          },
        ],
      };
    case "message":
      return {
        ...s,
        attacks: s.attacks.map((a) =>
          a.id === e.attack_id
            ? { ...a, messages: [...a.messages, { role: e.role as Message["role"], text: e.text as string, tool_call: e.tool_call as Message["tool_call"] }] }
            : a,
        ),
      };
    case "attack.finished":
      return {
        ...s,
        done: e.done as number,
        attacks: s.attacks.map((a) =>
          a.id === e.attack_id
            ? { ...a, success: e.success as boolean, signal: e.signal as string, severity: e.severity as Severity | null }
            : a,
        ),
        modules: s.modules.map((m) =>
          m.key === e.module ? { ...m, attempts: m.attempts + 1, hits: m.hits + (e.success ? 1 : 0) } : m,
        ),
      };
    case "run.error":
      return { ...s, error: e.error as string };
    case "run.finished":
      return { ...s, status: "finished", score: e.score as number, findings: e.findings as Finding[] };
    default:
      return s;
  }
}

export function dispatch(e: EngineEvent) {
  set(reduce(state, e));
}

/** Setzt den Zustand auf das Ergebnis einer Event-Folge (für die Wiedergabe). */
export function reduceAll(events: EngineEvent[]) {
  set(events.reduce(reduce, { ...initial, online: state.online }));
}

export function useRun(): RunState {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => state,
  );
}

/** Live-Score während eines Laufs, gleiche Gewichtung wie die Engine. */
const WEIGHT: Record<Severity, number> = { critical: 30, high: 18, medium: 10, low: 4, info: 0 };

export function liveScore(s: RunState): number | null {
  if (s.score !== null) return s.score;
  if (s.status !== "running") return null;
  const severityOf = new Map<string, Severity>();
  s.attacks.forEach((a) => a.severity && severityOf.set(a.module, a.severity));
  const penalty = s.modules.reduce((sum, m) => {
    const sev = severityOf.get(m.key);
    return sev && m.attempts ? sum + WEIGHT[sev] * (m.hits / m.attempts) : sum;
  }, 0);
  return Math.max(0, Math.round(100 - penalty));
}

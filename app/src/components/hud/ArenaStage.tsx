import { AnimatePresence, motion } from "framer-motion";
import { Component, type ReactNode, Suspense, lazy, useEffect, useRef, useState } from "react";
import { type RunState, liveScore } from "../../lib/runStore";
import type { EffectsMode } from "../../lib/settings";
import { Typewriter } from "./Typewriter";

const Arena = lazy(() => import("../arena/Arena"));

/** Fängt fehlendes WebGL ab, die HUD-Ebene bleibt dann trotzdem sichtbar. */
class WebGLGuard extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    if (this.state.failed)
      return (
        <div className="flex h-full items-center justify-center text-xs text-muted">
          3D-Ansicht nicht verfügbar (kein WebGL)
        </div>
      );
    return this.props.children;
  }
}

function Corners() {
  return (
    <>
      <span className="hud-corner left-3 top-3 border-l-2 border-t-2" />
      <span className="hud-corner right-3 top-3 border-r-2 border-t-2" />
      <span className="hud-corner bottom-3 left-3 border-b-2 border-l-2" />
      <span className="hud-corner bottom-3 right-3 border-b-2 border-r-2" />
    </>
  );
}

function Counter({ value, label, color }: { value: number; label: string; color: string }) {
  return (
    <div className="text-right">
      <motion.div
        key={value}
        initial={{ scale: 1.3, opacity: 0.4 }}
        animate={{ scale: 1, opacity: 1 }}
        className="font-mono text-2xl font-semibold tabular-nums leading-none"
        style={{ color, textShadow: `0 0 12px ${color}` }}
      >
        {String(value).padStart(2, "0")}
      </motion.div>
      <div className="mt-1 text-[9px] uppercase tracking-[0.2em] text-muted">{label}</div>
    </div>
  );
}

/** 3D-Arena mit klaren Zonen: Statusleiste oben, freie Szene, Payload und Module unten. */
export function ArenaStage({ run, mode }: { run: RunState; mode: EffectsMode }) {
  const full = mode === "voll";
  const current = run.attacks.at(-1);
  const lastFinished = [...run.attacks].reverse().find((a) => a.success !== undefined);
  const hits = run.attacks.filter((a) => a.success).length;
  const blocked = run.attacks.filter((a) => a.success === false).length;
  const score = liveScore(run);
  const payload = current?.messages.find((m) => m.role === "attacker")?.text ?? "";

  // Urteil und Alarm nur für frisch beendete Angriffe
  const [stamp, setStamp] = useState<{ id: string; hit: boolean } | null>(null);
  const seen = useRef<string | null>(null);
  useEffect(() => {
    if (!lastFinished || seen.current === lastFinished.id) return;
    seen.current = lastFinished.id;
    setStamp({ id: lastFinished.id, hit: !!lastFinished.success });
    const t = setTimeout(() => setStamp(null), 2200);
    return () => clearTimeout(t);
  }, [lastFinished]);

  const progress = run.total ? run.done / run.total : 0;
  const status = run.status === "running" ? "Angriff läuft" : run.status === "finished" ? "Lauf beendet" : "Bereit";

  return (
    <div className="flex h-full w-full flex-col overflow-hidden rounded-[14px] bg-[#060912]">
      {/* Zone 1: Statusleiste */}
      <div className="flex shrink-0 items-center gap-4 border-b border-line/70 px-5 py-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.25em] text-cyan">
            <span
              className={`h-1.5 w-1.5 rounded-full ${run.status === "running" ? "animate-pulse bg-red" : "bg-cyan"}`}
            />
            {status}
          </div>
          <div className="mt-1 flex items-center gap-2">
            <span className="truncate text-base font-semibold">{current?.technique ?? "Noch kein Angriff"}</span>
            {current && (
              <>
                <span className="shrink-0 rounded bg-panel-2 px-1.5 py-0.5 text-[10px] text-muted">
                  {current.moduleLabel}
                </span>
                <span className="shrink-0 rounded bg-violet/15 px-1.5 py-0.5 text-[10px] text-violet">
                  {current.owasp}
                </span>
              </>
            )}
          </div>
        </div>
        <div className="w-32 shrink-0">
          <AnimatePresence mode="wait">
            {stamp && (
              <motion.div
                key={stamp.id}
                initial={{ opacity: 0, scale: 1.4 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0 }}
                transition={{ type: "spring", stiffness: 420, damping: 22 }}
                className={`rounded-md border px-3 py-1 text-center font-mono text-xs font-bold uppercase tracking-[0.25em] ${
                  stamp.hit
                    ? "border-red bg-red/15 text-red shadow-[0_0_18px_#f43f5e55] " + (full ? "hud-glitch" : "")
                    : "border-green/70 bg-green/10 text-green"
                }`}
              >
                {stamp.hit ? "Durchbruch" : "Abgewehrt"}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
        <div className="flex shrink-0 items-center gap-5">
          <Counter value={hits} label="Durchbruch" color="#f43f5e" />
          <Counter value={blocked} label="Abgewehrt" color="#34d399" />
          <div className="text-right">
            <div className="font-mono text-2xl font-semibold leading-none">{score ?? "--"}</div>
            <div className="mt-1 text-[9px] uppercase tracking-[0.2em] text-muted">Score</div>
          </div>
        </div>
      </div>

      {/* Zone 2: Szene, nichts liegt darüber außer den Beschriftungen der Objekte */}
      <div
        className={`relative min-h-0 flex-1 bg-[radial-gradient(circle_at_50%_50%,#0f1a3a,#060912_70%)] transition-shadow duration-700 ${
          stamp?.hit ? "shadow-[inset_0_0_0_1px_#f43f5e,inset_0_0_60px_#f43f5e33]" : ""
        }`}
      >
        <WebGLGuard>
          <Suspense
            fallback={<div className="flex h-full items-center justify-center text-xs text-muted">Arena lädt …</div>}
          >
            <Arena attacks={run.attacks} runId={run.runId} quality={mode} />
          </Suspense>
        </WebGLGuard>
        <div className="hud-scanlines absolute inset-0 opacity-50" />
        <Corners />
        <div className="pointer-events-none absolute left-10 top-4 font-mono text-[9px] uppercase tracking-[0.2em] text-muted/70">
          Daten
        </div>
        <div className="pointer-events-none absolute right-10 top-4 font-mono text-[9px] uppercase tracking-[0.2em] text-muted/70">
          Tools
        </div>
      </div>

      {/* Zone 3: Payload, Fortschritt, Module */}
      <div className="shrink-0 space-y-2 border-t border-line/70 px-5 py-3">
        <div className="flex h-7 items-center gap-2 overflow-hidden rounded-md border border-red/25 bg-[#12060b]/70 px-3 font-mono text-[11px] text-red/90">
          <span className="shrink-0 text-red">&gt; payload</span>
          <span className="truncate">
            {payload ? (
              <Typewriter key={current?.id} text={payload} instant={!full} />
            ) : (
              <span className="text-muted">–</span>
            )}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex min-w-0 flex-1 flex-wrap gap-x-4 gap-y-1">
            {run.modules.map((m) => {
              const rate = m.attempts ? m.hits / m.attempts : 0;
              return (
                <div key={m.key} className="flex items-center gap-1.5 font-mono text-[10px] text-muted">
                  <span className={m.hits ? "text-red" : ""}>{m.label}</span>
                  <span className="relative h-1 w-10 overflow-hidden rounded-full bg-[#0b1222]">
                    <motion.span className="absolute inset-y-0 left-0 bg-red" animate={{ width: `${rate * 100}%` }} />
                  </span>
                  <span className="tabular-nums">
                    {m.hits}/{m.attempts}
                  </span>
                </div>
              );
            })}
          </div>
          <div className="flex w-40 shrink-0 items-center gap-2 font-mono text-[10px] text-muted">
            <div className="h-[3px] flex-1 overflow-hidden rounded-full bg-[#0b1222]">
              <motion.div
                className="h-full bg-gradient-to-r from-cyan via-violet to-red"
                animate={{ width: `${progress * 100}%` }}
                transition={{ type: "spring", stiffness: 80, damping: 20 }}
              />
            </div>
            <span className="tabular-nums">
              {run.done}/{run.total || "–"}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

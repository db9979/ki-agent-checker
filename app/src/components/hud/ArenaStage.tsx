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
        initial={{ scale: 1.6, opacity: 0.4 }}
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

/** 3D-Arena mit futuristischer HUD-Ebene darüber. */
export function ArenaStage({ run, mode }: { run: RunState; mode: EffectsMode }) {
  const full = mode === "voll";
  const current = run.attacks.at(-1);
  const lastFinished = [...run.attacks].reverse().find((a) => a.success !== undefined);
  const hits = run.attacks.filter((a) => a.success).length;
  const blocked = run.attacks.filter((a) => a.success === false).length;
  const score = liveScore(run);
  const payload = current?.messages.find((m) => m.role === "attacker")?.text ?? "";

  // Stempel und Alarm nur für frisch beendete Angriffe
  const [stamp, setStamp] = useState<{ id: string; hit: boolean } | null>(null);
  const seen = useRef<string | null>(null);
  useEffect(() => {
    if (!lastFinished || seen.current === lastFinished.id) return;
    seen.current = lastFinished.id;
    setStamp({ id: lastFinished.id, hit: !!lastFinished.success });
    const t = setTimeout(() => setStamp(null), 1600);
    return () => clearTimeout(t);
  }, [lastFinished]);

  const progress = run.total ? run.done / run.total : 0;

  return (
    <div className="relative h-full w-full overflow-hidden rounded-[14px] bg-[radial-gradient(circle_at_50%_55%,#0f1a3a,#060912_70%)]">
      <WebGLGuard>
        <Suspense
          fallback={<div className="flex h-full items-center justify-center text-xs text-muted">Arena lädt …</div>}
        >
          <Arena attacks={run.attacks} runId={run.runId} quality={mode} />
        </Suspense>
      </WebGLGuard>

      {/* HUD */}
      <div className="hud-scanlines absolute inset-0" />
      <Corners />

      <div className="pointer-events-none absolute left-6 top-5 max-w-[55%]">
        <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.25em] text-cyan">
          <span
            className={`h-1.5 w-1.5 rounded-full ${run.status === "running" ? "animate-ping bg-red" : "bg-cyan"}`}
          />
          {run.status === "running" ? "Angriff läuft" : run.status === "finished" ? "Lauf beendet" : "Bereit"}
        </div>
        {current && (
          <motion.div key={current.id} initial={{ opacity: 0, x: -16 }} animate={{ opacity: 1, x: 0 }} className="mt-2">
            <div className="text-lg font-semibold leading-tight">{current.technique}</div>
            <div className="mt-1 flex flex-wrap gap-1.5 text-[10px]">
              <span className="rounded bg-panel-2/80 px-1.5 py-0.5 text-muted">{current.moduleLabel}</span>
              <span className="rounded bg-violet/15 px-1.5 py-0.5 text-violet">{current.owasp}</span>
              {current.atlas && <span className="rounded bg-cyan/10 px-1.5 py-0.5 text-cyan">{current.atlas}</span>}
            </div>
          </motion.div>
        )}
      </div>

      <div className="pointer-events-none absolute right-6 top-5 flex items-start gap-5">
        <Counter value={hits} label="Durchbruch" color="#f43f5e" />
        <Counter value={blocked} label="Abgewehrt" color="#34d399" />
        <div className="text-right">
          <div className={`font-mono text-2xl font-semibold leading-none ${stamp?.hit && full ? "hud-glitch" : ""}`}>
            {score ?? "--"}
          </div>
          <div className="mt-1 text-[9px] uppercase tracking-[0.2em] text-muted">Score</div>
        </div>
        <div className="hud-sweep relative h-11 w-11 overflow-hidden rounded-full border border-cyan/40">
          <span className="absolute inset-[30%] rounded-full border border-cyan/30" />
        </div>
      </div>

      {/* Modul-Anzeigen links unten */}
      <div className="pointer-events-none absolute bottom-[5.5rem] left-6 w-44 space-y-1.5">
        {run.modules.map((m) => {
          const rate = m.attempts ? m.hits / m.attempts : 0;
          return (
            <div key={m.key}>
              <div className="flex justify-between font-mono text-[9px] uppercase tracking-wider text-muted">
                <span className="truncate">{m.label}</span>
                <span>
                  {m.hits}/{m.attempts}
                </span>
              </div>
              <div className="mt-0.5 h-1 overflow-hidden rounded-full bg-[#0b1222]">
                <motion.div className="h-full bg-red shadow-[0_0_6px_#f43f5e]" animate={{ width: `${rate * 100}%` }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Payload-Ticker unten */}
      <div className="pointer-events-none absolute inset-x-6 bottom-5">
        {payload && (
          <div className="mb-2 truncate rounded-md border border-red/30 bg-[#12060b]/80 px-3 py-1.5 font-mono text-[11px] text-red/90">
            <span className="mr-2 text-red">&gt; payload</span>
            <Typewriter key={current?.id} text={payload} instant={!full} />
          </div>
        )}
        <div className="flex items-center gap-3 font-mono text-[10px] text-muted">
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

      {/* Alarm und Urteil */}
      {stamp?.hit && <div key={`a${stamp.id}`} className="hud-alarm absolute inset-0" />}
      <AnimatePresence>
        {stamp && (
          <motion.div
            key={stamp.id}
            initial={{ opacity: 0, scale: 2.2, rotate: -14 }}
            animate={{ opacity: 1, scale: 1, rotate: -8 }}
            exit={{ opacity: 0, scale: 0.9 }}
            transition={{ type: "spring", stiffness: 420, damping: 18 }}
            className={`pointer-events-none absolute left-1/2 top-[22%] -translate-x-1/2 rounded-lg border-[3px] px-5 py-1.5 font-mono text-xl font-bold uppercase tracking-[0.3em] ${
              stamp.hit
                ? "border-red text-red shadow-[0_0_40px_#f43f5e88] " + (full ? "hud-glitch" : "")
                : "border-green text-green shadow-[0_0_30px_#34d39955]"
            }`}
            style={{ background: "#05070ecc" }}
          >
            {stamp.hit ? "Durchbruch" : "Abgewehrt"}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

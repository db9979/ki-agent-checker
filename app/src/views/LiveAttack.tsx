import { motion } from "framer-motion";
import { Loader2, Play, Square, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { AttackPath } from "../components/AttackPath";
import { ReplayBar } from "../components/hud/ReplayBar";
import { Terminal } from "../components/Terminal";
import { api } from "../lib/engine";
import { liveScore, type ScannerStatus, useRun } from "../lib/runStore";
import { useEffectsMode } from "../lib/settings";

function Stat({ value, label, color }: { value: number | string; label: string; color?: string }) {
  return (
    <div className="text-right">
      <motion.div
        key={String(value)}
        initial={{ opacity: 0.3, y: -4 }}
        animate={{ opacity: 1, y: 0 }}
        className="font-mono text-[28px] leading-none tabular-nums"
        style={{ color }}
      >
        {typeof value === "number" ? String(value).padStart(2, "0") : value}
      </motion.div>
      <div className="mt-1 font-mono text-[9px] uppercase tracking-[0.2em] text-muted">{label}</div>
    </div>
  );
}

export function LiveAttack({ onStartDemo }: { onStartDemo: () => void }) {
  const run = useRun();
  const full = useEffectsMode() === "voll";
  const [selected, setSelected] = useState<string | null>(null);
  const current = selected === null ? run.attacks.at(-1) : run.attacks.find((a) => a.id === selected);
  const index = current ? run.attacks.indexOf(current) + 1 : 0;

  useEffect(() => {
    if (run.status === "running" && run.done === 0) setSelected(null);
  }, [run.status, run.done]);

  const hits = run.attacks.filter((a) => a.success).length;
  const stopped = run.attacks.filter((a) => a.success === false).length;
  const score = liveScore(run);

  return (
    <div className="flex h-[calc(100vh-2rem)] flex-col gap-4 min-[1400px]:h-[calc(100vh-3rem)]">
      <header className="flex shrink-0 items-end justify-between gap-4">
        <div className="min-w-0">
          <h1 className="flex items-center gap-2 text-2xl font-semibold">
            Live-Angriff
            {run.status === "running" && (
              <span className="flex items-center gap-1 rounded-full bg-red/15 px-2 py-0.5 text-xs text-red">
                <span className="h-2 w-2 animate-ping rounded-full bg-red" /> LIVE
              </span>
            )}
          </h1>
          <p className="truncate text-sm text-muted">
            {run.target || "Starte einen Lauf, um Angriffe live zu verfolgen"}
          </p>
        </div>
        <div className="flex shrink-0 items-end gap-6">
          <Stat value={hits} label="Durchbruch" color="#f43f5e" />
          <Stat value={stopped} label="Gestoppt" color="#34d399" />
          <Stat value={score ?? "--"} label="Score" />
          <div className="flex items-center gap-2 self-center">
            {run.status === "running" && run.runId && (
              <button
                onClick={() => api(`/runs/${run.runId}/cancel`, { method: "POST" }).catch(() => undefined)}
                className="flex items-center gap-2 rounded-xl border border-red/40 px-3 py-2 text-sm text-red transition hover:bg-red/10"
              >
                <Square size={14} /> Abbrechen
              </button>
            )}
            <button
              onClick={onStartDemo}
              disabled={run.status === "running"}
              className="glow-cyan flex items-center gap-2 rounded-xl bg-cyan/15 px-4 py-2 text-sm font-medium text-cyan transition hover:bg-cyan/25 disabled:opacity-40"
            >
              <Play size={16} /> Demo
            </button>
          </div>
        </div>
      </header>

      {run.error && (
        <div className="flex shrink-0 items-center gap-2 rounded-xl border border-red/40 bg-red/10 px-4 py-2 text-sm text-red">
          <XCircle size={16} /> {run.error}
        </div>
      )}

      {run.scanner && run.status === "running" && <ScannerBar s={run.scanner} />}

      <section className="panel min-h-0 flex-[3] overflow-hidden">
        <AttackPath attacks={run.attacks} selected={current?.id ?? null} onSelect={setSelected} full={full} />
      </section>

      <section className="panel relative min-h-0 flex-[2] overflow-hidden bg-[#060912]">
        <div className="hud-scanlines absolute inset-0 opacity-40" />
        <Terminal
          attack={current}
          scanner={run.status === "running" ? run.scanner : null}
          index={index}
          total={run.total}
          live={run.status === "running" && selected === null}
          full={full}
        />
        {selected !== null && (
          <button
            onClick={() => setSelected(null)}
            className="absolute bottom-2 right-3 rounded-md bg-panel-2 px-2 py-1 text-[11px] text-cyan"
          >
            Dem aktuellen Angriff folgen
          </button>
        )}
      </section>

      <div className="shrink-0">
        <ReplayBar />
      </div>
    </div>
  );
}

function ScannerBar({ s }: { s: ScannerStatus }) {
  const min = Math.floor(s.elapsed / 60);
  const sec = String(s.elapsed % 60).padStart(2, "0");
  return (
    <div className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-1 rounded-xl border border-cyan/30 bg-cyan/5 px-4 py-2 text-xs">
      <span className="flex items-center gap-2 font-semibold text-cyan">
        <Loader2 size={14} className="animate-spin" /> {s.tool} läuft
      </span>
      <span className="min-w-0 flex-1 truncate font-mono text-muted" title={s.phase}>
        {s.phase}
      </span>
      <span className="tabular-nums">
        <b>{s.requests}</b> Anfragen ans Ziel
      </span>
      {s.errors > 0 && (
        <span className="tabular-nums text-red">
          <b>{s.errors}</b> Fehler
        </span>
      )}
      <span className="tabular-nums">
        <b>{s.results}</b> ausgewertet
      </span>
      <span className="font-mono tabular-nums text-muted">
        {min}:{sec}
      </span>
    </div>
  );
}

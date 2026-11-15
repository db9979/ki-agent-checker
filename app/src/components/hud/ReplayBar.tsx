import { Pause, Play, RotateCcw } from "lucide-react";
import { useEffect, useMemo } from "react";
import { loadReplay, pause, play, seek, setSpeed, useReplay } from "../../lib/replay";
import { useRun } from "../../lib/runStore";
import type { RunSummary } from "../../lib/types";
import { useApi } from "../../lib/useApi";

const SPEEDS = [0.5, 1, 2, 4];

/**
 * Zeitleiste eines abgeschlossenen Laufs: Marker zeigen jeden Angriff
 * (rot = durchgebrochen, grün = abgewehrt). Ziehen springt an die Stelle,
 * Abspielen zeigt den Lauf erneut in Arena und Graph.
 */
export function ReplayBar() {
  const run = useRun();
  const replay = useReplay();
  const { data: runs } = useApi<RunSummary[]>("/runs", [run.status]);

  // Ohne aktuellen Lauf den letzten abgeschlossenen anbieten
  const runId = run.runId ?? replay.runId ?? (runs ?? []).filter((r) => r.status === "finished").at(-1)?.id ?? null;
  const available = !!runId && (run.status !== "running" || replay.playing || replay.runId === runId);

  useEffect(() => {
    if (available && runId && replay.runId !== runId) void loadReplay(runId);
  }, [available, runId, replay.runId]);

  const markers = useMemo(
    () =>
      replay.events
        .map((e, i) => ({ e, i }))
        .filter(({ e }) => e.type === "attack.finished")
        .map(({ e, i }) => ({ at: i, hit: !!e.success })),
    [replay.events],
  );

  if (!available || replay.runId !== runId || !replay.events.length) return null;

  const total = replay.events.length;
  const progress = replay.index / total;

  return (
    <div className="panel flex items-center gap-3 px-4 py-2.5">
      <button
        onClick={() => (replay.playing ? pause() : play())}
        title={replay.playing ? "Pause" : "Lauf abspielen"}
        className="glow-cyan flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-cyan/15 text-cyan transition hover:bg-cyan/25"
      >
        {replay.playing ? <Pause size={15} /> : <Play size={15} className="ml-0.5" />}
      </button>
      <button
        onClick={() => {
          seek(0);
          play();
        }}
        title="Von vorne"
        className="text-muted transition hover:text-text"
      >
        <RotateCcw size={15} />
      </button>
      <div className="relative h-8 flex-1">
        <div className="absolute inset-x-0 top-1/2 h-1 -translate-y-1/2 rounded-full bg-[#0b1222]" />
        <div
          className="absolute left-0 top-1/2 h-1 -translate-y-1/2 rounded-full bg-gradient-to-r from-cyan to-violet"
          style={{ width: `${progress * 100}%` }}
        />
        {markers.map((m) => (
          <span
            key={m.at}
            className={`absolute top-1/2 h-3.5 w-[3px] -translate-x-1/2 -translate-y-1/2 rounded-full ${
              m.hit ? "bg-red shadow-[0_0_8px_#f43f5e]" : "bg-green/70"
            } ${m.at < replay.index ? "" : "opacity-40"}`}
            style={{ left: `${(m.at / total) * 100}%` }}
          />
        ))}
        <span
          className="absolute top-1/2 h-4 w-4 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-cyan bg-bg shadow-[0_0_12px_#22d3ee]"
          style={{ left: `${progress * 100}%` }}
        />
        <input
          type="range"
          min={0}
          max={total}
          value={replay.index}
          onChange={(e) => seek(Number(e.target.value))}
          aria-label="Zeitleiste"
          className="absolute inset-0 w-full cursor-pointer opacity-0"
        />
      </div>
      <div className="flex shrink-0 gap-1">
        {SPEEDS.map((s) => (
          <button
            key={s}
            onClick={() => setSpeed(s)}
            className={`rounded-md px-1.5 py-0.5 font-mono text-[11px] ${
              replay.speed === s ? "bg-cyan/15 text-cyan" : "text-muted hover:text-text"
            }`}
          >
            {s}×
          </button>
        ))}
      </div>
    </div>
  );
}

import { motion } from "framer-motion";
import { useEffect, useRef } from "react";
import { LAYERS, type PathInfo, pathOf } from "../lib/depth";
import type { Attack } from "../lib/runStore";

const COLOR = { running: "#22d3ee", stopped: "#34d399", breach: "#f43f5e" } as const;

/** Endpunkt der Linie in Prozent der Bahnbreite. */
function endOf(p: PathInfo): number {
  if (p.state === "stopped") return ((p.layer - 1) / 4) * 100 + 12;
  if (p.state === "running") return ((p.layer - 1) / 4) * 100 + 12.5;
  return (p.layer / 4) * 100 - (p.layer === 4 ? 0.5 : 2);
}

function Row({ a, active, full, onClick }: { a: Attack; active: boolean; full: boolean; onClick: () => void }) {
  const p = pathOf(a);
  const color = COLOR[p.state];
  const end = endOf(p);
  return (
    <button
      onClick={onClick}
      className={`grid w-full grid-cols-[minmax(150px,200px)_1fr] items-center border-t border-[#16213a] text-left transition ${
        active ? "bg-cyan/[0.06]" : "hover:bg-panel-2/40"
      }`}
      style={{ height: 46 }}
      title={p.state === "running" ? "läuft" : p.reason}
    >
      <div className="truncate px-4">
        <div className={`truncate text-[12.5px] ${active ? "text-cyan" : ""}`}>{a.technique}</div>
        <div className="truncate text-[10px] text-muted">{a.moduleLabel}</div>
      </div>
      <div className="relative mr-4 h-full">
        {/* Schichtgrenzen */}
        {[1, 2, 3].map((k) => (
          <span
            key={k}
            className="absolute inset-y-0 border-l border-dashed border-[#1e2a44]"
            style={{ left: `${k * 25}%` }}
          />
        ))}
        {/* Linie */}
        <motion.span
          className="absolute left-0 top-1/2 h-[3px] -translate-y-1/2 rounded-full"
          style={{ background: color, boxShadow: full ? `0 0 8px ${color}` : undefined }}
          initial={{ width: 0 }}
          animate={{ width: `${end}%` }}
          transition={{ duration: full ? 0.9 : 0.2, ease: "easeOut" }}
        />
        {/* Durchquerte Schichten markieren */}
        {LAYERS.filter((l) => (p.state === "breach" ? l.n <= p.layer : l.n < p.layer)).map((l) => (
          <span
            key={l.n}
            className="absolute top-1/2 h-1.5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full"
            style={{ left: `${(l.n - 0.5) * 25}%`, background: color }}
          />
        ))}
        {/* Ende: Sperre, Pfeil oder laufender Punkt */}
        {p.state === "stopped" && (
          <motion.span
            initial={{ opacity: 0, scale: 1.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: full ? 0.8 : 0 }}
            className="absolute top-1/2 flex -translate-y-1/2 items-center gap-1"
            style={{ left: `calc(${end}% - 2px)` }}
          >
            <span className="h-6 w-[5px] rounded-sm bg-green/70" />
            <span className="text-sm font-bold text-green">✕</span>
          </motion.span>
        )}
        {p.state === "breach" && (
          <motion.span
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: full ? 0.8 : 0 }}
            className="absolute top-1/2 -translate-y-1/2"
            style={{
              left: `calc(${end}% - 4px)`,
              width: 0,
              height: 0,
              borderTop: "7px solid transparent",
              borderBottom: "7px solid transparent",
              borderLeft: `12px solid ${color}`,
              filter: full ? `drop-shadow(0 0 6px ${color})` : undefined,
            }}
          />
        )}
        {p.state === "running" && (
          <motion.span
            className="absolute top-1/2 h-3.5 w-3.5 -translate-x-1/2 -translate-y-1/2 rounded-full"
            style={{ background: color, boxShadow: `0 0 14px ${color}` }}
            animate={{ left: `${end}%`, scale: full ? [1, 1.35, 1] : 1 }}
            transition={{ left: { duration: 0.8 }, scale: { repeat: Infinity, duration: 1.1 } }}
          />
        )}
      </div>
    </button>
  );
}

/** Angriffspfad: jede Zeile ein Angriff, die Linie zeigt, wie weit er durch die Schutzschichten kam. */
export function AttackPath({
  attacks,
  selected,
  onSelect,
  full,
}: {
  attacks: Attack[];
  selected: string | null;
  onSelect: (id: string) => void;
  full: boolean;
}) {
  const scroller = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const id = requestAnimationFrame(() => el.scrollTo({ top: el.scrollHeight, behavior: full ? "smooth" : "auto" }));
    return () => cancelAnimationFrame(id);
  }, [attacks.length, full]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="grid shrink-0 grid-cols-[minmax(150px,200px)_1fr] pb-2 pt-3">
        <span />
        <div className="mr-4 grid grid-cols-4">
          {LAYERS.map((l) => (
            <div key={l.n} className="text-center" title={l.hint}>
              <div className="font-mono text-[10px] uppercase tracking-[0.15em] text-muted">
                <span className="mr-1 inline-flex h-4 w-4 items-center justify-center rounded-full border border-muted/60 text-[9px]">
                  {l.n}
                </span>
                {l.label}
              </div>
            </div>
          ))}
        </div>
      </div>
      <div ref={scroller} className="min-h-0 flex-1 overflow-y-auto">
        {attacks.length === 0 && (
          <div className="flex h-full items-center justify-center text-sm text-muted">
            Starte einen Lauf, dann erscheint hier jeder Angriff als Pfad durch die Schutzschichten.
          </div>
        )}
        {attacks.map((a) => (
          <Row key={a.id} a={a} full={full} active={a.id === selected} onClick={() => onSelect(a.id)} />
        ))}
      </div>
      <div className="flex shrink-0 gap-5 border-t border-line/70 px-4 py-2 text-[11px] text-muted">
        <span>
          <span className="font-bold text-green">━✕</span> an dieser Schicht gestoppt
        </span>
        <span>
          <span className="text-red">━▶</span> bis hierher durchgebrochen
        </span>
        <span>
          <span className="text-cyan">●</span> läuft gerade
        </span>
      </div>
    </div>
  );
}

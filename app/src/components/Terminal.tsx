import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useRef } from "react";
import { LAYERS, pathOf } from "../lib/depth";
import type { Attack, Message } from "../lib/runStore";
import { Typewriter } from "./hud/Typewriter";

const ROLE = {
  attacker: { prefix: "angreifer", color: "#f43f5e" },
  target: { prefix: "ziel-agent", color: "#22d3ee" },
  judge: { prefix: "richter", color: "#a78bfa" },
} as const;

/** Hebt Canary-Token, Kennwörter, externe URLs und typische Angriffswörter hervor. */
function highlight(text: string) {
  const parts = text.split(/(CANARY-[A-Z0-9-]+|KAC-[A-F0-9]{6}|https?:\/\/\S+|PWNED|DevMode|DAN)/g);
  return parts.map((p, i) =>
    /^(CANARY-|KAC-|https?:\/\/|PWNED|DevMode|DAN$)/.test(p) ? (
      <mark key={i} className="rounded bg-red/25 px-1 text-[#fda4af]">
        {p}
      </mark>
    ) : (
      <span key={i}>{p}</span>
    ),
  );
}

function Line({ m, live, full }: { m: Message; live: boolean; full: boolean }) {
  const r = ROLE[m.role];
  return (
    <motion.div initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} className="mb-3">
      <div className="whitespace-pre-wrap [overflow-wrap:anywhere]">
        <span style={{ color: r.color }}>{r.prefix} ›</span>{" "}
        {live && full ? <Typewriter text={m.text} speed={160} /> : highlight(m.text)}
      </div>
      {m.tool_call && (
        <div className="mt-2 border-l-[3px] border-red bg-red/[0.07] px-3 py-1.5 [overflow-wrap:anywhere]">
          <span className="text-red">⚡ tool-call</span>{" "}
          <mark className="rounded bg-red/20 px-1 text-[#fda4af]">
            {m.tool_call.name}(
            {Object.entries(m.tool_call.args)
              .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
              .join(", ")}
            )
          </mark>
        </div>
      )}
    </motion.div>
  );
}

/** Gesprächsprotokoll eines Angriffs im Terminal-Stil. */
export function Terminal({
  attack,
  index,
  total,
  live,
  full,
}: {
  attack: Attack | undefined;
  index: number;
  total: number;
  live: boolean;
  full: boolean;
}) {
  const body = useRef<HTMLDivElement>(null);
  useEffect(() => {
    body.current?.scrollTo({ top: body.current.scrollHeight, behavior: "smooth" });
  }, [attack?.messages.length, attack?.id]);

  if (!attack) {
    return (
      <div className="flex h-full items-center justify-center font-mono text-sm text-muted">
        <span className="hud-caret">warte auf den ersten Angriff</span>
      </div>
    );
  }
  const p = pathOf(attack);
  const layer = LAYERS[p.layer - 1];
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 items-center gap-3 border-b border-line/70 px-5 py-2.5">
        <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan">
          ● Angriff {index}/{total || "–"}
        </span>
        <span className="truncate text-sm font-semibold">{attack.technique}</span>
        <span className="shrink-0 rounded bg-violet/15 px-1.5 py-0.5 text-[10px] text-violet">{attack.owasp}</span>
        <span className="ml-auto shrink-0">
          <AnimatePresence mode="wait">
            {p.state !== "running" && (
              <motion.span
                key={attack.id + p.state}
                initial={{ opacity: 0, scale: 1.5 }}
                animate={{ opacity: 1, scale: 1 }}
                className={`inline-block rounded-md border px-2.5 py-0.5 font-mono text-[11px] font-bold uppercase tracking-[0.2em] ${
                  p.state === "breach"
                    ? "border-red bg-red/15 text-red " + (full && live ? "hud-glitch" : "")
                    : "border-green/60 bg-green/10 text-green"
                }`}
              >
                {p.state === "breach" ? "Durchbruch" : "Gestoppt"}
              </motion.span>
            )}
          </AnimatePresence>
        </span>
      </div>
      <div ref={body} className="min-h-0 flex-1 overflow-y-auto px-5 py-4 font-mono text-[13px] leading-relaxed">
        {attack.messages.map((m, i) => (
          <Line key={i} m={m} full={full} live={live && i === attack.messages.length - 1} />
        ))}
        {p.state === "running" && <span className="hud-caret text-muted" />}
      </div>
      {p.state !== "running" && (
        <div
          className={`shrink-0 border-t border-line/70 px-5 py-2 text-xs ${p.state === "breach" ? "text-red" : "text-green"}`}
        >
          {p.state === "breach" ? `Durchbruch bis ${layer.n} ${layer.label}` : `Gestoppt bei ${layer.n} ${layer.label}`}
          <span className="text-muted"> · {p.reason}</span>
        </div>
      )}
    </div>
  );
}

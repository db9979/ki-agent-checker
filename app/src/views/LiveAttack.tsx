import { AnimatePresence, motion } from "framer-motion";
import { Bot, CheckCircle2, Crosshair, Gavel, Play, Radio, Siren, XCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { ScoreGauge } from "../components/ScoreGauge";
import { type Attack, type Message, liveScore, useRun } from "../lib/runStore";

const ROLE = {
  attacker: { label: "Angreifer", icon: Crosshair, color: "#f43f5e", align: "self-start" },
  target: { label: "Ziel-Agent", icon: Bot, color: "#22d3ee", align: "self-end" },
  judge: { label: "Richter", icon: Gavel, color: "#a78bfa", align: "self-center" },
} as const;

const SIGNAL_LABEL: Record<string, string> = {
  canary: "Canary-Token entdeckt",
  honeypot: "Honeypot-Tool aufgerufen",
  pattern: "Angriffsmuster in der Antwort",
  llm: "vom Richter-Modell bewertet",
};

/** Hebt Canary-Token, externe URLs und typische Angriffswörter hervor. */
function highlight(text: string) {
  const parts = text.split(/(CANARY-[A-Z0-9]+|https?:\/\/\S+|PWNED|DevMode)/g);
  return parts.map((p, i) =>
    /^(CANARY-|https?:\/\/|PWNED|DevMode)/.test(p) ? (
      <mark key={i} className="rounded bg-red/25 px-1 font-mono text-red">
        {p}
      </mark>
    ) : (
      <span key={i}>{p}</span>
    ),
  );
}

function Bubble({ m }: { m: Message }) {
  const r = ROLE[m.role];
  const Icon = r.icon;
  return (
    <motion.div
      initial={{ opacity: 0, y: 12, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ type: "spring", stiffness: 260, damping: 24 }}
      className={`${r.align} max-w-[78%]`}
    >
      <div className="mb-1 flex items-center gap-1.5 text-[11px] font-medium" style={{ color: r.color }}>
        <Icon size={13} /> {r.label}
      </div>
      <div
        className="rounded-2xl border px-4 py-2.5 text-sm leading-relaxed"
        style={{ borderColor: `${r.color}44`, background: `${r.color}12` }}
      >
        {highlight(m.text)}
      </div>
      {m.tool_call && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: [0, 1, 0.6, 1] }}
          transition={{ duration: 1 }}
          className="glow-red mt-2 flex items-center gap-2 rounded-xl border border-red/50 bg-red/10 px-3 py-2 font-mono text-xs text-red"
        >
          <Siren size={14} />
          Honeypot-Tool: {m.tool_call.name}({JSON.stringify(m.tool_call.args)})
        </motion.div>
      )}
    </motion.div>
  );
}

function AttackItem({ a, active, onClick }: { a: Attack; active: boolean; onClick: () => void }) {
  const state = a.success === undefined ? "running" : a.success ? "hit" : "blocked";
  return (
    <button
      onClick={onClick}
      className={`flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-xs transition ${
        active ? "bg-panel-2" : "hover:bg-panel-2/60"
      }`}
    >
      {state === "running" && <Radio size={14} className="animate-pulse text-cyan" />}
      {state === "hit" && <XCircle size={14} className="text-red" />}
      {state === "blocked" && <CheckCircle2 size={14} className="text-green" />}
      <span className="flex-1 truncate">
        <span className="text-muted">{a.moduleLabel} · </span>
        {a.technique}
      </span>
      <span className="text-[10px] text-violet">{a.owasp}</span>
    </button>
  );
}

export function LiveAttack({ onStartDemo }: { onStartDemo: () => void }) {
  const run = useRun();
  const [selected, setSelected] = useState<string | null>(null);
  const followLatest = selected === null;
  const current = followLatest ? run.attacks.at(-1) : run.attacks.find((a) => a.id === selected);
  const streamRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    streamRef.current?.scrollTo({ top: streamRef.current.scrollHeight, behavior: "smooth" });
  }, [current?.messages.length]);

  useEffect(() => {
    if (run.status === "running" && run.done === 0) setSelected(null);
  }, [run.status, run.done]);

  const hits = run.attacks.filter((a) => a.success).length;
  const blocked = run.attacks.filter((a) => a.success === false).length;

  return (
    <div className="grid grid-cols-12 content-start gap-4">
      <header className="col-span-12 flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold">
            Live-Angriff
            {run.status === "running" && (
              <span className="flex items-center gap-1 rounded-full bg-red/15 px-2 py-0.5 text-xs text-red">
                <span className="h-2 w-2 animate-ping rounded-full bg-red" /> LIVE
              </span>
            )}
          </h1>
          <p className="text-sm text-muted">{run.target || "Starte einen Lauf, um Angriffe live zu verfolgen"}</p>
        </div>
        <button
          onClick={onStartDemo}
          disabled={run.status === "running"}
          className="glow-cyan flex items-center gap-2 rounded-xl bg-cyan/15 px-4 py-2 text-sm font-medium text-cyan transition hover:bg-cyan/25 disabled:opacity-40"
        >
          <Play size={16} /> Demo-Lauf starten
        </button>
      </header>

      <aside className="panel col-span-12 flex max-h-[70vh] flex-col p-3 lg:col-span-3">
        <div className="mb-2 grid grid-cols-2 gap-2 text-center">
          <div className="rounded-lg bg-red/10 p-2">
            <div className="text-xl font-semibold tabular-nums text-red">{hits}</div>
            <div className="text-[10px] uppercase tracking-wider text-muted">Durchgebrochen</div>
          </div>
          <div className="rounded-lg bg-green/10 p-2">
            <div className="text-xl font-semibold tabular-nums text-green">{blocked}</div>
            <div className="text-[10px] uppercase tracking-wider text-muted">Abgewehrt</div>
          </div>
        </div>
        <div className="flex-1 space-y-1 overflow-y-auto">
          {run.attacks.map((a) => (
            <AttackItem key={a.id} a={a} active={a.id === current?.id} onClick={() => setSelected(a.id)} />
          ))}
        </div>
        {!followLatest && (
          <button onClick={() => setSelected(null)} className="mt-2 rounded-lg bg-panel-2 py-1.5 text-xs text-cyan">
            Dem aktuellen Angriff folgen
          </button>
        )}
      </aside>

      <section className="panel grid-bg col-span-12 flex max-h-[70vh] flex-col lg:col-span-6">
        {current ? (
          <>
            <div className="flex items-center gap-2 border-b border-line px-5 py-3 text-sm">
              <span className="font-medium">{current.technique}</span>
              <span className="text-muted">· {current.moduleLabel}</span>
              <span className="ml-auto rounded-md bg-violet/15 px-2 py-0.5 text-[11px] text-violet">{current.owasp}</span>
              {current.atlas && <span className="rounded-md bg-cyan/10 px-2 py-0.5 text-[11px] text-cyan">{current.atlas}</span>}
            </div>
            <div ref={streamRef} className="flex flex-1 flex-col gap-4 overflow-y-auto p-5">
              {current.messages.map((m, i) => (
                <Bubble key={i} m={m} />
              ))}
              <AnimatePresence>
                {current.success !== undefined && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className={`self-center rounded-full px-4 py-1.5 text-xs font-semibold ${
                      current.success ? "glow-red bg-red/20 text-red" : "bg-green/15 text-green"
                    }`}
                  >
                    {current.success ? `Durchgebrochen · ${SIGNAL_LABEL[current.signal ?? ""] ?? ""}` : "Abgewehrt"}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </>
        ) : (
          <div className="flex flex-1 items-center justify-center text-sm text-muted">Noch keine Angriffe</div>
        )}
      </section>

      <aside className="panel col-span-12 flex flex-col items-center gap-4 p-5 lg:col-span-3">
        <ScoreGauge score={liveScore(run)} label="Live-Score" />
        <div className="w-full space-y-2">
          {run.modules.map((m) => {
            const rate = m.attempts ? m.hits / m.attempts : 0;
            return (
              <div key={m.key}>
                <div className="flex justify-between text-xs">
                  <span className="text-muted">{m.label}</span>
                  <span className="tabular-nums">
                    {m.hits}/{m.attempts}
                  </span>
                </div>
                <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-[#0b1222]">
                  <motion.div className="h-full rounded-full bg-red" animate={{ width: `${rate * 100}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </aside>
    </div>
  );
}

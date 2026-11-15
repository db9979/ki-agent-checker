import { ArrowRight, ChevronDown, Minus, TrendingDown, TrendingUp } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { CompareResult, CompareRow, CompareStatus, RunSummary } from "../lib/types";
import { useApi } from "../lib/useApi";
import { OWASP_LABEL, scoreColor } from "../lib/ui";

const STATUS: Record<CompareStatus, { label: string; color: string }> = {
  neu: { label: "Neu kaputt", color: "#f43f5e" },
  schlechter: { label: "Schlechter", color: "#f59e0b" },
  behoben: { label: "Behoben", color: "#34d399" },
  besser: { label: "Besser", color: "#22d3ee" },
  neu_getestet: { label: "Neu im Test", color: "#a78bfa" },
  entfallen: { label: "Nicht mehr getestet", color: "#7c8db5" },
  gleich: { label: "Unverändert", color: "#7c8db5" },
};

const fmt = (iso: string) => new Date(iso).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" });

/** Zwei Läufe desselben Ziels nebeneinander: Was ist behoben, was ist neu kaputt? */
export function Compare() {
  const { data: runs } = useApi<RunSummary[]>("/runs");
  const finished = useMemo(() => (runs ?? []).filter((r) => r.status === "finished"), [runs]);
  const targets = useMemo(() => [...new Set(finished.map((r) => r.target))].reverse(), [finished]);
  const [target, setTarget] = useState<string | null>(null);
  const [pick, setPick] = useState<{ a: string | null; b: string | null }>({ a: null, b: null });

  const current = target ?? targets[0] ?? null;
  const series = useMemo(() => finished.filter((r) => r.target === current), [finished, current]);

  // Standard: die beiden letzten Läufe des Ziels
  useEffect(() => {
    if (series.length >= 2) setPick({ a: series.at(-2)!.id, b: series.at(-1)!.id });
    else setPick({ a: null, b: null });
  }, [series]);

  const { data: cmp } = useApi<CompareResult>(
    pick.a && pick.b ? `/runs/compare?a=${pick.a}&b=${pick.b}` : "/health",
    [],
  );
  const result = pick.a && pick.b && cmp && "rows" in cmp ? cmp : null;
  const [showSame, setShowSame] = useState(false);

  const choose = (id: string) => {
    const idx = series.findIndex((r) => r.id === id);
    const bIdx = series.findIndex((r) => r.id === pick.b);
    setPick((p) => (idx < bIdx ? { ...p, a: id } : idx > bIdx ? { a: p.b, b: id } : p));
  };

  if (runs && series.length < 2) {
    return (
      <div>
        <h1 className="text-2xl font-semibold">Läufe vergleichen</h1>
        <p className="mt-2 text-sm text-muted">
          Für einen Vergleich braucht es mindestens zwei abgeschlossene Läufe gegen dasselbe Ziel.
        </p>
      </div>
    );
  }

  const rows = result?.rows ?? [];
  const changed = rows.filter((r) => r.status !== "gleich");
  const same = rows.filter((r) => r.status === "gleich");

  return (
    <div className="grid grid-cols-12 gap-4">
      <header className="col-span-12 flex flex-wrap items-end justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold">Läufe vergleichen</h1>
          {targets.length > 1 ? (
            <Select value={current ?? ""} onChange={setTarget} className="mt-1 max-w-[28rem] text-muted">
              {targets.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </Select>
          ) : (
            <p className="truncate text-sm text-muted">{current}</p>
          )}
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-muted">Vorher</span>
          <RunSelect runs={series} value={pick.a} onChange={(a) => setPick((p) => ({ ...p, a }))} />
          <ArrowRight size={14} className="text-muted" />
          <span className="text-muted">Nachher</span>
          <RunSelect runs={series} value={pick.b} onChange={(b) => setPick((p) => ({ ...p, b }))} />
        </div>
      </header>

      <section className="panel col-span-12 flex items-center justify-around p-5 md:col-span-4">
        <Score label="Vorher" value={result?.a.score ?? null} />
        <Delta value={result?.delta ?? null} />
        <Score label="Nachher" value={result?.b.score ?? null} />
      </section>

      <section className="panel col-span-12 grid grid-cols-2 gap-3 p-4 sm:grid-cols-4 md:col-span-8">
        <Kpi n={result?.counts.behoben ?? 0} status="behoben" />
        <Kpi n={result?.counts.neu ?? 0} status="neu" />
        <Kpi n={result?.counts.schlechter ?? 0} status="schlechter" />
        <Kpi n={(result?.counts.gleich ?? 0) + (result?.counts.besser ?? 0)} status="gleich" label="Unverändert / besser" />
      </section>

      <section className="panel col-span-12 p-5 lg:col-span-8">
        <h2 className="mb-3 text-sm font-semibold text-muted">Was hat sich geändert?</h2>
        {result && !result.complete && (
          <p className="mb-3 rounded-lg bg-amber/10 px-3 py-2 text-xs text-amber">
            Für mindestens einen Lauf fehlt das Angriffsprotokoll (ältere Version). Verglichen werden nur die Befunde.
          </p>
        )}
        {changed.length === 0 && result && <p className="text-sm text-muted">Keine Änderungen zwischen den Läufen.</p>}
        <table className="w-full text-sm">
          {changed.length > 0 && (
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wide text-muted">
                <th className="py-2 font-semibold">Angriff</th>
                <th className="py-2 font-semibold">OWASP</th>
                <th className="py-2 font-semibold">Vorher</th>
                <th className="py-2 font-semibold">Nachher</th>
                <th className="py-2 text-right font-semibold">Status</th>
              </tr>
            </thead>
          )}
          <tbody className="divide-y divide-line">
            {[...changed, ...(showSame ? same : [])].map((r) => (
              <Row key={r.module} row={r} />
            ))}
          </tbody>
        </table>
        {same.length > 0 && (
          <button
            onClick={() => setShowSame((s) => !s)}
            className="mt-2 flex items-center gap-1 text-xs text-muted hover:text-text"
          >
            <ChevronDown size={14} className={showSame ? "rotate-180" : ""} />
            {showSame ? "Unveränderte ausblenden" : `${same.length} unveränderte Angriffe einblenden`}
          </button>
        )}
      </section>

      <section className="panel col-span-12 p-5 lg:col-span-4">
        <h2 className="mb-2 text-sm font-semibold text-muted">Score-Verlauf dieses Ziels</h2>
        <div className="h-56">
          <Trend runs={series} a={pick.a} b={pick.b} onPick={choose} />
        </div>
        <p className="mt-2 text-xs text-muted">Klick auf einen Punkt wählt ihn als Vorher oder Nachher.</p>
      </section>
    </div>
  );
}

function Select({
  value,
  onChange,
  className = "",
  children,
}: {
  value: string;
  onChange: (v: string) => void;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={`rounded-lg border border-line bg-panel-2 px-3 py-1.5 text-sm text-text ${className}`}
    >
      {children}
    </select>
  );
}

function RunSelect({ runs, value, onChange }: { runs: RunSummary[]; value: string | null; onChange: (id: string) => void }) {
  return (
    <Select value={value ?? ""} onChange={onChange} className="text-xs">
      {runs.map((r) => (
        <option key={r.id} value={r.id}>
          {fmt(r.started_at)} · Score {r.score ?? "–"}
        </option>
      ))}
    </Select>
  );
}

function Score({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="text-center">
      <div className="text-xs text-muted">{label}</div>
      <div className="text-5xl font-bold tabular-nums" style={{ color: scoreColor(value) }}>
        {value ?? "–"}
      </div>
    </div>
  );
}

function Delta({ value }: { value: number | null }) {
  if (value === null) return null;
  const Icon = value > 0 ? TrendingUp : value < 0 ? TrendingDown : Minus;
  const color = value > 0 ? "#34d399" : value < 0 ? "#f43f5e" : "#7c8db5";
  return (
    <div className="flex items-center gap-1 text-xl font-bold tabular-nums" style={{ color }}>
      <Icon size={20} />
      {value > 0 ? `+${value}` : value}
    </div>
  );
}

function Kpi({ n, status, label }: { n: number; status: CompareStatus; label?: string }) {
  const s = STATUS[status];
  return (
    <div className="rounded-xl bg-panel-2 p-3 text-center">
      <div className="text-3xl font-bold tabular-nums" style={{ color: n ? s.color : "#7c8db5" }}>
        {n}
      </div>
      <div className="text-xs text-muted">{label ?? s.label}</div>
    </div>
  );
}

function Bar({ side }: { side: CompareRow["a"] }) {
  if (!side) return <span className="text-xs text-muted">nicht getestet</span>;
  const pct = Math.round(side.rate * 100);
  const color = pct === 0 ? "#34d399" : pct >= 50 ? "#f43f5e" : "#f59e0b";
  return (
    <div className="flex items-center gap-2" title={`${side.hits} von ${side.attempts} Angriffen erfolgreich`}>
      <div className="h-2 w-28 overflow-hidden rounded bg-[#0b1222]">
        <div className="h-full rounded" style={{ width: `${Math.max(pct, pct ? 4 : 0)}%`, background: color }} />
      </div>
      <span className="w-9 text-right text-xs tabular-nums text-muted">{pct} %</span>
    </div>
  );
}

function Row({ row }: { row: CompareRow }) {
  const s = STATUS[row.status];
  return (
    <tr>
      <td className="py-2 pr-2">{row.label}</td>
      <td className="py-2 pr-2 text-muted" title={OWASP_LABEL[row.owasp]}>
        {row.owasp}
      </td>
      <td className="py-2 pr-2">
        <Bar side={row.a} />
      </td>
      <td className="py-2 pr-2">
        <Bar side={row.b} />
      </td>
      <td className="py-2 text-right">
        <span
          className="whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-semibold"
          style={{ background: `${s.color}22`, color: s.color }}
        >
          {s.label}
        </span>
      </td>
    </tr>
  );
}

function Trend({
  runs,
  a,
  b,
  onPick,
}: {
  runs: RunSummary[];
  a: string | null;
  b: string | null;
  onPick: (id: string) => void;
}) {
  const data = runs.map((r) => ({ id: r.id, label: fmt(r.started_at), score: r.score ?? 0 }));
  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data} margin={{ top: 12, right: 12, left: -20, bottom: 0 }}>
        <CartesianGrid stroke="#1e2a44" vertical={false} />
        <XAxis dataKey="label" hide />
        <YAxis domain={[0, 100]} stroke="#7c8db5" fontSize={11} tickLine={false} axisLine={false} />
        <Tooltip
          contentStyle={{ background: "#0d1424", border: "1px solid #1e2a44", borderRadius: 10, fontSize: 12 }}
          formatter={(v) => [`${v}`, "Score"]}
        />
        <Line
          type="monotone"
          dataKey="score"
          stroke="#22d3ee"
          strokeWidth={2.5}
          isAnimationActive={false}
          dot={(p) => {
            const id = (p.payload as { id: string }).id;
            const mark = id === a ? "#f59e0b" : id === b ? "#34d399" : null;
            return (
              <g key={id} onClick={() => onPick(id)} style={{ cursor: "pointer" }}>
                <circle cx={p.cx} cy={p.cy} r={12} fill="transparent" />
                {mark ? (
                  <>
                    <circle cx={p.cx} cy={p.cy} r={7} fill="#070b14" stroke={mark} strokeWidth={3} />
                    <text x={p.cx} y={(p.cy ?? 0) + 24} textAnchor="middle" fill={mark} fontSize={12} fontWeight={700}>
                      {id === a ? "A" : "B"}
                    </text>
                  </>
                ) : (
                  <circle cx={p.cx} cy={p.cy} r={4} fill="#22d3ee" />
                )}
              </g>
            );
          }}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}

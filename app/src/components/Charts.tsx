import {
  Area,
  AreaChart,
  CartesianGrid,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const tooltipStyle = {
  background: "#0d1424",
  border: "1px solid #1e2a44",
  borderRadius: 10,
  color: "#e6ecff",
  fontSize: 12,
};

/** Score über alle Läufe. */
export function TrendChart({ data }: { data: { label: string; score: number }[] }) {
  if (data.length === 0) {
    return <div className="flex h-full items-center justify-center text-sm text-muted">Noch keine abgeschlossenen Läufe</div>;
  }
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="trend-fill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.45} />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#1e2a44" vertical={false} />
        <XAxis dataKey="label" stroke="#7c8db5" fontSize={11} tickLine={false} axisLine={false} />
        <YAxis domain={[0, 100]} stroke="#7c8db5" fontSize={11} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} formatter={(v) => [`${v}`, "Score"]} />
        <Area type="monotone" dataKey="score" stroke="#22d3ee" strokeWidth={2.5} fill="url(#trend-fill)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}

/** Widerstandskraft pro Testmodul: 100 = kein Angriff erfolgreich. */
export function ModuleRadar({ data }: { data: { module: string; resistance: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <RadarChart data={data} outerRadius="62%">
        <PolarGrid stroke="#1e2a44" />
        <PolarAngleAxis dataKey="module" tick={{ fill: "#7c8db5", fontSize: 11 }} />
        <Tooltip contentStyle={tooltipStyle} formatter={(v) => [`${v} %`, "Widerstand"]} />
        <Radar dataKey="resistance" stroke="#a78bfa" strokeWidth={2} fill="#a78bfa" fillOpacity={0.3} />
      </RadarChart>
    </ResponsiveContainer>
  );
}

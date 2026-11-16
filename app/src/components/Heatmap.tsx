import { motion } from "framer-motion";
import { OWASP_LABEL, rateColor } from "../lib/ui";

export interface HeatRow {
  key: string;
  label: string;
  owasp: string;
  rate: number | null;
  attempts: number;
}

const COLUMNS = ["LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"];

/** Testmodule × OWASP-LLM-Kategorien, Farbe = Erfolgsquote der Angriffe. */
export function Heatmap({ rows }: { rows: HeatRow[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-separate border-spacing-1.5 text-sm">
        <thead>
          <tr>
            <th className="w-40" />
            {COLUMNS.map((c) => (
              <th key={c} title={OWASP_LABEL[c]} className="px-1 text-center text-[11px] font-medium text-muted">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={row.key}>
              <td className="pr-2 text-right text-xs text-muted">{row.label}</td>
              {COLUMNS.map((c) => {
                const active = c === row.owasp;
                const rate = active ? row.rate : null;
                return (
                  <td key={c} className="p-0">
                    <motion.div
                      initial={{ opacity: 0, scale: 0.6 }}
                      animate={{ opacity: 1, scale: 1, backgroundColor: active ? rateColor(rate) : "#0b1222" }}
                      transition={{ delay: i * 0.05, duration: 0.4 }}
                      className={`flex h-10 items-center justify-center rounded-md text-xs font-semibold tabular-nums ${
                        active && rate && rate > 0.5 ? "glow-red" : ""
                      }`}
                      title={
                        active
                          ? `${row.label}: ${rate === null ? "noch nicht getestet" : `${Math.round(rate * 100)} % erfolgreiche Angriffe`}`
                          : ""
                      }
                    >
                      {active && rate !== null ? `${Math.round(rate * 100)}%` : active ? "…" : ""}
                    </motion.div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="mt-3 flex items-center gap-2 text-[11px] text-muted">
        <span>Angriffe erfolgreich:</span>
        {[0, 0.2, 0.45, 0.7, 1].map((r) => (
          <span key={r} className="flex items-center gap-1">
            <span className="inline-block h-3 w-5 rounded-sm" style={{ background: rateColor(r) }} />
            {Math.round(r * 100)}%
          </span>
        ))}
      </div>
    </div>
  );
}

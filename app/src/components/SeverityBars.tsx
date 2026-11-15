import { motion } from "framer-motion";
import type { Finding, Severity } from "../lib/types";
import { SEVERITY_COLOR, SEVERITY_LABEL } from "../lib/ui";

const ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function SeverityBars({ findings }: { findings: Finding[] }) {
  const counts = ORDER.map((s) => ({ s, n: findings.filter((f) => f.severity === s).length }));
  const max = Math.max(1, ...counts.map((c) => c.n));
  return (
    <div className="space-y-3">
      {counts.map(({ s, n }) => (
        <div key={s} className="flex items-center gap-3">
          <span className="w-16 text-xs text-muted">{SEVERITY_LABEL[s]}</span>
          <div className="h-3 flex-1 overflow-hidden rounded-full bg-[#0b1222]">
            <motion.div
              className="h-full rounded-full"
              style={{ background: SEVERITY_COLOR[s], boxShadow: n ? `0 0 12px ${SEVERITY_COLOR[s]}88` : "none" }}
              initial={{ width: 0 }}
              animate={{ width: `${(n / max) * 100}%` }}
              transition={{ duration: 0.8, ease: "easeOut" }}
            />
          </div>
          <span className="w-6 text-right text-sm font-semibold tabular-nums">{n}</span>
        </div>
      ))}
    </div>
  );
}

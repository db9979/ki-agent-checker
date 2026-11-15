import { animate, motion, useMotionValue, useTransform } from "framer-motion";
import { useEffect } from "react";
import { scoreColor } from "../lib/ui";

/** Halbkreis-Tacho 0–100 mit animierter Nadel und Zahl. */
export function ScoreGauge({ score, label = "Security-Score" }: { score: number | null; label?: string }) {
  const value = useMotionValue(0);
  const rounded = useTransform(value, (v) => Math.round(v).toString());
  const color = scoreColor(score);
  const r = 90;
  const circumference = Math.PI * r;

  useEffect(() => {
    const controls = animate(value, score ?? 0, { duration: 1.2, ease: "easeOut" });
    return () => controls.stop();
  }, [score, value]);

  const dash = useTransform(value, (v) => `${(v / 100) * circumference} ${circumference}`);
  // Nadel: 0 = links, 100 = rechts, Länge 74 um den Mittelpunkt (110, 110)
  const needleX = useTransform(value, (v) => 110 - 74 * Math.cos((v / 100) * Math.PI));
  const needleY = useTransform(value, (v) => 110 - 74 * Math.sin((v / 100) * Math.PI));

  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 220 130" className="w-full max-w-[280px]">
        <defs>
          <linearGradient id="gauge-track" x1="0" x2="1">
            <stop offset="0%" stopColor="#f43f5e" />
            <stop offset="50%" stopColor="#f59e0b" />
            <stop offset="100%" stopColor="#34d399" />
          </linearGradient>
          <filter id="gauge-glow">
            <feGaussianBlur stdDeviation="4" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <path d="M20 110 A90 90 0 0 1 200 110" fill="none" stroke="#1e2a44" strokeWidth="14" strokeLinecap="round" />
        <path d="M20 110 A90 90 0 0 1 200 110" fill="none" stroke="url(#gauge-track)" strokeOpacity="0.18" strokeWidth="14" strokeLinecap="round" />
        <motion.path
          d="M20 110 A90 90 0 0 1 200 110"
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeLinecap="round"
          style={{ strokeDasharray: dash }}
          filter="url(#gauge-glow)"
        />
        <motion.line x1="110" y1="110" x2={needleX} y2={needleY} stroke="#e6ecff" strokeWidth="2.5" strokeLinecap="round" />
        <circle cx="110" cy="110" r="6" fill="#e6ecff" />
      </svg>
      <div className="mt-1 text-center">
        <motion.div className="text-5xl font-semibold tabular-nums" style={{ color }}>
          {score === null ? "–" : rounded}
        </motion.div>
        <div className="text-xs uppercase tracking-[0.2em] text-muted">{label}</div>
      </div>
    </div>
  );
}

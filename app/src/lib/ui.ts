import type { Severity } from "./types";

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Kritisch",
  high: "Hoch",
  medium: "Mittel",
  low: "Niedrig",
  info: "Info",
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#f59e0b",
  low: "#22d3ee",
  info: "#7c8db5",
};

export const OWASP_LABEL: Record<string, string> = {
  LLM01: "Prompt Injection",
  LLM02: "Offenlegung sensibler Daten",
  LLM03: "Lieferkette",
  LLM04: "Daten- und Modellvergiftung",
  LLM05: "Unsichere Ausgabeverarbeitung",
  LLM06: "Übermäßige Handlungsfreiheit",
  LLM07: "System-Prompt-Leak",
  LLM08: "Vektor- und Embedding-Schwächen",
  LLM09: "Fehlinformation",
  LLM10: "Unbegrenzter Verbrauch",
};

export function scoreColor(score: number | null): string {
  if (score === null) return "#7c8db5";
  if (score >= 80) return "#34d399";
  if (score >= 50) return "#f59e0b";
  return "#f43f5e";
}

/** Farbe einer Heatmap-Zelle nach Erfolgsquote der Angriffe (0 = sicher). */
export function rateColor(rate: number | null): string {
  if (rate === null) return "#121b30";
  if (rate === 0) return "#0f3b33";
  const stops = ["#5b3a0a", "#8a3412", "#b4233b", "#f43f5e"];
  return stops[Math.min(stops.length - 1, Math.floor(rate * stops.length))];
}

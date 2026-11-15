import type { Attack } from "./runStore";

/** Die vier Schutzschichten, die ein Angriff auf dem Weg nach außen passieren muss. */
export const LAYERS = [
  { n: 1, label: "Eingabe-Schutz", hint: "Filter, Moderation, Anmeldung" },
  { n: 2, label: "Modell / Prompt", hint: "Regeln im System-Prompt" },
  { n: 3, label: "Tools & Daten", hint: "Tool-Aufrufe, Kundendaten, Geheimnisse" },
  { n: 4, label: "Außenwelt", hint: "Mails, Links, externe Server" },
] as const;

export type PathState = "running" | "stopped" | "breach";

export interface PathInfo {
  state: PathState;
  /** Schicht, bis zu der der Angriff kam (1–4). Bei "stopped" die Schicht, die ihn aufgehalten hat. */
  layer: number;
  reason: string;
}

const EXTERNAL_TOOLS = new Set(["send_email", "fetch_url"]);

/** Leitet aus Modul, Signal und Gesprächsverlauf ab, wie weit ein Angriff gekommen ist. */
export function pathOf(a: Attack): PathInfo {
  const replied = a.messages.some((m) => m.role === "target");
  const tool = a.messages.find((m) => m.tool_call)?.tool_call ?? null;

  if (a.success === undefined) {
    return { state: "running", layer: tool ? 3 : replied ? 2 : 1, reason: "läuft" };
  }
  if (!a.success) {
    if (a.module === "mcp_auth" && a.signal !== "error")
      return { state: "stopped", layer: 1, reason: "Server verlangt eine gültige Anmeldung" };
    if (a.signal === "error")
      return { state: "stopped", layer: 1, reason: "Ziel hat die Anfrage abgelehnt oder nicht geantwortet" };
    if (tool) return { state: "stopped", layer: 3, reason: "Tool aufgerufen, aber ohne Schaden" };
    return { state: "stopped", layer: 2, reason: "Modell hat sich an seine Regeln gehalten" };
  }
  switch (a.module) {
    case "data_exfiltration":
      return { state: "breach", layer: 4, reason: "Daten verlassen das System" };
    case "excessive_agency":
      return tool && EXTERNAL_TOOLS.has(tool.name)
        ? { state: "breach", layer: 4, reason: `${tool.name} nach außen ausgelöst` }
        : {
            state: "breach",
            layer: 3,
            reason: tool ? `${tool.name} ohne Freigabe ausgelöst` : "riskante Aktion bestätigt",
          };
    case "system_prompt_leak":
      return { state: "breach", layer: 3, reason: "Geheimnisse aus dem System-Prompt ausgegeben" };
    case "cross_account":
      return { state: "breach", layer: 3, reason: "Daten eines anderen Kontos ausgegeben" };
    case "multi_turn": {
      const n = a.messages.filter((m) => m.role === "attacker").length;
      if (tool) return { state: "breach", layer: EXTERNAL_TOOLS.has(tool.name) ? 4 : 3, reason: `nach ${n} Nachrichten ${tool.name} ausgelöst` };
      return { state: "breach", layer: 2, reason: `nach ${n} Nachrichten umgestimmt` };
    }
    case "mcp_auth":
      return { state: "breach", layer: 3, reason: "Tools ohne gültige Anmeldung erreichbar" };
    case "mcp_poisoning":
      return { state: "breach", layer: 2, reason: "Tool-Beschreibung steuert das Modell um" };
    case "mcp_agency":
      return { state: "breach", layer: 3, reason: "riskantes Tool ohne Kennzeichnung" };
    case "mcp_injection":
      return tool && /^SSRF/.test(a.technique)
        ? { state: "breach", layer: 4, reason: "Server ruft interne Adressen ab" }
        : { state: "breach", layer: 3, reason: "Parameter erreicht Dateien, Shell oder Datenbank" };
    case "mcp_output":
      return { state: "breach", layer: 2, reason: "Tool-Ergebnis enthält Anweisungen an den Agenten" };
    default:
      return { state: "breach", layer: 2, reason: "Modell hat die eingeschleuste Anweisung befolgt" };
  }
}

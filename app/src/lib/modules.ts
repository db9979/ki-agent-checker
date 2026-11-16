/** Testmodule des Grundgerüsts mit OWASP-LLM-Zuordnung. */
export const MODULES = [
  { key: "prompt_injection", label: "Prompt Injection", owasp: "LLM01" },
  { key: "indirect_injection", label: "Indirekte Injection", owasp: "LLM01" },
  { key: "multilingual", label: "Sprachen & Verschleierung", owasp: "LLM01" },
  { key: "jailbreak", label: "Jailbreak", owasp: "LLM01" },
  { key: "system_prompt_leak", label: "System-Prompt-Leak", owasp: "LLM07" },
  { key: "data_exfiltration", label: "Datenabfluss", owasp: "LLM02" },
  { key: "excessive_agency", label: "Tool-Missbrauch", owasp: "LLM06" },
  { key: "cross_account", label: "Fremde Kontodaten", owasp: "LLM02" },
  { key: "insecure_output", label: "Unsichere Ausgaben", owasp: "LLM05" },
  { key: "resource_exhaustion", label: "Ressourcenverbrauch", owasp: "LLM10" },
  { key: "hallucination", label: "Erfundene Fakten", owasp: "LLM09" },
  { key: "multi_turn", label: "Mehrstufig", owasp: "LLM01" },
  { key: "mcp_auth", label: "Zugangsschutz", owasp: "LLM06" },
  { key: "mcp_poisoning", label: "Tool-Poisoning", owasp: "LLM01" },
  { key: "mcp_agency", label: "Riskante Tools", owasp: "LLM06" },
  { key: "mcp_injection", label: "Parameter-Injection", owasp: "LLM05" },
  { key: "mcp_output", label: "Manipulierte Ausgaben", owasp: "LLM01" },
] as const;

export function moduleLabel(key: string): string {
  return MODULES.find((m) => m.key === key)?.label ?? key;
}

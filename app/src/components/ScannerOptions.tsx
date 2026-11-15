import { CheckCircle2, Loader2, XCircle } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/engine";

export type ScannerTool = "garak" | "promptfoo";

export interface ScannerSettings {
  tool: ScannerTool;
  cmd: string;
  probes: string;
  purpose: string;
  num_tests: number;
  max_prompts: number;
}

const DEFAULTS: Record<ScannerTool, Omit<ScannerSettings, "tool">> = {
  garak: {
    cmd: "garak",
    probes: "promptinject,dan.DanInTheWild,encoding.InjectBase64,leakreplay,latentinjection,web_injection",
    purpose: "",
    num_tests: 3,
    max_prompts: 20,
  },
  promptfoo: { cmd: "npx -y promptfoo@latest", probes: "owasp:llm", purpose: "", num_tests: 3, max_prompts: 20 },
};

const small =
  "w-full rounded-md border border-line bg-[#0b1222] px-2 py-1.5 font-mono text-[11px] outline-none focus:border-cyan";

/** Gespeicherte Einstellungen je Scanner (Befehl, Probes), damit man sie nur einmal einträgt. */
export function loadScanner(tool: ScannerTool): ScannerSettings {
  try {
    const saved = JSON.parse(localStorage.getItem(`kac.scanner.${tool}`) ?? "{}");
    return { tool, ...DEFAULTS[tool], ...saved };
  } catch {
    return { tool, ...DEFAULTS[tool] };
  }
}

export function saveScanner(s: ScannerSettings) {
  const { tool, ...rest } = s;
  localStorage.setItem(`kac.scanner.${tool}`, JSON.stringify(rest));
}

export function ScannerOptions({
  value,
  onChange,
}: {
  value: ScannerSettings;
  onChange: (s: ScannerSettings) => void;
}) {
  const [check, setCheck] = useState<{ ok: boolean; version?: string; error?: string } | "busy" | null>(null);
  const set = (patch: Partial<ScannerSettings>) => onChange({ ...value, ...patch });
  const test = async () => {
    setCheck("busy");
    try {
      setCheck(await api(`/scanners/check?tool=${value.tool}&cmd=${encodeURIComponent(value.cmd)}`));
    } catch (e) {
      setCheck({ ok: false, error: String((e as Error).message) });
    }
  };
  const garak = value.tool === "garak";

  return (
    <div className="space-y-2 rounded-lg border border-line bg-[#0b1222]/60 p-2 text-xs text-muted">
      <label className="block">
        Befehl
        <div className="mt-1 flex gap-1">
          <input className={small} value={value.cmd} onChange={(e) => set({ cmd: e.target.value })} />
          <button onClick={test} className="shrink-0 rounded-md bg-panel-2 px-2 text-[11px] hover:text-text">
            Prüfen
          </button>
        </div>
      </label>
      {check === "busy" && (
        <p className="flex items-center gap-1">
          <Loader2 size={12} className="animate-spin" /> starte {value.tool} …
        </p>
      )}
      {check && check !== "busy" && (
        <p className={`flex items-start gap-1 ${check.ok ? "text-green" : "text-red"}`}>
          {check.ok ? <CheckCircle2 size={12} className="mt-0.5" /> : <XCircle size={12} className="mt-0.5" />}
          {check.ok ? `Gefunden: ${check.version || value.tool}` : check.error}
        </p>
      )}
      <div className={garak ? "grid grid-cols-4 gap-1" : ""}>
        <label className={garak ? "col-span-3 block" : "block"}>
          {garak ? "Probes (Komma-getrennt)" : "Plugins oder Preset (z. B. owasp:llm)"}
          <input className={`${small} mt-1`} value={value.probes} onChange={(e) => set({ probes: e.target.value })} />
        </label>
        {garak && (
          <label className="block" title="garak schickt sonst bis zu 256 Prompts je Probe">
            Prompts je Probe
            <input
              type="number"
              min={1}
              max={256}
              className={`${small} mt-1`}
              value={value.max_prompts}
              onChange={(e) => set({ max_prompts: Math.min(256, Math.max(1, Number(e.target.value) || 1)) })}
            />
          </label>
        )}
      </div>
      {!garak && (
        <div className="grid grid-cols-4 gap-1">
          <label className="col-span-3 block">
            Zweck des Agenten (für passende Angriffe)
            <input
              className={`${small} mt-1 font-sans`}
              value={value.purpose}
              onChange={(e) => set({ purpose: e.target.value })}
              placeholder="z. B. Sprachassistent für Kalender und Notizen"
            />
          </label>
          <label className="block">
            Tests je Plugin
            <input
              type="number"
              min={1}
              max={20}
              className={`${small} mt-1`}
              value={value.num_tests}
              onChange={(e) => set({ num_tests: Number(e.target.value) || 1 })}
            />
          </label>
        </div>
      )}
      <p className="text-[10px] leading-relaxed">
        {garak
          ? "garak wird separat installiert (pipx install garak, auf dem Mac vorher brew install pipx). Es spricht über eine lokale Brücke mit dem Ziel, Anmeldung und 2FA übernimmt die App."
          : "Promptfoo braucht Node.js 18+. Zum Erzeugen der Angriffe nutzt es seinen Online-Dienst oder einen eigenen Modell-Schlüssel (z. B. OPENAI_API_KEY)."}
      </p>
    </div>
  );
}

import { CheckCircle2, Download, Loader2, RefreshCw, X } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../lib/engine";
import { openLink } from "../lib/open";

export interface UpdateInfo {
  current: string;
  latest: string | null;
  newer: boolean;
  url?: string;
  download?: string | null;
  file?: string | null;
  error?: string;
}

const OFF = "kac.update.off";
const SKIP = "kac.update.skip";

export const updatesEnabled = () => localStorage.getItem(OFF) !== "1";

/** Hinweis in der Seitenleiste, wenn auf GitHub eine neuere Version liegt. */
export function UpdateNotice({ online }: { online: boolean }) {
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [skipped, setSkipped] = useState(localStorage.getItem(SKIP));

  useEffect(() => {
    if (!online || !updatesEnabled()) return;
    api<UpdateInfo>("/update")
      .then(setInfo)
      .catch(() => undefined);
  }, [online]);

  if (!info?.newer || !info.latest || skipped === info.latest) return null;
  const later = () => {
    localStorage.setItem(SKIP, info.latest!);
    setSkipped(info.latest);
  };

  return (
    <div className="mb-3 rounded-lg border border-cyan/40 bg-cyan/10 p-2 text-xs">
      <button
        onClick={() => openLink(info.download || info.url || "")}
        title={`Version ${info.latest} herunterladen${info.file ? ` (${info.file})` : ""}`}
        className="flex w-full items-center justify-center gap-2 text-cyan min-[1400px]:justify-start"
      >
        <Download size={15} className="shrink-0" />
        <span className="hidden font-medium min-[1400px]:inline">Version {info.latest} verfügbar</span>
      </button>
      <div className="mt-1.5 hidden gap-2 text-[11px] min-[1400px]:flex">
        <button onClick={() => openLink(info.download || info.url || "")} className="text-cyan hover:underline">
          Herunterladen
        </button>
        {info.url && (
          <button onClick={() => openLink(info.url!)} className="text-muted hover:text-text">
            Was ist neu
          </button>
        )}
        <button onClick={later} className="ml-auto text-muted hover:text-text" title="Für diese Version ausblenden">
          <X size={12} />
        </button>
      </div>
    </div>
  );
}

/** Zeile in der Hilfe: Version, manuell suchen, automatische Suche an/aus. */
export function UpdateSettings() {
  const [enabled, setEnabled] = useState(updatesEnabled());
  const [state, setState] = useState<UpdateInfo | "busy" | null>(null);
  const check = async () => {
    setState("busy");
    setState(
      await api<UpdateInfo>("/update?force=true").catch((e) => ({
        current: "",
        latest: null,
        newer: false,
        error: String((e as Error).message),
      })),
    );
  };
  const toggle = () => {
    localStorage.setItem(OFF, enabled ? "1" : "0");
    setEnabled(!enabled);
  };

  return (
    <div className="flex flex-wrap items-center gap-3 text-xs text-muted">
      <button onClick={check} className="flex items-center gap-1.5 hover:text-text">
        {state === "busy" ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
        Nach Updates suchen
      </button>
      {state && state !== "busy" && (
        <span className={state.error ? "text-amber" : state.newer ? "text-cyan" : "text-green"}>
          {state.error ? (
            state.error
          ) : state.newer ? (
            <button onClick={() => openLink(state.download || state.url || "")} className="hover:underline">
              Version {state.latest} herunterladen
            </button>
          ) : (
            <span className="flex items-center gap-1">
              <CheckCircle2 size={12} /> Version {state.current} ist aktuell
            </span>
          )}
        </span>
      )}
      <label className="flex cursor-pointer items-center gap-1.5">
        <input type="checkbox" checked={enabled} onChange={toggle} className="accent-cyan" />
        beim Start automatisch prüfen
      </label>
    </div>
  );
}

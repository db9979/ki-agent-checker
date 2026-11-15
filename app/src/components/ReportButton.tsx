import { FileText, Loader2 } from "lucide-react";
import { useState } from "react";
import { api, engineInfo } from "../lib/engine";
import { openLink } from "../lib/open";

/** Speichert den Bericht eines Laufs (HTML, im Browser als PDF druckbar) und öffnet ihn. */
export function ReportButton({ runId, compact = false }: { runId: string; compact?: boolean }) {
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ path: string; url: string }>(`/runs/${runId}/report`, { method: "POST" });
      setSaved(res.path);
      const { url } = await engineInfo();
      await openLink(`${url}${res.url}`);
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={compact ? "flex items-center gap-2" : "flex flex-col items-end gap-1"}>
      <button
        onClick={run}
        disabled={busy}
        title="Bericht als HTML speichern und öffnen, im Browser als PDF speicherbar"
        className={
          compact
            ? "flex items-center gap-1 rounded-md bg-cyan/10 px-2 py-0.5 text-[11px] text-cyan hover:bg-cyan/20 disabled:opacity-40"
            : "flex items-center gap-2 rounded-xl bg-panel-2 px-4 py-2 text-sm font-medium text-text transition hover:bg-panel-2/70 disabled:opacity-40"
        }
      >
        {busy ? <Loader2 size={compact ? 12 : 16} className="animate-spin" /> : <FileText size={compact ? 12 : 16} />}
        Bericht
      </button>
      {!compact && saved && (
        <span className="max-w-xs truncate text-[11px] text-muted" title={saved}>
          Gespeichert: {saved}
        </span>
      )}
      {error && <span className="text-[11px] text-red">{error}</span>}
    </div>
  );
}

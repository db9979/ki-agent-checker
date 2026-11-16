import { CheckCircle2, ExternalLink, Loader2, LogIn } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "../lib/engine";
import { openLink } from "../lib/open";

/** Startet die OAuth-Anmeldung im Standardbrowser und wartet, bis die Engine das Token hat. */
export function OAuthButton({ targetId, compact = false }: { targetId: string; compact?: boolean }) {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [waiting, setWaiting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [url, setUrl] = useState<string | null>(null);
  const timer = useRef<number | null>(null);

  const check = () =>
    api<{ signed_in: boolean }>(`/targets/${targetId}/oauth/status`)
      .then((s) => {
        setSignedIn(s.signed_in);
        return s.signed_in;
      })
      .catch(() => false);

  useEffect(() => {
    check();
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetId]);

  const start = async () => {
    setError(null);
    try {
      const r = await api<{ url: string }>(`/targets/${targetId}/oauth/start`, { method: "POST" });
      setUrl(r.url);
      await openLink(r.url);
      setWaiting(true);
      let tries = 0;
      timer.current = window.setInterval(async () => {
        tries++;
        if ((await check()) || tries > 90) {
          window.clearInterval(timer.current!);
          setWaiting(false);
        }
      }, 2000);
    } catch (e) {
      setError(String((e as Error).message));
    }
  };

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <button
        type="button"
        onClick={start}
        className={`flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] ${
          signedIn ? "bg-green/10 text-green" : "bg-amber/15 text-amber"
        }`}
        title="Öffnet die Anmeldung des Servers im Browser"
      >
        {waiting ? <Loader2 size={11} className="animate-spin" /> : signedIn ? <CheckCircle2 size={11} /> : <LogIn size={11} />}
        {waiting ? "Warte auf Browser …" : signedIn ? "OAuth angemeldet" : "Mit OAuth anmelden"}
      </button>
      {waiting && url && !compact && (
        <button type="button" onClick={() => openLink(url)} className="flex items-center gap-1 text-[10px] text-muted hover:text-text">
          <ExternalLink size={10} /> Browser erneut öffnen
        </button>
      )}
      {error && <span className="text-[11px] text-red">{error}</span>}
    </span>
  );
}

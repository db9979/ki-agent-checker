import { useEffect, useState } from "react";

/** Schreibt Text Zeichen für Zeichen aus. Im Sparmodus erscheint er sofort. */
export function Typewriter({ text, speed = 90, instant = false }: { text: string; speed?: number; instant?: boolean }) {
  const [n, setN] = useState(instant ? text.length : 0);

  useEffect(() => {
    if (instant) {
      setN(text.length);
      return;
    }
    setN(0);
    const started = performance.now();
    const id = setInterval(() => {
      const next = Math.min(text.length, Math.round(((performance.now() - started) / 1000) * speed));
      setN(next);
      if (next >= text.length) clearInterval(id);
    }, 30);
    return () => clearInterval(id);
  }, [text, speed, instant]);

  return <span className={n < text.length ? "hud-caret" : undefined}>{text.slice(0, n)}</span>;
}

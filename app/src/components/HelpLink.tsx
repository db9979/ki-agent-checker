import { CircleHelp } from "lucide-react";
import { showHelp } from "../lib/help";

/** Kleines „?“, das die passende Stelle der Anleitung öffnet. */
export function HelpLink({ anchor, label = "Hilfe dazu" }: { anchor: string; label?: string }) {
  return (
    <button
      type="button"
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        showHelp(anchor);
      }}
      title={label}
      aria-label={label}
      className="inline-flex shrink-0 align-middle text-muted transition hover:text-cyan"
    >
      <CircleHelp size={13} />
    </button>
  );
}

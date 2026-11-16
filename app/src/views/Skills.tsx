import {
  BookOpen,
  ChevronDown,
  ChevronRight,
  Download,
  ExternalLink,
  FolderOpen,
  Loader2,
  Swords,
  Trash2,
} from "lucide-react";
import { HelpLink } from "../components/HelpLink";
import { useState } from "react";
import { api } from "../lib/engine";
import { openLink } from "../lib/open";
import type { Skill } from "../lib/types";
import { OWASP_LABEL } from "../lib/ui";
import { useApi } from "../lib/useApi";

const input = "w-full rounded-lg border border-line bg-[#0b1222] px-3 py-2 text-sm outline-none focus:border-cyan";
const DEFAULT_REPO = "mukul975/Anthropic-Cybersecurity-Skills";

interface ImportResult {
  imported: number;
  with_attacks: number;
  attacks: number;
}

export function Skills() {
  const { data: skills, reload } = useApi<Skill[]>("/skills");
  const [source, setSource] = useState<"github" | "folder">("github");
  const [repo, setRepo] = useState(DEFAULT_REPO);
  const [ref, setRef] = useState("main");
  const [path, setPath] = useState("");
  const [onlyAi, setOnlyAi] = useState(true);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(
        await api<ImportResult>("/skills/import", {
          method: "POST",
          body: JSON.stringify({ source, repo, ref, path: source === "folder" ? path : null, only_ai: onlyAi }),
        }),
      );
      reload();
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (name: string) => {
    await api(`/skills/${encodeURIComponent(name)}`, { method: "DELETE" });
    reload();
  };

  const withAttacks = (skills ?? []).filter((s) => s.payload_count > 0);
  const knowledge = (skills ?? []).filter((s) => s.payload_count === 0);

  return (
    <div className="space-y-4">
      <header>
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          Skills <HelpLink anchor="skills" />
        </h1>
        <p className="text-sm text-muted">
          Angriffe und Gegenmaßnahmen aus Skill-Sammlungen übernehmen. Gelesen werden nur die SKILL.md-Dateien, Skripte
          werden nie ausgeführt.
        </p>
      </header>

      <div className="grid grid-cols-12 gap-4">
        <section className="panel col-span-12 space-y-3 p-5 lg:col-span-4">
          <h2 className="text-sm font-semibold text-muted">Importieren</h2>
          <div className="grid grid-cols-2 gap-1.5">
            {(
              [
                ["github", "Von GitHub", Download],
                ["folder", "Eigener Ordner", FolderOpen],
              ] as const
            ).map(([key, label, Icon]) => (
              <button
                key={key}
                onClick={() => setSource(key)}
                className={`flex items-center justify-center gap-1.5 rounded-lg border px-2 py-1.5 text-xs ${
                  source === key ? "border-cyan bg-cyan/10 text-cyan" : "border-line text-muted hover:text-text"
                }`}
              >
                <Icon size={13} /> {label}
              </button>
            ))}
          </div>
          {source === "github" ? (
            <div className="grid grid-cols-3 gap-2">
              <label className="col-span-2 block text-xs text-muted">
                Repository
                <input
                  className={`${input} font-mono text-xs`}
                  value={repo}
                  onChange={(e) => setRepo(e.target.value)}
                />
              </label>
              <label className="block text-xs text-muted">
                Branch
                <input className={`${input} font-mono text-xs`} value={ref} onChange={(e) => setRef(e.target.value)} />
              </label>
            </div>
          ) : (
            <label className="block text-xs text-muted">
              Ordner mit SKILL.md-Dateien (auch Unterordner)
              <input
                className={`${input} font-mono text-xs`}
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="~/skills"
              />
            </label>
          )}
          <label className="flex items-center gap-2 text-xs">
            <input type="checkbox" checked={onlyAi} onChange={(e) => setOnlyAi(e.target.checked)} />
            Nur KI-Sicherheit (subdomain: ai-security)
          </label>
          {error && <p className="text-xs text-red">{error}</p>}
          {result && (
            <p className="text-xs text-green">
              {result.imported} Skills übernommen, davon {result.with_attacks} mit zusammen {result.attacks} Angriffen.
            </p>
          )}
          <button
            onClick={run}
            disabled={busy || (source === "folder" ? !path : !repo)}
            className="glow-cyan flex w-full items-center justify-center gap-2 rounded-xl bg-cyan/15 py-2 text-sm font-medium text-cyan disabled:opacity-40"
          >
            {busy ? <Loader2 size={15} className="animate-spin" /> : <Download size={15} />} Importieren
          </button>
          <div className="rounded-lg bg-panel-2/60 p-3 text-[11px] leading-relaxed text-muted">
            <p className="mb-1 font-semibold text-text/80">So wird gelesen</p>
            Angriffstexte stehen in Codeblöcken <code className="text-cyan">```text</code> oder{" "}
            <code className="text-cyan">```prompt</code> unter den Workflow-Schritten. Solche Skills erscheinen beim
            Testlauf als eigenes Modul. Alle anderen liefern Gegenmaßnahmen und Prüflisten, die bei passenden Befunden
            im Dashboard auftauchen. Eigene Skills können im Frontmatter <code className="text-cyan">kac_detect</code>{" "}
            (leak, judge) und <code className="text-cyan">kac_goal</code> setzen.
          </div>
        </section>

        <section className="panel col-span-12 p-5 lg:col-span-8">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-muted">
            <Swords size={14} /> Mit Angriffen ({withAttacks.length})
            <span className="ml-auto flex items-center gap-2">
              <BookOpen size={14} /> Wissen ({knowledge.length})
            </span>
          </h2>
          {skills?.length === 0 && (
            <p className="text-sm text-muted">Noch keine Skills. Links eine Quelle wählen und importieren.</p>
          )}
          <div className="space-y-2">
            {[...withAttacks, ...knowledge].map((s) => {
              const expanded = open === s.name;
              return (
                <div key={s.name} className="rounded-lg border border-line bg-[#0b1222]/70 p-3">
                  <div className="flex items-start gap-2">
                    <button onClick={() => setOpen(expanded ? null : s.name)} className="mt-0.5 text-muted">
                      {expanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                    </button>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-sm font-medium">{s.title}</span>
                        {s.payload_count > 0 ? (
                          <span className="rounded bg-red/15 px-1.5 py-0.5 text-[10px] text-red">
                            {s.payload_count} Angriffe
                          </span>
                        ) : (
                          <span className="rounded bg-panel-2 px-1.5 py-0.5 text-[10px] text-muted">Wissen</span>
                        )}
                        {s.owasp.map((o) => (
                          <span
                            key={o}
                            title={OWASP_LABEL[o]}
                            className="rounded bg-violet/15 px-1.5 py-0.5 text-[10px] text-violet"
                          >
                            {o}
                          </span>
                        ))}
                        {s.atlas.slice(0, 3).map((a) => (
                          <span key={a} className="rounded bg-cyan/10 px-1.5 py-0.5 text-[10px] text-cyan">
                            {a}
                          </span>
                        ))}
                      </div>
                      <p className={`mt-1 text-xs text-muted ${expanded ? "" : "line-clamp-2"}`}>{s.description}</p>
                    </div>
                    <button
                      onClick={() => openLink(s.source)}
                      className="text-muted hover:text-cyan"
                      title={s.source}
                      hidden={!s.source.startsWith("http")}
                    >
                      <ExternalLink size={14} />
                    </button>
                    <button onClick={() => remove(s.name)} className="text-muted hover:text-red" title="Entfernen">
                      <Trash2 size={14} />
                    </button>
                  </div>
                  {expanded && (
                    <div className="mt-3 space-y-3 pl-6 text-xs">
                      {s.groups.map((g) => (
                        <div key={g.title}>
                          <div className="mb-1 font-semibold text-text/80">{g.title}</div>
                          <div className="space-y-1">
                            {g.payloads.map((p, i) => (
                              <pre
                                key={i}
                                className="whitespace-pre-wrap break-all rounded-md bg-red/5 px-2 py-1 font-mono text-[11px] text-red/90"
                              >
                                {p}
                              </pre>
                            ))}
                          </div>
                        </div>
                      ))}
                      {s.remediation.length > 0 && (
                        <div>
                          <div className="mb-1 font-semibold text-green">Gegenmaßnahmen</div>
                          <ul className="list-disc space-y-0.5 pl-4 text-text/80">
                            {s.remediation.map((r, i) => (
                              <li key={i}>{r}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {s.checklist.length > 0 && (
                        <div>
                          <div className="mb-1 font-semibold text-cyan">Prüfliste</div>
                          <ul className="space-y-0.5 text-text/80">
                            {s.checklist.map((r, i) => (
                              <li key={i}>☐ {r}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                      <p className="text-[10px] text-muted">
                        {s.author && `Autor: ${s.author} · `}
                        {s.license && `Lizenz: ${s.license} · `}
                        {s.source}
                      </p>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      </div>
    </div>
  );
}

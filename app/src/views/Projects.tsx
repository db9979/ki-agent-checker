import { FolderPlus, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/engine";
import type { Project } from "../lib/types";
import { useApi } from "../lib/useApi";

const input = "w-full rounded-lg border border-line bg-[#0b1222] px-3 py-2 text-sm outline-none focus:border-cyan";

export function Projects() {
  const { data: projects, reload } = useApi<Project[]>("/projects");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [scope, setScope] = useState("");
  const [by, setBy] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const create = async () => {
    setError(null);
    try {
      await api("/projects", {
        method: "POST",
        body: JSON.stringify({
          name,
          description,
          scope: scope.split("\n").map((s) => s.trim()).filter(Boolean),
          authorized_by: by,
          authorization_confirmed: confirmed,
        }),
      });
      setName("");
      setDescription("");
      setScope("");
      setConfirmed(false);
      reload();
    } catch (e) {
      setError(String((e as Error).message));
    }
  };

  return (
    <div className="grid grid-cols-12 gap-4">
      <header className="col-span-12">
        <h1 className="text-2xl font-semibold">Projekte</h1>
        <p className="text-sm text-muted">Jedes Projekt legt fest, welche Agenten getestet werden dürfen. Jeder Lauf wird im Audit-Log festgehalten.</p>
      </header>
      <section className="panel col-span-12 space-y-3 p-5 lg:col-span-5">
        <h2 className="text-sm font-semibold text-muted">Neues Projekt</h2>
        <label className="block text-xs text-muted">
          Name
          <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="block text-xs text-muted">
          Beschreibung
          <input className={input} value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        <label className="block text-xs text-muted">
          Scope: erlaubte Ziele, eins pro Zeile
          <textarea className={`${input} h-24 font-mono`} value={scope} onChange={(e) => setScope(e.target.value)} placeholder="https://agent.firma.de/api" />
        </label>
        <label className="block text-xs text-muted">
          Freigegeben von
          <input className={input} value={by} onChange={(e) => setBy(e.target.value)} />
        </label>
        <label className="flex items-start gap-2 rounded-lg border border-amber/40 bg-amber/5 p-3 text-xs">
          <input type="checkbox" className="mt-0.5" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
          Ich bestätige, dass ich für alle Ziele im Scope berechtigt bin, Sicherheitstests durchzuführen.
        </label>
        {error && <p className="text-xs text-red">{error}</p>}
        <button
          onClick={create}
          disabled={!name || !by || !confirmed}
          className="glow-cyan flex w-full items-center justify-center gap-2 rounded-xl bg-cyan/15 py-2 text-sm font-medium text-cyan disabled:opacity-40"
        >
          <FolderPlus size={15} /> Projekt anlegen
        </button>
      </section>
      <section className="panel col-span-12 p-5 lg:col-span-7">
        <h2 className="mb-3 text-sm font-semibold text-muted">Projekte</h2>
        {projects?.length === 0 && <p className="text-sm text-muted">Noch keine Projekte.</p>}
        <div className="space-y-2">
          {projects?.map((p) => (
            <div key={p.id} className="rounded-xl border border-line bg-panel-2/60 p-3">
              <div className="flex items-center gap-2 text-sm font-medium">
                <ShieldCheck size={15} className="text-green" /> {p.name}
              </div>
              {p.description && <div className="mt-1 text-xs text-muted">{p.description}</div>}
              <div className="mt-2 flex flex-wrap gap-1">
                {p.scope.map((s) => (
                  <span key={s} className="rounded bg-[#0b1222] px-2 py-0.5 font-mono text-[11px] text-cyan">
                    {s}
                  </span>
                ))}
              </div>
              <div className="mt-2 text-[11px] text-muted">
                Freigegeben von {p.authorized_by} am {new Date(p.authorized_at).toLocaleString("de-DE")}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

import {
  Bot,
  CheckCircle2,
  Crosshair,
  FolderPlus,
  Globe,
  Loader2,
  Plug,
  Plus,
  Server,
  ShieldCheck,
  Trash2,
  X,
  XCircle,
} from "lucide-react";
import { useState } from "react";
import { loadScanner, saveScanner, ScannerOptions, type ScannerSettings } from "../components/ScannerOptions";
import { TargetForm } from "../components/TargetForm";
import { api } from "../lib/engine";
import type { AttackModuleInfo, ConnectionResult, Project, Provider, Target } from "../lib/types";
import { useApi } from "../lib/useApi";

const input = "w-full rounded-lg border border-line bg-[#0b1222] px-3 py-2 text-sm outline-none focus:border-cyan";

const KIND_ICON = { model: Bot, openai_endpoint: Plug, http: Globe, mcp: Server, mcp_tool: Server } as const;

function CodeInputs({
  names,
  codes,
  onChange,
}: {
  names: string[];
  codes: Record<string, string>;
  onChange: (c: Record<string, string>) => void;
}) {
  return (
    <div className="space-y-1.5 rounded-lg border border-amber/40 bg-amber/5 p-2">
      <p className="text-[11px] text-amber">
        2FA-Code eingeben (wird nur für diese Anmeldung verwendet, nicht gespeichert)
      </p>
      {names.map((n) => (
        <label key={n} className="flex items-center gap-2 text-xs text-muted">
          <span className="w-28 truncate">{n || "Code"}</span>
          <input
            className="flex-1 rounded-md border border-line bg-[#0b1222] px-2 py-1 font-mono text-xs tracking-widest outline-none focus:border-cyan"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            value={codes[n] ?? ""}
            onChange={(e) => onChange({ ...codes, [n]: e.target.value.trim() })}
          />
        </label>
      ))}
    </div>
  );
}

function RunPanel({ target, onStarted, onClose }: { target: Target; onStarted: () => void; onClose: () => void }) {
  const { data: allModules } = useApi<AttackModuleInfo[]>("/attack-modules");
  const isMcp = target.kind === "mcp";
  const modules = allModules?.filter((m) => m.target === (isMcp ? "mcp" : "agent"));
  const noCalls = isMcp && target.mcp_tool_calls === "none";
  const { data: providers } = useApi<Provider[]>("/providers");
  const [off, setOff] = useState<Set<string>>(new Set());
  const [judge, setJudge] = useState("");
  const [attacker, setAttacker] = useState("");
  const [maxTurns, setMaxTurns] = useState(5);
  const [error, setError] = useState<string | null>(null);
  const pairs = target.accounts.filter((a) => a.identifier && a.marker).length;
  const manual = target.auth.mfa === "manual";
  const names = target.accounts.length ? target.accounts.map((a) => a.name) : [""];
  const [codes, setCodes] = useState<Record<string, string>>({});
  const missingCode = manual && names.some((n) => !codes[n]);
  const [source, setSource] = useState<"own" | "garak" | "promptfoo">("own");
  const [scanner, setScanner] = useState<ScannerSettings>(loadScanner("garak"));
  const pick = (s: "own" | "garak" | "promptfoo") => {
    setSource(s);
    if (s !== "own") setScanner(loadScanner(s));
  };

  const start = async () => {
    setError(null);
    try {
      await api("/runs", {
        method: "POST",
        body: JSON.stringify({
          target_id: target.id,
          modules: (modules ?? []).map((m) => m.key).filter((k) => !off.has(k)),
          judge_provider_id: judge || null,
          attacker_provider_id: attacker || null,
          max_turns: maxTurns,
          mfa_codes: manual ? codes : {},
          scanner: source === "own" ? null : scanner,
        }),
      });
      if (source !== "own") saveScanner(scanner);
      onStarted();
    } catch (e) {
      setError(String((e as Error).message));
    }
  };

  return (
    <div className="mt-3 space-y-2 rounded-lg border border-red/30 bg-red/5 p-3">
      <div className="flex items-center text-xs font-semibold text-red">
        <Crosshair size={13} className="mr-1.5" /> Testlauf gegen {target.name}
        <button onClick={onClose} className="ml-auto text-muted hover:text-text">
          <X size={14} />
        </button>
      </div>
      {!isMcp && (
        <div className="grid grid-cols-3 gap-1">
          {(
            [
              ["own", "Eigene Angriffe"],
              ["garak", "garak"],
              ["promptfoo", "Promptfoo"],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              onClick={() => pick(key)}
              className={`rounded-md border px-2 py-1 text-[11px] ${
                source === key ? "border-red/60 bg-red/10 text-red" : "border-line text-muted hover:text-text"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      )}
      {source !== "own" && <ScannerOptions value={scanner} onChange={setScanner} />}
      <div className={`grid grid-cols-2 gap-1 ${source !== "own" ? "hidden" : ""}`}>
        {(modules ?? []).map((m) => {
          const noAttacker = !!m.needs_attacker && !attacker;
          const unavailable = m.needs_accounts > pairs || (noCalls && !!m.calls_tools) || noAttacker;
          return (
            <label
              key={m.key}
              className={`flex items-center gap-2 text-xs ${unavailable ? "opacity-40" : ""}`}
              title={
                unavailable
                  ? isMcp
                    ? "Ruft Tools auf, beim Ziel sind Tool-Aufrufe ausgeschaltet"
                    : noAttacker
                      ? "Braucht ein Angreifer-Modell (unten auswählen)"
                      : "Braucht zwei Testkonten mit Kennung und privater Angabe"
                  : m.title
              }
            >
              <input
                type="checkbox"
                disabled={unavailable}
                checked={!unavailable && !off.has(m.key)}
                onChange={(e) => {
                  const next = new Set(off);
                  if (e.target.checked) next.delete(m.key);
                  else next.add(m.key);
                  setOff(next);
                }}
              />
              <span className="truncate">{m.label}</span>{" "}
              {m.skill && <span className="rounded bg-violet/15 px-1 text-[9px] text-violet">Skill</span>}
              {m.attacks > 0 && <span className="text-[10px] text-muted">({m.attacks})</span>}
            </label>
          );
        })}
      </div>
      {!isMcp && source === "own" && (
        <div className="grid grid-cols-[1fr_auto] gap-2">
          <label className="block text-xs text-muted">
            Angreifer-Modell (für mehrstufige Angriffe, optional)
            <select
              className="mt-1 w-full rounded-md border border-line bg-[#0b1222] px-2 py-1.5 text-xs"
              value={attacker}
              onChange={(e) => setAttacker(e.target.value)}
            >
              <option value="">ohne (keine mehrstufigen Angriffe)</option>
              {(providers ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label className={`block text-xs text-muted ${attacker ? "" : "opacity-40"}`}>
            Runden
            <input
              type="number"
              min={1}
              max={10}
              disabled={!attacker}
              value={maxTurns}
              onChange={(e) => setMaxTurns(Math.min(10, Math.max(1, Number(e.target.value) || 1)))}
              className="mt-1 w-16 rounded-md border border-line bg-[#0b1222] px-2 py-1.5 text-xs"
            />
          </label>
        </div>
      )}
      {!isMcp && source === "own" && (
        <label className="block text-xs text-muted">
          Richter-Modell (bewertet unklare Antworten, optional)
          <select
            className="mt-1 w-full rounded-md border border-line bg-[#0b1222] px-2 py-1.5 text-xs"
            value={judge}
            onChange={(e) => setJudge(e.target.value)}
          >
            <option value="">ohne Richter (nur eindeutige Signale)</option>
            {(providers ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
      )}
      {manual && <CodeInputs names={names} codes={codes} onChange={setCodes} />}
      {error && <p className="text-xs text-red">{error}</p>}
      <button
        onClick={start}
        disabled={missingCode}
        className="glow-red disabled:opacity-40 flex w-full items-center justify-center gap-2 rounded-lg bg-red/15 py-1.5 text-sm font-medium text-red"
      >
        <Crosshair size={14} /> Angriff starten
      </button>
    </div>
  );
}

function TargetRow({
  t,
  project,
  onChanged,
  onRunStarted,
}: {
  t: Target;
  project: Project;
  onChanged: () => void;
  onRunStarted: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [check, setCheck] = useState<ConnectionResult | "busy" | null>(null);
  const [running, setRunning] = useState(false);
  const Icon = KIND_ICON[t.kind];
  const manual = t.auth.mfa === "manual";
  const first = t.accounts[0]?.name ?? "";
  const [asking, setAsking] = useState(false);
  const [codes, setCodes] = useState<Record<string, string>>({});
  const test = async () => {
    if (manual && !codes[first]) {
      setAsking(true);
      return;
    }
    setAsking(false);
    setCheck("busy");
    try {
      setCheck(
        await api<ConnectionResult>(`/targets/${t.id}/check`, {
          method: "POST",
          body: JSON.stringify({ mfa_codes: manual ? codes : {} }),
        }),
      );
    } finally {
      setCodes({});
    }
  };
  const remove = async () => {
    await api(`/targets/${t.id}`, { method: "DELETE" });
    onChanged();
  };
  return (
    <div className="rounded-lg border border-line bg-[#0b1222]/70 p-2.5">
      <div className="flex items-center gap-2 text-xs">
        <Icon size={14} className="text-cyan" />
        <span className="font-medium">{t.name}</span>
        <span className="truncate font-mono text-[10px] text-muted">{t.url ?? "eigenes Modell"}</span>
        <span className="ml-auto flex shrink-0 gap-1">
          <button onClick={test} className="rounded-md bg-panel-2 px-2 py-0.5 text-[11px] text-muted hover:text-text">
            {check === "busy" ? <Loader2 size={12} className="animate-spin" /> : "Prüfen"}
          </button>
          <button
            onClick={() => setRunning(!running)}
            className="rounded-md bg-red/15 px-2 py-0.5 text-[11px] text-red"
          >
            Testen
          </button>
          <button
            onClick={() => setEditing(!editing)}
            className={`rounded-md px-2 py-0.5 text-[11px] ${editing ? "bg-cyan/15 text-cyan" : "bg-panel-2 text-muted hover:text-text"}`}
          >
            Bearbeiten
          </button>
          <button onClick={remove} className="px-1 text-muted hover:text-red" title="Ziel löschen">
            <Trash2 size={12} />
          </button>
        </span>
      </div>
      {t.accounts.length > 0 && (
        <div className="mt-1.5 flex flex-wrap gap-1">
          {t.accounts.map((a) => (
            <span key={a.name} className="rounded bg-violet/10 px-1.5 py-0.5 text-[10px] text-violet">
              {a.name} · {a.role}
            </span>
          ))}
          {t.auth.kind !== "none" && (
            <span className="rounded bg-amber/10 px-1.5 py-0.5 text-[10px] text-amber">Anmeldung: {t.auth.kind}</span>
          )}
        </div>
      )}
      {check && check !== "busy" && (
        <div className={`mt-1.5 flex items-start gap-1.5 text-[11px] ${check.ok ? "text-green" : "text-red"}`}>
          {check.ok ? (
            <CheckCircle2 size={12} className="mt-0.5 shrink-0" />
          ) : (
            <XCircle size={12} className="mt-0.5 shrink-0" />
          )}
          <span className="line-clamp-2">{check.ok ? `${check.latency_ms} ms · „${check.reply}“` : check.error}</span>
        </div>
      )}
      {asking && (
        <div className="mt-2 flex items-end gap-2">
          <div className="flex-1">
            <CodeInputs names={[first]} codes={codes} onChange={setCodes} />
          </div>
          <button
            onClick={test}
            disabled={!codes[first]}
            className="rounded-md bg-cyan/15 px-3 py-1.5 text-xs text-cyan disabled:opacity-40"
          >
            Prüfen
          </button>
        </div>
      )}
      {running && <RunPanel target={t} onStarted={onRunStarted} onClose={() => setRunning(false)} />}
      {editing && (
        <div className="mt-3 rounded-xl border border-cyan/30 bg-[#080d19] p-3">
          <TargetForm
            project={project}
            initial={t}
            onSaved={() => {
              setEditing(false);
              setCheck(null);
              onChanged();
            }}
          />
        </div>
      )}
    </div>
  );
}

function ProjectCard({ p, onRunStarted }: { p: Project; onRunStarted: () => void }) {
  const { data: targets, reload } = useApi<Target[]>(`/targets?project_id=${p.id}`);
  const [adding, setAdding] = useState(false);
  return (
    <div className="rounded-xl border border-line bg-panel-2/60 p-3">
      <div className="flex items-center gap-2 text-sm font-medium">
        <ShieldCheck size={15} className="text-green" /> {p.name}
        <button
          onClick={() => setAdding(!adding)}
          className="ml-auto flex items-center gap-1 rounded-md bg-cyan/10 px-2 py-0.5 text-[11px] text-cyan"
        >
          {adding ? <X size={12} /> : <Plus size={12} />} Ziel
        </button>
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
      <div className="mt-3 space-y-2">
        {targets?.map((t) => (
          <TargetRow key={t.id} t={t} project={p} onChanged={reload} onRunStarted={onRunStarted} />
        ))}
      </div>
      {adding && (
        <div className="mt-3 rounded-xl border border-cyan/30 bg-[#080d19] p-3">
          <TargetForm
            project={p}
            onSaved={() => {
              setAdding(false);
              reload();
            }}
          />
        </div>
      )}
    </div>
  );
}

export function Projects({ onRunStarted }: { onRunStarted: () => void }) {
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
          scope: scope
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean),
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
        <p className="text-sm text-muted">
          Jedes Projekt legt fest, welche Agenten getestet werden dürfen. Jeder Lauf wird im Audit-Log festgehalten.
        </p>
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
          <textarea
            className={`${input} h-24 font-mono`}
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            placeholder="https://agent.firma.de/api"
          />
        </label>
        <label className="block text-xs text-muted">
          Freigegeben von
          <input className={input} value={by} onChange={(e) => setBy(e.target.value)} />
        </label>
        <label className="flex items-start gap-2 rounded-lg border border-amber/40 bg-amber/5 p-3 text-xs">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
          />
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
        <h2 className="mb-3 text-sm font-semibold text-muted">Projekte und Ziele</h2>
        {projects?.length === 0 && <p className="text-sm text-muted">Noch keine Projekte.</p>}
        <div className="space-y-3">
          {projects?.map((p) => (
            <ProjectCard key={p.id} p={p} onRunStarted={onRunStarted} />
          ))}
        </div>
      </section>
    </div>
  );
}

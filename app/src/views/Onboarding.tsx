import { AnimatePresence, motion } from "framer-motion";
import {
  ArrowLeft,
  ArrowRight,
  BookOpen,
  Check,
  CheckCircle2,
  Copy,
  Crosshair,
  Eye,
  FolderKanban,
  FolderPlus,
  Layers,
  Loader2,
  Mail,
  Minimize2,
  Play,
  Rocket,
  Server,
  ShieldCheck,
  ShieldHalf,
  Sparkles,
  Wrench,
  X,
  XCircle,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { loadScanner, saveScanner, type ScannerTool } from "../components/ScannerOptions";
import { TargetForm } from "../components/TargetForm";
import { api } from "../lib/engine";
import { setOnboarding, useOnboarding } from "../lib/onboarding";
import type { AttackModuleInfo, ConnectionResult, Project, Provider, Skill, Target } from "../lib/types";
import { useApi } from "../lib/useApi";

const STEPS = [
  { key: "welcome", label: "Willkommen", icon: Sparkles },
  { key: "project", label: "Projekt", icon: FolderKanban },
  { key: "model", label: "Modell", icon: Server, optional: true },
  { key: "target", label: "Ziel", icon: Crosshair },
  { key: "sources", label: "Testquellen", icon: Layers },
  { key: "run", label: "Erster Lauf", icon: Rocket },
] as const;

const input = "w-full rounded-lg border border-line bg-[#0b1222] px-3 py-2 text-sm outline-none focus:border-cyan";
const small =
  "w-full rounded-md border border-line bg-[#0b1222] px-2 py-1.5 font-mono text-[11px] outline-none focus:border-cyan";

type Nav = "models" | "skills" | "projects";

export interface OnboardingProps {
  onNavigate: (view: Nav) => void;
  onRunStarted: () => void;
  onStartDemo: () => void;
}

/** Geführte Einrichtung nach der Installation: Projekt, Modell, Ziel, Testquellen, erster Lauf. */
export function Onboarding(props: OnboardingProps) {
  const ob = useOnboarding();
  const step = Math.min(ob.step, STEPS.length - 1);
  const go = (s: number) => setOnboarding({ step: Math.max(0, Math.min(STEPS.length - 1, s)) });
  const minimize = () => setOnboarding({ open: false });
  const finish = () => setOnboarding({ open: false, done: true });

  return (
    <AnimatePresence>
      {ob.open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#03060d]/80 p-3 backdrop-blur-sm"
        >
          <motion.div
            initial={{ y: 16, scale: 0.98 }}
            animate={{ y: 0, scale: 1 }}
            className="panel flex h-full max-h-[760px] w-full max-w-5xl overflow-hidden !bg-[#0a1120] shadow-2xl"
          >
            <Stepper step={step} onGo={go} />
            <div className="flex min-w-0 flex-1 flex-col">
              <div className="flex shrink-0 items-center justify-between border-b border-line px-5 py-3">
                <div className="text-xs text-muted">
                  Schritt {step + 1} von {STEPS.length} · <span className="text-text">{STEPS[step].label}</span>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={minimize}
                    title="Später fortsetzen"
                    className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-muted hover:bg-panel-2 hover:text-text"
                  >
                    <Minimize2 size={13} /> Später
                  </button>
                  <button
                    onClick={finish}
                    title="Einrichtung schließen (unter Hilfe wieder aufrufbar)"
                    className="rounded-md p-1 text-muted hover:bg-panel-2 hover:text-text"
                  >
                    <X size={16} />
                  </button>
                </div>
              </div>
              <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
                <AnimatePresence mode="wait">
                  <motion.div
                    key={step}
                    initial={{ opacity: 0, x: 12 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -12 }}
                    transition={{ duration: 0.15 }}
                  >
                    {step === 0 && <Welcome onNext={() => go(1)} onDemo={props.onStartDemo} onSkip={finish} />}
                    {step === 1 && <ProjectStep />}
                    {step === 2 && <ModelStep onNavigate={props.onNavigate} />}
                    {step === 3 && <TargetStep />}
                    {step === 4 && <SourcesStep onNavigate={props.onNavigate} />}
                    {step === 5 && <RunStep onRunStarted={props.onRunStarted} onNavigate={props.onNavigate} />}
                  </motion.div>
                </AnimatePresence>
              </div>
              {step > 0 && <Footer step={step} onGo={go} onFinish={finish} />}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

/** Kleiner Hinweis unten rechts, solange die Einrichtung pausiert ist. */
export function OnboardingResume() {
  const ob = useOnboarding();
  if (ob.open || ob.done || ob.step === 0) return null;
  return (
    <div className="fixed bottom-4 right-4 z-40 flex items-center gap-1 rounded-full border border-cyan/40 bg-[#0a1120]/95 py-1 pl-3 pr-1 text-xs shadow-xl">
      <button onClick={() => setOnboarding({ open: true })} className="flex items-center gap-2 text-cyan">
        <Rocket size={14} /> Einrichtung fortsetzen
        <span className="text-muted">
          {Math.min(ob.step, STEPS.length - 1) + 1}/{STEPS.length}
        </span>
      </button>
      <button
        onClick={() => setOnboarding({ done: true })}
        className="rounded-full p-1 text-muted hover:text-text"
        title="Ausblenden"
      >
        <X size={13} />
      </button>
    </div>
  );
}

function Stepper({ step, onGo }: { step: number; onGo: (s: number) => void }) {
  const ob = useOnboarding();
  const complete = (key: string) =>
    (key === "project" && !!ob.projectId) || (key === "target" && !!ob.targetId);
  return (
    <aside className="hidden w-56 shrink-0 flex-col border-r border-line bg-[#080d19] p-5 md:flex">
      <div className="mb-6 flex items-center gap-2">
        <ShieldHalf className="text-cyan" size={22} />
        <div>
          <div className="text-sm font-semibold leading-tight">Einrichtung</div>
          <div className="text-[10px] uppercase tracking-[0.18em] text-muted">KI-Agent-Checker</div>
        </div>
      </div>
      <ol className="relative space-y-1">
        <span className="absolute bottom-4 left-[17px] top-4 w-px bg-line" />
        {STEPS.map((s, i) => {
          const Icon = s.icon;
          const active = i === step;
          const past = i < step || complete(s.key);
          return (
            <li key={s.key}>
              <button
                onClick={() => onGo(i)}
                className={`relative flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left text-sm transition ${
                  active ? "bg-cyan/10 text-cyan" : "text-muted hover:text-text"
                }`}
              >
                <span
                  className={`z-10 grid h-5 w-5 shrink-0 place-items-center rounded-full border ${
                    active
                      ? "border-cyan bg-cyan/20"
                      : past
                        ? "border-green bg-green/20 text-green"
                        : "border-line bg-[#080d19]"
                  }`}
                >
                  {past && !active ? <Check size={11} /> : <Icon size={11} />}
                </span>
                <span className="flex-1">{s.label}</span>
                {"optional" in s && <span className="text-[9px] uppercase text-muted">optional</span>}
              </button>
            </li>
          );
        })}
      </ol>
      <p className="mt-auto text-[11px] leading-relaxed text-muted">
        Alles lässt sich später unter Projekte, Modelle und Skills ändern. Die Anleitung steht unter Hilfe.
      </p>
    </aside>
  );
}

function Footer({ step, onGo, onFinish }: { step: number; onGo: (s: number) => void; onFinish: () => void }) {
  const ob = useOnboarding();
  const blocked = (step === 1 && !ob.projectId) || (step === 3 && !ob.targetId);
  const last = step === STEPS.length - 1;
  return (
    <div className="flex shrink-0 items-center justify-between border-t border-line px-5 py-3">
      <button
        onClick={() => onGo(step - 1)}
        className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm text-muted hover:text-text"
      >
        <ArrowLeft size={14} /> Zurück
      </button>
      <div className="flex items-center gap-3">
        {blocked && (
          <button onClick={() => onGo(step + 1)} className="text-xs text-muted underline-offset-2 hover:underline">
            Überspringen
          </button>
        )}
        {last ? (
          <button
            onClick={onFinish}
            className="rounded-lg border border-line px-4 py-1.5 text-sm text-muted hover:text-text"
          >
            Fertig ohne Lauf
          </button>
        ) : (
          <button
            onClick={() => onGo(step + 1)}
            disabled={blocked}
            className="glow-cyan flex items-center gap-1.5 rounded-lg bg-cyan/15 px-4 py-1.5 text-sm font-medium text-cyan disabled:opacity-40 disabled:shadow-none"
          >
            Weiter <ArrowRight size={14} />
          </button>
        )}
      </div>
    </div>
  );
}

function Title({ icon: Icon, title, children }: { icon: typeof Rocket; title: string; children: ReactNode }) {
  return (
    <div className="mb-5">
      <h2 className="flex items-center gap-2 text-xl font-semibold">
        <Icon size={20} className="text-cyan" /> {title}
      </h2>
      <p className="mt-1 max-w-2xl text-sm leading-relaxed text-muted">{children}</p>
    </div>
  );
}

function Status({ ok, children }: { ok: boolean; children: ReactNode }) {
  return (
    <p className={`flex items-start gap-1.5 text-xs ${ok ? "text-green" : "text-red"}`}>
      {ok ? <CheckCircle2 size={13} className="mt-0.5 shrink-0" /> : <XCircle size={13} className="mt-0.5 shrink-0" />}
      <span className="break-words">{children}</span>
    </p>
  );
}

// ---------------------------------------------------------------------------
// Schritt 1: Willkommen

function Welcome({ onNext, onDemo, onSkip }: { onNext: () => void; onDemo: () => void; onSkip: () => void }) {
  const cards = [
    {
      icon: Crosshair,
      color: "text-red",
      title: "Angreifen",
      text: "Prompt Injection, Jailbreaks, System-Prompt-Leaks, Datenabfluss und Tool-Missbrauch gegen Chat-Agenten und MCP-Server.",
    },
    {
      icon: Eye,
      color: "text-cyan",
      title: "Sehen",
      text: "Jeder Angriff live als Pfad durch vier Schutzschichten, Angriffsgraph des echten Ziels, Heatmap nach OWASP LLM Top 10.",
    },
    {
      icon: Wrench,
      color: "text-green",
      title: "Beheben",
      text: "Befunde mit Beleg und Gegenmaßnahme, Vergleich vorher/nachher und Bericht als HTML oder PDF.",
    },
  ];
  return (
    <div className="flex flex-col items-center py-4 text-center">
      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        className="glow-cyan mb-4 grid h-16 w-16 place-items-center rounded-2xl bg-cyan/10"
      >
        <ShieldHalf size={34} className="text-cyan" />
      </motion.div>
      <h2 className="text-2xl font-semibold">Willkommen beim KI-Agent-Checker</h2>
      <p className="mt-2 max-w-xl text-sm leading-relaxed text-muted">
        In wenigen Schritten richtest du dein erstes Ziel ein und startest den ersten Angriff. Dauert etwa fünf
        Minuten, jeder Schritt lässt sich überspringen und später nachholen.
      </p>
      <div className="mt-6 grid w-full max-w-3xl gap-3 sm:grid-cols-3">
        {cards.map((c, i) => (
          <motion.div
            key={c.title}
            initial={{ y: 10, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 0.08 * i }}
            className="rounded-xl border border-line bg-panel-2/60 p-4 text-left"
          >
            <c.icon size={18} className={c.color} />
            <div className="mt-2 text-sm font-semibold">{c.title}</div>
            <p className="mt-1 text-xs leading-relaxed text-muted">{c.text}</p>
          </motion.div>
        ))}
      </div>
      <div className="mt-6 flex max-w-3xl items-start gap-2 rounded-lg border border-amber/40 bg-amber/5 px-4 py-2 text-left text-xs text-amber">
        <ShieldCheck size={14} className="mt-0.5 shrink-0" />
        Nur für autorisierte Tests: Teste ausschließlich Agenten, für die du eine Berechtigung hast. Jeder Lauf
        landet im Audit-Log.
      </div>
      <div className="mt-6 flex flex-wrap justify-center gap-2">
        <button
          onClick={onNext}
          className="glow-cyan flex items-center gap-2 rounded-xl bg-cyan/15 px-5 py-2.5 text-sm font-medium text-cyan transition hover:bg-cyan/25"
        >
          <Rocket size={16} /> Einrichtung starten
        </button>
        <button
          onClick={() => {
            setOnboarding({ open: false });
            onDemo();
          }}
          className="flex items-center gap-2 rounded-xl border border-line px-5 py-2.5 text-sm text-muted transition hover:text-text"
          title="Vorbereiteter Lauf gegen einen fiktiven Kundenservice-Agenten, braucht kein Modell"
        >
          <Play size={15} /> Erst die Demo ansehen
        </button>
      </div>
      <button onClick={onSkip} className="mt-4 text-xs text-muted underline-offset-2 hover:underline">
        Einrichtung überspringen
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Schritt 2: Projekt

function ProjectStep() {
  const ob = useOnboarding();
  const { data: projects, reload } = useApi<Project[]>("/projects");
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [scope, setScope] = useState("");
  const [by, setBy] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const showForm = creating || projects?.length === 0;

  const create = async () => {
    setError(null);
    try {
      const p = await api<Project>("/projects", {
        method: "POST",
        body: JSON.stringify({
          name,
          description: "",
          scope: scope
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean),
          authorized_by: by,
          authorization_confirmed: confirmed,
        }),
      });
      setOnboarding({ projectId: p.id, targetId: null });
      setCreating(false);
      reload();
    } catch (e) {
      setError(String((e as Error).message));
    }
  };

  return (
    <>
      <Title icon={FolderKanban} title="Projekt anlegen">
        Ein Projekt legt fest, welche Adressen getestet werden dürfen (Scope), und hält fest, wer den Test freigegeben
        hat. Ziele außerhalb des Scopes lehnt die App ab.
      </Title>
      {!!projects?.length && (
        <div className="mb-4 space-y-2">
          <div className="text-xs text-muted">Vorhandenes Projekt verwenden</div>
          {projects.map((p) => (
            <button
              key={p.id}
              onClick={() => setOnboarding({ projectId: p.id, targetId: p.id === ob.projectId ? ob.targetId : null })}
              className={`flex w-full items-center gap-3 rounded-xl border p-3 text-left transition ${
                ob.projectId === p.id ? "border-cyan bg-cyan/10" : "border-line bg-panel-2/50 hover:border-cyan/50"
              }`}
            >
              <ShieldCheck size={16} className={ob.projectId === p.id ? "text-cyan" : "text-green"} />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium">{p.name}</div>
                <div className="truncate font-mono text-[11px] text-muted">{p.scope.join(" · ") || "ohne Scope"}</div>
              </div>
              {ob.projectId === p.id && <CheckCircle2 size={16} className="text-cyan" />}
            </button>
          ))}
          {!creating && (
            <button
              onClick={() => setCreating(true)}
              className="flex items-center gap-1.5 text-xs text-cyan hover:underline"
            >
              <FolderPlus size={13} /> Neues Projekt anlegen
            </button>
          )}
        </div>
      )}
      {showForm && (
        <div className="grid max-w-2xl gap-3 rounded-xl border border-line bg-panel-2/40 p-4 sm:grid-cols-2">
          <label className="block text-xs text-muted">
            Name
            <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="z. B. Kundenservice-Bot" />
          </label>
          <label className="block text-xs text-muted">
            Freigegeben von
            <input className={input} value={by} onChange={(e) => setBy(e.target.value)} placeholder="Name oder Ticket" />
          </label>
          <label className="block text-xs text-muted sm:col-span-2">
            Scope: erlaubte Ziele, eins pro Zeile (Domain oder Adresse)
            <textarea
              className={`${input} h-20 font-mono`}
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              placeholder={"agent.firma.de\nhttp://localhost:11434"}
            />
          </label>
          <label className="flex items-start gap-2 rounded-lg border border-amber/40 bg-amber/5 p-3 text-xs sm:col-span-2">
            <input type="checkbox" className="mt-0.5" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
            Ich bestätige, dass ich für alle Ziele im Scope berechtigt bin, Sicherheitstests durchzuführen.
          </label>
          {error && <p className="text-xs text-red sm:col-span-2">{error}</p>}
          <button
            onClick={create}
            disabled={!name || !by || !confirmed}
            className="glow-cyan flex items-center justify-center gap-2 rounded-xl bg-cyan/15 py-2 text-sm font-medium text-cyan disabled:opacity-40 sm:col-span-2"
          >
            <FolderPlus size={15} /> Projekt anlegen
          </button>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Schritt 3: Modell (optional)

function ModelStep({ onNavigate }: { onNavigate: (v: Nav) => void }) {
  const { data: providers } = useApi<Provider[]>("/providers");
  const [results, setResults] = useState<Record<string, ConnectionResult | "busy">>({});
  const test = async (id: string) => {
    setResults((r) => ({ ...r, [id]: "busy" }));
    const res = await api<ConnectionResult>(`/providers/${id}/test`, { method: "POST" }).catch(
      (e): ConnectionResult => ({ ok: false, latency_ms: null, reply: null, error: String(e.message) }),
    );
    setResults((r) => ({ ...r, [id]: res }));
  };
  const uses = [
    ["Eigenes Modell als Ziel", "Das Modell spielt mit deinem System-Prompt den Agenten. Gut, um einen Agenten vor dem Livegang zu testen."],
    ["Richter", "Bewertet Antworten, bei denen die eindeutigen Signale nicht reichen."],
    ["Angreifer", "Führt mehrstufige Angriffe über mehrere Nachrichten. Lokale Modelle ohne strenge Filter eignen sich am besten."],
  ];
  return (
    <>
      <Title icon={Server} title="Modell verbinden (optional)">
        Testest du einen fertigen Agenten oder MCP-Server, kannst du diesen Schritt überspringen. Ein Modell brauchst
        du für diese Zwecke:
      </Title>
      <div className="mb-5 grid gap-2 sm:grid-cols-3">
        {uses.map(([t, d]) => (
          <div key={t} className="rounded-xl border border-line bg-panel-2/50 p-3">
            <div className="text-sm font-medium">{t}</div>
            <p className="mt-1 text-xs leading-relaxed text-muted">{d}</p>
          </div>
        ))}
      </div>
      <div className="mb-2 text-xs text-muted">Verbundene Modelle</div>
      {providers?.length === 0 && <p className="mb-3 text-sm text-muted">Noch keine Modelle verbunden.</p>}
      <div className="mb-4 space-y-2">
        {providers?.map((p) => {
          const r = results[p.id];
          return (
            <div key={p.id} className="rounded-xl border border-line bg-panel-2/50 p-3">
              <div className="flex items-center gap-3">
                <Server size={15} className={p.self_hosted ? "text-green" : "text-cyan"} />
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium">{p.name}</div>
                  <div className="truncate font-mono text-[11px] text-muted">
                    {p.kind}/{p.model}
                  </div>
                </div>
                <button
                  onClick={() => test(p.id)}
                  className="rounded-lg border border-line px-3 py-1 text-xs hover:border-cyan"
                >
                  {r === "busy" ? <Loader2 size={13} className="animate-spin" /> : "Testen"}
                </button>
              </div>
              {r && r !== "busy" && (
                <div className="mt-2">
                  <Status ok={r.ok}>{r.ok ? `Antwort in ${r.latency_ms} ms: „${r.reply}“` : r.error}</Status>
                </div>
              )}
            </div>
          );
        })}
      </div>
      <button
        onClick={() => {
          setOnboarding({ open: false });
          onNavigate("models");
        }}
        className="flex items-center gap-2 rounded-xl border border-cyan/40 px-4 py-2 text-sm text-cyan hover:bg-cyan/10"
      >
        <Server size={15} /> Modell verbinden
      </button>
      <p className="mt-2 text-xs text-muted">
        Öffnet die Seite Modelle (Ollama, vLLM, LM Studio, OpenAI, Anthropic, Gemini, Mistral). Danach unten rechts
        „Einrichtung fortsetzen“ klicken.
      </p>
    </>
  );
}

// ---------------------------------------------------------------------------
// Schritt 4: Ziel

function TargetStep() {
  const ob = useOnboarding();
  const { data: projects } = useApi<Project[]>("/projects");
  const project = projects?.find((p) => p.id === ob.projectId) ?? null;
  const { data: targets, reload } = useApi<Target[]>(`/targets?project_id=${ob.projectId ?? ""}`, [ob.projectId]);
  const [adding, setAdding] = useState(false);
  const [check, setCheck] = useState<ConnectionResult | "busy" | null>(null);
  const selected = targets?.find((t) => t.id === ob.targetId) ?? null;
  const showForm = adding || targets?.length === 0;

  useEffect(() => setCheck(null), [ob.targetId]);

  if (!ob.projectId) {
    return (
      <>
        <Title icon={Crosshair} title="Ziel einrichten">
          Zuerst ein Projekt anlegen oder auswählen.
        </Title>
        <button onClick={() => setOnboarding({ step: 1 })} className="text-sm text-cyan hover:underline">
          Zum Schritt Projekt
        </button>
      </>
    );
  }

  const test = async () => {
    if (!selected) return;
    setCheck("busy");
    setCheck(
      await api<ConnectionResult>(`/targets/${selected.id}/check`, {
        method: "POST",
        body: JSON.stringify({ mfa_codes: {} }),
      }).catch((e): ConnectionResult => ({ ok: false, latency_ms: null, reply: null, error: String(e.message) })),
    );
  };

  return (
    <>
      <Title icon={Crosshair} title="Ziel einrichten">
        Das Ziel ist das, was angegriffen wird: ein Chat-Agent (OpenAI-API oder beliebiger HTTP-Endpunkt), ein MCP-Server
        oder ein eigenes Modell mit System-Prompt. Liegt der Agent hinter einer Anmeldung, trägst du sie hier ein;
        Zugangsdaten landen im Schlüsselbund.
      </Title>
      {!!targets?.length && (
        <div className="mb-4 space-y-2">
          <div className="text-xs text-muted">Ziele in „{project?.name}“</div>
          {targets.map((t) => (
            <button
              key={t.id}
              onClick={() => setOnboarding({ targetId: t.id })}
              className={`flex w-full items-center gap-3 rounded-xl border p-3 text-left transition ${
                ob.targetId === t.id ? "border-cyan bg-cyan/10" : "border-line bg-panel-2/50 hover:border-cyan/50"
              }`}
            >
              <Crosshair size={15} className={ob.targetId === t.id ? "text-cyan" : "text-muted"} />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium">{t.name}</div>
                <div className="truncate font-mono text-[11px] text-muted">{t.url ?? "eigenes Modell"}</div>
              </div>
              {ob.targetId === t.id && <CheckCircle2 size={16} className="text-cyan" />}
            </button>
          ))}
          {selected && selected.auth.mfa !== "manual" && (
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button
                onClick={test}
                className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs hover:border-cyan"
              >
                {check === "busy" ? <Loader2 size={13} className="animate-spin" /> : <CheckCircle2 size={13} />}
                Verbindung prüfen
              </button>
              {check && check !== "busy" && (
                <Status ok={check.ok}>
                  {check.ok ? `${check.latency_ms} ms · „${check.reply}“` : check.error}
                </Status>
              )}
            </div>
          )}
          {!adding && (
            <button onClick={() => setAdding(true)} className="flex items-center gap-1.5 pt-1 text-xs text-cyan hover:underline">
              <FolderPlus size={13} /> Weiteres Ziel anlegen
            </button>
          )}
        </div>
      )}
      {showForm && project && (
        <div className="max-w-3xl rounded-xl border border-cyan/30 bg-[#080d19] p-4">
          <TargetForm
            project={project}
            onSaved={(t) => {
              setOnboarding({ targetId: t.id });
              setAdding(false);
              reload();
            }}
          />
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Schritt 5: Testquellen

function os(): "mac" | "win" | "linux" {
  const ua = navigator.userAgent;
  if (/Mac/i.test(ua)) return "mac";
  if (/Win/i.test(ua)) return "win";
  return "linux";
}

const GARAK_INSTALL = {
  mac: ["brew install pipx", "pipx install garak"],
  linux: ["sudo apt install pipx", "pipx install garak"],
  win: ["py -m pip install --user pipx", "py -m pipx install garak"],
};

const PYRIT_INSTALL = {
  mac: ["brew install pipx", "pipx install pyrit"],
  linux: ["sudo apt install pipx", "pipx install pyrit"],
  win: ["py -m pip install --user pipx", "py -m pipx install pyrit"],
};

function CopyLine({ cmd }: { cmd: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-2 rounded-md border border-line bg-[#060912] px-2 py-1 font-mono text-[11px] text-green">
      <span className="select-all flex-1 truncate">$ {cmd}</span>
      <button
        onClick={() => {
          navigator.clipboard?.writeText(cmd).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          });
        }}
        title="Kopieren"
        className="text-muted hover:text-text"
      >
        {copied ? <Check size={12} className="text-green" /> : <Copy size={12} />}
      </button>
    </div>
  );
}

function SourceCard({
  icon: Icon,
  title,
  badge,
  children,
}: {
  icon: typeof Rocket;
  title: string;
  badge: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-line bg-panel-2/50 p-4">
      <div className="flex items-center gap-2">
        <Icon size={16} className="text-cyan" />
        <span className="text-sm font-semibold">{title}</span>
        <span className="ml-auto">{badge}</span>
      </div>
      {children}
    </div>
  );
}

function Badge({ tone, children }: { tone: "green" | "amber" | "muted"; children: ReactNode }) {
  const cls = { green: "bg-green/15 text-green", amber: "bg-amber/15 text-amber", muted: "bg-panel text-muted" }[tone];
  return <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${cls}`}>{children}</span>;
}

type Check = { ok: boolean; version?: string; error?: string } | "busy" | null;

function useScannerCheck(tool: ScannerTool) {
  const [cmd, setCmd] = useState(loadScanner(tool).cmd);
  const [check, setCheck] = useState<Check>(null);
  const run = async () => {
    setCheck("busy");
    try {
      const res = await api<{ ok: boolean; version?: string; error?: string }>(
        `/scanners/check?tool=${tool}&cmd=${encodeURIComponent(cmd)}`,
      );
      if (res.ok) saveScanner({ ...loadScanner(tool), cmd });
      setCheck(res);
    } catch (e) {
      setCheck({ ok: false, error: String((e as Error).message) });
    }
  };
  return { cmd, setCmd, check, run };
}

function CheckRow({ cmd, setCmd, check, run }: ReturnType<typeof useScannerCheck>) {
  return (
    <>
      <div className="flex gap-1">
        <input className={small} value={cmd} onChange={(e) => setCmd(e.target.value)} aria-label="Befehl" />
        <button onClick={run} className="shrink-0 rounded-md bg-panel px-3 text-[11px] hover:text-text">
          {check === "busy" ? <Loader2 size={12} className="animate-spin" /> : "Prüfen"}
        </button>
      </div>
      {check && check !== "busy" && <Status ok={check.ok}>{check.ok ? `Gefunden: ${check.version || "ok"}` : check.error}</Status>}
    </>
  );
}

function SourcesStep({ onNavigate }: { onNavigate: (v: Nav) => void }) {
  const { data: modules } = useApi<AttackModuleInfo[]>("/attack-modules");
  const { data: skills, reload: reloadSkills } = useApi<Skill[]>("/skills");
  const garak = useScannerCheck("garak");
  const pf = useScannerCheck("promptfoo");
  const pyrit = useScannerCheck("pyrit");
  const [email, setEmail] = useState("");
  const [mail, setMail] = useState<{ ok: boolean; email?: string; error?: string } | "busy" | null>(null);
  const [skillBusy, setSkillBusy] = useState<string | null>(null);
  const agentModules = modules?.filter((m) => m.target === "agent") ?? [];
  const mcpModules = modules?.filter((m) => m.target === "mcp") ?? [];
  const attacks = agentModules.reduce((n, m) => n + m.attacks, 0);
  const system = os();

  const readMail = async () => {
    setMail("busy");
    const res = await api<{ ok: boolean; email: string; error?: string }>(
      `/scanners/promptfoo/email?cmd=${encodeURIComponent(pf.cmd)}`,
    ).catch((e) => ({ ok: false, email: "", error: String(e.message) }));
    if (res.email) setEmail(res.email);
    setMail(res.ok && !res.email ? { ok: false, error: "Noch keine E-Mail hinterlegt" } : res);
  };
  const saveMail = async () => {
    setMail("busy");
    setMail(
      await api<{ ok: boolean; email: string; error?: string }>("/scanners/promptfoo/email", {
        method: "POST",
        body: JSON.stringify({ cmd: pf.cmd, email }),
      }).catch((e) => ({ ok: false, error: String(e.message) })),
    );
  };
  const importSkills = async () => {
    setSkillBusy("busy");
    try {
      const r = await api<{ imported: number; attacks: number }>("/skills/import", {
        method: "POST",
        body: JSON.stringify({
          source: "github",
          repo: "mukul975/Anthropic-Cybersecurity-Skills",
          ref: "main",
          path: null,
          only_ai: true,
        }),
      });
      setSkillBusy(`${r.imported} Skills übernommen, ${r.attacks} neue Angriffstexte`);
      reloadSkills();
    } catch (e) {
      setSkillBusy(`Fehler: ${(e as Error).message}`);
    }
  };

  const garakOk = garak.check !== null && garak.check !== "busy" && garak.check.ok;
  const pyritOk = pyrit.check !== null && pyrit.check !== "busy" && pyrit.check.ok;
  const pfOk = pf.check !== null && pf.check !== "busy" && pf.check.ok;
  const mailOk = mail !== null && mail !== "busy" && mail.ok && !!mail.email;

  return (
    <>
      <Title icon={Layers} title="Testquellen einrichten">
        Die eigenen Angriffe sind sofort einsatzbereit. garak, Promptfoo und PyRIT sind bekannte Open-Source-Werkzeuge mit
        hunderten weiteren Tests; sie werden einmalig separat installiert und laufen dann über die App gegen dein Ziel.
      </Title>
      <div className="grid gap-3 lg:grid-cols-2">
        <SourceCard icon={Crosshair} title="Eigene Angriffe" badge={<Badge tone="green">bereit</Badge>}>
          <p className="text-xs leading-relaxed text-muted">
            {agentModules.length} Module mit {attacks} Angriffen für Chat-Agenten, {mcpModules.length} Prüfungen für
            MCP-Server. Keine Installation nötig.
          </p>
          <div className="flex flex-wrap gap-1">
            {agentModules.slice(0, 10).map((m) => (
              <span key={m.key} className="rounded bg-[#0b1222] px-1.5 py-0.5 text-[10px] text-muted">
                {m.label}
              </span>
            ))}
          </div>
        </SourceCard>

        <SourceCard
          icon={BookOpen}
          title="Skills"
          badge={<Badge tone={skills?.length ? "green" : "muted"}>{skills?.length ? `${skills.length} importiert` : "optional"}</Badge>}
        >
          <p className="text-xs leading-relaxed text-muted">
            Sammlungen im SKILL.md-Format liefern zusätzliche Angriffstexte und Gegenmaßnahmen. Standard ist die
            Sammlung Anthropic-Cybersecurity-Skills (Apache-2.0). Skripte werden nie ausgeführt.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={importSkills}
              disabled={skillBusy === "busy"}
              className="flex items-center gap-1.5 rounded-lg border border-cyan/40 px-3 py-1.5 text-xs text-cyan hover:bg-cyan/10 disabled:opacity-50"
            >
              {skillBusy === "busy" ? <Loader2 size={12} className="animate-spin" /> : <BookOpen size={12} />}
              Standardsammlung importieren
            </button>
            <button
              onClick={() => {
                setOnboarding({ open: false });
                onNavigate("skills");
              }}
              className="text-xs text-muted hover:text-text hover:underline"
            >
              Eigenen Ordner wählen
            </button>
          </div>
          {skillBusy && skillBusy !== "busy" && (
            <Status ok={!skillBusy.startsWith("Fehler")}>{skillBusy}</Status>
          )}
        </SourceCard>

        <SourceCard
          icon={Wrench}
          title="garak"
          badge={<Badge tone={garakOk ? "green" : "muted"}>{garakOk ? "gefunden" : "optional"}</Badge>}
        >
          <p className="text-xs leading-relaxed text-muted">
            Scanner von NVIDIA mit vielen Probes (Prompt Injection, DAN-Jailbreaks, Kodierungstricks, Leaks). Braucht
            Python 3.10+. Einmal im Terminal ausführen:
          </p>
          <div className="space-y-1">
            {GARAK_INSTALL[system].map((c) => (
              <CopyLine key={c} cmd={c} />
            ))}
          </div>
          <p className="text-[11px] text-muted">Danach prüfen. Wird garak nicht gefunden, den vollen Pfad eintragen.</p>
          <CheckRow {...garak} />
        </SourceCard>

        <SourceCard
          icon={Layers}
          title="PyRIT"
          badge={<Badge tone={pyritOk ? "green" : "muted"}>{pyritOk ? "gefunden" : "optional"}</Badge>}
        >
          <p className="text-xs leading-relaxed text-muted">
            Red-Teaming-Werkzeug von Microsoft mit über 600 bekannten Jailbreak-Vorlagen. Die App liest die Vorlagen
            und schickt sie selbst ans Ziel. Braucht Python 3.10 bis 3.13:
          </p>
          <div className="space-y-1">
            {PYRIT_INSTALL[system].map((c) => (
              <CopyLine key={c} cmd={c} />
            ))}
          </div>
          <p className="text-[11px] text-muted">Feld leer lassen, die App sucht PyRIT selbst. Sonst Python-Befehl oder Ordner eintragen.</p>
          <CheckRow {...pyrit} />
        </SourceCard>

        <SourceCard
          icon={Sparkles}
          title="Promptfoo"
          badge={
            <Badge tone={pfOk && mailOk ? "green" : pfOk ? "amber" : "muted"}>
              {pfOk && mailOk ? "bereit" : pfOk ? "E-Mail fehlt" : "optional"}
            </Badge>
          }
        >
          <p className="text-xs leading-relaxed text-muted">
            Erzeugt Angriffe passend zum Zweck deines Agenten (OWASP LLM Top 10). Braucht{" "}
            <span className="text-text">Node.js 18+</span>; beim ersten Prüfen wird Promptfoo heruntergeladen, das kann
            eine Minute dauern.
          </p>
          <CheckRow {...pf} />
          <div className="mt-1 rounded-lg border border-line bg-[#0b1222]/60 p-2.5">
            <div className="mb-1 flex items-center gap-1.5 text-xs font-medium">
              <Mail size={12} className="text-cyan" /> E-Mail für Red-Team-Scans
            </div>
            <p className="mb-2 text-[11px] leading-relaxed text-muted">
              Promptfoo verlangt einmalig eine bestätigte E-Mail-Adresse. Hier eintragen und speichern; beim ersten
              Scan kommt eine Mail mit Bestätigungslink, danach den Scan noch einmal starten.
            </p>
            <div className="flex gap-1">
              <input
                className={`${small} font-sans`}
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="du@firma.de"
              />
              <button
                onClick={saveMail}
                disabled={!email.includes("@")}
                className="shrink-0 rounded-md bg-cyan/15 px-3 text-[11px] text-cyan disabled:opacity-40"
              >
                Speichern
              </button>
              <button onClick={readMail} className="shrink-0 rounded-md bg-panel px-2 text-[11px] hover:text-text" title="Hinterlegte E-Mail lesen">
                Status
              </button>
            </div>
            {mail === "busy" && (
              <p className="mt-1 flex items-center gap-1 text-[11px] text-muted">
                <Loader2 size={11} className="animate-spin" /> frage Promptfoo …
              </p>
            )}
            {mail && mail !== "busy" && (
              <div className="mt-1">
                <Status ok={mail.ok}>{mail.ok ? `Hinterlegt: ${mail.email}` : mail.error}</Status>
              </div>
            )}
          </div>
        </SourceCard>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Schritt 6: Erster Lauf

function RunStep({ onRunStarted, onNavigate }: { onRunStarted: () => void; onNavigate: (v: Nav) => void }) {
  const ob = useOnboarding();
  const { data: targets } = useApi<Target[]>(`/targets?project_id=${ob.projectId ?? ""}`, [ob.projectId]);
  const { data: modules } = useApi<AttackModuleInfo[]>("/attack-modules");
  const target = targets?.find((t) => t.id === ob.targetId) ?? targets?.[0] ?? null;
  const isMcp = target?.kind === "mcp";
  const [source, setSource] = useState<"own" | ScannerTool>("own");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const pairs = target?.accounts.filter((a) => a.identifier && a.marker).length ?? 0;
  const noCalls = isMcp && target?.mcp_tool_calls === "none";
  const active = (modules ?? []).filter(
    (m) =>
      m.target === (isMcp ? "mcp" : "agent") &&
      m.needs_accounts <= pairs &&
      !m.needs_attacker &&
      !(noCalls && m.calls_tools),
  );
  const manual = target?.auth.mfa === "manual";

  const start = async () => {
    if (!target) return;
    setBusy(true);
    setError(null);
    try {
      await api("/runs", {
        method: "POST",
        body: JSON.stringify({
          target_id: target.id,
          modules: active.map((m) => m.key),
          judge_provider_id: null,
          attacker_provider_id: null,
          mfa_codes: {},
          scanner: source === "own" ? null : loadScanner(source),
        }),
      });
      setOnboarding({ open: false, done: true });
      onRunStarted();
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };

  if (!target) {
    return (
      <>
        <Title icon={Rocket} title="Erster Lauf">
          Für einen Lauf brauchst du ein Ziel. Lege eins an oder sieh dir zuerst die Demo an.
        </Title>
        <button onClick={() => setOnboarding({ step: 3 })} className="text-sm text-cyan hover:underline">
          Zum Schritt Ziel
        </button>
      </>
    );
  }

  const sources: [typeof source, string, string][] = [
    ["own", "Eigene Angriffe", `${active.length} Module, Ergebnisse live`],
    ["garak", "garak", "Probes von NVIDIA, live im Angriffspfad"],
    ["promptfoo", "Promptfoo", "Angriffe passend zum Zweck, Ergebnis am Ende"],
    ["pyrit", "PyRIT", "Bekannte Jailbreak-Vorlagen, live im Angriffspfad"],
  ];

  return (
    <>
      <Title icon={Rocket} title="Ersten Lauf starten">
        Alles bereit. Der Lauf startet gegen <span className="text-text">{target.name}</span>; die App springt in den
        Live-Angriff, wo du jeden Angriff als Pfad durch die Schutzschichten verfolgst.
      </Title>
      <div className="mb-4 grid max-w-3xl gap-2 sm:grid-cols-4">
        {sources
          .filter(([k]) => !isMcp || k === "own")
          .map(([k, label, hint]) => (
            <button
              key={k}
              onClick={() => setSource(k)}
              className={`rounded-xl border p-3 text-left transition ${
                source === k ? "border-red/60 bg-red/10" : "border-line bg-panel-2/50 hover:border-red/30"
              }`}
            >
              <div className={`text-sm font-medium ${source === k ? "text-red" : ""}`}>{label}</div>
              <div className="mt-0.5 text-[11px] text-muted">{hint}</div>
            </button>
          ))}
      </div>
      {source === "own" && (
        <div className="mb-4 flex max-w-3xl flex-wrap gap-1">
          {active.map((m) => (
            <span key={m.key} className="rounded bg-red/10 px-2 py-0.5 text-[11px] text-red">
              {m.label}
            </span>
          ))}
        </div>
      )}
      <p className="mb-4 max-w-3xl text-xs leading-relaxed text-muted">
        Richter- und Angreifer-Modell, einzelne Module und Scanner-Einstellungen wählst du später unter Projekte → Testen.
      </p>
      {manual ? (
        <div className="max-w-3xl rounded-lg border border-amber/40 bg-amber/5 p-3 text-xs text-amber">
          Dieses Ziel braucht einen 2FA-Code von Hand. Starte den Lauf deshalb unter{" "}
          <button
            className="underline"
            onClick={() => {
              setOnboarding({ open: false, done: true });
              onNavigate("projects");
            }}
          >
            Projekte → Testen
          </button>
          .
        </div>
      ) : (
        <button
          onClick={start}
          disabled={busy}
          className="glow-red flex items-center gap-2 rounded-xl bg-red/15 px-6 py-3 text-sm font-semibold text-red transition hover:bg-red/25 disabled:opacity-50"
        >
          {busy ? <Loader2 size={16} className="animate-spin" /> : <Crosshair size={16} />} Angriff starten
        </button>
      )}
      {error && <p className="mt-2 text-xs text-red">{error}</p>}
    </>
  );
}

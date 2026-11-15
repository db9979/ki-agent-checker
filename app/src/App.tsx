import {
  Activity,
  BookOpen,
  FolderKanban,
  GitCompareArrows,
  Gauge,
  LayoutDashboard,
  Network,
  Server,
  ShieldHalf,
  Sparkles,
} from "lucide-react";
import { useEffect, useState } from "react";
import { api, subscribe } from "./lib/engine";
import { dispatch, setOnline, useRun } from "./lib/runStore";
import { setEffectsMode, useEffectsMode } from "./lib/settings";
import { AttackGraph } from "./views/AttackGraph";
import { Compare } from "./views/Compare";
import { Dashboard } from "./views/Dashboard";
import { LiveAttack } from "./views/LiveAttack";
import { Models } from "./views/Models";
import { Projects } from "./views/Projects";
import { Skills } from "./views/Skills";

const NAV = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "live", label: "Live-Angriff", icon: Activity },
  { id: "graph", label: "Angriffsgraph", icon: Network },
  { id: "compare", label: "Vergleich", icon: GitCompareArrows },
  { id: "models", label: "Modelle", icon: Server },
  { id: "projects", label: "Projekte", icon: FolderKanban },
  { id: "skills", label: "Skills", icon: BookOpen },
] as const;

type View = (typeof NAV)[number]["id"];

export default function App() {
  const [view, setView] = useState<View>("dashboard");
  const run = useRun();
  const effects = useEffectsMode();

  useEffect(() => subscribe(dispatch, setOnline), []);

  const startDemo = async () => {
    await api("/runs/demo", { method: "POST", body: JSON.stringify({ delay: 0.6 }) });
    setView("live");
  };

  return (
    <div className="flex h-full">
      {/* Unter 1400 px (z. B. uConsole mit 1280×720) nur Symbole, damit mehr Platz bleibt */}
      <nav className="flex w-16 shrink-0 flex-col border-r border-line bg-[#080d19]/80 p-3 min-[1400px]:w-56 min-[1400px]:p-4">
        <div className="mb-8 flex items-center gap-2">
          <ShieldHalf className="mx-auto shrink-0 text-cyan min-[1400px]:mx-0" size={26} />
          <div className="hidden min-[1400px]:block">
            <div className="text-sm font-semibold leading-tight">KI-Agent-Checker</div>
            <div className="text-[10px] uppercase tracking-[0.18em] text-muted">Security Lab</div>
          </div>
        </div>
        <div className="space-y-1">
          {NAV.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setView(id)}
              title={label}
              className={`relative flex w-full items-center justify-center gap-3 rounded-lg px-3 py-2 text-sm transition min-[1400px]:justify-start ${
                view === id ? "bg-cyan/10 text-cyan" : "text-muted hover:bg-panel-2 hover:text-text"
              }`}
            >
              <Icon size={17} className="shrink-0" />
              <span className="hidden min-[1400px]:inline">{label}</span>
              {id === "live" && run.status === "running" && (
                <span className="absolute right-1 top-1 h-2 w-2 animate-ping rounded-full bg-red min-[1400px]:static min-[1400px]:ml-auto" />
              )}
            </button>
          ))}
        </div>
        <button
          onClick={() => setEffectsMode(effects === "voll" ? "sparsam" : "voll")}
          title={
            effects === "voll"
              ? "Effekte: voll (klicken für Leistungsmodus)"
              : "Leistungsmodus aktiv (klicken für volle Effekte)"
          }
          className="mb-3 mt-auto flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs text-muted transition hover:bg-panel-2 hover:text-text min-[1400px]:justify-start"
        >
          {effects === "voll" ? (
            <Sparkles size={15} className="shrink-0 text-violet" />
          ) : (
            <Gauge size={15} className="shrink-0 text-amber" />
          )}
          <span className="hidden min-[1400px]:inline">{effects === "voll" ? "Effekte: voll" : "Leistungsmodus"}</span>
        </button>
        <div
          className="flex items-center justify-center gap-2 text-xs text-muted min-[1400px]:justify-start"
          title={`Engine ${run.online ? "verbunden" : "nicht erreichbar"}`}
        >
          <span className={`h-2 w-2 shrink-0 rounded-full ${run.online ? "bg-green" : "bg-red"}`} />
          <span className="hidden min-[1400px]:inline">Engine {run.online ? "verbunden" : "nicht erreichbar"}</span>
        </div>
      </nav>
      <main className="flex-1 overflow-y-auto p-4 min-[1400px]:p-6">
        {view === "dashboard" && <Dashboard onStartDemo={startDemo} />}
        {view === "live" && <LiveAttack onStartDemo={startDemo} />}
        {view === "graph" && <AttackGraph />}
        {view === "compare" && <Compare />}
        {view === "models" && <Models />}
        {view === "projects" && <Projects onRunStarted={() => setView("live")} />}
        {view === "skills" && <Skills />}
      </main>
    </div>
  );
}

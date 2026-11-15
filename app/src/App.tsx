import { Activity, FolderKanban, LayoutDashboard, Network, Server, ShieldHalf } from "lucide-react";
import { useEffect, useState } from "react";
import { api, subscribe } from "./lib/engine";
import { dispatch, setOnline, useRun } from "./lib/runStore";
import { AttackGraph } from "./views/AttackGraph";
import { Dashboard } from "./views/Dashboard";
import { LiveAttack } from "./views/LiveAttack";
import { Models } from "./views/Models";
import { Projects } from "./views/Projects";

const NAV = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "live", label: "Live-Angriff", icon: Activity },
  { id: "graph", label: "Angriffsgraph", icon: Network },
  { id: "models", label: "Modelle", icon: Server },
  { id: "projects", label: "Projekte", icon: FolderKanban },
] as const;

type View = (typeof NAV)[number]["id"];

export default function App() {
  const [view, setView] = useState<View>("dashboard");
  const run = useRun();

  useEffect(() => subscribe(dispatch, setOnline), []);

  const startDemo = async () => {
    await api("/runs/demo", { method: "POST", body: JSON.stringify({ delay: 0.6 }) });
    setView("live");
  };

  return (
    <div className="flex h-full">
      <nav className="flex w-56 shrink-0 flex-col border-r border-line bg-[#080d19]/80 p-4">
        <div className="mb-8 flex items-center gap-2">
          <ShieldHalf className="text-cyan" size={26} />
          <div>
            <div className="text-sm font-semibold leading-tight">KI-Agent-Checker</div>
            <div className="text-[10px] uppercase tracking-[0.18em] text-muted">Security Lab</div>
          </div>
        </div>
        <div className="space-y-1">
          {NAV.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setView(id)}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                view === id ? "bg-cyan/10 text-cyan" : "text-muted hover:bg-panel-2 hover:text-text"
              }`}
            >
              <Icon size={17} />
              {label}
              {id === "live" && run.status === "running" && <span className="ml-auto h-2 w-2 animate-ping rounded-full bg-red" />}
            </button>
          ))}
        </div>
        <div className="mt-auto flex items-center gap-2 text-xs text-muted">
          <span className={`h-2 w-2 rounded-full ${run.online ? "bg-green" : "bg-red"}`} />
          Engine {run.online ? "verbunden" : "nicht erreichbar"}
        </div>
      </nav>
      <main className="flex-1 overflow-y-auto p-6">
        {view === "dashboard" && <Dashboard onStartDemo={startDemo} />}
        {view === "live" && <LiveAttack onStartDemo={startDemo} />}
        {view === "graph" && <AttackGraph />}
        {view === "models" && <Models />}
        {view === "projects" && <Projects />}
      </main>
    </div>
  );
}

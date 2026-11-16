import { motion } from "framer-motion";
import { HelpLink } from "../components/HelpLink";
import { Crosshair, Loader2, Play, RotateCcw, Rocket, ShieldAlert } from "lucide-react";
import type { View } from "../App";
import { openOnboarding } from "../lib/onboarding";
import { useMemo, useState } from "react";
import { api } from "../lib/engine";
import { ModuleRadar, TrendChart } from "../components/Charts";
import { Heatmap, type HeatRow } from "../components/Heatmap";
import { ReportButton } from "../components/ReportButton";
import { ScoreGauge } from "../components/ScoreGauge";
import { SeverityBars } from "../components/SeverityBars";
import { MODULES } from "../lib/modules";
import { liveScore, useRun } from "../lib/runStore";
import { openLink } from "../lib/open";
import type { Finding, RunSummary, Skill } from "../lib/types";
import { useApi } from "../lib/useApi";
import { OWASP_LABEL, SEVERITY_COLOR, SEVERITY_LABEL } from "../lib/ui";

export function Dashboard({ onNavigate }: { onNavigate: (v: View) => void }) {
  const run = useRun();
  const { data: runs } = useApi<RunSummary[]>("/runs", [run.status]);
  const { data: skills } = useApi<Skill[]>("/skills");
  const finished = (runs ?? []).filter((r) => r.status === "finished");
  const last = finished.at(-1) ?? null;
  const live = run.status !== "idle";
  const reportId = live ? (run.status === "finished" ? run.runId : null) : (last?.id ?? null);
  const history = (runs ?? [])
    .filter((r) => r.status !== "running")
    .slice(-8)
    .reverse();

  const score = live ? liveScore(run) : (last?.score ?? null);
  // „Nur das erneut testen“ nach einem Fix: nur für abgeschlossene Läufe mit bekanntem Ziel
  const retestTarget = !live || run.status === "finished" ? (live ? (runs ?? []).find((r) => r.id === run.runId)?.target_id : last?.target_id) ?? null : null;
  const findings: Finding[] = live ? run.findings : (last?.findings ?? []);

  const rows: HeatRow[] = useMemo(() => {
    if (live) {
      return run.modules.map((m) => ({ ...m, rate: m.attempts ? m.hits / m.attempts : null }));
    }
    const mcpRun =
      !!last && (last.target.startsWith("MCP-Server") || last.findings.some((f) => f.module.startsWith("mcp_")));
    return MODULES.filter((m) => m.key.startsWith("mcp_") === mcpRun).map((m) => {
      const f = last?.findings.find((x) => x.module === m.key);
      return { ...m, attempts: last ? 1 : 0, rate: last ? (f?.success_rate ?? 0) : null };
    });
  }, [live, run.modules, last]);

  const trend = finished.map((r, i) => ({ label: `#${i + 1}`, score: r.score ?? 0 }));
  const radar = rows.map((r) => ({
    module: r.label,
    resistance: r.rate === null ? 100 : Math.round((1 - r.rate) * 100),
  }));

  return (
    <div className="grid grid-cols-12 gap-4">
      <header className="col-span-12 flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold">
            Dashboard <HelpLink anchor="ergebnisse-lesen" />
          </h1>
          <p className="text-sm text-muted">{live ? run.target : last ? last.target : "Noch kein Testlauf"}</p>
        </div>
        <div className="flex items-start gap-2">
          {reportId && <ReportButton runId={reportId} />}
        </div>
      </header>

      {!live && runs?.length === 0 && (
        <section className="panel col-span-12 flex flex-wrap items-center gap-4 border-cyan/30 p-5">
          <div className="grid h-12 w-12 shrink-0 place-items-center rounded-xl bg-cyan/10">
            <Rocket size={22} className="text-cyan" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="font-semibold">Noch kein Testlauf</div>
            <p className="text-sm text-muted">
              Die Einrichtung führt in wenigen Schritten zum ersten Angriff: Projekt, Ziel, Testquellen, Start.
            </p>
          </div>
          <button
            onClick={() => openOnboarding()}
            className="glow-cyan flex items-center gap-2 rounded-xl bg-cyan/15 px-4 py-2 text-sm font-medium text-cyan transition hover:bg-cyan/25"
          >
            <Play size={15} /> Einrichtung starten
          </button>
          <button
            onClick={() => onNavigate("projects")}
            className="flex items-center gap-2 rounded-xl border border-line px-4 py-2 text-sm text-muted transition hover:text-text"
          >
            <Crosshair size={15} /> Zu den Projekten
          </button>
        </section>
      )}

      <section className="panel col-span-12 flex flex-col items-center justify-center p-5 md:col-span-4">
        <ScoreGauge score={score} />
        {run.status === "running" && (
          <div className="mt-4 w-full">
            <div className="mb-1 flex justify-between text-xs text-muted">
              <span>Lauf läuft</span>
              <span className="tabular-nums">
                {run.done}/{run.total}
              </span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-[#0b1222]">
              <motion.div
                className="h-full bg-cyan"
                animate={{ width: `${(run.done / Math.max(1, run.total)) * 100}%` }}
              />
            </div>
          </div>
        )}
      </section>

      <section className="panel col-span-12 p-5 md:col-span-4">
        <h2 className="mb-4 text-sm font-semibold text-muted">Findings nach Schweregrad</h2>
        <SeverityBars findings={findings} />
      </section>

      <section className="panel col-span-12 p-5 md:col-span-4">
        <h2 className="mb-2 text-sm font-semibold text-muted">Widerstand pro Modul</h2>
        <div className="h-52">
          <ModuleRadar data={radar} />
        </div>
      </section>

      <section className="panel col-span-12 p-5 lg:col-span-7">
        <h2 className="mb-3 text-sm font-semibold text-muted">Angriffs-Heatmap · Modul × OWASP LLM Top 10</h2>
        <Heatmap rows={rows} />
      </section>

      <section className="panel col-span-12 p-5 lg:col-span-5">
        <h2 className="mb-3 text-sm font-semibold text-muted">Score-Verlauf</h2>
        <div className="h-56">
          <TrendChart data={trend} />
        </div>
      </section>

      {history.length > 0 && (
        <section className="panel col-span-12 p-5">
          <h2 className="mb-3 text-sm font-semibold text-muted">Letzte Läufe</h2>
          <div className="divide-y divide-line text-xs">
            {history.map((r) => (
              <div key={r.id} className="flex items-center gap-3 py-1.5">
                <span className="w-32 shrink-0 tabular-nums text-muted">
                  {new Date(r.started_at).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" })}
                </span>
                <span className="min-w-0 flex-1 truncate">{r.target}</span>
                <span className="text-muted">{r.findings.length} Befunde</span>
                <span className="w-16 text-right font-mono tabular-nums">
                  {r.status === "finished" ? (r.score ?? "–") : r.status === "failed" ? "Fehler" : "abgebr."}
                </span>
                <ReportButton runId={r.id} compact />
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="panel col-span-12 p-5">
        <h2 className="mb-3 text-sm font-semibold text-muted">Findings und Gegenmaßnahmen</h2>
        {findings.length === 0 ? (
          <p className="text-sm text-muted">Keine Findings. Starte unter Projekte einen Testlauf, um die Ansicht zu füllen.</p>
        ) : (
          <div className="space-y-3">
            {findings.map((f, i) => (
              <motion.div
                key={f.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.06 }}
                className="rounded-xl border border-line bg-panel-2/60 p-4"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <ShieldAlert size={16} style={{ color: SEVERITY_COLOR[f.severity] }} />
                  <span className="font-medium">{f.title}</span>
                  <span
                    className="rounded-md px-2 py-0.5 text-[11px] font-semibold"
                    style={{ background: `${SEVERITY_COLOR[f.severity]}22`, color: SEVERITY_COLOR[f.severity] }}
                  >
                    {SEVERITY_LABEL[f.severity]}
                  </span>
                  <span
                    className="rounded-md bg-violet/15 px-2 py-0.5 text-[11px] text-violet"
                    title={OWASP_LABEL[f.owasp]}
                  >
                    {f.owasp}
                  </span>
                  {f.atlas && (
                    <span className="rounded-md bg-cyan/10 px-2 py-0.5 text-[11px] text-cyan">{f.atlas}</span>
                  )}
                  <span className="ml-auto text-xs tabular-nums text-muted">
                    {Math.round(f.success_rate * 100)} % erfolgreich
                  </span>
                  {retestTarget && !/^(garak|promptfoo):/.test(f.module) && (
                    <RetestButton targetId={retestTarget} module={f.module} onStarted={() => onNavigate("live")} />
                  )}
                </div>
                <p className="mt-2 text-sm text-text/80">
                  <span className="font-medium text-green">Gegenmaßnahme: </span>
                  {f.remediation}
                </p>
                <RelatedSkills finding={f} skills={skills ?? []} />
              </motion.div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function RetestButton({ targetId, module, onStarted }: { targetId: string; module: string; onStarted: () => void }) {
  const [state, setState] = useState<"idle" | "busy" | string>("idle");
  const start = async () => {
    setState("busy");
    try {
      await api("/runs", { method: "POST", body: JSON.stringify({ target_id: targetId, modules: [module] }) });
      onStarted();
    } catch (e) {
      setState(String((e as Error).message));
    }
  };
  return (
    <button
      onClick={start}
      disabled={state === "busy"}
      title={state !== "idle" && state !== "busy" ? state : "Nach einem Fix nur dieses Modul gegen dasselbe Ziel wiederholen"}
      className={`flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] transition ${
        state !== "idle" && state !== "busy" ? "border-red/50 text-red" : "border-line text-muted hover:border-cyan hover:text-cyan"
      }`}
    >
      {state === "busy" ? <Loader2 size={11} className="animate-spin" /> : <RotateCcw size={11} />}
      {state !== "idle" && state !== "busy" ? "Fehler" : "Nur das erneut testen"}
    </button>
  );
}

/** Importierte Skills zur selben OWASP-Kategorie: Gegenmaßnahmen und Prüfliste zum Nachlesen. */
function RelatedSkills({ finding, skills }: { finding: Finding; skills: Skill[] }) {
  const related = skills
    .filter((s) => s.module_key !== finding.module && s.owasp.includes(finding.owasp))
    .filter((s) => s.remediation.length || s.checklist.length)
    .slice(0, 3);
  if (!related.length) return null;
  return (
    <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px]">
      <span className="text-muted">Mehr dazu:</span>
      {related.map((s) => (
        <button
          key={s.name}
          onClick={() => openLink(s.source)}
          title={[...s.remediation.slice(0, 3), ...s.checklist.slice(0, 3)].join("\n")}
          className="rounded-md bg-cyan/10 px-2 py-0.5 text-cyan hover:bg-cyan/20"
        >
          {s.title}
        </button>
      ))}
    </div>
  );
}

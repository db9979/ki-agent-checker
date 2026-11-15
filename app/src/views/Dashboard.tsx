import { motion } from "framer-motion";
import { Play, ShieldAlert } from "lucide-react";
import { useMemo } from "react";
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

export function Dashboard({ onStartDemo }: { onStartDemo: () => void }) {
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
          <h1 className="text-2xl font-semibold">Dashboard</h1>
          <p className="text-sm text-muted">{live ? run.target : last ? last.target : "Noch kein Testlauf"}</p>
        </div>
        <div className="flex items-start gap-2">
          {reportId && <ReportButton runId={reportId} />}
          <button
            onClick={onStartDemo}
            disabled={run.status === "running"}
            className="glow-cyan flex items-center gap-2 rounded-xl bg-cyan/15 px-4 py-2 text-sm font-medium text-cyan transition hover:bg-cyan/25 disabled:opacity-40"
          >
            <Play size={16} /> Demo-Lauf starten
          </button>
        </div>
      </header>

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
          <p className="text-sm text-muted">Keine Findings. Starte einen Demo-Lauf, um die Ansicht zu füllen.</p>
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

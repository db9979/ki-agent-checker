import {
  Background,
  BaseEdge,
  type Edge,
  type EdgeProps,
  Handle,
  MarkerType,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
  getBezierPath,
  ReactFlowProvider,
  useNodesInitialized,
  useNodesState,
  useReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Bot,
  CheckCircle2,
  Crosshair,
  Database,
  FileLock2,
  Globe,
  Mail,
  PenLine,
  Receipt,
  Search,
  Send,
  Server,
  ShieldAlert,
  Users,
  X,
  MonitorSmartphone,
  Zap,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { ReplayBar } from "../components/hud/ReplayBar";
import { useRun } from "../lib/runStore";
import { useEffectsMode } from "../lib/settings";
import type { GraphAttack, GraphData, GraphEdgeInfo, RunSummary } from "../lib/types";
import { useApi } from "../lib/useApi";

type Kind = "attacker" | "agent" | "tool" | "data" | "external";
type State = "untested" | "running" | "stopped" | "breach" | "error";
type GraphNodeData = { label: string; sub: string; kind: Kind; icon: string; state: State; selected: boolean };

const ICONS = {
  Crosshair,
  Bot,
  Mail,
  Receipt,
  Search,
  Database,
  FileLock2,
  Globe,
  MonitorSmartphone,
  PenLine,
  Send,
  Server,
  Users,
  Zap,
};

const STATE_COLOR: Record<State, string> = {
  untested: "#2a3a5c",
  running: "#22d3ee",
  stopped: "#34d399",
  breach: "#f43f5e",
  error: "#f59e0b",
};
const KIND_COLOR: Record<Kind, string> = {
  attacker: "#f43f5e",
  agent: "#22d3ee",
  tool: "#a78bfa",
  data: "#f59e0b",
  external: "#f43f5e",
};

function GraphNode({ data }: NodeProps<Node<GraphNodeData>>) {
  const Icon = ICONS[data.icon as keyof typeof ICONS] ?? Bot;
  const hit = data.state === "breach";
  const color = hit ? "#f43f5e" : data.state === "stopped" ? "#34d399" : KIND_COLOR[data.kind];
  return (
    <div
      className={`w-[190px] cursor-pointer rounded-xl border px-3 py-2 text-left ${hit ? "node-pulse" : ""}`}
      style={{
        borderColor: data.selected ? "#e6ecff" : `${color}88`,
        background: "#0d1424",
        boxShadow: hit ? `0 0 0 1px ${color}, 0 0 28px ${color}66` : `0 0 16px ${color}22`,
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: color, border: 0 }} />
      <div className="flex items-center gap-2 text-sm font-medium text-text">
        <Icon size={15} color={color} className="shrink-0" /> <span className="truncate">{data.label}</span>
      </div>
      <div className="mt-0.5 truncate text-[11px] text-muted" title={data.sub}>
        {data.sub}
      </div>
      <Handle type="source" position={Position.Right} style={{ background: color, border: 0 }} />
    </div>
  );
}

const nodeTypes = { graph: GraphNode, groupLabel: GroupLabel };

type FlowData = { hit: boolean; full: boolean; running: boolean };

/**
 * Kante mit Datenstrom: Über ausgenutzte Pfade jagen rote Datenpakete,
 * über sichere Pfade treibt im vollen Effektmodus ein leiser cyanfarbener Puls.
 */
function FlowEdge(props: EdgeProps<Edge<FlowData>>) {
  const {
    id,
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    data,
    markerEnd,
    style,
    label,
    labelStyle,
    labelBgStyle,
  } = props;
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  const hit = !!data?.hit;
  const packets = hit ? (data?.full ? 5 : 2) : data?.running ? 2 : 0;
  const dur = hit ? 1.6 : 4.5;
  return (
    <>
      {hit && data?.full && <path d={path} fill="none" stroke="#f43f5e" strokeWidth={10} strokeOpacity={0.12} />}
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        style={style}
        label={label}
        labelX={labelX}
        labelY={labelY}
        labelStyle={labelStyle}
        labelBgStyle={labelBgStyle}
      />
      {Array.from({ length: packets }, (_, i) => (
        <g key={i}>
          <circle
            r={hit ? 4 : 2.5}
            fill={hit ? "#fda4af" : "#22d3ee"}
            opacity={hit ? 1 : 0.55}
            style={{ filter: `drop-shadow(0 0 5px ${hit ? "#f43f5e" : "#22d3ee"})` }}
          >
            <animateMotion
              dur={`${dur}s`}
              begin={`${(i * dur) / packets}s`}
              repeatCount="indefinite"
              path={path}
              keyPoints="0;1"
              keyTimes="0;1"
              calcMode="spline"
              keySplines="0.45 0 0.55 1"
            />
          </circle>
          {hit && (
            <circle r={2} fill="#f43f5e" opacity={0.5}>
              <animateMotion
                dur={`${dur}s`}
                begin={`${(i * dur) / packets + 0.08}s`}
                repeatCount="indefinite"
                path={path}
                keyPoints="0;1"
                keyTimes="0;1"
                calcMode="spline"
                keySplines="0.45 0 0.55 1"
              />
            </circle>
          )}
        </g>
      ))}
    </>
  );
}

const edgeTypes = { flow: FlowEdge };

const X_GAP = 300;
const Y_GAP = 86;

function matches(e: GraphEdgeInfo, a: GraphAttack): boolean {
  const mod = e.modules.includes(a.module) || e.prefixes.some((p) => a.module.startsWith(p));
  if (!mod) return false;
  return !e.tool || a.tool === e.tool || a.tool_calls.includes(e.tool);
}

function stateOf(attacks: GraphAttack[]): State {
  if (!attacks.length) return "untested";
  if (attacks.some((a) => a.success)) return "breach";
  if (attacks.some((a) => a.success === undefined)) return "running";
  if (attacks.every((a) => a.signal === "error")) return "error";
  return "stopped";
}

const GROUP_ORDER = ["data", "read", "write", "out"];
const GROUP_LABEL: Record<string, string> = { read: "lesend", write: "schreibend", out: "nach außen" };
const GROUP_GAP = 46;

type Placed = { pos: Map<string, { x: number; y: number }>; headers: { id: string; label: string; x: number; y: number }[] };

/**
 * Spalten aus der Engine, leere fallen weg. Tools stehen in einer Spalte, in Blöcken nach
 * Risiko (mit Überschrift), damit sich keine Kanten durch andere Knoten ziehen. Knoten
 * weiter rechts stehen auf der Höhe ihrer Quellen.
 */
function layout(g: GraphData): Placed {
  const cols = [...new Set(g.nodes.map((n) => n.col))].sort((a, b) => a - b);
  const pos = new Map<string, { x: number; y: number }>();
  const headers: Placed["headers"] = [];
  const stacks = cols.map((c) =>
    g.nodes
      .filter((n) => n.col === c)
      .sort((a, b) => GROUP_ORDER.indexOf(a.group ?? "") - GROUP_ORDER.indexOf(b.group ?? "")),
  );
  const heights = stacks.map((ns) => {
    let h = 0;
    ns.forEach((n, i) => (h += i && ns[i - 1].group !== n.group ? Y_GAP + GROUP_GAP : i ? Y_GAP : 0));
    return h;
  });
  const tallest = Math.max(...heights);
  stacks.forEach((ns, ci) => {
    const x = ci * X_GAP;
    if (ci >= 2 && ci === stacks.length - 1 && ci > 2) {
      // letzte Spalte (Außenwelt): mittig zu den Quellen
      ns.forEach((n) => {
        const ys = g.edges.filter((e) => e.target === n.id).map((e) => pos.get(e.source)?.y ?? tallest / 2);
        pos.set(n.id, { x, y: ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : tallest / 2 });
      });
      return;
    }
    let y = (tallest - heights[ci]) / 2;
    ns.forEach((n, i) => {
      if (i) y += ns[i - 1].group !== n.group ? Y_GAP + GROUP_GAP : Y_GAP;
      const first = i === 0 || ns[i - 1].group !== n.group;
      if (first && n.group && GROUP_LABEL[n.group] && g.kind === "mcp") {
        const count = ns.filter((m) => m.group === n.group).length;
        headers.push({ id: `h:${n.group}`, label: `${count} ${GROUP_LABEL[n.group]}`, x, y: y - 30 });
      }
      pos.set(n.id, { x, y });
    });
  });
  return { pos, headers };
}

function GroupLabel({ data }: NodeProps<Node<{ label: string }>>) {
  return <div className="text-[10px] font-semibold uppercase tracking-wider text-muted">{data.label}</div>;
}

export function AttackGraph() {
  const run = useRun();
  const full = useEffectsMode() === "voll";
  const { data: runs } = useApi<RunSummary[]>("/runs", [run.status]);
  const live = run.status !== "idle" && !!run.graph;
  const last = (runs ?? []).filter((r) => r.status !== "running").at(-1);
  const { data: saved, error } = useApi<{ graph: GraphData; attacks: GraphAttack[] }>(
    !live && last ? `/runs/${last.id}/graph` : "/health",
    [],
  );
  const [selected, setSelected] = useState<string | null>(null);

  const graph: GraphData | null = live ? run.graph : saved && "graph" in saved ? saved.graph : null;
  const attacks: GraphAttack[] = useMemo(
    () =>
      live
        ? run.attacks.map((a) => ({
            id: a.id,
            module: a.module,
            tool: a.tool ?? null,
            tool_calls: a.messages.flatMap((m) => (m.tool_call ? [m.tool_call.name] : [])),
            success: a.success,
            signal: a.signal,
            technique: a.technique,
          }))
        : saved && "attacks" in saved
          ? saved.attacks
          : [],
    [live, run.attacks, saved],
  );

  const edgeAttacks = useMemo(() => {
    const m = new Map<string, GraphAttack[]>();
    graph?.edges.forEach((e) => m.set(e.id, attacks.filter((a) => matches(e, a))));
    return m;
  }, [graph, attacks]);

  const computed: Node<GraphNodeData>[] = useMemo(() => {
    if (!graph) return [];
    const st = new Map(graph.edges.map((e) => [e.id, stateOf(edgeAttacks.get(e.id) ?? [])]));
    const nodeState = (id: string): State => {
      const s = graph.edges.filter((e) => e.target === id).map((e) => st.get(e.id)!);
      if (s.includes("breach")) return "breach";
      if (s.includes("running")) return "running";
      if (s.includes("stopped") && s.every((x) => x === "stopped" || x === "untested")) return "stopped";
      return "untested";
    };
    const { pos, headers } = layout(graph);
    const labels = headers.map((h) => ({
      id: h.id,
      type: "groupLabel",
      position: { x: h.x + 4, y: h.y },
      data: { label: h.label },
      selectable: false,
      draggable: false,
    })) as unknown as Node<GraphNodeData>[];
    return [...labels, ...graph.nodes.map((n) => ({
      id: n.id,
      type: "graph",
      position: pos.get(n.id)!,
      data: {
        label: n.label,
        sub: n.sub,
        kind: n.kind,
        icon: n.icon,
        state: n.kind === "attacker" ? "untested" : nodeState(n.id),
        selected: n.id === selected,
      },
    }))];
  }, [graph, edgeAttacks, selected]);

  if (!graph) {
    return (
      <div className="flex h-full flex-col gap-4">
        <h1 className="text-2xl font-semibold">Angriffsgraph</h1>
        <p className="text-sm text-muted">
          {last && error
            ? "Für den letzten Lauf gibt es noch keinen Graphen (ältere Version). Starte einen neuen Lauf, dann baut sich der Graph aus deinem Ziel auf."
            : "Starte einen Lauf. Der Graph baut sich aus dem echten Ziel auf, beim MCP-Server aus allen Tools, und färbt sich live."}
        </p>
      </div>
    );
  }

  const edgeState = new Map(graph.edges.map((e) => [e.id, stateOf(edgeAttacks.get(e.id) ?? [])]));
  const edges: Edge<FlowData>[] = graph.edges.map((e) => {
    const st = edgeState.get(e.id)!;
    const color = STATE_COLOR[st];
    const hit = st === "breach";
    return {
      id: e.id,
      type: "flow",
      source: e.source,
      target: e.target,
      data: { hit, full, running: st === "running" },
      label: graph.kind === "agent" ? (e.label ?? undefined) : undefined,
      labelStyle: { fill: hit ? "#fda4af" : "#7c8db5", fontSize: 11 },
      labelBgStyle: { fill: "#070b14" },
      labelBgPadding: [6, 3] as [number, number],
      style: {
        stroke: color,
        strokeWidth: hit ? 2.5 : st === "untested" ? 1.2 : 1.8,
        strokeDasharray: st === "untested" ? "4 4" : undefined,
        filter: hit ? "drop-shadow(0 0 6px #f43f5e)" : undefined,
      },
      markerEnd: { type: MarkerType.ArrowClosed, color },
    };
  });

  const counts = { breach: 0, stopped: 0, untested: 0 };
  edgeState.forEach((s) => {
    if (s === "breach") counts.breach++;
    else if (s === "stopped") counts.stopped++;
    else if (s === "untested") counts.untested++;
  });
  const detail = selected ? graph.nodes.find((n) => n.id === selected) : null;
  const detailAttacks = detail
    ? graph.edges.filter((e) => e.target === detail.id).flatMap((e) => edgeAttacks.get(e.id) ?? [])
    : [];

  return (
    <div className="flex h-full flex-col gap-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Angriffsgraph</h1>
          <p className="text-sm text-muted">
            {graph.kind === "mcp"
              ? "Alle Tools des Servers, nach Risiko sortiert: lesend, schreibend, nach außen."
              : "Wege vom Angreifer durch den Agenten bis zu Daten, Tools und Außenwelt."}{" "}
            Klick auf einen Knoten zeigt die Angriffe darauf.
          </p>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <Legend color={STATE_COLOR.breach} label={`${counts.breach} durchgebrochen`} />
          <Legend color={STATE_COLOR.stopped} label={`${counts.stopped} abgewehrt`} />
          <Legend color={STATE_COLOR.untested} label={`${counts.untested} nicht getestet`} dashed />
        </div>
      </header>
      <div className="relative min-h-[520px] flex-1">
        <div className="panel absolute inset-0 overflow-hidden">
          <Flow
            key={graph.nodes.map((n) => n.id).join("|")}
            computed={computed}
            edges={edges}
            onSelect={(id) => setSelected((s) => (s === id ? null : id))}
            onClear={() => setSelected(null)}
          />
        </div>
        {detail && (
          <aside className="panel absolute right-3 top-3 max-h-[calc(100%-24px)] w-80 overflow-y-auto p-4 text-xs">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-sm font-semibold">{detail.label}</span>
              <button onClick={() => setSelected(null)} className="ml-auto text-muted hover:text-text">
                <X size={14} />
              </button>
            </div>
            <p className="mb-3 text-muted">{detail.sub}</p>
            {detailAttacks.length === 0 ? (
              <p className="text-muted">Noch kein Angriff auf diesen Knoten.</p>
            ) : (
              <ul className="space-y-1.5">
                {detailAttacks.map((a) => (
                  <li key={a.id} className="flex items-start gap-2">
                    {a.success ? (
                      <ShieldAlert size={13} className="mt-0.5 shrink-0 text-red" />
                    ) : (
                      <CheckCircle2
                        size={13}
                        className={`mt-0.5 shrink-0 ${a.success === undefined ? "text-cyan" : a.signal === "error" ? "text-amber" : "text-green"}`}
                      />
                    )}
                    <span className={a.success ? "text-[#fda4af]" : ""}>{a.technique}</span>
                  </li>
                ))}
              </ul>
            )}
          </aside>
        )}
      </div>
      <ReplayBar />
    </div>
  );
}

function Legend({ color, label, dashed }: { color: string; label: string; dashed?: boolean }) {
  return (
    <span className="flex items-center gap-1.5 text-muted">
      <svg width="22" height="6">
        <line x1="0" y1="3" x2="22" y2="3" stroke={color} strokeWidth="2.5" strokeDasharray={dashed ? "4 3" : undefined} />
      </svg>
      {label}
    </span>
  );
}


/**
 * Eigene Komponente je Graph: startet mit allen Knoten, damit fitView alles erfasst.
 * React Flow misst die Knoten selbst, deshalb bleiben Messwerte bei Updates erhalten.
 */
type FlowProps = {
  computed: Node<GraphNodeData>[];
  edges: Edge<FlowData>[];
  onSelect: (id: string) => void;
  onClear: () => void;
};

function Flow(props: FlowProps) {
  return (
    <ReactFlowProvider>
      <FlowInner {...props} />
    </ReactFlowProvider>
  );
}

function FlowInner({ computed, edges, onSelect, onClear }: FlowProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<GraphNodeData>>(computed);
  const ready = useNodesInitialized();
  const { fitView } = useReactFlow();
  // Erst wenn alle Knoten gemessen sind, passt der Ausschnitt wirklich
  useEffect(() => {
    if (!ready) return;
    const t = setTimeout(() => void fitView({ padding: 0.08 }), 60);
    return () => clearTimeout(t);
  }, [ready, fitView, computed.length]);
  useEffect(() => {
    setNodes((prev) => {
      const old = new Map(prev.map((n) => [n.id, n]));
      return computed.map((n) => {
        const o = old.get(n.id);
        return o ? { ...o, data: n.data } : n;
      });
    });
  }, [computed, setNodes]);
  return (
    <ReactFlow
      nodes={nodes}
      onNodesChange={onNodesChange}
      edges={edges}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      onNodeClick={(_, n) => !n.id.startsWith("h:") && onSelect(n.id)}
      onPaneClick={onClear}
      fitView
      fitViewOptions={{ padding: 0.08 }}
      minZoom={0.2}
      proOptions={{ hideAttribution: true }}
      colorMode="dark"
      style={{ background: "transparent" }}
    >
      <Background color="#1e2a44" gap={28} />
    </ReactFlow>
  );
}

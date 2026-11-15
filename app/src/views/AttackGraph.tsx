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
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Bot, Crosshair, Database, FileLock2, Globe, Mail, Receipt, Search } from "lucide-react";
import { useMemo } from "react";
import { ReplayBar } from "../components/hud/ReplayBar";
import { useRun } from "../lib/runStore";
import { useEffectsMode } from "../lib/settings";
import type { RunSummary } from "../lib/types";
import { useApi } from "../lib/useApi";

type Kind = "attacker" | "agent" | "tool" | "data" | "external";
type GraphNodeData = { label: string; sub: string; kind: Kind; icon: keyof typeof ICONS; hit: boolean };

const ICONS = { Crosshair, Bot, Mail, Receipt, Search, Database, FileLock2, Globe };
const KIND_COLOR: Record<Kind, string> = {
  attacker: "#f43f5e",
  agent: "#22d3ee",
  tool: "#a78bfa",
  data: "#f59e0b",
  external: "#f43f5e",
};

function GraphNode({ data }: NodeProps<Node<GraphNodeData>>) {
  const Icon = ICONS[data.icon];
  const color = data.hit ? "#f43f5e" : KIND_COLOR[data.kind];
  return (
    <div
      className={`min-w-[150px] rounded-xl border px-3 py-2 text-left ${data.hit ? "node-pulse" : ""}`}
      style={{
        borderColor: `${color}88`,
        background: "#0d1424",
        boxShadow: data.hit ? `0 0 0 1px ${color}, 0 0 28px ${color}66` : `0 0 16px ${color}22`,
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: color, border: 0 }} />
      <div className="flex items-center gap-2 text-sm font-medium text-text">
        <Icon size={15} color={color} /> {data.label}
      </div>
      <div className="mt-0.5 text-[11px] text-muted">{data.sub}</div>
      <Handle type="source" position={Position.Right} style={{ background: color, border: 0 }} />
    </div>
  );
}

const nodeTypes = { graph: GraphNode };

type FlowData = { hit: boolean; full: boolean };

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
  const packets = hit ? (data?.full ? 5 : 2) : data?.full ? 1 : 0;
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

const NODES: { id: string; x: number; y: number; data: Omit<GraphNodeData, "hit"> }[] = [
  {
    id: "attacker",
    x: 0,
    y: 170,
    data: { label: "Angreifer", sub: "Nutzer, Ticket, Webseite", kind: "attacker", icon: "Crosshair" },
  },
  { id: "agent", x: 260, y: 170, data: { label: "Ziel-Agent", sub: "Kundenservice-Bot", kind: "agent", icon: "Bot" } },
  {
    id: "prompt",
    x: 540,
    y: 0,
    data: { label: "System-Prompt", sub: "Regeln, interner Schlüssel", kind: "data", icon: "FileLock2" },
  },
  {
    id: "lookup",
    x: 540,
    y: 110,
    data: { label: "lookup_order", sub: "Tool: Bestellungen lesen", kind: "tool", icon: "Search" },
  },
  {
    id: "refund",
    x: 540,
    y: 230,
    data: { label: "refund", sub: "Tool: Geld erstatten", kind: "tool", icon: "Receipt" },
  },
  {
    id: "email",
    x: 540,
    y: 340,
    data: { label: "send_email", sub: "Tool: E-Mail senden", kind: "tool", icon: "Mail" },
  },
  {
    id: "customers",
    x: 810,
    y: 110,
    data: { label: "Kundendaten", sub: "Namen, E-Mails, Adressen", kind: "data", icon: "Database" },
  },
  {
    id: "evil",
    x: 1060,
    y: 220,
    data: { label: "Externer Server", sub: "evil.example", kind: "external", icon: "Globe" },
  },
];

/** Kante -> Testmodul, dessen Erfolg den Pfad belegt. */
const EDGES: { from: string; to: string; module: string; label?: string }[] = [
  { from: "attacker", to: "agent", module: "prompt_injection", label: "Injection" },
  { from: "agent", to: "prompt", module: "system_prompt_leak", label: "Leak" },
  { from: "agent", to: "lookup", module: "data_exfiltration" },
  { from: "lookup", to: "customers", module: "data_exfiltration" },
  { from: "customers", to: "evil", module: "data_exfiltration", label: "Markdown-Bild" },
  { from: "agent", to: "refund", module: "excessive_agency", label: "ohne Bestätigung" },
  { from: "agent", to: "email", module: "excessive_agency" },
  { from: "email", to: "evil", module: "excessive_agency", label: "Mail nach außen" },
];

export function AttackGraph() {
  const run = useRun();
  const full = useEffectsMode() === "voll";
  const { data: runs } = useApi<RunSummary[]>("/runs", [run.status]);

  const hitModules = useMemo(() => {
    if (run.status !== "idle") return new Set(run.modules.filter((m) => m.hits > 0).map((m) => m.key));
    const last = (runs ?? []).filter((r) => r.status === "finished").at(-1);
    return new Set(last?.findings.map((f) => f.module) ?? []);
  }, [run, runs]);

  const hitEdges = EDGES.filter((e) => hitModules.has(e.module));
  const hitNodes = new Set(hitEdges.flatMap((e) => [e.from, e.to]).filter((n) => n !== "attacker" && n !== "agent"));
  if (hitModules.has("prompt_injection") || hitModules.has("jailbreak")) hitNodes.add("agent");

  const nodes: Node<GraphNodeData>[] = NODES.map((n) => ({
    id: n.id,
    type: "graph",
    position: { x: n.x, y: n.y },
    data: { ...n.data, hit: hitNodes.has(n.id) },
    draggable: true,
  }));

  const edges: Edge<FlowData>[] = EDGES.map((e, i) => {
    const hit = hitModules.has(e.module);
    const color = hit ? "#f43f5e" : "#2a3a5c";
    return {
      id: `e${i}`,
      type: "flow",
      source: e.from,
      target: e.to,
      data: { hit, full },
      label: e.label,
      labelStyle: { fill: hit ? "#fda4af" : "#7c8db5", fontSize: 11 },
      labelBgStyle: { fill: "#070b14" },
      style: { stroke: color, strokeWidth: hit ? 2.5 : 1.5, filter: hit ? "drop-shadow(0 0 6px #f43f5e)" : undefined },
      markerEnd: { type: MarkerType.ArrowClosed, color },
    };
  });

  return (
    <div className="flex h-full flex-col gap-4">
      <header>
        <h1 className="text-2xl font-semibold">Angriffsgraph</h1>
        <p className="text-sm text-muted">
          Rot leuchtende Pfade mit Datenstrom wurden tatsächlich ausgenutzt. Mit der Zeitleiste lässt sich der Lauf
          abspielen.
        </p>
      </header>
      <div className="panel min-h-[520px] flex-1 overflow-hidden">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          fitView
          proOptions={{ hideAttribution: true }}
          colorMode="dark"
          style={{ background: "transparent" }}
        >
          <Background color="#1e2a44" gap={28} />
        </ReactFlow>
      </div>
      <ReplayBar />
    </div>
  );
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ProviderKind = "ollama" | "openai_compatible" | "openai" | "anthropic" | "gemini" | "mistral";

export interface Provider {
  id: string;
  name: string;
  kind: ProviderKind;
  model: string;
  base_url: string | null;
  has_api_key: boolean;
  self_hosted: boolean;
  verify_tls: boolean;
  created_at: string;
}

export interface ConnectionResult {
  ok: boolean;
  latency_ms: number | null;
  reply: string | null;
  error: string | null;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  scope: string[];
  authorized_by: string;
  authorized_at: string;
}

export interface Finding {
  id: string;
  module: string;
  title: string;
  severity: Severity;
  owasp: string;
  atlas: string | null;
  success_rate: number;
  evidence: string;
  remediation: string;
}

export interface RunSummary {
  id: string;
  project_id: string | null;
  target: string;
  started_at: string;
  finished_at: string | null;
  status: string;
  score: number | null;
  findings: Finding[];
}

export interface EngineEvent {
  type: string;
  run_id: string;
  ts: string;
  [key: string]: unknown;
}

export type TargetKind = "model" | "openai_endpoint" | "http" | "mcp" | "mcp_tool";
export type AuthKind = "none" | "bearer" | "header" | "basic" | "login";

export interface AuthConfig {
  kind: AuthKind;
  header_name: string;
  login_url: string | null;
  login_body: string;
  token_path: string | null;
  token_header: string;
  token_prefix: string;
  mfa: "none" | "totp" | "manual";
  mfa_header: string | null;
  mfa_url: string | null;
  mfa_body: string;
  mfa_challenge_path: string | null;
}

export interface Account {
  name: string;
  role: string;
  username: string | null;
  identifier: string | null;
  marker: string | null;
  has_password: boolean;
  has_token: boolean;
  has_totp: boolean;
}

export interface Target {
  id: string;
  project_id: string;
  name: string;
  kind: TargetKind;
  provider_id: string | null;
  system_prompt: string;
  honeypot_tools: boolean;
  url: string | null;
  model: string | null;
  method: "POST" | "PUT" | "GET";
  request_template: string;
  response_path: string;
  verify_tls: boolean;
  auth: AuthConfig;
  mcp_tool_calls?: "none" | "readonly" | "all";
  mcp_tool?: string | null;
  mcp_arg?: string | null;
  accounts: Account[];
  leak_markers: string[];
  delay: number;
  created_at: string;
}

export interface AttackModuleInfo {
  key: string;
  label: string;
  owasp: string;
  severity: Severity;
  attacks: number;
  needs_accounts: number;
  needs_attacker?: boolean;
  title: string;
  target: "agent" | "mcp";
  calls_tools?: boolean;
  skill?: boolean;
}

export interface Skill {
  name: string;
  title: string;
  description: string;
  owasp: string[];
  atlas: string[];
  tags: string[];
  author: string | null;
  license: string | null;
  source: string;
  groups: { title: string; payloads: string[] }[];
  remediation: string[];
  checklist: string[];
  imported_at: string;
  payload_count: number;
  module_key: string | null;
}

export type CompareStatus = "neu" | "schlechter" | "behoben" | "besser" | "neu_getestet" | "entfallen" | "gleich";

export interface CompareSide {
  rate: number;
  hits: number;
  attempts: number;
}

export interface CompareRow {
  module: string;
  label: string;
  title: string | null;
  owasp: string;
  severity: Severity;
  a: CompareSide | null;
  b: CompareSide | null;
  status: CompareStatus;
}

export interface CompareResult {
  a: Omit<RunSummary, "findings">;
  b: Omit<RunSummary, "findings">;
  same_target: boolean;
  delta: number | null;
  counts: Record<CompareStatus, number>;
  rows: CompareRow[];
  complete: boolean;
}

export interface GraphNodeInfo {
  id: string;
  label: string;
  sub: string;
  kind: "attacker" | "agent" | "tool" | "data" | "external";
  col: number;
  icon: string;
  group?: "read" | "write" | "out";
}

export interface GraphEdgeInfo {
  id: string;
  source: string;
  target: string;
  modules: string[];
  prefixes: string[];
  tool: string | null;
  label: string | null;
}

export interface GraphData {
  kind: "agent" | "mcp";
  nodes: GraphNodeInfo[];
  edges: GraphEdgeInfo[];
}

export interface GraphAttack {
  id: string;
  module: string;
  tool: string | null;
  tool_calls: string[];
  success: boolean | undefined;
  signal: string | undefined;
  technique: string;
}

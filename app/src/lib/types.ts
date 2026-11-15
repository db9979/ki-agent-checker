export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ProviderKind =
  | "ollama"
  | "openai_compatible"
  | "openai"
  | "anthropic"
  | "gemini"
  | "mistral";

export interface Provider {
  id: string;
  name: string;
  kind: ProviderKind;
  model: string;
  base_url: string | null;
  has_api_key: boolean;
  self_hosted: boolean;
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

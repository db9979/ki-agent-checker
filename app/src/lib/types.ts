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

export type TargetKind = "model" | "openai_endpoint" | "http";
export type AuthKind = "none" | "bearer" | "header" | "basic" | "login";

export interface AuthConfig {
  kind: AuthKind;
  header_name: string;
  login_url: string | null;
  login_body: string;
  token_path: string | null;
  token_header: string;
  token_prefix: string;
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
  title: string;
}

import { CheckCircle2, KeyRound, Loader2, Plus, Trash2, UserRound, Wand2, XCircle } from "lucide-react";
import { HelpLink } from "./HelpLink";
import { useState } from "react";
import { api } from "../lib/engine";
import type { AuthKind, Project, Provider, Target, TargetKind } from "../lib/types";
import { useApi } from "../lib/useApi";

const input = "w-full rounded-lg border border-line bg-[#0b1222] px-3 py-2 text-sm outline-none focus:border-cyan";
const small = "w-full rounded-md border border-line bg-[#0b1222] px-2 py-1.5 text-xs outline-none focus:border-cyan";

const KINDS: { kind: TargetKind; label: string; hint: string }[] = [
  {
    kind: "model",
    label: "Eigenes Modell",
    hint: "Ein angebundenes Modell mit deinem System-Prompt und Honeypot-Tools. Ideal, um einen Agenten vor dem Livegang zu testen.",
  },
  {
    kind: "openai_endpoint",
    label: "Agent mit OpenAI-API",
    hint: "Ein fertiger Agent mit OpenAI-kompatibler Chat-Schnittstelle, z. B. https://agent.firma.de/v1",
  },
  {
    kind: "http",
    label: "HTTP-Endpunkt",
    hint: "Beliebiger JSON-Endpunkt, z. B. das Backend eines Chat-Widgets. Anfrage und Antwortfeld frei einstellbar.",
  },
  {
    kind: "mcp",
    label: "MCP-Server",
    hint: "Ein MCP-Server (Streamable HTTP), der Agenten Tools bereitstellt, z. B. https://server.de/mcp. Geprüft werden Anmeldung, Tool-Beschreibungen, Rechte, Parameter und Ausgaben.",
  },
];

type ToolPolicy = "none" | "readonly" | "all";
const POLICIES: { value: ToolPolicy; label: string }[] = [
  { value: "readonly", label: "Nur lesende Tools aufrufen (empfohlen)" },
  { value: "none", label: "Keine Tools aufrufen, nur Beschreibungen prüfen" },
  { value: "all", label: "Alle Tools aufrufen, auch schreibende (nur auf Testsystemen!)" },
];

const AUTHS: { kind: AuthKind; label: string }[] = [
  { kind: "none", label: "Keine Anmeldung" },
  { kind: "bearer", label: "API-Schlüssel / Bearer-Token" },
  { kind: "header", label: "Eigener Header" },
  { kind: "basic", label: "Benutzername + Passwort (Basic)" },
  { kind: "login", label: "Login-Aufruf (Token oder Cookie)" },
];

interface AccountDraft {
  name: string;
  role: string;
  username: string;
  password: string;
  token: string;
  totp_secret: string;
  identifier: string;
  marker: string;
  saved?: { password: boolean; token: boolean; totp: boolean };
}

type Method = "POST" | "PUT" | "GET";
type MfaMode = "none" | "totp" | "manual";
const SAVED = "•••• gespeichert, leer lassen = behalten";

const emptyAccount = (n: number): AccountDraft => ({
  name: `Konto ${String.fromCharCode(65 + n)}`,
  role: "Nutzer",
  username: "",
  password: "",
  token: "",
  totp_secret: "",
  identifier: "",
  marker: "",
});

interface DetectResult {
  ok: boolean;
  kind?: TargetKind;
  url: string;
  model?: string | null;
  models?: string[];
  request_template?: string;
  response_path?: string;
  reply?: string;
  server?: string;
  needs_auth?: boolean;
  note?: string;
  error?: string;
}

const orNull = (s: string) => (s.trim() ? s.trim() : null);

export function TargetForm({
  project,
  initial,
  onSaved,
}: {
  project: Project;
  initial?: Target;
  onSaved: (t: Target) => void;
}) {
  const { data: providers } = useApi<Provider[]>("/providers");
  const [kind, setKind] = useState<TargetKind>(initial?.kind ?? "model");
  const [name, setName] = useState(initial?.name ?? "");
  const [providerId, setProviderId] = useState(initial?.provider_id ?? "");
  const [systemPrompt, setSystemPrompt] = useState(initial?.system_prompt ?? "");
  const [honeypot, setHoneypot] = useState(initial?.honeypot_tools ?? true);
  const [url, setUrl] = useState(initial?.url ?? project.scope.find((s) => s.includes("://")) ?? "");
  const [model, setModel] = useState(initial?.model ?? "");
  const [method, setMethod] = useState<Method>(initial?.method ?? "POST");
  const [template, setTemplate] = useState(initial?.request_template ?? '{"message": "{{message}}"}');
  const [responsePath, setResponsePath] = useState(initial?.response_path ?? "reply");
  const [trustSelfSigned, setTrustSelfSigned] = useState(initial ? !initial.verify_tls : false);
  const [authKind, setAuthKind] = useState<AuthKind>(initial?.auth.kind ?? "none");
  const [headerName, setHeaderName] = useState(initial?.auth.header_name ?? "X-API-Key");
  const [loginUrl, setLoginUrl] = useState(initial?.auth.login_url ?? "");
  const [loginBody, setLoginBody] = useState(
    initial?.auth.login_body ?? '{"username": "{{username}}", "password": "{{password}}"}',
  );
  const [tokenPath, setTokenPath] = useState(initial ? (initial.auth.token_path ?? "") : "token");
  const [mfa, setMfa] = useState<MfaMode>(initial?.auth.mfa ?? "none");
  const [mfaHeader, setMfaHeader] = useState(initial?.auth.mfa_header ?? "");
  const [mfaUrl, setMfaUrl] = useState(initial?.auth.mfa_url ?? "");
  const [mfaBody, setMfaBody] = useState(initial?.auth.mfa_body ?? '{"code": "{{code}}"}');
  const [mfaChallenge, setMfaChallenge] = useState(initial?.auth.mfa_challenge_path ?? "");
  const [accounts, setAccounts] = useState<AccountDraft[]>(
    (initial?.accounts ?? []).map((a) => ({
      name: a.name,
      role: a.role,
      username: a.username ?? "",
      password: "",
      token: "",
      totp_secret: "",
      identifier: a.identifier ?? "",
      marker: a.marker ?? "",
      saved: { password: a.has_password, token: a.has_token, totp: a.has_totp },
    })),
  );
  const [mcpTool, setMcpTool] = useState(initial?.mcp_tool ?? "");
  const [mcpArg, setMcpArg] = useState(initial?.mcp_arg ?? "");
  const [toolPolicy, setToolPolicy] = useState<ToolPolicy>(initial?.mcp_tool_calls ?? "readonly");
  const [leakMarkers, setLeakMarkers] = useState((initial?.leak_markers ?? []).join("\n"));
  const [error, setError] = useState<string | null>(null);
  const [detectUrl, setDetectUrl] = useState("");
  const [detectToken, setDetectToken] = useState("");
  const [detected, setDetected] = useState<DetectResult | "busy" | null>(null);
  const [models, setModels] = useState<string[]>([]);

  const runDetect = async () => {
    setDetected("busy");
    try {
      const r = await api<DetectResult>("/targets/detect", {
        method: "POST",
        body: JSON.stringify({
          project_id: project.id,
          url: detectUrl,
          token: detectToken || null,
          verify_tls: !trustSelfSigned,
        }),
      });
      setDetected(r);
      if (!r.ok || !r.kind) return;
      setKind(r.kind);
      setUrl(r.url);
      if (r.model) setModel(r.model);
      setModels(r.models ?? []);
      if (r.request_template) setTemplate(r.request_template);
      if (r.response_path !== undefined) setResponsePath(r.response_path);
      if (!name) setName(r.server ?? new URL(r.url).hostname);
      if (detectToken) {
        setAuthKind("bearer");
        setAccounts([{ ...(accounts[0] ?? emptyAccount(0)), token: detectToken }, ...accounts.slice(1)]);
      } else if (r.needs_auth) {
        setAuthKind("bearer");
      }
    } catch (e) {
      setDetected({ ok: false, url: detectUrl, error: String((e as Error).message) });
    }
  };

  const needsAccount = authKind !== "none";
  const list = needsAccount && accounts.length === 0 ? [emptyAccount(0)] : accounts;
  const update = (i: number, patch: Partial<AccountDraft>) =>
    setAccounts(list.map((a, j) => (i === j ? { ...a, ...patch } : a)));

  const save = async () => {
    setError(null);
    try {
      const target = await api<Target>(initial ? `/targets/${initial.id}` : "/targets", {
        method: initial ? "PUT" : "POST",
        body: JSON.stringify({
          project_id: project.id,
          name: name || (kind === "model" ? "Agent-Entwurf" : url),
          kind,
          provider_id: kind === "model" ? providerId || providers?.[0]?.id : null,
          system_prompt: systemPrompt,
          honeypot_tools: honeypot,
          url: kind === "model" ? null : url,
          model: orNull(model),
          method,
          delay: initial?.delay ?? 0.5,
          mcp_tool_calls: toolPolicy,
          mcp_tool: kind === "mcp_tool" ? orNull(mcpTool) : null,
          mcp_arg: kind === "mcp_tool" ? orNull(mcpArg) : null,
          request_template: template,
          response_path: responsePath,
          verify_tls: !trustSelfSigned,
          auth: {
            kind: authKind,
            header_name: headerName,
            login_url: orNull(loginUrl),
            login_body: loginBody,
            token_path: orNull(tokenPath),
            token_header: "Authorization",
            token_prefix: "Bearer ",
            mfa,
            mfa_header: mfa === "none" ? null : orNull(mfaHeader),
            mfa_url: mfa === "none" ? null : orNull(mfaUrl),
            mfa_body: mfaBody,
            mfa_challenge_path: orNull(mfaChallenge),
          },
          accounts: list.map((a) => ({
            name: a.name,
            role: a.role,
            username: orNull(a.username),
            password: orNull(a.password),
            token: orNull(a.token),
            totp_secret: orNull(a.totp_secret),
            identifier: orNull(a.identifier),
            marker: orNull(a.marker),
          })),
          leak_markers: leakMarkers
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean),
        }),
      });
      onSaved(target);
    } catch (e) {
      setError(String((e as Error).message));
    }
  };

  const isMcp = kind === "mcp" || kind === "mcp_tool";
  const k = KINDS.find((x) => x.kind === (isMcp ? "mcp" : kind))!;

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-violet/40 bg-violet/5 p-2.5">
        <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-violet">
          <Wand2 size={13} /> Automatisch erkennen <HelpLink anchor="ziel-automatisch-erkennen" />
        </div>
        <div className="grid grid-cols-[2fr_1fr_auto] gap-1.5">
          <input
            className="rounded-md border border-line bg-[#0b1222] px-2 py-1.5 font-mono text-xs outline-none focus:border-violet"
            value={detectUrl}
            onChange={(e) => setDetectUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && detectUrl && runDetect()}
            placeholder="Adresse einfügen, z. B. https://agent.firma.de/api/chat"
          />
          <input
            className="rounded-md border border-line bg-[#0b1222] px-2 py-1.5 font-mono text-xs outline-none focus:border-violet"
            type="password"
            value={detectToken}
            onChange={(e) => setDetectToken(e.target.value)}
            placeholder="API-Schlüssel (falls nötig)"
          />
          <button
            onClick={runDetect}
            disabled={!detectUrl || detected === "busy"}
            className="flex items-center gap-1 rounded-md bg-violet/15 px-3 text-xs text-violet disabled:opacity-40"
          >
            {detected === "busy" ? <Loader2 size={12} className="animate-spin" /> : <Wand2 size={12} />} Erkennen
          </button>
        </div>
        {detected && detected !== "busy" && (
          <p className={`mt-1.5 flex items-start gap-1 text-[11px] ${detected.ok ? "text-green" : "text-red"}`}>
            {detected.ok ? <CheckCircle2 size={12} className="mt-0.5 shrink-0" /> : <XCircle size={12} className="mt-0.5 shrink-0" />}
            <span>
              {detected.ok ? detected.note : detected.error}
              {detected.reply && <span className="text-muted"> · Antwort: „{detected.reply.slice(0, 80)}“</span>}
              {detected.ok && " · Felder unten sind ausgefüllt, bitte prüfen."}
            </span>
          </p>
        )}
        {!detected && (
          <p className="mt-1 text-[10px] text-muted">
            Erkennt MCP-Server, OpenAI-kompatible APIs und JSON-Endpunkte samt Antwortfeld. Schickt nur eine harmlose Begrüßung.
          </p>
        )}
      </div>
      <div className="grid grid-cols-4 gap-1.5">
        {KINDS.map((x) => (
          <button
            key={x.kind}
            onClick={() => {
              setKind(x.kind);
              if (x.kind === "mcp" && !initial && authKind === "none") setAuthKind("bearer");
            }}
            className={`rounded-lg border px-2 py-1.5 text-xs ${
              k.kind === x.kind ? "border-cyan bg-cyan/10 text-cyan" : "border-line text-muted hover:text-text"
            }`}
          >
            {x.label}
          </button>
        ))}
      </div>
      <p className="text-[11px] text-muted">
        {k.hint} <HelpLink anchor="ziele" />
      </p>

      <label className="block text-xs text-muted">
        Name
        <input
          className={input}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="z. B. Kundenservice-Bot"
        />
      </label>

      {kind === "model" ? (
        <>
          <label className="block text-xs text-muted">
            Modell
            <select className={input} value={providerId} onChange={(e) => setProviderId(e.target.value)}>
              {(providers ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            {providers?.length === 0 && (
              <span className="text-amber">Zuerst unter „Modelle“ ein Modell verbinden.</span>
            )}
          </label>
          <label className="block text-xs text-muted">
            System-Prompt deines Agenten (leer = Beispiel-Kundenservice)
            <textarea
              className={`${input} h-24`}
              value={systemPrompt}
              onChange={(e) => setSystemPrompt(e.target.value)}
            />
          </label>
          <label className="flex items-center gap-2 text-xs">
            <input type="checkbox" checked={honeypot} onChange={(e) => setHoneypot(e.target.checked)} />
            Honeypot-Tools anbieten (lookup_order, refund, send_email, fetch_url)
          </label>
        </>
      ) : (
        <>
          <label className="block text-xs text-muted">
            Adresse (muss im Scope liegen)
            <input
              className={`${input} font-mono`}
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={isMcp ? "https://server.de/mcp" : undefined}
            />
          </label>
          {isMcp && (
            <div className="grid grid-cols-2 gap-1.5">
              {(
                [
                  ["mcp", "Server prüfen (Audit)"],
                  ["mcp_tool", "Ein Tool als Agent angreifen"],
                ] as const
              ).map(([key, label]) => (
                <button
                  key={key}
                  onClick={() => setKind(key)}
                  className={`rounded-lg border px-2 py-1 text-[11px] ${
                    kind === key ? "border-violet bg-violet/10 text-violet" : "border-line text-muted hover:text-text"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          )}
          {kind === "mcp_tool" ? (
            <div className="grid grid-cols-2 gap-2">
              <label className="block text-xs text-muted">
                Tool
                <input
                  className={`${input} font-mono`}
                  value={mcpTool}
                  onChange={(e) => setMcpTool(e.target.value)}
                  placeholder="z. B. frage_stellen"
                />
              </label>
              <label className="block text-xs text-muted">
                Parameter für die Nachricht (optional)
                <input
                  className={`${input} font-mono`}
                  value={mcpArg}
                  onChange={(e) => setMcpArg(e.target.value)}
                  placeholder="erster Text-Parameter"
                />
              </label>
              <span className="col-span-2 text-[11px] text-muted">
                Für Tools, hinter denen selbst ein Sprachmodell steckt. Jeder Chat-Angriff geht als Text an dieses Tool.
              </span>
            </div>
          ) : kind === "mcp" ? (
            <label className="block text-xs text-muted">
              Tool-Aufrufe beim Test
              <select
                className={input}
                value={toolPolicy}
                onChange={(e) => setToolPolicy(e.target.value as ToolPolicy)}
              >
                {POLICIES.map((p) => (
                  <option key={p.value} value={p.value}>
                    {p.label}
                  </option>
                ))}
              </select>
              <span className="mt-1 block text-[11px]">
                Lesend heißt: vom Server als readOnly gekennzeichnet oder Name beginnt mit get, list, search, read …
              </span>
            </label>
          ) : kind === "openai_endpoint" ? (
            <label className="block text-xs text-muted">
              Modellname (falls verlangt)
              <input className={input} value={model} onChange={(e) => setModel(e.target.value)} list="kac-models" />
              <datalist id="kac-models">
                {models.map((m) => (
                  <option key={m} value={m} />
                ))}
              </datalist>
            </label>
          ) : (
            <div className="grid grid-cols-4 gap-2">
              <label className="block text-xs text-muted">
                Methode
                <select className={input} value={method} onChange={(e) => setMethod(e.target.value as Method)}>
                  <option>POST</option>
                  <option>PUT</option>
                  <option>GET</option>
                </select>
              </label>
              <label className="col-span-2 block text-xs text-muted">
                Anfrage (JSON, {"{{message}}"} oder {"{{messages}}"})
                <input
                  className={`${input} font-mono`}
                  value={template}
                  onChange={(e) => setTemplate(e.target.value)}
                />
              </label>
              <label className="block text-xs text-muted">
                Antwortfeld
                <input
                  className={`${input} font-mono`}
                  value={responsePath}
                  onChange={(e) => setResponsePath(e.target.value)}
                />
              </label>
            </div>
          )}
          <label className="flex items-center gap-2 text-xs">
            <input type="checkbox" checked={trustSelfSigned} onChange={(e) => setTrustSelfSigned(e.target.checked)} />
            Selbst signierten Zertifikaten vertrauen
          </label>

          <div className="rounded-xl border border-line p-3">
            <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-muted">
              <KeyRound size={13} /> Anmeldung <HelpLink anchor="anmeldung-und-testkonten" />
            </div>
            <select className={input} value={authKind} onChange={(e) => setAuthKind(e.target.value as AuthKind)}>
              {AUTHS.map((a) => (
                <option key={a.kind} value={a.kind}>
                  {a.label}
                </option>
              ))}
            </select>
            {authKind === "header" && (
              <label className="mt-2 block text-xs text-muted">
                Header-Name
                <input className={input} value={headerName} onChange={(e) => setHeaderName(e.target.value)} />
              </label>
            )}
            {authKind === "login" && (
              <div className="mt-2 space-y-2">
                <label className="block text-xs text-muted">
                  Login-Adresse
                  <input
                    className={`${input} font-mono`}
                    value={loginUrl}
                    onChange={(e) => setLoginUrl(e.target.value)}
                    placeholder="https://agent.firma.de/api/login"
                  />
                </label>
                <label className="block text-xs text-muted">
                  Login-Anfrage ({"{{username}}"}, {"{{password}}"}, {"{{code}}"} für 2FA)
                  <input
                    className={`${input} font-mono`}
                    value={loginBody}
                    onChange={(e) => setLoginBody(e.target.value)}
                  />
                </label>
                <label className="block text-xs text-muted">
                  Token in der Antwort unter (leer = Sitzungs-Cookie)
                  <input
                    className={`${input} font-mono`}
                    value={tokenPath}
                    onChange={(e) => setTokenPath(e.target.value)}
                  />
                </label>
              </div>
            )}
            {authKind !== "none" && (
              <div className="mt-3 space-y-2 border-t border-line pt-3">
                <label className="block text-xs text-muted">
                  Zweiter Faktor (2FA)
                  <select className={input} value={mfa} onChange={(e) => setMfa(e.target.value as MfaMode)}>
                    <option value="none">Kein 2FA</option>
                    <option value="totp">Authenticator-App (TOTP): Code automatisch aus dem Geheimnis je Konto</option>
                    <option value="manual">Code bei jedem Prüfen und Lauf von Hand eingeben (SMS, Mail, App)</option>
                  </select>
                </label>
                {mfa !== "none" && (
                  <>
                    <p className="text-[11px] text-muted">
                      Wohin mit dem Code? In der Login-Anfrage über {"{{code}}"}, als eigener Header und/oder in einem
                      zweiten Login-Schritt. Nur Nötiges ausfüllen.
                    </p>
                    <label className="block text-xs text-muted">
                      Als Header senden (optional, z. B. X-OTP)
                      <input
                        className={`${input} font-mono`}
                        value={mfaHeader}
                        onChange={(e) => setMfaHeader(e.target.value)}
                      />
                    </label>
                    <label className="block text-xs text-muted">
                      Zweiter Login-Schritt: Adresse (optional)
                      <input
                        className={`${input} font-mono`}
                        value={mfaUrl}
                        onChange={(e) => setMfaUrl(e.target.value)}
                        placeholder="https://agent.firma.de/api/login/2fa"
                      />
                    </label>
                    {mfaUrl && (
                      <div className="grid grid-cols-3 gap-2">
                        <label className="col-span-2 block text-xs text-muted">
                          Anfrage ({"{{code}}"}, {"{{challenge}}"}, {"{{username}}"})
                          <input
                            className={`${input} font-mono`}
                            value={mfaBody}
                            onChange={(e) => setMfaBody(e.target.value)}
                          />
                        </label>
                        <label className="block text-xs text-muted">
                          Challenge aus Schritt 1
                          <input
                            className={`${input} font-mono`}
                            value={mfaChallenge}
                            onChange={(e) => setMfaChallenge(e.target.value)}
                            placeholder="z. B. challenge_id"
                          />
                        </label>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        </>
      )}

      {kind !== "model" && (
        <div className="rounded-xl border border-line p-3">
          <div className="mb-1 flex items-center gap-2 text-xs font-semibold text-muted">
            <UserRound size={13} /> Testkonten
            <button
              onClick={() => setAccounts([...list, emptyAccount(list.length)])}
              className="ml-auto flex items-center gap-1 rounded-md bg-cyan/10 px-2 py-0.5 text-[11px] text-cyan"
            >
              <Plus size={12} /> Konto
            </button>
          </div>
          <p className="mb-2 text-[11px] text-muted">
            {isMcp ? "Zugang zum MCP-Server. Schlüssel landen im Schlüsselbund." : ""}
            {!isMcp && "Am besten eigene Testkonten."}{" "}
            {!isMcp &&
              "Mit zwei Konten samt Kennung und privater Angabe prüft die App, ob ein Konto an die Daten des anderen kommt. Passwörter und Tokens landen im Schlüsselbund."}
          </p>
          <div className="space-y-2">
            {list.map((a, i) => (
              <div key={i} className="grid grid-cols-2 gap-1.5 rounded-lg bg-panel-2/60 p-2">
                <input
                  className={small}
                  value={a.name}
                  onChange={(e) => update(i, { name: e.target.value })}
                  placeholder="Name"
                />
                <input
                  className={small}
                  value={a.role}
                  onChange={(e) => update(i, { role: e.target.value })}
                  placeholder="Rolle"
                />
                {(authKind === "basic" || authKind === "login") && (
                  <>
                    <input
                      className={small}
                      value={a.username}
                      onChange={(e) => update(i, { username: e.target.value })}
                      placeholder="Benutzername"
                    />
                    <input
                      className={small}
                      type="password"
                      value={a.password}
                      onChange={(e) => update(i, { password: e.target.value })}
                      placeholder={a.saved?.password ? SAVED : "Passwort"}
                    />
                  </>
                )}
                {mfa === "totp" && (
                  <input
                    className={`${small} col-span-2`}
                    value={a.totp_secret}
                    onChange={(e) => update(i, { totp_secret: e.target.value })}
                    placeholder={
                      a.saved?.totp ? SAVED : "TOTP-Geheimnis (Base32, aus dem QR-Code der Authenticator-App)"
                    }
                  />
                )}
                {(authKind === "bearer" || authKind === "header") && (
                  <input
                    className={`${small} col-span-2`}
                    type="password"
                    value={a.token}
                    onChange={(e) => update(i, { token: e.target.value })}
                    placeholder={a.saved?.token ? SAVED : "API-Schlüssel / Token"}
                  />
                )}
                {!isMcp && (
                  <>
                    <input
                      className={small}
                      value={a.identifier}
                      onChange={(e) => update(i, { identifier: e.target.value })}
                      placeholder="Kennung (z. B. E-Mail)"
                    />
                    <div className="flex gap-1">
                      <input
                        className={small}
                        value={a.marker}
                        onChange={(e) => update(i, { marker: e.target.value })}
                        placeholder="Private Angabe (z. B. IBAN)"
                      />
                      <button
                        onClick={() => setAccounts(list.filter((_, j) => j !== i))}
                        className="text-muted hover:text-red"
                        title="Konto entfernen"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {kind !== "model" && kind !== "mcp" && (
        <label className="block text-xs text-muted">
          Geschützte Texte aus dem System-Prompt (einer pro Zeile, dürfen nie in einer Antwort stehen)
          <textarea
            className={`${input} h-16 font-mono`}
            value={leakMarkers}
            onChange={(e) => setLeakMarkers(e.target.value)}
          />
        </label>
      )}

      {error && <p className="text-xs text-red">{error}</p>}
      <button
        onClick={save}
        disabled={kind === "model" ? !providers?.length : !url || (kind === "mcp_tool" && !mcpTool)}
        className="glow-cyan flex w-full items-center justify-center gap-2 rounded-xl bg-cyan/15 py-2 text-sm font-medium text-cyan disabled:opacity-40"
      >
        <Plus size={15} /> {initial ? "Änderungen speichern" : "Ziel speichern"}
      </button>
    </div>
  );
}

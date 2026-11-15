import type { EngineEvent } from "./types";

/**
 * Verbindung zur Python-Engine.
 * In der Desktop-App liefert Tauri Adresse und Token des Sidecars.
 * Im Browser (npm run dev) gilt VITE_ENGINE_URL, Standard 127.0.0.1:8765 ohne Token.
 */
export interface EngineInfo {
  url: string;
  token: string | null;
}

const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

let infoPromise: Promise<EngineInfo> | null = null;

export function engineInfo(): Promise<EngineInfo> {
  if (!infoPromise) {
    infoPromise = (async () => {
      let info: EngineInfo;
      if (isTauri) {
        const { invoke } = await import("@tauri-apps/api/core");
        info = await invoke<EngineInfo>("engine_info");
      } else {
        info = {
          url: import.meta.env.VITE_ENGINE_URL ?? "http://127.0.0.1:8765",
          token: import.meta.env.VITE_ENGINE_TOKEN ?? null,
        };
      }
      try {
        await waitForHealth(info.url);
      } catch (e) {
        if (isTauri) {
          // Ausgabe des Sidecars anzeigen, damit Startfehler erkennbar sind
          const { invoke } = await import("@tauri-apps/api/core");
          const log = await invoke<string[]>("engine_log").catch(() => []);
          if (log.length) throw new Error(`${(e as Error).message}. Letzte Ausgabe: ${log.slice(-6).join(" | ")}`);
        }
        throw e;
      }
      return info;
    })();
    // Fehlgeschlagene Verbindung beim nächsten Aufruf erneut versuchen
    infoPromise.catch(() => (infoPromise = null));
  }
  return infoPromise;
}

/** Wartet, bis die Engine antwortet (der Sidecar braucht beim Start einige Sekunden). */
async function waitForHealth(url: string, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(`${url}/health`);
      if (resp.ok) return;
    } catch {
      /* noch nicht bereit */
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`Engine unter ${url} antwortet nicht`);
}

export class EngineError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const { url, token } = await engineInfo();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body) headers.set("Content-Type", "application/json");
  const resp = await fetch(`${url}${path}`, { ...init, headers });
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = await resp.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* Antwort ohne JSON */
    }
    throw new EngineError(detail, resp.status);
  }
  return resp.status === 204 ? (undefined as T) : resp.json();
}

/** Abonniert Live-Events; verbindet sich bei Abbruch automatisch neu. */
export function subscribe(
  onEvent: (e: EngineEvent) => void,
  onStatus: (online: boolean) => void,
): () => void {
  let ws: WebSocket | null = null;
  let stopped = false;
  let retry: ReturnType<typeof setTimeout> | undefined;

  const connect = async () => {
    const { url, token } = await engineInfo();
    if (stopped) return;
    const wsUrl = url.replace(/^http/, "ws") + "/ws" + (token ? `?token=${encodeURIComponent(token)}` : "");
    ws = new WebSocket(wsUrl);
    ws.onopen = () => onStatus(true);
    ws.onmessage = (msg) => !stopped && onEvent(JSON.parse(msg.data));
    ws.onclose = () => {
      onStatus(false);
      if (!stopped) retry = setTimeout(connect, 1500);
    };
  };
  connect().catch(() => {
    onStatus(false);
    if (!stopped) retry = setTimeout(connect, 1500);
  });

  return () => {
    stopped = true;
    clearTimeout(retry);
    ws?.close();
  };
}

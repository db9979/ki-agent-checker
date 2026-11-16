import { CheckCircle2, Cloud, HardDrive, Loader2, Plug, Search, Trash2, XCircle } from "lucide-react";
import { HelpLink } from "../components/HelpLink";
import { useState } from "react";
import { api } from "../lib/engine";
import type { ConnectionResult, Provider, ProviderKind } from "../lib/types";
import { useApi } from "../lib/useApi";

const PRESETS: { kind: ProviderKind; label: string; url: string; needsKey: boolean; local: boolean }[] = [
  { kind: "ollama", label: "Ollama", url: "http://localhost:11434", needsKey: false, local: true },
  { kind: "openai_compatible", label: "vLLM", url: "http://localhost:8000/v1", needsKey: false, local: true },
  { kind: "openai_compatible", label: "LM Studio", url: "http://localhost:1234/v1", needsKey: false, local: true },
  {
    kind: "openai_compatible",
    label: "OpenAI-kompatibel",
    url: "http://localhost:8080/v1",
    needsKey: false,
    local: true,
  },
  { kind: "openai", label: "OpenAI", url: "", needsKey: true, local: false },
  { kind: "anthropic", label: "Anthropic", url: "", needsKey: true, local: false },
  { kind: "gemini", label: "Google Gemini", url: "", needsKey: true, local: false },
  { kind: "mistral", label: "Mistral", url: "", needsKey: true, local: false },
];

const input = "w-full rounded-lg border border-line bg-[#0b1222] px-3 py-2 text-sm outline-none focus:border-cyan";

export function Models() {
  const { data: providers, error, reload } = useApi<Provider[]>("/providers");
  const [preset, setPreset] = useState(0);
  const p = PRESETS[preset];
  const [name, setName] = useState("");
  const [model, setModel] = useState("");
  const [url, setUrl] = useState(p.url);
  const [key, setKey] = useState("");
  const [trustSelfSigned, setTrustSelfSigned] = useState(true);
  const [found, setFound] = useState<string[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, ConnectionResult>>({});
  const [message, setMessage] = useState<string | null>(null);

  const choose = (i: number) => {
    setPreset(i);
    setUrl(PRESETS[i].url);
    setFound([]);
  };

  const discover = async () => {
    setBusy("discover");
    setMessage(null);
    const res = await api<{ ok: boolean; models: string[]; error?: string }>("/providers/discover", {
      method: "POST",
      body: JSON.stringify({
        kind: p.kind,
        base_url: url || null,
        api_key: key || null,
        verify_tls: !(p.local && trustSelfSigned),
      }),
    });
    setBusy(null);
    setFound(res.models);
    if (!res.ok) setMessage(`Server nicht erreichbar: ${res.error}`);
    else if (res.models.length === 0) setMessage("Keine Modelle gefunden");
    else if (!model) setModel(res.models[0]);
  };

  const add = async () => {
    setMessage(null);
    try {
      await api<Provider>("/providers", {
        method: "POST",
        body: JSON.stringify({
          name: name || `${p.label} · ${model}`,
          kind: p.kind,
          model,
          base_url: url || null,
          api_key: key || null,
          verify_tls: !(p.local && trustSelfSigned),
        }),
      });
      setName("");
      setModel("");
      setKey("");
      reload();
    } catch (e) {
      setMessage(String((e as Error).message));
    }
  };

  const test = async (id: string) => {
    setBusy(id);
    const res = await api<ConnectionResult>(`/providers/${id}/test`, { method: "POST" });
    setResults((r) => ({ ...r, [id]: res }));
    setBusy(null);
  };

  const remove = async (id: string) => {
    await api(`/providers/${id}`, { method: "DELETE" });
    reload();
  };

  return (
    <div className="grid grid-cols-12 gap-4">
      <header className="col-span-12">
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          Modelle <HelpLink anchor="modelle" />
        </h1>
        <p className="text-sm text-muted">
          Selbst gehostete und Cloud-Modelle für Angreifer, Richter und Ziel. API-Schlüssel liegen im Schlüsselbund des
          Systems.
        </p>
      </header>

      <section className="panel col-span-12 space-y-4 p-5 lg:col-span-5">
        <h2 className="text-sm font-semibold text-muted">Modell verbinden</h2>
        <div className="grid grid-cols-2 gap-2">
          {PRESETS.map((x, i) => (
            <button
              key={x.label}
              onClick={() => choose(i)}
              className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-left text-sm transition ${
                i === preset ? "border-cyan bg-cyan/10 text-cyan" : "border-line hover:border-muted"
              }`}
            >
              {x.local ? <HardDrive size={14} /> : <Cloud size={14} />}
              {x.label}
            </button>
          ))}
        </div>
        {p.local && (
          <>
            <label className="block text-xs text-muted">
              Server-Adresse
              <input className={input} value={url} onChange={(e) => setUrl(e.target.value)} />
            </label>
            <label className="flex items-center gap-2 text-xs text-muted">
              <input type="checkbox" checked={trustSelfSigned} onChange={(e) => setTrustSelfSigned(e.target.checked)} />
              Selbst signierten Zertifikaten vertrauen (Server im Heimnetz)
            </label>
          </>
        )}
        <label className="block text-xs text-muted">
          API-Schlüssel {p.needsKey ? "" : "(optional)"}
          <input className={input} type="password" value={key} onChange={(e) => setKey(e.target.value)} />
        </label>
        <div className="flex items-end gap-2">
          <label className="block flex-1 text-xs text-muted">
            Modell
            <input
              className={input}
              list="found-models"
              placeholder={p.local ? "z. B. llama3.1:8b" : "z. B. gpt-4o-mini"}
              value={model}
              onChange={(e) => setModel(e.target.value)}
            />
            <datalist id="found-models">
              {found.map((m) => (
                <option key={m} value={m} />
              ))}
            </datalist>
          </label>
          {p.local && (
            <button
              onClick={discover}
              className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-2 text-sm hover:border-cyan"
            >
              {busy === "discover" ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />} Suchen
            </button>
          )}
        </div>
        <label className="block text-xs text-muted">
          Anzeigename (optional)
          <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        {message && <p className="text-xs text-amber">{message}</p>}
        <button
          onClick={add}
          disabled={!model || (p.needsKey && !key)}
          className="glow-cyan flex w-full items-center justify-center gap-2 rounded-xl bg-cyan/15 py-2 text-sm font-medium text-cyan disabled:opacity-40"
        >
          <Plug size={15} /> Verbinden
        </button>
      </section>

      <section className="panel col-span-12 p-5 lg:col-span-7">
        <h2 className="mb-3 text-sm font-semibold text-muted">Verbundene Modelle</h2>
        {error && <p className="text-sm text-red">Engine nicht erreichbar: {error}</p>}
        {providers?.length === 0 && <p className="text-sm text-muted">Noch kein Modell verbunden.</p>}
        <div className="space-y-2">
          {providers?.map((pr) => {
            const r = results[pr.id];
            return (
              <div key={pr.id} className="rounded-xl border border-line bg-panel-2/60 p-3">
                <div className="flex items-center gap-3">
                  {pr.self_hosted ? (
                    <HardDrive size={16} className="text-green" />
                  ) : (
                    <Cloud size={16} className="text-cyan" />
                  )}
                  <div className="flex-1">
                    <div className="text-sm font-medium">{pr.name}</div>
                    <div className="font-mono text-[11px] text-muted">
                      {pr.kind}/{pr.model} {pr.base_url ? `· ${pr.base_url}` : ""}
                    </div>
                    {!pr.verify_tls && (
                      <div className="mt-0.5 text-[10px] text-amber">vertraut selbst signierten Zertifikaten</div>
                    )}
                  </div>
                  <button
                    onClick={() => test(pr.id)}
                    className="rounded-lg border border-line px-3 py-1.5 text-xs hover:border-cyan"
                  >
                    {busy === pr.id ? <Loader2 size={13} className="animate-spin" /> : "Testen"}
                  </button>
                  <button
                    onClick={() => remove(pr.id)}
                    className="rounded-lg p-1.5 text-muted hover:text-red"
                    title="Entfernen"
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
                {r && (
                  <div className={`mt-2 flex items-center gap-2 text-xs ${r.ok ? "text-green" : "text-red"}`}>
                    {r.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                    {r.ok ? `Antwort in ${r.latency_ms} ms: „${r.reply}“` : r.error}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

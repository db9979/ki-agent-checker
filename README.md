# KI-Agent-Checker

Desktop-Programm für Windows, macOS und Linux, das KI-Agenten auf Schwachstellen prüft
(Prompt Injection, Jailbreaks, System-Prompt-Leaks, Datenabfluss, Tool-Missbrauch),
die Ergebnisse visualisiert und Gegenmaßnahmen vorschlägt. Selbst gehostete Modelle
(Ollama, vLLM, LM Studio, jeder OpenAI-kompatible Server) und Cloud-Modelle
(OpenAI, Anthropic, Gemini, Mistral) werden gleichermaßen unterstützt.

> **Nur für autorisierte Tests.** Teste ausschließlich Agenten, für die du eine
> Berechtigung hast. Jedes Projekt verlangt eine Bestätigung, und jeder Lauf
> landet im Audit-Log.

## Stand: Grundgerüst (Phase 1)

| Bereich | Enthalten |
| --- | --- |
| Desktop-Hülle | Tauri 2, startet die Engine als Sidecar auf freiem Port mit zufälligem Token |
| Engine | Python, FastAPI, SQLite, WebSocket für Live-Events |
| Modelle | LiteLLM-Anbindung, Modellsuche für Ollama und OpenAI-kompatible Server, Verbindungstest, Schlüssel im System-Schlüsselbund |
| Projekte | Scope-Liste, Berechtigungsbestätigung, Audit-Log |
| Visualisierung | Dashboard mit Security-Score, Heatmap Modul × OWASP LLM Top 10, Radar, Score-Verlauf, Live-Angriffsansicht, Angriffsgraph |
| Demo-Lauf | Vorbereiteter Lauf gegen einen fiktiven Kundenservice-Agenten, braucht kein Modell |

Echte Testmodule gegen eigene Agenten folgen in Phase 2 (siehe Konzept).

| Dashboard | Live-Angriff |
| --- | --- |
| ![Dashboard](docs/screenshots/dashboard.png) | ![Live-Angriff](docs/screenshots/live-angriff.png) |
| **Angriffsgraph** | **Modelle** |
| ![Angriffsgraph](docs/screenshots/angriffsgraph.png) | ![Modelle](docs/screenshots/modelle.png) |

## Aufbau

```
app/                 Oberfläche (React, Vite, Tailwind, Recharts, React Flow, Framer Motion)
app/src-tauri/       Desktop-Hülle (Rust, Tauri 2)
engine/              Test-Engine (Python, FastAPI, LiteLLM)
scripts/             Build-Hilfen, z. B. Engine als Sidecar-Binary bauen
.github/workflows/   CI und Installer-Builds für alle drei Plattformen
```

## Entwickeln

Voraussetzungen: [uv](https://docs.astral.sh/uv/), Node.js 22, Rust (stable) und unter
Linux die [Tauri-Systempakete](https://tauri.app/start/prerequisites/).

```bash
# 1. Engine starten (Terminal 1)
cd app && npm install
npm run dev:engine          # Engine auf 127.0.0.1:8765, im Entwicklungsmodus ohne Token

# 2a. Desktop-App starten (Terminal 2)
npm run tauri dev

# 2b. oder nur im Browser
npm run dev                 # http://localhost:1420
```

Im Dashboard auf **Demo-Lauf starten** klicken, um alle Ansichten mit Daten zu füllen.

### Lokales Modell anbinden

1. Ollama installieren und z. B. `ollama pull llama3.1` ausführen.
2. In der App unter **Modelle** „Ollama“ wählen, **Suchen** klicken, Modell auswählen, **Verbinden**.
3. Mit **Testen** prüfen, ob das Modell antwortet.

vLLM (`http://localhost:8000/v1`) und LM Studio (`http://localhost:1234/v1`) funktionieren genauso.

### Tests

```bash
cd engine && uv run pytest && uv run ruff check .
cd app && npm run build
```

## Installer bauen

```bash
uv run --project engine python scripts/build_sidecar.py      # Engine als Einzeldatei
cd app && npx tauri build --config src-tauri/tauri.release.conf.json
```

Der Workflow `Desktop-Build` baut MSI/EXE, DMG sowie AppImage/DEB automatisch bei jedem Push
auf `main` und bei Tags `v*`. Für signierte Installer werden später ein Apple-Developer-Konto
und ein Windows-Code-Signing-Zertifikat benötigt.

## Grundlage

Die Testplaybooks und Gegenmaßnahmen werden ab Phase 2 aus
[mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
(Apache 2.0) importiert. Das Projekt ist nicht mit Anthropic verbunden.

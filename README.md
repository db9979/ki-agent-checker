# KI-Agent-Checker

Desktop-Programm für Windows, macOS und Linux, das KI-Agenten auf Schwachstellen prüft
(Prompt Injection, Jailbreaks, System-Prompt-Leaks, Datenabfluss, Tool-Missbrauch),
die Ergebnisse visualisiert und Gegenmaßnahmen vorschlägt. Selbst gehostete Modelle
(Ollama, vLLM, LM Studio, jeder OpenAI-kompatible Server) und Cloud-Modelle
(OpenAI, Anthropic, Gemini, Mistral) werden gleichermaßen unterstützt.

> **Nur für autorisierte Tests.** Teste ausschließlich Agenten, für die du eine
> Berechtigung hast. Jedes Projekt verlangt eine Bestätigung, und jeder Lauf
> landet im Audit-Log.

## Stand: Phase 2 (echte Tests)

| Bereich | Enthalten |
| --- | --- |
| Desktop-Hülle | Tauri 2, startet die Engine als Sidecar auf freiem Port mit zufälligem Token |
| Engine | Python, FastAPI, SQLite, WebSocket für Live-Events |
| Modelle | LiteLLM-Anbindung, Modellsuche für Ollama und OpenAI-kompatible Server, Verbindungstest, Schlüssel im System-Schlüsselbund |
| Projekte | Scope-Liste, Berechtigungsbestätigung, Audit-Log |
| Visualisierung | Dashboard mit Security-Score, Heatmap Modul × OWASP LLM Top 10, Radar, Score-Verlauf, 3D-Angriffsarena mit HUD, Angriffsgraph mit Datenstrom, Zeitleiste zum Abspielen eines Laufs |
| Demo-Lauf | Vorbereiteter Lauf gegen einen fiktiven Kundenservice-Agenten, braucht kein Modell |
| Ziele | Eigenes Modell mit System-Prompt und Honeypot-Tools, Agent mit OpenAI-kompatibler API oder beliebiger HTTP-Endpunkt (JSON-Vorlage) |
| Anmeldung | API-Schlüssel, eigener Header, Basic Auth, Login-Aufruf mit Token oder Cookie, TOTP für 2FA, mehrere Testkonten mit Rollen |
| Testmodule | 23 Angriffe: Prompt Injection, Jailbreak, System-Prompt-Leak, Datenabfluss, Tool-Missbrauch, Zugriff auf fremde Kontodaten |
| Bewertung | Canary-Token, Honeypot-Tool-Aufrufe, Leak-Marker, private Angaben anderer Konten; optional Richter-Modell für unklare Fälle |

### Einen eigenen Agenten testen

1. Unter **Modelle** ein Modell verbinden (für „Eigenes Modell“ und als optionalen Richter).
2. Unter **Projekte** ein Projekt mit Scope anlegen, z. B. `agent.firma.de` oder `https://agent.firma.de/api`.
   Ziele außerhalb des Scopes lehnt die Engine ab.
3. Mit **+ Ziel** das Ziel einrichten. Für Agenten hinter einer Anmeldung die Anmeldeart wählen und Testkonten
   anlegen. Mit zwei Konten samt Kennung (z. B. E-Mail) und privater Angabe (z. B. IBAN) prüft die App,
   ob ein Konto an die Daten des anderen kommt. Passwörter, Tokens und TOTP-Geheimnisse liegen im Schlüsselbund.
4. **Prüfen** schickt eine harmlose Nachricht, **Testen** startet den Angriff. Der Lauf erscheint live in der Arena.

| Ziele und Testlauf | Echter Lauf mit Login und zwei Konten |
| --- | --- |
| ![Ziele](docs/screenshots/ziele.png) | ![Echter Lauf](docs/screenshots/echter-lauf.png) |

![Angriffsarena](docs/screenshots/arena.gif)

Die Live-Ansicht zeigt den Ziel-Agenten als Kern hinter einem Schutzschild. Jeder Angriff fliegt als
Lichtgeschoss heran: abgewehrt prallt er ab, ein Durchbruch reißt das Schild auf, löst Alarm aus und lässt
die missbrauchten Tools und Datenquellen rot glühen. Über die Zeitleiste lässt sich jeder Lauf erneut
abspielen, vorspulen oder an eine Stelle springen, in der Arena und im Angriffsgraphen.

Unten in der Seitenleiste schaltet **Effekte: voll / Leistungsmodus** zwischen voller Darstellung
(Bloom, Partikel, Glitch) und einer sparsamen Variante für schwache Geräte wie den uConsole um.
Auf kleinen Bildschirmen mit wenigen Kernen und bei „Bewegung reduzieren“ ist der Leistungsmodus voreingestellt.

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

Der Workflow `Desktop-Build` baut automatisch bei jedem Push auf `main` und bei Tags `v*`:

| System | Pakete |
| --- | --- |
| Windows (x64) | MSI, EXE |
| macOS (Apple Silicon) | DMG |
| Linux (x64) | DEB, AppImage |
| Linux (ARM64), z. B. ClockworkPi uConsole mit Raspberry Pi OS | DEB, AppImage |

Die macOS-App ist nur ad hoc signiert (ohne Apple-Developer-Konto). Beim ersten Start meldet macOS,
dass der Entwickler nicht überprüft werden kann: unter **Systemeinstellungen → Datenschutz & Sicherheit**
auf **Dennoch öffnen** klicken. Alternativ im Terminal: `xattr -cr "/Applications/KI-Agent-Checker.app"`.

Auf dem uConsole: `sudo apt install ./KI-Agent-Checker_*_arm64.deb`. Bei Bildschirmen unter
1500 × 960 startet die App maximiert, unter 1400 px Breite zeigt die Seitenleiste nur Symbole. Für signierte Installer werden später ein Apple-Developer-Konto
und ein Windows-Code-Signing-Zertifikat benötigt.

## Grundlage

Der Import weiterer Testplaybooks und Gegenmaßnahmen folgt aus
[mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
(Apache 2.0) importiert. Das Projekt ist nicht mit Anthropic verbunden.

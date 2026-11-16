# Anleitung

Diese Anleitung steht in der App unter **Hilfe** und im Repo unter `docs/ANLEITUNG.md`. Sie erklärt Schritt für Schritt, wie man
einen KI-Agenten einrichtet, testet und die Ergebnisse liest.

> **Nur für autorisierte Tests.** Teste ausschließlich Agenten, für die du eine Berechtigung hast.
> Jedes Projekt verlangt eine Bestätigung, und jeder Lauf landet im Audit-Log.

## Erste Schritte

Beim ersten Start öffnet sich die **Einrichtung**. Sie führt in sechs Schritten zum ersten Testlauf:

1. **Willkommen**: kurzer Überblick. Wer erst schauen will, startet hier einen Demo-Lauf gegen einen
   fiktiven Kundenservice-Agenten (braucht kein Modell und kein Ziel).
2. **Projekt**: legt fest, welche Adressen getestet werden dürfen, und hält die Freigabe fest.
3. **Modell** (optional): ein Sprachmodell verbinden. Nötig für den Zieltyp „Eigenes Modell“ und
   als Richter oder Angreifer bei mehrstufigen Angriffen.
4. **Ziel**: den Agenten oder MCP-Server eintragen, den du testen willst.
5. **Testquellen**: eigene Angriffe sind sofort da. garak, Promptfoo und Skill-Sammlungen lassen
   sich hier prüfen und einrichten.
6. **Erster Lauf**: Ziel und Testquelle wählen und starten. Die App springt in den Live-Angriff.

Die Einrichtung lässt sich jederzeit schließen und später fortsetzen. Unter **Hilfe → Einrichtung
starten** öffnet sie sich erneut.

## Projekte und Berechtigung

Ein Projekt bündelt Ziele und legt den **Scope** fest: eine Liste erlaubter Adressen, eine pro Zeile,
z. B. `agent.firma.de` oder `https://agent.firma.de/api`. Ziele außerhalb des Scopes lehnt die Engine ab.
Beim Anlegen trägst du ein, wer den Test freigegeben hat, und bestätigst die Berechtigung. Beides steht
später im Bericht.

## Modelle

Unter **Modelle** verbindest du Sprachmodelle. Selbst gehostet: Ollama, vLLM, LM Studio oder jeder
OpenAI-kompatible Server. Cloud: OpenAI, Anthropic, Google Gemini, Mistral. **Suchen** listet die Modelle
eines lokalen Servers auf, **Testen** prüft, ob das Modell antwortet. API-Schlüssel liegen im
Schlüsselbund des Betriebssystems, nicht in der Datenbank.

Modelle werden an drei Stellen gebraucht:

| Zweck | Wofür |
| --- | --- |
| Zieltyp „Eigenes Modell“ | Das Modell spielt mit deinem System-Prompt und Honeypot-Tools den Agenten |
| Richter | Bewertet Antworten, bei denen die eindeutigen Signale nicht reichen |
| Angreifer | Führt mehrstufige Angriffe (Crescendo) über bis zu 10 Nachrichten |

Als Angreifer eignen sich lokale Modelle ohne strenge Filter am besten, z. B. über Ollama.

## Ziele

Ein Ziel ist das, was angegriffen wird. Mit **+ Ziel** im Projekt (oder in der Einrichtung) wählst du den Typ:

| Typ | Wann |
| --- | --- |
| Eigenes Modell | Ein angebundenes Modell mit deinem System-Prompt und Honeypot-Tools, ideal vor dem Livegang |
| Agent mit OpenAI-API | Ein fertiger Agent mit OpenAI-kompatibler Chat-Schnittstelle (`…/v1`) |
| HTTP-Endpunkt | Beliebiger JSON-Endpunkt, z. B. das Backend eines Chat-Widgets. Anfrage mit `{{message}}` oder `{{messages}}`, Antwortfeld frei einstellbar |
| MCP-Server, Audit | Prüft einen MCP-Server (Streamable HTTP, meist `…/mcp`): Zugangsschutz, Tool-Beschreibungen, Rechte, Parameter, Ausgaben |
| MCP-Server, ein Tool als Agent | Steckt hinter einem MCP-Tool selbst ein Sprachmodell, laufen alle Chat-Angriffe gegen dieses Tool |

**Prüfen** schickt eine harmlose Nachricht und zeigt Antwortzeit und Antwort. Beim MCP-Server zeigt es
Servername und Tools.

### Anmeldung und Testkonten

Für Agenten hinter einer Anmeldung: API-Schlüssel/Bearer-Token, eigener Header, Basic Auth oder ein
Login-Aufruf, der Token oder Cookie liefert. 2FA geht per TOTP-Geheimnis je Konto oder per Code, den du
vor dem Lauf von Hand eingibst (wird nicht gespeichert).

Mit **zwei Testkonten**, jeweils mit Kennung (z. B. E-Mail) und privater Angabe (z. B. IBAN), prüft das
Modul „Fremde Kontodaten“, ob ein Konto an die Daten des anderen kommt. Passwörter, Tokens und
TOTP-Geheimnisse liegen im Schlüsselbund.

### MCP-Tools aufrufen

Beim MCP-Audit ruft die App standardmäßig nur lesende Tools auf. „Alle Tools aufrufen“ nur auf
Testsystemen einschalten, weil dann auch schreibende oder löschende Tools ausgeführt werden.

## Testquellen

### Eigene Angriffe

Sofort verfügbar, ohne Installation. Für Chat-Ziele:

| Modul | Prüft |
| --- | --- |
| Prompt Injection | Ob sich die Anweisungen des Systems überschreiben lassen |
| Jailbreak | Rollenspiele und Tricks, die Schutzregeln aushebeln |
| System-Prompt-Leak | Ob der Agent seinen System-Prompt oder Geheimnisse darin verrät |
| Datenabfluss | Ob Daten über Links, Bilder oder Tool-Aufrufe nach außen gelangen |
| Tool-Missbrauch | Ob der Agent riskante Tools ohne Rückfrage nutzt |
| Fremde Kontodaten | Ob ein Konto an private Angaben eines anderen kommt (braucht zwei Testkonten) |
| Mehrstufig | Angriffe über mehrere Nachrichten (braucht ein Angreifer-Modell) |

Für MCP-Server: Zugangsschutz, Tool-Poisoning, Riskante Tools, Parameter-Injection und Manipulierte Ausgaben.

### Skills

Unter **Skills** lassen sich Sammlungen im SKILL.md-Format importieren, standardmäßig
[Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) (Apache-2.0),
oder ein eigener Ordner. Gelesen werden nur die SKILL.md-Dateien, Skripte werden nie ausgeführt.
Angriffstexte aus Codeblöcken ` ```text ` oder ` ```prompt ` werden zu eigenen Testmodulen (Markierung
„Skill“), Gegenmaßnahmen erscheinen im Dashboard bei passenden Befunden.

### garak

[garak](https://github.com/NVIDIA/garak) ist ein Open-Source-Scanner von NVIDIA mit vielen Probes.
Er wird einmalig separat installiert:

| System | Befehl |
| --- | --- |
| macOS | `brew install pipx` und danach `pipx install garak` |
| Linux, auch uConsole | `sudo apt install pipx` und danach `pipx install garak` |
| Windows | `py -m pip install --user pipx`, dann `py -m pipx install garak` |

Danach in der Einrichtung oder im Testlauf auf **Prüfen** klicken. Findet die App garak nicht, den
vollen Pfad eintragen (z. B. `~/.local/bin/garak`). Standardmäßig schickt garak höchstens 20 Prompts je
Probe, damit ein Lauf nicht Stunden dauert. Ergebnisse erscheinen live im Angriffspfad.

### Promptfoo

[Promptfoo](https://www.promptfoo.dev/) erzeugt Angriffe passend zum Zweck des Agenten. Es braucht
[Node.js](https://nodejs.org/) 18 oder neuer; die App startet es mit `npx -y promptfoo@latest`, beim ersten
Mal wird es heruntergeladen.

Für Red-Team-Scans verlangt Promptfoo **einmalig eine bestätigte E-Mail-Adresse**:

1. In der Einrichtung unter Testquellen bei Promptfoo die E-Mail eintragen und **Speichern** klicken.
   (Entspricht `promptfoo config set email du@firma.de` im Terminal.)
2. Promptfoo schickt beim ersten Scan eine Mail. Den Bestätigungslink anklicken.
3. Den Scan noch einmal starten.

Wer ein Promptfoo-Konto hat, kann stattdessen im Terminal `promptfoo auth login` ausführen. Zum Erzeugen
der Angriffe nutzt Promptfoo seinen Online-Dienst oder einen eigenen Modell-Schlüssel (z. B.
`OPENAI_API_KEY`). Ergebnisse erscheinen nach dem Lauf.

Beide externen Scanner sprechen über eine lokale Brücke der App mit dem Ziel. Anmeldung, 2FA, eigene
Modelle und MCP-Tools funktionieren damit genauso wie bei den eigenen Angriffen.

## Einen Lauf starten und verfolgen

Unter **Projekte** beim Ziel auf **Testen** klicken, Testquelle und Module wählen, **Angriff starten**.
Die App springt in den **Live-Angriff**:

- **Angriffspfad**: jeder Angriff als Linie durch vier Schutzschichten (Eingabe-Schutz, Modell/Prompt,
  Tools & Daten, Außenwelt). Eine grüne Sperre zeigt, wo er gestoppt wurde, ein roter Pfeil, wie weit er
  durchgebrochen ist.
- **Terminal**: das Gespräch mit dem Ziel, Tool-Aufrufe hervorgehoben. Ein Klick auf einen Angriff im
  Pfad zeigt dessen Verlauf.
- **Zeitleiste**: jeden Lauf erneut abspielen, vorspulen oder an eine Stelle springen.
- **Abbrechen** beendet einen laufenden Test.

## Ergebnisse lesen

| Ansicht | Zeigt |
| --- | --- |
| Dashboard | Security-Score (0 bis 100), Befunde nach Schwere, Heatmap Modul × OWASP LLM Top 10, Radar, Score-Verlauf, letzte Läufe |
| Angriffsgraph | Das echte Ziel als Graph: Agent, Tools und Daten, live eingefärbt. Beim MCP-Server alle Tools nach Risiko gruppiert. Ein Klick zeigt die Angriffe auf einen Knoten |
| Vergleich | Zwei Läufe desselben Ziels nebeneinander: behoben, neu kaputt, schlechter geworden |
| Bericht | Eigenständige HTML-Datei mit Score, Befunden, Beleg, Gegenmaßnahme und Anhang; im Browser als PDF speicherbar |

Der Score sinkt mit jedem erfolgreichen Angriff, gewichtet nach Schwere. Jeder Befund nennt die
OWASP-LLM-Kategorie, den Beleg aus dem Gespräch und eine konkrete Gegenmaßnahme.

## Kommandozeile und CI

`kac-engine scan` führt einen Testlauf ohne Oberfläche aus. Exit-Code 0 heißt bestanden, 1 Befunde ab
`--fail-on` (Standard „Hoch“), 2 Fehler.

```bash
# Ziel, das in der App angelegt ist
kac-engine scan --target spark --report bericht.html

# Alles aus einer Datei, Geheimnisse aus Umgebungsvariablen (für CI)
MCP_TOKEN=... kac-engine scan --config kac.yaml --junit ergebnis.xml --json ergebnis.json
```

Ein Beispiel liegt unter `docs/beispiele/kac.yaml`. Als GitHub Action:

```yaml
- uses: db9979/ki-agent-checker@main
  with:
    config: kac.yaml
    fail-on: high
```

## Leistungsmodus

Unten in der Seitenleiste schaltet **Effekte: voll / Leistungsmodus** Animationen und Leuchteffekte
für schwache Geräte wie den uConsole herunter. Unter 1400 px Breite zeigt die Seitenleiste nur Symbole.

## Häufige Probleme

**„Engine nicht erreichbar“ unten links.** Die App startet ihre Engine beim Start selbst. Hilft ein
Neustart der App nicht, steht die letzte Ausgabe der Engine in der Fehlermeldung.

**Ziel wird abgelehnt.** Die Adresse liegt nicht im Scope des Projekts. Scope um die Adresse ergänzen
(neues Projekt anlegen) oder die Adresse im Ziel korrigieren.

**garak wird nicht gefunden.** Desktop-Apps starten unter macOS mit kurzem Suchpfad. Den vollen Pfad
eintragen, z. B. die Ausgabe von `which garak` im Terminal.

**garak läuft, aber nichts passiert.** In der Statusleiste über dem Angriffspfad stehen Phase, Anfragen
ans Ziel und Fehler. Viele Fehler heißen meist: Ziel nicht erreichbar oder Anmeldung abgelaufen.

**Promptfoo bricht mit einer E-Mail-Abfrage ab.** Siehe [Promptfoo](#promptfoo): E-Mail hinterlegen,
Bestätigungslink anklicken, Scan neu starten.

**Modul ist ausgegraut.** „Fremde Kontodaten“ braucht zwei Testkonten mit Kennung und privater Angabe,
„Mehrstufig“ ein Angreifer-Modell. Beim MCP-Server mit „Keine Tools aufrufen“ sind Module aus, die Tools
aufrufen.

**macOS meldet, der Entwickler könne nicht überprüft werden.** Unter Systemeinstellungen → Datenschutz &
Sicherheit auf **Dennoch öffnen** klicken oder `xattr -cr "/Applications/KI-Agent-Checker.app"` ausführen.

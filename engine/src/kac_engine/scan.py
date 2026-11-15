"""``kac-engine scan``: ein Testlauf ohne Oberfläche, für Kommandozeile und CI.

Zwei Wege zum Ziel:

* ``--config kac.yaml`` beschreibt Projekt, Ziel und Lauf in einer Datei. Geheimnisse
  stehen dort als ``${UMGEBUNGSVARIABLE}`` und kommen aus der Umgebung (CI-Secrets).
  Nichts wird dauerhaft gespeichert.
* ``--target NAME`` nimmt ein Ziel, das in der Desktop-App angelegt ist, samt
  Zugangsdaten aus dem Schlüsselbund.

Die Engine läuft dabei im selben Prozess auf einem freien Port auf localhost, damit
auch garak und Promptfoo über die Brücke das Ziel erreichen.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

import httpx
import uvicorn
import yaml

from .api import create_app
from .keystore import SecretStore

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_LABEL = {
    "critical": "Kritisch",
    "high": "Hoch",
    "medium": "Mittel",
    "low": "Niedrig",
    "info": "Info",
}
ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


class ScanError(Exception):
    pass


def expand_env(value: Any, env: dict[str, str] | None = None) -> Any:
    """Ersetzt ``${NAME}`` in allen Texten. Fehlt eine Variable, bricht der Lauf ab."""
    env = os.environ if env is None else env
    if isinstance(value, str):

        def sub(m: re.Match) -> str:
            if m.group(1) not in env:
                raise ScanError(f"Umgebungsvariable {m.group(1)} ist nicht gesetzt")
            return env[m.group(1)]

        return ENV_REF.sub(sub, value)
    if isinstance(value, list):
        return [expand_env(v, env) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v, env) for k, v in value.items()}
    return value


def load_config(path: Path, env: dict[str, str] | None = None) -> dict:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ScanError(f"Konfiguration nicht lesbar: {exc}") from exc
    if not isinstance(raw, dict) or "target" not in raw:
        raise ScanError("Die Konfiguration braucht mindestens einen Abschnitt 'target'")
    return expand_env(raw, env)


class Engine:
    """Startet die API in einem Hintergrund-Thread und spricht per HTTP mit ihr."""

    def __init__(self, db_path: Path | str, keys: SecretStore) -> None:
        self.token = secrets.token_urlsafe(24)
        app = create_app(token=self.token, db_path=db_path, secrets=keys)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.client = httpx.Client(
            base_url=f"http://127.0.0.1:{port}",
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=60,
        )

    def __enter__(self) -> Engine:
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise ScanError("Engine startet nicht")

    def __exit__(self, *_: object) -> None:
        self.client.close()
        self.server.should_exit = True
        self.thread.join(timeout=5)

    def call(self, method: str, path: str, **kw: Any) -> Any:
        r = self.client.request(method, path, **kw)
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except ValueError:
                detail = r.text
            if isinstance(detail, list):  # Validierungsfehler von FastAPI
                detail = "; ".join(
                    f"{'.'.join(str(p) for p in d.get('loc', [])[1:])}: {d.get('msg')}"
                    for d in detail
                )
            raise ScanError(f"{method} {path}: {detail}")
        return r.json() if r.content else None


def setup_from_config(engine: Engine, cfg: dict) -> tuple[str, dict]:
    """Legt Projekt, Modelle und Ziel an. Gibt Ziel-ID und Lauf-Optionen zurück."""
    project = dict(cfg.get("project") or {})
    if project.get("authorization_confirmed") is not True:
        raise ScanError(
            "project.authorization_confirmed muss true sein: Teste nur Systeme, "
            "für die du eine Berechtigung hast"
        )
    project.setdefault("name", "CI")
    project.setdefault("authorized_by", "CI")
    target = dict(cfg["target"])
    if not project.get("scope") and target.get("url"):
        project["scope"] = [target["url"]]
    project_id = engine.call("POST", "/projects", json=project)["id"]

    providers: dict[str, str] = {}
    for p in cfg.get("providers") or []:
        providers[p["name"]] = engine.call("POST", "/providers", json=p)["id"]

    def provider_ref(name: str | None) -> str | None:
        if not name:
            return None
        if name not in providers:
            raise ScanError(f"Modell '{name}' ist unter providers nicht beschrieben")
        return providers[name]

    if "provider" in target:
        target["provider_id"] = provider_ref(target.pop("provider"))
    target["project_id"] = project_id
    target_id = engine.call("POST", "/targets", json=target)["id"]

    run = dict(cfg.get("run") or {})
    if "judge" in run:
        run["judge_provider_id"] = provider_ref(run.pop("judge"))
    if "attacker" in run:
        run["attacker_provider_id"] = provider_ref(run.pop("attacker"))
    return target_id, run


def find_target(engine: Engine, name: str) -> str:
    targets = engine.call("GET", "/targets")
    hits = [t for t in targets if name in (t["id"], t["name"])]
    if not hits:
        known = ", ".join(t["name"] for t in targets) or "keine"
        raise ScanError(f"Ziel '{name}' nicht gefunden. Vorhanden: {known}")
    if len(hits) > 1:
        raise ScanError(f"Mehrere Ziele heißen '{name}', bitte die ID angeben")
    return hits[0]["id"]


def follow(engine: Engine, run_id: str, out, timeout: float) -> dict:
    """Gibt den Fortschritt aus, bis der Lauf endet, und liefert die Zusammenfassung."""
    seen = 0
    started = time.monotonic()
    while True:
        events = engine.call("GET", f"/runs/{run_id}/events")
        for e in events[seen:]:
            line = describe(e)
            if line:
                print(line, file=out, flush=True)
        seen = len(events)
        run = next((r for r in engine.call("GET", "/runs") if r["id"] == run_id), None)
        if run and run["status"] != "running":
            return run
        if time.monotonic() - started > timeout:
            engine.call("POST", f"/runs/{run_id}/cancel")
            raise ScanError(f"Lauf nach {int(timeout)} s abgebrochen (--timeout)")
        time.sleep(0.3)


def describe(e: dict) -> str | None:
    t = e["type"]
    if t == "run.started":
        return f"▶ {e.get('target', '')}"
    if t == "attack.finished":
        mark = "✗ DURCHBRUCH" if e.get("success") else "✓ gestoppt"
        if e.get("signal") == "error":
            mark = "! Fehler"
        return f"  [{e.get('done', '?')}/{e.get('total', '?')}] {e.get('module', '')}: {mark}"
    if t == "run.error":
        return f"! {e.get('error', '')}"
    if t == "log":
        return f"  {e.get('text', '')}"
    return None


def failing(findings: list[dict], fail_on: str) -> list[dict]:
    if fail_on == "never":
        return []
    limit = SEVERITIES.index(fail_on)
    return [f for f in findings if SEVERITIES.index(f["severity"]) >= limit]


def summary(run: dict, fail_on: str) -> str:
    lines = [
        "",
        f"Ziel:   {run['target']}",
        f"Status: {run['status']}",
        f"Score:  {run['score'] if run['score'] is not None else '–'}/100",
    ]
    findings = sorted(run["findings"], key=lambda f: -SEVERITIES.index(f["severity"]))
    if findings:
        lines.append(f"Befunde ({len(findings)}):")
        for f in findings:
            lines.append(
                f"  {SEVERITY_LABEL[f['severity']]:<9} {f['owasp']:<6} {f['title']}"
                f" ({round(f['success_rate'] * 100)} %)"
            )
    else:
        lines.append("Keine Befunde.")
    bad = failing(run["findings"], fail_on)
    if bad:
        lines.append(
            f"Fehlgeschlagen: {len(bad)} Befund(e) ab „{SEVERITY_LABEL.get(fail_on, fail_on)}“"
        )
    return "\n".join(lines)


def junit(run: dict, modules: list[str], fail_on: str) -> str:
    """JUnit-XML: ein Testfall je Angriffsmodul, damit CI-Systeme die Ergebnisse anzeigen."""
    by_module = {f["module"]: f for f in run["findings"]}
    names = list(dict.fromkeys([*modules, *by_module]))
    bad = {f["module"] for f in failing(run["findings"], fail_on)}
    cases = []
    for m in names:
        f = by_module.get(m)
        body = ""
        if f and m in bad:
            body = (
                f'<failure message="{escape(f["title"], {chr(34): "&quot;"})}" '
                f'type="{f["severity"]}">{escape(f["evidence"])}\n\n'
                f"Gegenmaßnahme: {escape(f['remediation'])}</failure>"
            )
        elif f:
            body = f"<system-out>{escape(f['title'])} ({f['severity']})</system-out>"
        cases.append(
            f'  <testcase classname="ki-agent-checker" name="{escape(m)}">{body}</testcase>'
        )
    error = "" if run["status"] == "finished" else ' errors="1"'
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="{escape(run["target"], {chr(34): "&quot;"})}" tests="{len(names)}" '
        f'failures="{len(bad)}"{error}>\n' + "\n".join(cases) + "\n</testsuite>\n"
    )


def run_scan(args, out=None, err=None) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    from .cli import default_data_dir

    try:
        if args.config:
            cfg = load_config(Path(args.config))
            db: Path | str = ":memory:"
            keys = SecretStore(use_keyring=False)
        else:
            cfg = {}
            data_dir = args.data_dir or default_data_dir()
            if not (data_dir / "engine.sqlite3").exists():
                raise ScanError(f"Keine Daten der Desktop-App unter {data_dir}")
            db, keys = data_dir / "engine.sqlite3", SecretStore()
        fail_on = args.fail_on or cfg.get("fail_on") or "high"
        if fail_on not in [*SEVERITIES, "never"]:
            raise ScanError(f"--fail-on: unbekannte Stufe '{fail_on}'")
        with Engine(db, keys) as engine:
            if args.config:
                target_id, run_opts = setup_from_config(engine, cfg)
            else:
                target_id, run_opts = find_target(engine, args.target), {}
            if args.modules:
                run_opts["modules"] = [m.strip() for m in args.modules.split(",") if m.strip()]
            if args.scanner:
                run_opts["scanner"] = {**(run_opts.get("scanner") or {}), "tool": args.scanner}
            run_id = engine.call("POST", "/runs", json={"target_id": target_id, **run_opts})[
                "run_id"
            ]
            run = follow(engine, run_id, err, args.timeout)
            if args.report:
                html = engine.client.get(f"/runs/{run_id}/report").text
                Path(args.report).write_text(html, encoding="utf-8")
            planned = run_opts.get("modules") or [
                e["key"]
                for ev in engine.call("GET", f"/runs/{run_id}/events")
                if ev["type"] == "run.started"
                for e in ev.get("modules", [])
            ]
    except ScanError as exc:
        print(f"Fehler: {exc}", file=err)
        return EXIT_ERROR

    print(summary(run, fail_on), file=out)
    if args.json:
        Path(args.json).write_text(json.dumps(run, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.junit:
        Path(args.junit).write_text(junit(run, planned, fail_on), encoding="utf-8")
    if run["status"] != "finished":
        return EXIT_ERROR
    return EXIT_FINDINGS if failing(run["findings"], fail_on) else EXIT_OK


def add_parser(sub) -> None:
    p = sub.add_parser(
        "scan",
        help="Testlauf ohne Oberfläche (für Kommandozeile und CI)",
        description="Exit-Code 0: bestanden, 1: Befunde ab --fail-on, 2: Fehler.",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--config", help="YAML-Datei mit project, target, run (siehe README)")
    src.add_argument("--target", help="Name oder ID eines Ziels aus der Desktop-App")
    p.add_argument("--data-dir", type=Path, default=None, help="Datenordner der Desktop-App")
    p.add_argument(
        "--fail-on",
        choices=[*SEVERITIES, "never"],
        default=None,
        help="Ab dieser Schwere schlägt der Lauf fehl (Standard: high)",
    )
    p.add_argument("--modules", help="Kommagetrennte Modul-Schlüssel, Standard: alle")
    p.add_argument("--scanner", choices=["garak", "promptfoo"], help="Externen Scanner nutzen")
    p.add_argument("--report", help="HTML-Bericht hierhin schreiben")
    p.add_argument("--json", help="Ergebnis als JSON hierhin schreiben")
    p.add_argument("--junit", help="Ergebnis als JUnit-XML hierhin schreiben")
    p.add_argument("--timeout", type=float, default=3600, help="Sekunden bis zum Abbruch")

"""HTTP- und WebSocket-API der Engine."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import secrets as pysecrets
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from . import __version__, mcp, providers, report, scanners, skills
from . import attacks as attack_lib
from .demo import run_demo
from .events import EventHub
from .keystore import SecretStore
from .models import (
    ConnectionResult,
    Project,
    ProjectIn,
    Provider,
    ProviderIn,
    ProviderKind,
    RunSummary,
)
from .runner import Conversations, RunConfig, run_target
from .store import Store
from .targets import (
    SECRET_FIELDS,
    Account,
    Target,
    TargetIn,
    TargetKind,
    in_scope,
    secret_key,
)

ALLOWED_ORIGINS = [
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
    "http://localhost:1420",
    "http://127.0.0.1:1420",
]


class DiscoverIn(BaseModel):
    kind: ProviderKind
    base_url: str | None = None
    api_key: str | None = None
    verify_tls: bool = True


class ScannerIn(BaseModel):
    tool: Literal["garak", "promptfoo"]
    cmd: str = ""
    probes: str = ""
    purpose: str = ""
    num_tests: int = Field(default=3, ge=1, le=20)


class RunIn(BaseModel):
    target_id: str
    scanner: ScannerIn | None = None
    modules: list[str] | None = None
    judge_provider_id: str | None = None
    mfa_codes: dict[str, str] = Field(
        default_factory=dict, description="Von Hand eingegebene 2FA-Codes je Testkonto"
    )


class SkillImportIn(BaseModel):
    source: Literal["github", "folder"] = "github"
    repo: str = skills.DEFAULT_REPO
    ref: str = "main"
    path: str | None = None
    only_ai: bool = True


class CheckIn(BaseModel):
    mfa_codes: dict[str, str] = Field(default_factory=dict)


class DemoRunIn(BaseModel):
    project_id: str | None = None
    delay: float = 0.6


def create_app(
    *,
    token: str | None = None,
    db_path: Path | str = ":memory:",
    secrets: SecretStore | None = None,
    reports_dir: Path | str | None = None,
) -> FastAPI:
    """Erzeugt die App. Mit ``token`` verlangt jede Anfrage ``Authorization: Bearer <token>``."""
    app = FastAPI(title="KI-Agent-Checker Engine", version=__version__)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    store = Store(db_path)
    hub = EventHub()
    keys = secrets or SecretStore()
    tasks: dict[str, asyncio.Task] = {}
    app.state.store, app.state.hub, app.state.keys = store, hub, keys
    attack_lib.register([m for s in store.list_skills() if (m := skills.to_module(s))])

    def check(supplied: str | None) -> None:
        if token is None:
            return
        if not supplied or not hmac.compare_digest(supplied, token):
            raise HTTPException(status_code=401, detail="Ungültiges Engine-Token")

    def auth(request: Request) -> None:
        header = request.headers.get("authorization", "")
        check(header.removeprefix("Bearer ").strip() or None)

    protected = [Depends(auth)]

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "keyring": keys.persistent}

    # Provider ------------------------------------------------------------
    @app.get("/providers", dependencies=protected)
    def list_providers() -> list[Provider]:
        return store.list_providers()

    @app.post("/providers", dependencies=protected, status_code=201)
    def add_provider(data: ProviderIn) -> Provider:
        provider = store.add_provider(data, has_api_key=bool(data.api_key))
        if data.api_key:
            keys.set(f"provider:{provider.id}", data.api_key)
        store.audit(
            "provider.added", {"id": provider.id, "kind": provider.kind, "model": provider.model}
        )
        return provider

    @app.delete("/providers/{provider_id}", dependencies=protected, status_code=204)
    def delete_provider(provider_id: str) -> None:
        if not store.delete_provider(provider_id):
            raise HTTPException(404, "Provider nicht gefunden")
        keys.delete(f"provider:{provider_id}")
        store.audit("provider.deleted", {"id": provider_id})

    @app.post("/providers/{provider_id}/test", dependencies=protected)
    async def test_provider(provider_id: str) -> ConnectionResult:
        provider = store.get_provider(provider_id)
        if not provider:
            raise HTTPException(404, "Provider nicht gefunden")
        return await providers.test_connection(provider, keys.get(f"provider:{provider_id}"))

    @app.post("/providers/discover", dependencies=protected)
    async def discover(data: DiscoverIn) -> dict:
        try:
            models = await providers.discover_models(
                data.kind, data.base_url, data.api_key, data.verify_tls
            )
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "models": [], "error": providers.describe_error(exc)}
        return {"ok": True, "models": models}

    # Projekte ------------------------------------------------------------
    @app.get("/projects", dependencies=protected)
    def list_projects() -> list[Project]:
        return store.list_projects()

    @app.post("/projects", dependencies=protected, status_code=201)
    def add_project(data: ProjectIn) -> Project:
        if not data.authorization_confirmed:
            raise HTTPException(
                422, "Tests sind nur mit bestätigter Berechtigung für alle Ziele im Scope erlaubt"
            )
        project = store.add_project(data)
        store.audit(
            "project.authorized",
            {"id": project.id, "scope": project.scope, "by": project.authorized_by},
        )
        return project

    # Ziele ----------------------------------------------------------------
    @app.get("/targets", dependencies=protected)
    def list_targets(project_id: str | None = None) -> list[Target]:
        return store.list_targets(project_id)

    def _validate(data: TargetIn) -> Project:
        project = store.get_project(data.project_id)
        if not project:
            raise HTTPException(404, "Projekt nicht gefunden")
        if data.kind == TargetKind.MODEL:
            if not data.provider_id or not store.get_provider(data.provider_id):
                raise HTTPException(422, "Bitte ein angebundenes Modell auswählen")
        else:
            if not data.url:
                raise HTTPException(422, "Adresse des Ziels fehlt")
            for url in filter(None, [data.url, data.auth.login_url, data.auth.mfa_url]):
                if not in_scope(url, project.scope):
                    raise HTTPException(
                        403,
                        f"{url} liegt nicht im Scope des Projekts. Erlaubt: {', '.join(project.scope) or 'nichts'}",
                    )
        names = [a.name for a in data.accounts]
        if len(names) != len(set(names)):
            raise HTTPException(422, "Testkonten brauchen eindeutige Namen")
        return project

    def _build(data: TargetIn, target_id: str, created_at: datetime, old: Target | None) -> Target:
        """Erzeugt das Ziel. Leere Geheimnis-Felder behalten beim Bearbeiten den alten Wert."""
        previous = {a.name: a for a in (old.accounts if old else [])}
        accounts = []
        for a in data.accounts:
            prev = previous.get(a.name)
            for field in SECRET_FIELDS:
                value = getattr(a, field)
                if value:
                    keys.set(secret_key(target_id, a.name, field), value)
            accounts.append(
                Account(
                    name=a.name,
                    role=a.role,
                    username=a.username,
                    identifier=a.identifier,
                    marker=a.marker,
                    has_password=bool(a.password) or bool(prev and prev.has_password),
                    has_token=bool(a.token) or bool(prev and prev.has_token),
                    has_totp=bool(a.totp_secret) or bool(prev and prev.has_totp),
                )
            )
        # Geheimnisse entfernter Konten löschen
        for name in previous.keys() - {a.name for a in data.accounts}:
            for field in SECRET_FIELDS:
                keys.delete(secret_key(target_id, name, field))
        return Target(
            id=target_id,
            created_at=created_at,
            accounts=accounts,
            **data.model_dump(exclude={"accounts"}),
        )

    @app.post("/targets", dependencies=protected, status_code=201)
    def add_target(data: TargetIn) -> Target:
        project = _validate(data)
        target = _build(data, uuid.uuid4().hex[:12], datetime.now(UTC), None)
        store.save_target(target)
        store.audit(
            "target.added",
            {
                "id": target.id,
                "project": project.id,
                "kind": target.kind,
                "url": target.url,
                "accounts": [a.name for a in target.accounts],
            },
        )
        return target

    @app.put("/targets/{target_id}", dependencies=protected)
    def update_target(target_id: str, data: TargetIn) -> Target:
        old = store.get_target(target_id)
        if not old:
            raise HTTPException(404, "Ziel nicht gefunden")
        if data.project_id != old.project_id:
            raise HTTPException(422, "Ein Ziel kann nicht in ein anderes Projekt verschoben werden")
        project = _validate(data)
        target = _build(data, old.id, old.created_at, old)
        store.save_target(target)
        store.audit(
            "target.updated",
            {"id": target.id, "project": project.id, "kind": target.kind, "url": target.url},
        )
        return target

    @app.delete("/targets/{target_id}", dependencies=protected, status_code=204)
    def delete_target(target_id: str) -> None:
        target = store.get_target(target_id)
        if not target or not store.delete_target(target_id):
            raise HTTPException(404, "Ziel nicht gefunden")
        for a in target.accounts:
            for field in SECRET_FIELDS:
                keys.delete(secret_key(target_id, a.name, field))
        store.audit("target.deleted", {"id": target_id})

    @app.post("/targets/{target_id}/check", dependencies=protected)
    async def check_target(target_id: str, data: CheckIn | None = None) -> ConnectionResult:
        """Harmlose Testnachricht, prüft Erreichbarkeit und Anmeldung."""
        target = store.get_target(target_id)
        if not target:
            raise HTTPException(404, "Ziel nicht gefunden")
        provider = store.get_provider(target.provider_id) if target.provider_id else None
        codes = data.mfa_codes if data else {}
        if target.kind == TargetKind.MCP:
            start = time.perf_counter()
            try:
                client, tools = await mcp.connect(target, keys, codes)
                await client.close()
            except Exception as exc:  # noqa: BLE001
                return ConnectionResult(ok=False, error=providers.describe_error(exc))
            names = ", ".join(str(t.get("name")) for t in tools[:12])
            info = client.server_info
            return ConnectionResult(
                ok=True,
                latency_ms=int((time.perf_counter() - start) * 1000),
                reply=(
                    f"MCP-Server „{info.get('name', '?')}“ {info.get('version', '')}, "
                    f"{len(tools)} Tools: {names or 'keine'}"
                )[:300],
            )
        convo = Conversations(
            RunConfig(target=target, modules=[], provider=provider, mfa_codes=codes), keys
        )
        start = time.perf_counter()
        try:
            reply, _ = await convo.reply(
                0 if target.accounts else -1,
                [{"role": "user", "content": "Hallo! Wobei kannst du mir helfen?"}],
            )
        except Exception as exc:  # noqa: BLE001
            return ConnectionResult(ok=False, error=providers.describe_error(exc))
        finally:
            await convo.close()
        return ConnectionResult(
            ok=True, latency_ms=int((time.perf_counter() - start) * 1000), reply=reply.strip()[:300]
        )

    # Testläufe -----------------------------------------------------------
    @app.get("/runs", dependencies=protected)
    def list_runs() -> list[RunSummary]:
        return store.list_runs()

    @app.get("/runs/{run_id}/events", dependencies=protected)
    def run_events(run_id: str) -> list[dict]:
        return hub.history(run_id)

    @app.post("/runs/demo", dependencies=protected, status_code=202)
    async def start_demo(data: DemoRunIn) -> dict:
        run_id = uuid.uuid4().hex[:12]
        store.audit("run.started", {"id": run_id, "kind": "demo"})
        task = asyncio.create_task(
            run_demo(
                hub, store, project_id=data.project_id, delay=max(0.0, data.delay), run_id=run_id
            )
        )
        _track(run_id, task)
        return {"run_id": run_id}

    @app.post("/runs", dependencies=protected, status_code=202)
    async def start_run(data: RunIn, request: Request) -> dict:
        target = store.get_target(data.target_id)
        if not target:
            raise HTTPException(404, "Ziel nicht gefunden")
        project = store.get_project(target.project_id)
        if not project:
            raise HTTPException(422, "Projekt des Ziels fehlt")
        if target.url and not in_scope(target.url, project.scope):
            raise HTTPException(403, "Das Ziel liegt nicht im Scope des Projekts")
        if data.scanner:
            return _start_scanner(data, target, project.id, str(request.base_url).rstrip("/"))
        known = mcp.MCP_KEYS if target.kind == TargetKind.MCP else attack_lib.all_keys()
        modules = data.modules or (
            known if target.kind == TargetKind.MCP else attack_lib.MODULE_KEYS
        )
        unknown = set(modules) - set(known)
        if unknown:
            raise HTTPException(422, f"Unbekannte Module: {', '.join(sorted(unknown))}")
        provider = store.get_provider(target.provider_id) if target.provider_id else None
        if target.kind == TargetKind.MODEL and not provider:
            raise HTTPException(422, "Für dieses Ziel ist kein Modell ausgewählt")
        judge = store.get_provider(data.judge_provider_id) if data.judge_provider_id else None
        run_id = uuid.uuid4().hex[:12]
        store.audit(
            "run.started",
            {
                "id": run_id,
                "kind": "target",
                "target": target.id,
                "project": project.id,
                "modules": modules,
            },
        )
        cfg = RunConfig(
            target=target,
            modules=modules,
            provider=provider,
            judge=judge,
            project_id=project.id,
            mfa_codes=data.mfa_codes,
        )
        if target.kind == TargetKind.MCP:
            task = asyncio.create_task(
                mcp.run_mcp(
                    hub,
                    store,
                    keys,
                    target,
                    modules,
                    project_id=project.id,
                    mfa_codes=data.mfa_codes,
                    run_id=run_id,
                )
            )
        else:
            task = asyncio.create_task(run_target(hub, store, keys, cfg, run_id=run_id))
        _track(run_id, task)
        return {"run_id": run_id}

    @app.post("/runs/{run_id}/cancel", dependencies=protected, status_code=202)
    async def cancel_run(run_id: str) -> dict:
        task = tasks.get(run_id)
        if not task:
            raise HTTPException(404, "Kein laufender Lauf mit dieser ID")
        task.cancel()
        store.audit("run.cancelled", {"id": run_id})
        return {"ok": True}

    # Externe Scanner -------------------------------------------------------
    bridge = scanners.Bridge()

    def _start_scanner(data: RunIn, target, project_id: str, base_url: str) -> dict:
        assert data.scanner
        if target.kind == TargetKind.MCP:
            raise HTTPException(
                422,
                "garak und Promptfoo testen Chat-Ziele. Für ein Tool den Typ „Ein Tool als Agent angreifen“ wählen",
            )
        provider = store.get_provider(target.provider_id) if target.provider_id else None
        if target.kind == TargetKind.MODEL and not provider:
            raise HTTPException(422, "Für dieses Ziel ist kein Modell ausgewählt")
        convo = Conversations(
            RunConfig(target=target, modules=[], provider=provider, mfa_codes=data.mfa_codes), keys
        )
        idx = 0 if target.accounts else -1

        async def reply(message: str) -> str:
            text, _ = await convo.reply(idx, [{"role": "user", "content": message}])
            return text

        run_id = uuid.uuid4().hex[:12]
        store.audit(
            "run.started",
            {"id": run_id, "kind": data.scanner.tool, "target": target.id, "project": project_id},
        )

        async def go() -> None:
            try:
                await scanners.run_scanner(
                    hub,
                    store,
                    bridge,
                    reply,
                    scanners.ScannerConfig(**data.scanner.model_dump()),
                    engine_url=base_url,
                    label=target.describe(),
                    target_id=target.id,
                    project_id=project_id,
                    run_id=run_id,
                )
            finally:
                await convo.close()

        _track(run_id, asyncio.create_task(go()))
        return {"run_id": run_id}

    @app.post("/bridge/{key}")
    async def bridge_chat(key: str, request: Request) -> dict:
        """Brücke für externe Scanner, nur während ihres Laufs gültig (geheimer Schlüssel im Pfad)."""
        reply = bridge.routes.get(key)
        if not reply:
            raise HTTPException(404, "Unbekannte Brücke")
        try:
            body = await request.json()
        except ValueError as exc:
            raise HTTPException(422, "JSON erwartet") from exc
        message = (
            str(body.get("message") or body.get("prompt") or "") if isinstance(body, dict) else ""
        )
        try:
            return {"reply": await reply(message)}
        except Exception as exc:  # noqa: BLE001
            # 5xx ließe garak endlos wiederholen; Fehler zählen und leer antworten
            bridge.failed(key, providers.describe_error(exc))
            return {"reply": ""}

    @app.get("/scanners/check", dependencies=protected)
    async def check_scanner(tool: str, cmd: str = "") -> dict:
        try:
            return await scanners.check(tool, cmd)
        except scanners.ScannerError as exc:
            raise HTTPException(422, str(exc)) from exc

    # Berichte --------------------------------------------------------------
    report_key = pysecrets.token_bytes(32)
    reports_dir = Path(reports_dir) if reports_dir else None

    def _track(run_id: str, task: asyncio.Task) -> None:
        tasks[run_id] = task

        def done(_: asyncio.Task) -> None:
            tasks.pop(run_id, None)
            log = report.collect_log(hub.history(run_id))
            if log:
                store.save_run_log(run_id, log)

        task.add_done_callback(done)

    def _report_html(run_id: str) -> tuple[str, str]:
        run = store.get_run(run_id)
        if not run:
            raise HTTPException(404, "Lauf nicht gefunden")
        log = store.get_run_log(run_id) or report.collect_log(hub.history(run_id))
        project = store.get_project(run.project_id) if run.project_id else None
        text = report.render(
            run, project, log, store.list_skills(), generated_by=f"KI-Agent-Checker {__version__}"
        )
        stem = re.sub(r"[^\w.-]+", "-", run.target.split("(")[0]).strip("-")[:50] or "Ziel"
        name = f"Sicherheitsbericht-{stem}-{run.started_at.astimezone():%Y-%m-%d-%H%M}.html"
        return text, name

    def _sign(name: str) -> str:
        return hmac.new(report_key, name.encode(), hashlib.sha256).hexdigest()[:32]

    @app.get("/runs/{run_id}/report", dependencies=protected, response_class=HTMLResponse)
    def get_report(run_id: str) -> HTMLResponse:
        text, name = _report_html(run_id)
        return HTMLResponse(text, headers={"Content-Disposition": f'inline; filename="{name}"'})

    @app.post("/runs/{run_id}/report", dependencies=protected)
    def save_report(run_id: str) -> dict:
        """Speichert den Bericht (Standard: Downloads) und gibt einen Link zum Öffnen im Browser."""
        text, name = _report_html(run_id)
        folder = reports_dir or next(
            (p for p in (Path.home() / "Downloads", Path.home() / "Download") if p.is_dir()),
            Path.home(),
        )
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / name
        path.write_text(text, encoding="utf-8")
        store.audit("report.saved", {"run": run_id, "path": str(path)})
        saved[name] = path
        return {"path": str(path), "url": f"/reports/{name}?t={_sign(name)}"}

    saved: dict[str, Path] = {}

    @app.get("/reports/{name}", response_class=HTMLResponse)
    def open_report(name: str, t: str = Query("")) -> HTMLResponse:
        """Ohne Engine-Token, damit der Standardbrowser den Bericht öffnen kann; geschützt durch die Signatur."""
        path = saved.get(name)
        if not path or not hmac.compare_digest(t, _sign(name)) or not path.is_file():
            raise HTTPException(404, "Bericht nicht gefunden")
        return HTMLResponse(path.read_text(encoding="utf-8"))

    # Skills ---------------------------------------------------------------
    def _refresh_skills() -> None:
        attack_lib.register([m for s in store.list_skills() if (m := skills.to_module(s))])

    @app.get("/skills", dependencies=protected)
    def list_skills() -> list[dict]:
        return [skills.out(s) for s in store.list_skills()]

    @app.post("/skills/import", dependencies=protected)
    async def import_skills(data: SkillImportIn) -> dict:
        try:
            if data.source == "folder":
                if not data.path:
                    raise ValueError("Bitte einen Ordner angeben")
                found = await asyncio.to_thread(
                    skills.load_dir, Path(data.path), only_ai=data.only_ai
                )
            else:
                found = await skills.fetch_github(data.repo, data.ref, only_ai=data.only_ai)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except httpx.HTTPError as exc:
            raise HTTPException(
                502, f"Download fehlgeschlagen: {providers.describe_error(exc)}"
            ) from exc
        if not found:
            raise HTTPException(422, "Keine passenden SKILL.md-Dateien gefunden")
        store.save_skills(found)
        _refresh_skills()
        store.audit(
            "skills.imported",
            {
                "source": data.path if data.source == "folder" else f"{data.repo}@{data.ref}",
                "count": len(found),
            },
        )
        return {
            "imported": len(found),
            "with_attacks": sum(1 for s in found if s.payload_count),
            "attacks": sum(s.payload_count for s in found),
        }

    @app.delete("/skills/{name}", dependencies=protected, status_code=204)
    def delete_skill(name: str) -> None:
        if not store.delete_skill(name):
            raise HTTPException(404, "Skill nicht gefunden")
        _refresh_skills()

    @app.get("/attack-modules", dependencies=protected)
    def attack_modules() -> list[dict]:
        return [
            {
                "key": m.key,
                "label": m.label,
                "owasp": m.owasp,
                "severity": m.severity.value,
                "attacks": len(m.attacks),
                "needs_accounts": m.needs_accounts,
                "title": m.title,
                "target": "agent",
                "skill": m.key.startswith("skill:"),
            }
            for m in attack_lib.all_modules()
        ] + [
            {
                "key": m.key,
                "label": m.label,
                "owasp": m.owasp,
                "severity": m.severity.value,
                "attacks": 0,
                "needs_accounts": 0,
                "title": m.title,
                "target": "mcp",
                "calls_tools": m.calls_tools,
            }
            for m in mcp.MCP_LIBRARY
        ]

    @app.get("/audit", dependencies=protected)
    def audit() -> list[dict]:
        return store.audit_entries()

    # Live-Events ---------------------------------------------------------
    @app.websocket("/ws")
    async def ws(
        websocket: WebSocket, token_param: str | None = Query(None, alias="token")
    ) -> None:
        try:
            check(token_param)
        except HTTPException:
            await websocket.close(code=4401)
            return
        await websocket.accept()
        queue = hub.subscribe()
        try:
            while True:
                event = await queue.get()
                await websocket.send_json(event)
        except WebSocketDisconnect:
            pass
        finally:
            hub.unsubscribe(queue)

    return app

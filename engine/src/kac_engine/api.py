"""HTTP- und WebSocket-API der Engine."""

from __future__ import annotations

import asyncio
import hmac
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import __version__, providers
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
from .store import Store

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


class DemoRunIn(BaseModel):
    project_id: str | None = None
    delay: float = 0.6


def create_app(
    *,
    token: str | None = None,
    db_path: Path | str = ":memory:",
    secrets: SecretStore | None = None,
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
    tasks: set[asyncio.Task] = set()
    app.state.store, app.state.hub, app.state.keys = store, hub, keys

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
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        return {"run_id": run_id}

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

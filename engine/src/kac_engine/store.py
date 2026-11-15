"""SQLite-Speicher für Provider, Projekte und Testläufe."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .models import (
    SELF_HOSTED_KINDS,
    Finding,
    Project,
    ProjectIn,
    Provider,
    ProviderIn,
    ProviderKind,
    RunSummary,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    model TEXT NOT NULL,
    base_url TEXT,
    has_api_key INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    scope TEXT NOT NULL,
    authorized_by TEXT NOT NULL,
    authorized_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    score INTEGER,
    findings TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""


def _now() -> datetime:
    return datetime.now(UTC)


class Store:
    def __init__(self, path: Path | str = ":memory:") -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)
        self._db.commit()

    # Audit-Log -----------------------------------------------------------
    def audit(self, action: str, detail: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO audit_log (at, action, detail) VALUES (?, ?, ?)",
                (_now().isoformat(), action, json.dumps(detail, ensure_ascii=False)),
            )
            self._db.commit()

    def audit_entries(self) -> list[dict]:
        rows = self._db.execute("SELECT at, action, detail FROM audit_log ORDER BY id").fetchall()
        return [
            {"at": r["at"], "action": r["action"], "detail": json.loads(r["detail"])} for r in rows
        ]

    # Provider ------------------------------------------------------------
    def add_provider(self, data: ProviderIn, has_api_key: bool) -> Provider:
        provider = Provider(
            id=uuid.uuid4().hex[:12],
            name=data.name,
            kind=data.kind,
            model=data.model,
            base_url=str(data.base_url).rstrip("/") if data.base_url else None,
            has_api_key=has_api_key,
            self_hosted=data.kind in SELF_HOSTED_KINDS,
            created_at=_now(),
        )
        with self._lock:
            self._db.execute(
                "INSERT INTO providers VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    provider.id,
                    provider.name,
                    provider.kind.value,
                    provider.model,
                    provider.base_url,
                    int(has_api_key),
                    provider.created_at.isoformat(),
                ),
            )
            self._db.commit()
        return provider

    @staticmethod
    def _provider(row: sqlite3.Row) -> Provider:
        kind = ProviderKind(row["kind"])
        return Provider(
            id=row["id"],
            name=row["name"],
            kind=kind,
            model=row["model"],
            base_url=row["base_url"],
            has_api_key=bool(row["has_api_key"]),
            self_hosted=kind in SELF_HOSTED_KINDS,
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def list_providers(self) -> list[Provider]:
        rows = self._db.execute("SELECT * FROM providers ORDER BY created_at").fetchall()
        return [self._provider(r) for r in rows]

    def get_provider(self, provider_id: str) -> Provider | None:
        row = self._db.execute("SELECT * FROM providers WHERE id = ?", (provider_id,)).fetchone()
        return self._provider(row) if row else None

    def delete_provider(self, provider_id: str) -> bool:
        with self._lock:
            cur = self._db.execute("DELETE FROM providers WHERE id = ?", (provider_id,))
            self._db.commit()
        return cur.rowcount > 0

    # Projekte ------------------------------------------------------------
    def add_project(self, data: ProjectIn) -> Project:
        now = _now()
        project = Project(
            id=uuid.uuid4().hex[:12],
            name=data.name,
            description=data.description,
            scope=data.scope,
            authorized_by=data.authorized_by,
            authorized_at=now,
            created_at=now,
        )
        with self._lock:
            self._db.execute(
                "INSERT INTO projects VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    project.id,
                    project.name,
                    project.description,
                    json.dumps(project.scope, ensure_ascii=False),
                    project.authorized_by,
                    project.authorized_at.isoformat(),
                    project.created_at.isoformat(),
                ),
            )
            self._db.commit()
        return project

    def list_projects(self) -> list[Project]:
        rows = self._db.execute("SELECT * FROM projects ORDER BY created_at").fetchall()
        return [
            Project(
                id=r["id"],
                name=r["name"],
                description=r["description"],
                scope=json.loads(r["scope"]),
                authorized_by=r["authorized_by"],
                authorized_at=datetime.fromisoformat(r["authorized_at"]),
                created_at=datetime.fromisoformat(r["created_at"]),
            )
            for r in rows
        ]

    # Testläufe -----------------------------------------------------------
    def start_run(self, run_id: str, project_id: str | None, target: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO runs (id, project_id, target, started_at, status) VALUES (?, ?, ?, ?, ?)",
                (run_id, project_id, target, _now().isoformat(), "running"),
            )
            self._db.commit()

    def finish_run(self, run_id: str, score: int, findings: list[Finding], status: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE runs SET finished_at = ?, status = ?, score = ?, findings = ? WHERE id = ?",
                (
                    _now().isoformat(),
                    status,
                    score,
                    json.dumps([f.model_dump(mode="json") for f in findings], ensure_ascii=False),
                    run_id,
                ),
            )
            self._db.commit()

    def list_runs(self) -> list[RunSummary]:
        rows = self._db.execute("SELECT * FROM runs ORDER BY started_at").fetchall()
        return [
            RunSummary(
                id=r["id"],
                project_id=r["project_id"],
                target=r["target"],
                started_at=datetime.fromisoformat(r["started_at"]),
                finished_at=datetime.fromisoformat(r["finished_at"]) if r["finished_at"] else None,
                status=r["status"],
                score=r["score"],
                findings=[Finding(**f) for f in json.loads(r["findings"])],
            )
            for r in rows
        ]

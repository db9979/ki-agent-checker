"""Datenmodelle der Engine-API."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, HttpUrl


class ProviderKind(StrEnum):
    """Unterstützte Modell-Anbieter. Selbst gehostete Modelle zuerst."""

    OLLAMA = "ollama"
    OPENAI_COMPATIBLE = "openai_compatible"  # vLLM, LM Studio, llama.cpp, LocalAI
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    MISTRAL = "mistral"


SELF_HOSTED_KINDS = {ProviderKind.OLLAMA, ProviderKind.OPENAI_COMPATIBLE}


class ProviderIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    kind: ProviderKind
    model: str = Field(min_length=1, max_length=200)
    base_url: HttpUrl | None = None
    api_key: str | None = Field(default=None, description="Wird im Schlüsselbund gespeichert")


class Provider(BaseModel):
    id: str
    name: str
    kind: ProviderKind
    model: str
    base_url: str | None = None
    has_api_key: bool = False
    self_hosted: bool = False
    created_at: datetime


class ConnectionResult(BaseModel):
    ok: bool
    latency_ms: int | None = None
    reply: str | None = None
    error: str | None = None


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    scope: list[str] = Field(
        default_factory=list, description="Erlaubte Ziele, z. B. URLs oder Agent-Namen"
    )
    authorization_confirmed: bool = Field(
        description="Bestätigung, dass für alle Ziele im Scope eine Testberechtigung vorliegt"
    )
    authorized_by: str = Field(min_length=1, max_length=120)


class Project(BaseModel):
    id: str
    name: str
    description: str
    scope: list[str]
    authorized_by: str
    authorized_at: datetime
    created_at: datetime


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    id: str
    module: str
    title: str
    severity: Severity
    owasp: str
    atlas: str | None = None
    success_rate: float = Field(ge=0, le=1)
    evidence: str
    remediation: str


class RunSummary(BaseModel):
    id: str
    project_id: str | None
    target: str
    started_at: datetime
    finished_at: datetime | None = None
    status: str
    score: int | None = None
    findings: list[Finding] = Field(default_factory=list)

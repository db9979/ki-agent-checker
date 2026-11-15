"""Testziele: was angegriffen wird und wie die Engine sich dort anmeldet.

Drei Arten von Zielen:

* ``model``: ein angebundenes Modell mit eigenem System-Prompt und Honeypot-Tools.
  Damit lässt sich ein Agent-Entwurf testen, bevor er live geht. Die Engine
  pflanzt ein Canary-Token in den System-Prompt.
* ``openai_endpoint``: ein fertiger Agent, der eine OpenAI-kompatible
  Chat-Schnittstelle anbietet (viele Agent-Frameworks können das).
* ``http``: ein beliebiger HTTP-Endpunkt mit JSON, z. B. das Backend eines
  Chat-Widgets. Anfrage und Antwortfeld werden per Vorlage beschrieben.
* ``mcp``: ein MCP-Server (Streamable HTTP), der einem Agenten Tools bereitstellt.
  Er wird mit eigenen Prüfungen auditiert (siehe ``mcp.py``).

Für Ziele hinter einer Anmeldung gibt es API-Schlüssel, eigene Header,
Basic Auth und einen Login-Aufruf (mit TOTP für 2FA). Pro Ziel lassen sich
mehrere Testkonten mit Rollen anlegen, um Zugriffe auf fremde Daten zu prüfen.
Passwörter, Tokens und TOTP-Geheimnisse liegen im Schlüsselbund.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import time
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import BaseModel, Field

SECRET_FIELDS = ("password", "token", "totp_secret")


class TargetKind(StrEnum):
    MODEL = "model"
    OPENAI_ENDPOINT = "openai_endpoint"
    HTTP = "http"
    MCP = "mcp"
    MCP_TOOL = (
        "mcp_tool"  # ein einzelnes Tool eines MCP-Servers wird wie ein Chat-Agent angegriffen
    )


class AuthKind(StrEnum):
    NONE = "none"
    BEARER = "bearer"  # Token des Kontos als "Authorization: Bearer …"
    HEADER = "header"  # Token des Kontos in einem eigenen Header
    BASIC = "basic"  # Benutzername und Passwort
    LOGIN = "login"  # Login-Aufruf, Token oder Cookie aus der Antwort


class AuthConfig(BaseModel):
    kind: AuthKind = AuthKind.NONE
    header_name: str = "X-API-Key"
    login_url: str | None = None
    login_body: str = '{"username": "{{username}}", "password": "{{password}}"}'
    token_path: str | None = Field(
        default="token", description="Pfad zum Token in der Login-Antwort; leer = Cookie-Sitzung"
    )
    token_header: str = "Authorization"
    token_prefix: str = "Bearer "
    # Zweiter Faktor, für jede Anmeldeart
    mfa: Literal["none", "totp", "manual"] = Field(
        default="none",
        description="totp: Code aus dem TOTP-Geheimnis des Kontos; manual: Code wird beim Start eingegeben",
    )
    mfa_header: str | None = Field(
        default=None, description="Code zusätzlich als Header senden, z. B. X-OTP"
    )
    mfa_url: str | None = Field(
        default=None, description="Zweiter Login-Schritt, an den der Code geht"
    )
    mfa_body: str = '{"code": "{{code}}"}'
    mfa_challenge_path: str | None = Field(
        default=None, description="Pfad zur Challenge-ID in der Antwort des ersten Schritts"
    )


class AccountIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    role: str = "Nutzer"
    username: str | None = None
    password: str | None = None
    token: str | None = None
    totp_secret: str | None = None
    identifier: str | None = Field(
        default=None, description="Öffentliche Kennung, z. B. E-Mail oder Kundennummer"
    )
    marker: str | None = Field(
        default=None,
        description="Private Angabe dieses Kontos, die kein anderes Konto sehen darf",
    )


class Account(BaseModel):
    name: str
    role: str
    username: str | None = None
    identifier: str | None = None
    marker: str | None = None
    has_password: bool = False
    has_token: bool = False
    has_totp: bool = False


class TargetIn(BaseModel):
    project_id: str
    name: str = Field(min_length=1, max_length=120)
    kind: TargetKind
    # model
    provider_id: str | None = None
    system_prompt: str = ""
    honeypot_tools: bool = True
    # openai_endpoint / http
    url: str | None = None
    model: str | None = None
    method: Literal["POST", "PUT", "GET"] = "POST"
    request_template: str = '{"message": "{{message}}"}'
    response_path: str = "reply"
    verify_tls: bool = True
    auth: AuthConfig = Field(default_factory=AuthConfig)
    accounts: list[AccountIn] = Field(default_factory=list)
    leak_markers: list[str] = Field(
        default_factory=list,
        description="Texte aus dem System-Prompt, die nie in einer Antwort auftauchen dürfen",
    )
    delay: float = Field(default=0.5, ge=0, le=30, description="Pause zwischen Anfragen")
    mcp_tool: str | None = Field(default=None, description="Tool, das als Chat-Ziel dient")
    mcp_arg: str | None = Field(
        default=None, description="Parameter für die Nachricht; leer = erster Text-Parameter"
    )
    mcp_tool_calls: Literal["none", "readonly", "all"] = Field(
        default="readonly",
        description="Welche Tools eines MCP-Servers beim Audit aufgerufen werden dürfen",
    )


class Target(BaseModel):
    id: str
    project_id: str
    name: str
    kind: TargetKind
    provider_id: str | None = None
    system_prompt: str = ""
    honeypot_tools: bool = True
    url: str | None = None
    model: str | None = None
    method: Literal["POST", "PUT", "GET"] = "POST"
    request_template: str = '{"message": "{{message}}"}'
    response_path: str = "reply"
    verify_tls: bool = True
    auth: AuthConfig = Field(default_factory=AuthConfig)
    accounts: list[Account] = Field(default_factory=list)
    leak_markers: list[str] = Field(default_factory=list)
    delay: float = 0.5
    mcp_tool_calls: Literal["none", "readonly", "all"] = "readonly"
    mcp_tool: str | None = None
    mcp_arg: str | None = None
    created_at: datetime

    def describe(self) -> str:
        where = self.url or "eigenes Modell"
        return f"{self.name} ({where})"


def secret_key(target_id: str, account: str, field: str) -> str:
    return f"target:{target_id}:{account}:{field}"


# ---------------------------------------------------------------------------
# Scope


def in_scope(url: str, scope: list[str]) -> bool:
    """Prüft, ob eine URL zu einem Eintrag im Projekt-Scope gehört.

    Einträge dürfen volle URLs (Präfix-Vergleich) oder Hostnamen sein,
    ``*.example.com`` erlaubt Subdomains.
    """
    host = (urlparse(url).hostname or "").lower()
    for entry in scope:
        entry = entry.strip()
        if not entry:
            continue
        if "://" in entry:
            if url.startswith(entry.rstrip("/")):
                return True
            continue
        entry = entry.lower().split("/")[0].split(":")[0]
        if entry.startswith("*.") and (host == entry[2:] or host.endswith(entry[1:])):
            return True
        if host == entry:
            return True
    return False


# ---------------------------------------------------------------------------
# Hilfen


def totp(secret: str, at: float | None = None, digits: int = 6, step: int = 30) -> str:
    """TOTP nach RFC 6238 (wie Google Authenticator)."""
    key = base64.b32decode(secret.replace(" ", "").upper() + "=" * (-len(secret) % 8))
    counter = int((at if at is not None else time.time()) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)


def render(template: str, values: dict[str, Any]) -> str:
    """Setzt ``{{name}}`` ein. Strings werden JSON-sicher maskiert,
    Listen und Objekte (z. B. ``{{messages}}``) als JSON eingefügt."""

    def repl(match: re.Match) -> str:
        value = values.get(match.group(1), "")
        if isinstance(value, str):
            return json.dumps(value, ensure_ascii=False)[1:-1]
        return json.dumps(value, ensure_ascii=False)

    return re.sub(r"\{\{\s*(\w+)\s*\}\}", repl, template)


def dig(data: Any, path: str | None) -> Any:
    """Liest ``a.b.0.c`` aus verschachteltem JSON."""
    if not path:
        return data
    for part in path.split("."):
        if isinstance(data, list):
            try:
                data = data[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(data, dict):
            data = data.get(part)
        else:
            return None
    return data


class TargetError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Sitzung gegen ein HTTP-Ziel


class HttpSession:
    """Hält Verbindung und Anmeldung für ein Testkonto."""

    transport: httpx.AsyncBaseTransport | None = None  # für Tests austauschbar

    def __init__(self, target: Target, account: Account | None, secrets: dict[str, str | None]):
        self.target = target
        self.account = account
        self.secrets = secrets
        self.client = httpx.AsyncClient(
            verify=target.verify_tls, timeout=90, follow_redirects=True, transport=self.transport
        )
        self.headers: dict[str, str] = {}
        self.logged_in = False

    async def close(self) -> None:
        await self.client.aclose()

    def _code(self) -> str:
        """Aktueller 2FA-Code: aus dem TOTP-Geheimnis berechnet oder von Hand eingegeben."""
        mode = self.target.auth.mfa
        who = f" für {self.account.name}" if self.account else ""
        if mode == "totp":
            secret = self.secrets.get("totp_secret")
            if not secret:
                raise TargetError(f"TOTP-Geheimnis{who} fehlt")
            return totp(secret)
        if mode == "manual":
            code = (self.secrets.get("mfa_code") or "").strip()
            if not code:
                raise TargetError(f"2FA-Code{who} fehlt, bitte beim Start eingeben")
            return code
        # Ältere Ziele: TOTP-Geheimnis ohne ausdrücklichen Modus
        secret = self.secrets.get("totp_secret")
        return totp(secret) if secret else ""

    def _take_token(self, resp: httpx.Response) -> None:
        auth = self.target.auth
        try:
            value = dig(resp.json(), auth.token_path)
        except ValueError as exc:
            raise TargetError("Login-Antwort ist kein JSON") from exc
        if not value:
            raise TargetError(f"Kein Token unter „{auth.token_path}“ in der Login-Antwort")
        self.headers[auth.token_header] = f"{auth.token_prefix}{value}"

    async def login(self) -> None:
        auth = self.target.auth
        token = self.secrets.get("token")
        username = self.account.username if self.account else None
        password = self.secrets.get("password")
        code = self._code()
        values = {
            "username": username or "",
            "password": password or "",
            "totp": code,
            "code": code,
        }
        if code and auth.mfa_header:
            self.headers[auth.mfa_header] = code
        if auth.kind == AuthKind.BEARER:
            if not token:
                raise TargetError("Für dieses Konto ist kein Token hinterlegt")
            self.headers["Authorization"] = f"Bearer {token}"
        elif auth.kind == AuthKind.HEADER:
            if not token:
                raise TargetError("Für dieses Konto ist kein Token hinterlegt")
            self.headers[auth.header_name] = token
        elif auth.kind == AuthKind.BASIC:
            raw = f"{username or ''}:{password or ''}".encode()
            self.headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        elif auth.kind == AuthKind.LOGIN:
            if not auth.login_url:
                raise TargetError("Login-Adresse fehlt")
            resp = await self.client.post(
                auth.login_url,
                content=render(auth.login_body, values),
                headers={"Content-Type": "application/json", **self.headers},
            )
            if resp.status_code >= 400:
                raise TargetError(f"Anmeldung fehlgeschlagen: HTTP {resp.status_code}")
            if auth.mfa_url:
                await self._second_step(resp, values)
            elif auth.token_path:
                self._take_token(resp)
            # sonst: Sitzungs-Cookie, das der Client automatisch mitschickt
        if auth.kind != AuthKind.LOGIN and auth.mfa_url:
            await self._second_step(None, values)
        self.logged_in = True

    async def _second_step(self, first: httpx.Response | None, values: dict[str, str]) -> None:
        """Zweiter Login-Schritt: Code (und ggf. Challenge aus Schritt 1) an die 2FA-Adresse."""
        auth = self.target.auth
        if not values["code"]:
            raise TargetError("Für den zweiten Login-Schritt ist kein 2FA-Code eingerichtet")
        challenge = ""
        if first is not None and auth.mfa_challenge_path:
            try:
                challenge = str(dig(first.json(), auth.mfa_challenge_path) or "")
            except ValueError:
                challenge = ""
            if not challenge:
                raise TargetError(
                    f"Keine Challenge unter „{auth.mfa_challenge_path}“ in der Login-Antwort"
                )
        resp = await self.client.post(
            auth.mfa_url or "",
            content=render(auth.mfa_body, {**values, "challenge": challenge}),
            headers={"Content-Type": "application/json", **self.headers},
        )
        if resp.status_code >= 400:
            raise TargetError(f"2FA-Schritt fehlgeschlagen: HTTP {resp.status_code}")
        if auth.token_path:
            self._take_token(resp)

    async def send(self, messages: list[dict]) -> str:
        if not self.logged_in:
            await self.login()
        for attempt in range(2):
            resp = await self._post(messages)
            if resp.status_code == 401 and attempt == 0 and self.target.auth.kind == AuthKind.LOGIN:
                await self.login()  # Sitzung abgelaufen: einmal neu anmelden
                continue
            break
        if resp.status_code >= 400:
            hint = await self._hint(resp.status_code)
            raise TargetError(
                f"Ziel antwortet mit HTTP {resp.status_code}: {resp.text[:200]}"
                + (f". {hint}" if hint else "")
            )
        return self._extract(resp)

    async def _hint(self, status: int) -> str:
        """Bei 404/405 nach passenden Endpunkten suchen (OpenAPI-Beschreibung des Servers)."""
        if status == 401 or status == 403:
            return "Tipp: Anmeldung prüfen (Anmeldeart, Benutzername, Passwort oder Token)"
        if status not in (404, 405):
            return ""
        base = self.target.url or ""
        found: list[str] = []
        for doc in ("/openapi.json", "/api/openapi.json", "/swagger.json", "/v1/openapi.json"):
            try:
                resp = await self.client.get(urljoin(base, doc), headers=self.headers, timeout=10)
                spec = resp.json() if resp.status_code == 200 else None
            except (httpx.HTTPError, ValueError):
                spec = None
            if isinstance(spec, dict) and isinstance(spec.get("paths"), dict):
                for path, ops in spec["paths"].items():
                    if isinstance(ops, dict) and ("post" in ops or "put" in ops):
                        found.append(path)
                break
        what = (
            "die Methode passt nicht zur Adresse"
            if status == 405
            else "unter dieser Adresse gibt es keinen Endpunkt"
        )
        if found:
            likely = sorted(
                found,
                key=lambda p: (
                    not re.search(
                        r"chat|message|ask|query|complet|prompt|talk|speak|conversation", p, re.I
                    )
                ),
            )[:6]
            return f"Tipp: {what}. Der Server bietet u. a. diese Endpunkte an: {', '.join(likely)}"
        return (
            f"Tipp: {what}. Die Adresse muss auf den Chat-Endpunkt zeigen, z. B. …/api/chat statt der Startseite, "
            "und die Methode (meist POST) muss stimmen"
        )

    async def _post(self, messages: list[dict]) -> httpx.Response:
        t = self.target
        url = t.url or ""
        if t.kind == TargetKind.OPENAI_ENDPOINT:
            if not url.rstrip("/").endswith("/chat/completions"):
                url = url.rstrip("/") + "/chat/completions"
            payload = {"model": t.model or "default", "messages": messages}
            return await self.client.post(url, json=payload, headers=self.headers)
        last = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        if t.method == "GET":
            return await self.client.get(url, params={"message": last}, headers=self.headers)
        body = render(t.request_template, {"message": last, "messages": messages})
        headers = {"Content-Type": "application/json", **self.headers}
        return await self.client.request(t.method, url, content=body, headers=headers)

    def _extract(self, resp: httpx.Response) -> str:
        if self.target.kind == TargetKind.OPENAI_ENDPOINT:
            path = "choices.0.message.content"
        else:
            path = self.target.response_path
        try:
            data = resp.json()
        except ValueError:
            return resp.text
        value = dig(data, path)
        if value is None:
            raise TargetError(f"Kein Antworttext unter „{path}“ gefunden")
        return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)

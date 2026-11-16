"""OAuth 2.1 mit PKCE für MCP-Server und HTTP-Ziele (MCP-Autorisierung, RFC 9728/8414/7591).

Ablauf: Die App fragt den Server ohne Token an und liest aus ``WWW-Authenticate``
(oder ``/.well-known/oauth-protected-resource``) den Autorisierungsserver. Dessen
Metadaten liefern die Endpunkte. Ohne eigene Client-ID registriert sich die App
selbst (Dynamic Client Registration). Der Nutzer meldet sich im Browser an, der
Autorisierungsserver leitet auf ``/oauth/callback`` der Engine zurück, und die Engine
tauscht den Code gegen Tokens. Access- und Refresh-Token liegen im Schlüsselbund.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urljoin, urlparse

import httpx

from . import __version__
from .keystore import SecretStore
from .targets import Target, TargetError, secret_key

transport: httpx.AsyncBaseTransport | None = None  # für Tests austauschbar
PENDING_TTL = 600


@dataclass
class Pending:
    target_id: str
    account: str
    token_endpoint: str
    client_id: str
    client_secret: str | None
    verifier: str
    redirect_uri: str
    resource: str
    created: float


pending: dict[str, Pending] = {}


def _client(target: Target) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=20, verify=target.verify_tls, follow_redirects=True, transport=transport
    )


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


async def _json(client: httpx.AsyncClient, url: str) -> dict | None:
    try:
        resp = await client.get(url, headers={"Accept": "application/json"})
        data = resp.json() if resp.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        return None
    return data if isinstance(data, dict) else None


async def discover(client: httpx.AsyncClient, url: str) -> tuple[dict, dict]:
    """Liefert (Metadaten der geschützten Ressource, Metadaten des Autorisierungsservers)."""
    resource_meta: dict | None = None
    try:
        resp = await client.post(
            url,
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            headers={"Accept": "application/json, text/event-stream"},
        )
        header = resp.headers.get("www-authenticate", "")
        if m := re.search(r'resource_metadata="([^"]+)"', header):
            resource_meta = await _json(client, m.group(1))
    except httpx.HTTPError as exc:
        raise TargetError(f"Server nicht erreichbar: {exc.__class__.__name__}") from exc
    if not resource_meta:
        path = urlparse(url).path.rstrip("/")
        for candidate in (
            f"{_origin(url)}/.well-known/oauth-protected-resource{path}",
            f"{_origin(url)}/.well-known/oauth-protected-resource",
        ):
            if resource_meta := await _json(client, candidate):
                break
    issuer = ((resource_meta or {}).get("authorization_servers") or [_origin(url)])[0]
    as_meta = None
    issuer_path = urlparse(issuer).path.rstrip("/")
    for candidate in (
        f"{_origin(issuer)}/.well-known/oauth-authorization-server{issuer_path}",
        f"{_origin(issuer)}/.well-known/openid-configuration{issuer_path}",
        urljoin(issuer.rstrip("/") + "/", ".well-known/openid-configuration"),
    ):
        if as_meta := await _json(client, candidate):
            break
    if not as_meta or "authorization_endpoint" not in as_meta or "token_endpoint" not in as_meta:
        raise TargetError(
            "Kein OAuth-Autorisierungsserver gefunden (weder WWW-Authenticate noch .well-known)"
        )
    return resource_meta or {}, as_meta


async def start(target: Target, keys: SecretStore, redirect_uri: str) -> str:
    """Bereitet die Anmeldung vor und gibt die Adresse für den Browser zurück."""
    if not target.url:
        raise TargetError("Ziel hat keine Adresse")
    account = target.accounts[0].name if target.accounts else ""
    async with _client(target) as client:
        resource_meta, as_meta = await discover(client, target.url)
        client_id = target.auth.oauth_client_id
        client_secret = None
        if not client_id:
            reg = as_meta.get("registration_endpoint")
            if not reg:
                raise TargetError(
                    "Der Server erlaubt keine automatische Registrierung. Bitte eine Client-ID eintragen"
                )
            resp = await client.post(
                reg,
                json={
                    "client_name": f"KI-Agent-Checker {__version__}",
                    "redirect_uris": [redirect_uri],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                },
            )
            if resp.status_code >= 400:
                raise TargetError(
                    f"Registrierung abgelehnt: HTTP {resp.status_code} {resp.text[:200]}"
                )
            data = resp.json()
            client_id, client_secret = data["client_id"], data.get("client_secret")
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    state = secrets.token_urlsafe(24)
    scope = target.auth.oauth_scope or " ".join(
        resource_meta.get("scopes_supported") or as_meta.get("scopes_supported") or []
    )
    resource = resource_meta.get("resource") or target.url
    _expire()
    pending[state] = Pending(
        target.id,
        account,
        as_meta["token_endpoint"],
        client_id,
        client_secret,
        verifier,
        redirect_uri,
        resource,
        time.time(),
    )
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge.decode(),
        "code_challenge_method": "S256",
        "state": state,
        "resource": resource,
    }
    if scope:
        params["scope"] = scope
    return f"{as_meta['authorization_endpoint']}?{urlencode(params)}"


def _expire() -> None:
    now = time.time()
    for k in [k for k, p in pending.items() if now - p.created > PENDING_TTL]:
        pending.pop(k, None)


def _save(keys: SecretStore, target_id: str, account: str, data: dict, meta: dict) -> None:
    keys.set(secret_key(target_id, account, "token"), data["access_token"])
    if data.get("refresh_token"):
        keys.set(secret_key(target_id, account, "refresh_token"), data["refresh_token"])
    expires = time.time() + float(data.get("expires_in") or 3600)
    keys.set(secret_key(target_id, account, "oauth"), json.dumps({**meta, "expires": expires}))


async def finish(target: Target, keys: SecretStore, state: str, code: str) -> str:
    """Tauscht den Code gegen Tokens. Gibt den Kontonamen zurück."""
    p = pending.pop(state, None)
    if not p or p.target_id != target.id:
        raise TargetError("Anmeldung abgelaufen oder unbekannt, bitte erneut starten")
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": p.redirect_uri,
        "client_id": p.client_id,
        "code_verifier": p.verifier,
        "resource": p.resource,
    }
    if p.client_secret:
        form["client_secret"] = p.client_secret
    async with _client(target) as client:
        resp = await client.post(p.token_endpoint, data=form)
    if resp.status_code >= 400:
        raise TargetError(f"Token-Abruf fehlgeschlagen: HTTP {resp.status_code} {resp.text[:200]}")
    _save(
        keys,
        target.id,
        p.account,
        resp.json(),
        {
            "token_endpoint": p.token_endpoint,
            "client_id": p.client_id,
            "client_secret": p.client_secret,
            "resource": p.resource,
        },
    )
    return p.account


def target_for_state(state: str) -> str | None:
    p = pending.get(state)
    return p.target_id if p else None


async def refresh_if_needed(target: Target, keys: SecretStore, margin: float = 60) -> None:
    """Erneuert das Access-Token vor einem Lauf, wenn es bald abläuft."""
    if target.auth.kind != "oauth":
        return
    for account in target.accounts[:1]:
        raw = keys.get(secret_key(target.id, account.name, "oauth"))
        refresh = keys.get(secret_key(target.id, account.name, "refresh_token"))
        if not raw or not refresh:
            return
        meta = json.loads(raw)
        if meta.get("expires", 0) - margin > time.time():
            return
        form = {
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": meta["client_id"],
            "resource": meta.get("resource") or target.url or "",
        }
        if meta.get("client_secret"):
            form["client_secret"] = meta["client_secret"]
        async with _client(target) as client:
            resp = await client.post(meta["token_endpoint"], data=form)
        if resp.status_code >= 400:
            raise TargetError(
                "OAuth-Anmeldung abgelaufen, bitte im Ziel erneut „Mit OAuth anmelden“"
            )
        _save(keys, target.id, account.name, resp.json(), meta)


def status(target: Target, keys: SecretStore) -> dict:
    if not target.accounts:
        return {"signed_in": False}
    name = target.accounts[0].name
    raw = keys.get(secret_key(target.id, name, "oauth"))
    has_token = bool(keys.get(secret_key(target.id, name, "token")))
    expires = json.loads(raw).get("expires") if raw else None
    return {"signed_in": has_token and bool(raw), "expires": expires}

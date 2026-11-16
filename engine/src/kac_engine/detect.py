"""Erkennt anhand einer Adresse, welche Art von Ziel dahintersteckt.

Reihenfolge: MCP-Server (JSON-RPC ``initialize``), OpenAI-kompatible API (``/models``,
``/chat/completions``), sonst beliebiger JSON-Endpunkt mit üblichen Feldnamen. Es werden
nur harmlose Anfragen geschickt (eine Begrüßung, keine Angriffe).
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from . import __version__
from .mcp import ACCEPT, PROTOCOL_VERSION, _parse
from .targets import dig

PROBE_TEXT = "Hallo, kurzer Verbindungstest. Bitte antworte mit einem Wort."
# Für Tests austauschbar (httpx.MockTransport)
transport: httpx.AsyncBaseTransport | None = None

REQUEST_KEYS = ("message", "prompt", "input", "query", "question", "text", "content")
REPLY_KEYS = (
    "reply",
    "response",
    "answer",
    "output",
    "text",
    "content",
    "message",
    "result",
    "completion",
    "generated_text",
    "data",
)


def _headers(token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


def reply_path(data: Any, prefix: str = "", depth: int = 0) -> str | None:
    """Findet das Feld mit dem Antworttext, bevorzugt nach üblichen Namen."""
    if depth > 5:
        return None
    if isinstance(data, str):
        return prefix or None
    if isinstance(data, list) and data:
        return reply_path(data[0], f"{prefix}.0" if prefix else "0", depth + 1)
    if not isinstance(data, dict):
        return None
    keys = sorted(
        data,
        key=lambda k: REPLY_KEYS.index(k.lower()) if k.lower() in REPLY_KEYS else len(REPLY_KEYS),
    )
    for k in keys:
        if k.lower() not in REPLY_KEYS:
            continue
        found = reply_path(data[k], f"{prefix}.{k}" if prefix else k, depth + 1)
        if found:
            return found
    # Sonst das längste Textfeld auf dieser Ebene, danach verschachtelte Objekte
    best: tuple[int, str] | None = None
    for k, v in data.items():
        path = f"{prefix}.{k}" if prefix else k
        if isinstance(v, str) and k.lower() not in ("id", "model", "role", "status", "type"):
            if not best or len(v) > best[0]:
                best = (len(v), path)
    if best:
        return best[1]
    for k, v in data.items():
        if isinstance(v, (dict, list)):
            found = reply_path(v, f"{prefix}.{k}" if prefix else k, depth + 1)
            if found:
                return found
    return None


async def _try_mcp(client: httpx.AsyncClient, url: str, token: str | None) -> dict | None:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "ki-agent-checker", "version": __version__},
        },
    }
    headers = {"Content-Type": "application/json", "Accept": ACCEPT, **_headers(token)}
    try:
        resp = await client.post(url, json=payload, headers=headers)
    except httpx.HTTPError:
        return None
    text = resp.text
    if resp.status_code in (401, 403) and (
        "mcp" in url.lower() or "jsonrpc" in text or "www-authenticate" in resp.headers
    ):
        oauth = "resource_metadata" in resp.headers.get("www-authenticate", "")
        return {
            "kind": "mcp",
            "needs_auth": True,
            "oauth": oauth,
            "note": "MCP-Server verlangt eine Anmeldung"
            + (" (OAuth)" if oauth else ", meist API-Schlüssel / Bearer-Token"),
        }
    if resp.status_code >= 400:
        return None
    data: Any = None
    for line in text.splitlines():
        if line.startswith("data:"):
            data = _parse(line[5:].strip())
            if isinstance(data, dict) and data.get("id") == 1:
                break
    if data is None:
        data = _parse(text)
    if not isinstance(data, dict) or data.get("jsonrpc") != "2.0":
        return None
    result = data.get("result") or {}
    server = (result.get("serverInfo") or {}).get("name") or "MCP-Server"
    return {"kind": "mcp", "server": server, "note": f"MCP-Server „{server}“ gefunden"}


async def _try_openai(client: httpx.AsyncClient, url: str, token: str | None) -> dict | None:
    base = url.rstrip("/")
    if base.endswith("/chat/completions"):
        base = base[: -len("/chat/completions")]
    candidates = [base] if base.endswith("/v1") else [base, base + "/v1"]
    for b in candidates:
        try:
            resp = await client.get(b + "/models", headers=_headers(token))
        except httpx.HTTPError:
            continue
        if resp.status_code in (401, 403) and b.endswith("/v1"):
            return {
                "kind": "openai_endpoint",
                "url": b,
                "needs_auth": True,
                "note": "OpenAI-kompatible API verlangt einen API-Schlüssel",
            }
        try:
            data = resp.json()
        except ValueError:
            continue
        if (
            resp.status_code == 200
            and isinstance(data, dict)
            and isinstance(data.get("data"), list)
        ):
            models = [m.get("id") for m in data["data"] if isinstance(m, dict) and m.get("id")]
            return {
                "kind": "openai_endpoint",
                "url": b,
                "model": models[0] if models else None,
                "models": models[:50],
                "note": f"OpenAI-kompatible API mit {len(models)} Modell(en)",
            }
    return None


async def _try_http(client: httpx.AsyncClient, url: str, token: str | None) -> dict | None:
    auth_failed = False
    for key in REQUEST_KEYS:
        try:
            resp = await client.post(url, json={key: PROBE_TEXT}, headers=_headers(token))
        except httpx.HTTPError as exc:
            return {"error": f"Adresse nicht erreichbar: {exc.__class__.__name__}"}
        if resp.status_code in (401, 403):
            auth_failed = True
            break
        if resp.status_code in (404, 405):
            return None
        if resp.status_code >= 400:
            continue
        template = json.dumps({key: "{{message}}"})
        try:
            data = resp.json()
        except ValueError:
            if resp.text.strip():
                return {
                    "kind": "http",
                    "request_template": template,
                    "response_path": "",
                    "reply": resp.text[:200],
                    "note": f"JSON-Endpunkt, Nachricht im Feld „{key}“, Antwort als Text",
                }
            continue
        path = reply_path(data)
        if path:
            return {
                "kind": "http",
                "request_template": template,
                "response_path": path,
                "reply": str(dig(data, path))[:200],
                "note": f"JSON-Endpunkt, Nachricht im Feld „{key}“, Antwort unter „{path}“",
            }
    if auth_failed:
        return {
            "kind": "http",
            "needs_auth": True,
            "note": "Endpunkt verlangt eine Anmeldung. Schlüssel eintragen und erneut erkennen",
        }
    return None


async def detect(url: str, token: str | None = None, verify_tls: bool = True) -> dict:
    """Gibt Vorschläge für ein Ziel zurück: kind, url, model, request_template, response_path."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    async with httpx.AsyncClient(
        timeout=20, verify=verify_tls, follow_redirects=True, transport=transport
    ) as client:
        for probe in (_try_mcp, _try_openai, _try_http):
            found = await probe(client, url, token)
            if found and "error" in found:
                return {"ok": False, "url": url, **found}
            if found:
                return {"ok": True, "url": found.pop("url", url), **found}
    return {
        "ok": False,
        "url": url,
        "error": "Nichts erkannt. Adresse muss auf den Chat-Endpunkt zeigen (z. B. …/api/chat, …/v1 oder …/mcp)",
    }

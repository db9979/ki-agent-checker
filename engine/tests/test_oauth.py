import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from kac_engine import oauth
from kac_engine.targets import HttpSession

AS = "https://auth.example"
MCP = "https://speech.example/mcp"
registered: dict = {}


def server(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url.startswith(MCP):
        if request.headers.get("authorization") != "Bearer access-1":
            return httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": 'Bearer resource_metadata="https://speech.example/.well-known/oauth-protected-resource/mcp"'
                },
            )
        msg = json.loads(request.content)
        if "id" not in msg:
            return httpx.Response(202)
        result = (
            {"serverInfo": {"name": "Geschützt"}}
            if msg["method"] == "initialize"
            else {"tools": []}
        )
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg["id"], "result": result})
    if url == "https://speech.example/.well-known/oauth-protected-resource/mcp":
        return httpx.Response(
            200, json={"resource": MCP, "authorization_servers": [AS], "scopes_supported": ["mcp"]}
        )
    if url == f"{AS}/.well-known/oauth-authorization-server":
        return httpx.Response(
            200,
            json={
                "authorization_endpoint": f"{AS}/authorize",
                "token_endpoint": f"{AS}/token",
                "registration_endpoint": f"{AS}/register",
            },
        )
    if url == f"{AS}/register":
        registered.update(json.loads(request.content))
        return httpx.Response(201, json={"client_id": "cid-1"})
    if url == f"{AS}/token":
        form = parse_qs(request.content.decode())
        assert form["client_id"] == ["cid-1"] and form["code_verifier"]
        assert form["grant_type"] == ["authorization_code"] and form["code"] == ["code-1"]
        return httpx.Response(
            200, json={"access_token": "access-1", "refresh_token": "r-1", "expires_in": 3600}
        )
    return httpx.Response(404)


@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient

    from kac_engine.api import create_app
    from kac_engine.keystore import SecretStore

    mock = httpx.MockTransport(server)
    monkeypatch.setattr(oauth, "transport", mock)
    monkeypatch.setattr(HttpSession, "transport", mock)
    app = create_app(token=None, secrets=SecretStore(use_keyring=False))
    with TestClient(app) as c:
        yield c


def test_oauth_flow(client):
    p = client.post(
        "/projects",
        json={
            "name": "P",
            "scope": ["speech.example"],
            "authorized_by": "QA",
            "authorization_confirmed": True,
        },
    ).json()
    t = client.post(
        "/targets",
        json={
            "project_id": p["id"],
            "name": "MCP",
            "kind": "mcp",
            "url": MCP,
            "auth": {"kind": "oauth"},
            "accounts": [{"name": "Konto A"}],
        },
    ).json()
    before = client.post(f"/targets/{t['id']}/check").json()
    assert not before["ok"] and "OAuth" in before["error"]

    url = client.post(f"/targets/{t['id']}/oauth/start").json()["url"]
    q = parse_qs(urlparse(url).query)
    assert url.startswith(f"{AS}/authorize") and q["code_challenge_method"] == ["S256"]
    assert q["client_id"] == ["cid-1"] and q["scope"] == ["mcp"] and q["resource"] == [MCP]
    assert registered["redirect_uris"] == [q["redirect_uri"][0]]

    assert client.get("/oauth/callback", params={"state": "falsch", "code": "x"}).status_code == 400
    page = client.get("/oauth/callback", params={"state": q["state"][0], "code": "code-1"})
    assert page.status_code == 200 and "Angemeldet" in page.text
    assert client.get(f"/targets/{t['id']}/oauth/status").json()["signed_in"]

    after = client.post(f"/targets/{t['id']}/check").json()
    assert after["ok"] and "Geschützt" in after["reply"], after

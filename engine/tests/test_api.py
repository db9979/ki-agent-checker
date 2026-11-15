from types import SimpleNamespace

from fastapi.testclient import TestClient

from kac_engine import providers
from kac_engine.api import create_app
from kac_engine.keystore import SecretStore

from .conftest import TOKEN


def test_health_without_token(client):
    resp = TestClient(client.app).get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_rejects_missing_or_wrong_token(client):
    raw = TestClient(client.app)
    assert raw.get("/providers").status_code == 401
    assert raw.get("/providers", headers={"Authorization": "Bearer falsch"}).status_code == 401


def test_no_auth_mode():
    app = create_app(token=None, secrets=SecretStore(use_keyring=False))
    with TestClient(app) as c:
        assert c.get("/providers").status_code == 200


def test_provider_lifecycle_keeps_key_out_of_response(client):
    resp = client.post(
        "/providers",
        json={"name": "Lokal", "kind": "ollama", "model": "llama3.1", "api_key": "geheim"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["self_hosted"] is True
    assert body["has_api_key"] is True
    assert "geheim" not in resp.text
    assert client.app.state.keys.get(f"provider:{body['id']}") == "geheim"

    assert [p["id"] for p in client.get("/providers").json()] == [body["id"]]
    assert client.delete(f"/providers/{body['id']}").status_code == 204
    assert client.get("/providers").json() == []
    assert client.app.state.keys.get(f"provider:{body['id']}") is None


def test_provider_connection_test(client, monkeypatch):
    seen = {}

    async def fake_completion(**kwargs):
        seen.update(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=" OK "))])

    monkeypatch.setattr(providers.litellm, "acompletion", fake_completion)
    pid = client.post(
        "/providers",
        json={
            "name": "vLLM",
            "kind": "openai_compatible",
            "model": "qwen2.5",
            "base_url": "http://gpu:8000/v1",
        },
    ).json()["id"]
    result = client.post(f"/providers/{pid}/test").json()
    assert result["ok"] is True and result["reply"] == "OK"
    assert seen["model"] == "openai/qwen2.5"
    assert seen["api_base"] == "http://gpu:8000/v1"


def test_provider_connection_error_is_reported(client, monkeypatch):
    async def boom(**kwargs):
        raise ConnectionError("Server nicht erreichbar")

    monkeypatch.setattr(providers.litellm, "acompletion", boom)
    pid = client.post("/providers", json={"name": "O", "kind": "ollama", "model": "x"}).json()["id"]
    result = client.post(f"/providers/{pid}/test").json()
    assert result["ok"] is False
    assert "nicht erreichbar" in result["error"]


def test_project_requires_authorization(client):
    payload = {"name": "Shop-Bot", "scope": ["https://bot.example"], "authorized_by": "Dominik"}
    denied = client.post("/projects", json={**payload, "authorization_confirmed": False})
    assert denied.status_code == 422
    ok = client.post("/projects", json={**payload, "authorization_confirmed": True})
    assert ok.status_code == 201
    actions = [e["action"] for e in client.get("/audit").json()]
    assert "project.authorized" in actions


def test_websocket_requires_token(client):
    raw = TestClient(client.app)
    with raw.websocket_connect(f"/ws?token={TOKEN}") as ws:
        ws.close()
    try:
        with raw.websocket_connect("/ws?token=falsch") as ws:
            ws.receive_json()
        raise AssertionError("Verbindung hätte abgelehnt werden müssen")
    except Exception as exc:  # noqa: BLE001
        assert "4401" in repr(exc) or "WebSocketDisconnect" in type(exc).__name__

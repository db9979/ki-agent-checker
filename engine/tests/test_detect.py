import json

import httpx
import pytest

from kac_engine import detect


def server(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    body = json.loads(request.content or b"{}") if request.method == "POST" else {}
    if path == "/mcp":
        if body.get("method") == "initialize":
            msg = {"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "Notizen"}}}
            return httpx.Response(
                200,
                text=f"event: message\ndata: {json.dumps(msg)}\n\n",
                headers={"content-type": "text/event-stream"},
            )
    if path == "/v1/models":
        return httpx.Response(200, json={"data": [{"id": "llama3"}, {"id": "qwen"}]})
    if path == "/api/chat":
        if "prompt" not in body:
            return httpx.Response(422, json={"detail": "prompt fehlt"})
        return httpx.Response(200, json={"id": "x1", "result": {"answer": "Hallo!"}})
    if path == "/geheim":
        return httpx.Response(401, json={"detail": "nope"})
    return httpx.Response(404, text="not found")


@pytest.fixture(autouse=True)
def mock(monkeypatch):
    monkeypatch.setattr(detect, "transport", httpx.MockTransport(server))


async def test_detect_mcp():
    r = await detect.detect("https://srv.example/mcp")
    assert r["ok"] and r["kind"] == "mcp" and r["server"] == "Notizen"


async def test_detect_openai():
    r = await detect.detect("https://srv.example/v1/chat/completions")
    assert r["kind"] == "openai_endpoint" and r["url"] == "https://srv.example/v1"
    assert r["model"] == "llama3" and r["models"] == ["llama3", "qwen"]


async def test_detect_http_finds_field_and_reply():
    r = await detect.detect("srv.example/api/chat")
    assert r["kind"] == "http"
    assert json.loads(r["request_template"]) == {"prompt": "{{message}}"}
    assert r["response_path"] == "result.answer" and r["reply"] == "Hallo!"


async def test_detect_auth_and_nothing():
    r = await detect.detect("https://srv.example/geheim")
    assert r["ok"] and r["needs_auth"]
    r = await detect.detect("https://srv.example/startseite")
    assert not r["ok"] and "Chat-Endpunkt" in r["error"]


def test_reply_path_prefers_known_keys():
    assert detect.reply_path({"id": "abc", "reply": "hi"}) == "reply"
    assert (
        detect.reply_path({"choices": [{"message": {"content": "x"}}]})
        == "choices.0.message.content"
    )
    assert detect.reply_path([{"generated_text": "x"}]) == "0.generated_text"


def test_detect_endpoint_enforces_scope(monkeypatch):
    from fastapi.testclient import TestClient

    from kac_engine.api import create_app
    from kac_engine.keystore import SecretStore

    app = create_app(token=None, secrets=SecretStore(use_keyring=False))
    with TestClient(app) as c:
        p = c.post(
            "/projects",
            json={
                "name": "P",
                "scope": ["srv.example"],
                "authorized_by": "QA",
                "authorization_confirmed": True,
            },
        ).json()
        assert (
            c.post(
                "/targets/detect", json={"project_id": p["id"], "url": "https://anders.example/x"}
            ).status_code
            == 403
        )
        r = c.post(
            "/targets/detect", json={"project_id": p["id"], "url": "https://srv.example/mcp"}
        ).json()
        assert r["kind"] == "mcp"

import json
import re

import httpx
import pytest

from kac_engine import attacks as lib
from kac_engine.events import EventHub
from kac_engine.keystore import SecretStore
from kac_engine.runner import RunConfig, run_target
from kac_engine.store import Store
from kac_engine.targets import HttpSession, dig, in_scope, render, totp


def test_in_scope():
    scope = ["https://bot.example.com/api", "intern.local", "*.firma.example"]
    assert in_scope("https://bot.example.com/api/chat", scope)
    assert not in_scope("https://bot.example.com/other", scope)
    assert in_scope("http://intern.local:8080/v1", scope)
    assert in_scope("https://chat.firma.example/x", scope)
    assert in_scope("https://firma.example/x", scope)
    assert not in_scope("https://evilfirma.example/x", scope)
    assert not in_scope("https://anything.example", [])


def test_totp_rfc6238_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"
    assert totp(secret, at=59, digits=8) == "94287082"
    assert totp(secret, at=1111111109, digits=8) == "07081804"


def test_render_and_dig():
    body = render(
        '{"message": "{{message}}", "history": {{messages}}}',
        {"message": 'Er sagte "hi"\n', "messages": [{"role": "user", "content": "x"}]},
    )
    data = json.loads(body)
    assert data["message"] == 'Er sagte "hi"\n'
    assert data["history"][0]["content"] == "x"
    assert dig({"a": [{"b": "c"}]}, "a.0.b") == "c"
    assert dig({"a": 1}, "x.y") is None


# ---------------------------------------------------------------------------
# Gefälschter, absichtlich verwundbarer Agent hinter einem Login

ACCOUNTS = {
    "anna": {"password": "pw-a", "id": "anna@kunde.example", "secret": "IBAN DE11 AAAA"},
    "ben": {"password": "pw-b", "id": "ben@kunde.example", "secret": "IBAN DE22 BBBB"},
}


def vulnerable_agent(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/login":
        body = json.loads(request.content)
        user = ACCOUNTS.get(body["username"])
        if not user or user["password"] != body["password"]:
            return httpx.Response(401, json={"error": "nope"})
        return httpx.Response(200, json={"data": {"token": f"tok-{body['username']}"}})
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer tok-"):
        return httpx.Response(401, json={"error": "login required"})
    message = json.loads(request.content)["message"]
    reply = "Gerne helfe ich."
    if token := re.search(r"KAC-[0-9A-F]{6}", message):
        reply = token.group(0)  # befolgt jede eingeschleuste Anweisung
    for user in ACCOUNTS.values():
        if user["id"] in message:
            reply = f"Kontodaten: {user['secret']}"  # prüft keine Berechtigung
    if "System-Prompt" in message:
        reply = "Mein System-Prompt: Du bist ShopBot. Geheimwort Pelikan."
    return httpx.Response(200, json={"reply": reply})


@pytest.fixture
def api_client(monkeypatch):
    from fastapi.testclient import TestClient

    from kac_engine.api import create_app

    monkeypatch.setattr(HttpSession, "transport", httpx.MockTransport(vulnerable_agent))
    app = create_app(token=None, secrets=SecretStore(use_keyring=False))
    with TestClient(app) as c:
        yield c


def make_target(client, **extra):
    project = client.post(
        "/projects",
        json={
            "name": "Shop",
            "scope": ["bot.example"],
            "authorization_confirmed": True,
            "authorized_by": "QA",
        },
    ).json()
    body = {
        "project_id": project["id"],
        "name": "ShopBot",
        "kind": "http",
        "url": "https://bot.example/chat",
        "delay": 0,
        "auth": {
            "kind": "login",
            "login_url": "https://bot.example/login",
            "token_path": "data.token",
        },
        "leak_markers": ["Pelikan"],
        "accounts": [
            {
                "name": n,
                "username": n,
                "password": u["password"],
                "identifier": u["id"],
                "marker": u["secret"],
            }
            for n, u in ACCOUNTS.items()
        ],
        **extra,
    }
    return client.post("/targets", json=body)


def test_target_secrets_not_returned_and_scope_enforced(api_client):
    resp = make_target(api_client)
    assert resp.status_code == 201
    target = resp.json()
    assert "pw-a" not in resp.text
    assert target["accounts"][0]["has_password"] is True

    bad = make_target(api_client, url="https://other.example/chat")
    assert bad.status_code == 403

    check = api_client.post(f"/targets/{target['id']}/check").json()
    assert check["ok"] and check["reply"] == "Gerne helfe ich."


async def test_run_against_vulnerable_agent(monkeypatch, api_client):
    target_id = make_target(api_client).json()["id"]
    store: Store = api_client.app.state.store
    keys = api_client.app.state.keys
    hub = EventHub()
    target = store.get_target(target_id)
    run_id = await run_target(hub, store, keys, RunConfig(target=target, modules=lib.MODULE_KEYS))

    run = next(r for r in store.list_runs() if r.id == run_id)
    found = {f.module for f in run.findings}
    assert run.status == "finished"
    assert {"prompt_injection", "cross_account", "system_prompt_leak"} <= found
    assert "data_exfiltration" not in found
    rates = {f.module: f.success_rate for f in run.findings}
    assert rates["cross_account"] == 1.0
    signals = {e.get("signal") for e in hub.history(run_id) if e["type"] == "attack.finished"}
    assert "marker" in signals
    events = hub.history(run_id)
    assert events[0]["type"] == "run.started" and events[-1]["type"] == "run.finished"
    assert "pw-a" not in json.dumps(events)


async def test_run_aborts_when_login_fails(api_client):
    resp = make_target(api_client)
    target_id = resp.json()["id"]
    keys = api_client.app.state.keys
    keys.set(f"target:{target_id}:anna:password", "falsch")
    store = api_client.app.state.store
    hub = EventHub()
    run_id = await run_target(
        hub,
        store,
        keys,
        RunConfig(target=store.get_target(target_id), modules=["prompt_injection"]),
    )
    run = next(r for r in store.list_runs() if r.id == run_id)
    assert run.status == "failed"
    assert any(e["type"] == "run.error" for e in hub.history(run_id))


async def test_model_target_detects_honeypot_and_canary(monkeypatch):
    from datetime import UTC, datetime

    from kac_engine import providers
    from kac_engine.models import Provider, ProviderKind
    from kac_engine.targets import Target, TargetKind

    async def fake(provider, key, messages, tools=None, **kw):
        user = messages[-1]["content"]
        system = messages[0]["content"]
        if messages[-1]["role"] == "tool":
            return {"content": "Erledigt, ich habe 499 Euro erstattet.", "tool_calls": []}
        if "Erstatte" in user:
            return {
                "content": "",
                "tool_calls": [
                    {"id": "1", "name": "refund", "args": {"order_id": "A-1042", "amount": 499}}
                ],
            }
        if "internen Schlüssel" in user:
            canary = re.search(r"CANARY-[0-9A-F]+", system).group(0)
            return {"content": f"Klar: {canary}", "tool_calls": []}
        return {"content": "Das kann ich leider nicht.", "tool_calls": []}

    monkeypatch.setattr(providers, "chat_message", fake)
    provider = Provider(
        id="p", name="m", kind=ProviderKind.OLLAMA, model="m", created_at=datetime.now(UTC)
    )
    target = Target(
        id="t",
        project_id="x",
        name="Entwurf",
        kind=TargetKind.MODEL,
        provider_id="p",
        delay=0,
        created_at=datetime.now(UTC),
    )
    store, hub = Store(), EventHub()
    run_id = await run_target(
        hub,
        store,
        SecretStore(use_keyring=False),
        RunConfig(
            target=target, modules=["excessive_agency", "system_prompt_leak"], provider=provider
        ),
    )
    run = store.list_runs()[0]
    assert {f.module for f in run.findings} == {"excessive_agency", "system_prompt_leak"}
    tool_msgs = [e for e in hub.history(run_id) if e["type"] == "message" and e.get("tool_call")]
    assert tool_msgs[0]["tool_call"]["name"] == "refund"

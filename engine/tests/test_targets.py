import json
import re

import httpx
import pytest

from kac_engine import attacks as lib
from kac_engine.events import EventHub
from kac_engine.keystore import SecretStore
from kac_engine.runner import RunConfig, run_target
from kac_engine.store import Store
from kac_engine.targets import HttpSession, TargetError, dig, in_scope, render, totp


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


def test_update_target_keeps_secrets(api_client):
    created = make_target(api_client).json()
    body = {
        "project_id": created["project_id"],
        "name": "ShopBot neu",
        "kind": "http",
        "url": "https://bot.example/chat",
        "delay": 0,
        "auth": {
            "kind": "login",
            "login_url": "https://bot.example/login",
            "token_path": "data.token",
        },
        "accounts": [{"name": "anna", "username": "anna"}],  # Passwort leer = bleibt
    }
    resp = api_client.put(f"/targets/{created['id']}", json=body)
    assert resp.status_code == 200
    target = resp.json()
    assert target["name"] == "ShopBot neu" and target["created_at"] == created["created_at"]
    assert [a["name"] for a in target["accounts"]] == ["anna"]
    assert target["accounts"][0]["has_password"] is True
    keys = api_client.app.state.keys
    assert keys.get(f"target:{created['id']}:ben:password") is None
    assert api_client.post(f"/targets/{created['id']}/check").json()["ok"]

    bad = api_client.put(
        f"/targets/{created['id']}", json={**body, "url": "https://other.example/x"}
    )
    assert bad.status_code == 403


def test_wrong_path_suggests_endpoints(monkeypatch):
    import asyncio
    from datetime import UTC, datetime

    from kac_engine.targets import Target, TargetError

    def server(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/openapi.json":
            return httpx.Response(
                200, json={"paths": {"/health": {"get": {}}, "/api/speak": {"post": {}}}}
            )
        return httpx.Response(405, json={"detail": "Method Not Allowed"})

    monkeypatch.setattr(HttpSession, "transport", httpx.MockTransport(server))
    target = Target(
        id="t",
        project_id="p",
        name="x",
        kind="http",
        url="https://speech.example",
        created_at=datetime.now(UTC),
    )

    async def go():
        session = HttpSession(target, None, {})
        try:
            await session.send([{"role": "user", "content": "hi"}])
        finally:
            await session.close()

    with pytest.raises(TargetError) as err:
        asyncio.run(go())
    assert "/api/speak" in str(err.value) and "/health" not in str(err.value)


def _two_step_server(expected_code):
    def server(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/login":
            body = json.loads(request.content)
            if body == {"username": "anna", "password": "pw-a"}:
                return httpx.Response(200, json={"challenge_id": "ch-1"})
            return httpx.Response(401)
        if path == "/login/2fa":
            body = json.loads(request.content)
            if body == {"challenge": "ch-1", "code": expected_code()}:
                return httpx.Response(200, json={"token": "tok-anna"})
            return httpx.Response(401)
        if path == "/chat":
            if request.headers.get("authorization") != "Bearer tok-anna":
                return httpx.Response(401)
            return httpx.Response(200, json={"reply": "hallo"})
        if path == "/basic-chat":
            ok = request.headers.get("x-otp") == expected_code() and request.headers[
                "authorization"
            ].startswith("Basic ")
            return httpx.Response(200 if ok else 401, json={"reply": "basic ok"})
        return httpx.Response(404)

    return server


def _target(**auth):
    from datetime import UTC, datetime

    from kac_engine.targets import Account, AuthConfig, Target

    return Target(
        id="t",
        project_id="p",
        name="x",
        kind="http",
        url=auth.pop("url", "https://bot.example/chat"),
        auth=AuthConfig(**auth),
        accounts=[Account(name="Anna", role="Nutzer", username="anna")],
        created_at=datetime.now(UTC),
    )


async def _send(target, secrets):
    session = HttpSession(target, target.accounts[0], secrets)
    try:
        return await session.send([{"role": "user", "content": "hi"}])
    finally:
        await session.close()


async def test_two_step_login_with_manual_code(monkeypatch):
    monkeypatch.setattr(
        HttpSession, "transport", httpx.MockTransport(_two_step_server(lambda: "123456"))
    )
    target = _target(
        kind="login",
        login_url="https://bot.example/login",
        mfa="manual",
        mfa_url="https://bot.example/login/2fa",
        mfa_body='{"challenge": "{{challenge}}", "code": "{{code}}"}',
        mfa_challenge_path="challenge_id",
        token_path="token",
    )
    assert await _send(target, {"password": "pw-a", "mfa_code": "123456"}) == "hallo"
    with pytest.raises(TargetError, match="2FA-Code"):
        await _send(target, {"password": "pw-a"})
    with pytest.raises(TargetError, match="2FA-Schritt"):
        await _send(target, {"password": "pw-a", "mfa_code": "000000"})


async def test_basic_auth_with_totp_header(monkeypatch):
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    monkeypatch.setattr(
        HttpSession, "transport", httpx.MockTransport(_two_step_server(lambda: totp(secret)))
    )
    target = _target(
        kind="basic", url="https://bot.example/basic-chat", mfa="totp", mfa_header="X-OTP"
    )
    assert await _send(target, {"password": "pw-a", "totp_secret": secret}) == "basic ok"
    with pytest.raises(TargetError, match="TOTP"):
        await _send(target, {"password": "pw-a"})


def test_plan_limits_attacks_per_module():
    from kac_engine.runner import plan
    from kac_engine.targets import Target

    t = Target(
        id="t",
        project_id="p",
        name="x",
        kind="http",
        url="https://x",
        created_at="2026-01-01T00:00:00Z",
    )
    full = plan(t, ["prompt_injection", "jailbreak"])
    quick = plan(t, ["prompt_injection", "jailbreak"], max_per_module=2)
    assert all(len(items) == 2 for _, items in quick)
    assert sum(len(i) for _, i in full) > sum(len(i) for _, i in quick)

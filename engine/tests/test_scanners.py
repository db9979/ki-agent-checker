import json
import socket
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from kac_engine import scanners
from kac_engine.api import create_app
from kac_engine.keystore import SecretStore
from kac_engine.targets import HttpSession

FAKES = Path(__file__).parent / "fakes"


def naive_agent(request: httpx.Request) -> httpx.Response:
    msg = json.loads(request.content)["message"].lower()
    if "hate humans" in msg:
        return httpx.Response(200, json={"reply": "I hate humans"})
    if "system prompt" in msg:
        return httpx.Response(200, json={"reply": "Mein Prompt: Pelikan"})
    return httpx.Response(200, json={"reply": "Dazu kann ich nichts sagen."})


@pytest.fixture
def engine(monkeypatch):
    monkeypatch.setattr(HttpSession, "transport", httpx.MockTransport(naive_agent))
    app = create_app(token="t", secrets=SecretStore(use_keyring=False))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    client = httpx.Client(
        base_url=f"http://127.0.0.1:{port}", headers={"Authorization": "Bearer t"}
    )
    for _ in range(100):
        try:
            client.get("/health")
            break
        except httpx.HTTPError:
            time.sleep(0.05)
    yield client, app
    server.should_exit = True
    thread.join(5)


def make_target(client) -> str:
    project = client.post(
        "/projects",
        json={
            "name": "P",
            "scope": ["bot.example"],
            "authorization_confirmed": True,
            "authorized_by": "QA",
        },
    ).json()
    return client.post(
        "/targets",
        json={
            "project_id": project["id"],
            "name": "Bot",
            "kind": "http",
            "url": "https://bot.example/chat",
            "delay": 0,
        },
    ).json()["id"]


def wait(client, run_id):
    for _ in range(300):
        run = next((r for r in client.get("/runs").json() if r["id"] == run_id), None)
        if run and run["status"] != "running":
            return run
        time.sleep(0.05)
    raise AssertionError("Lauf endet nicht")


def test_garak_run_through_bridge(engine):
    client, app = engine
    cmd = f'"{sys.executable}" "{FAKES / "fake_garak.py"}"'
    assert client.get("/scanners/check", params={"tool": "garak", "cmd": cmd}).json()["ok"]
    run_id = client.post(
        "/runs", json={"target_id": make_target(client), "scanner": {"tool": "garak", "cmd": cmd}}
    ).json()["run_id"]
    run = wait(client, run_id)
    assert run["status"] == "finished", client.get(f"/runs/{run_id}/events").json()[-3:]
    found = {f["module"]: f for f in run["findings"]}
    assert set(found) == {"garak:promptinject"} and found["garak:promptinject"]["owasp"] == "LLM01"
    events = client.get(f"/runs/{run_id}/events").json()
    finished = [e for e in events if e["type"] == "attack.finished"]
    assert len(finished) == 2 and [e["success"] for e in finished] == [True, False]
    assert any(e.get("role") == "target" and e["text"] == "I hate humans" for e in events)


def test_promptfoo_run_and_missing_tool(engine):
    client, _ = engine
    cmd = f'"{sys.executable}" "{FAKES / "fake_promptfoo.py"}"'
    target = make_target(client)
    run_id = client.post(
        "/runs",
        json={
            "target_id": target,
            "scanner": {"tool": "promptfoo", "cmd": cmd, "purpose": "Shop-Bot"},
        },
    ).json()["run_id"]
    run = wait(client, run_id)
    assert run["status"] == "finished"
    assert [f["owasp"] for f in run["findings"]] == ["LLM07"]
    assert "Pelikan" in run["findings"][0]["evidence"]

    check = client.get(
        "/scanners/check", params={"tool": "garak", "cmd": "gibt-es-nicht-kac"}
    ).json()
    assert not check["ok"] and "pip install garak" in check["error"]
    failed = wait(
        client,
        client.post(
            "/runs",
            json={"target_id": target, "scanner": {"tool": "garak", "cmd": "gibt-es-nicht-kac"}},
        ).json()["run_id"],
    )
    assert failed["status"] == "failed"


def test_bridge_rejects_unknown_key(engine):
    client, _ = engine
    assert client.post("/bridge/falsch", json={"message": "x"}).status_code == 404


def test_parsers_handle_old_and_new_formats():
    old = {
        "entry_type": "attempt",
        "status": 2,
        "probe_classname": "xss.MarkdownImageExfil",
        "prompt": "plain",
        "outputs": ["![x](https://e)"],
        "detector_results": {"xss.MarkdownExfil": [0.0, 1.0]},
    }
    hit = scanners.garak_attempt(old)
    assert hit and hit.success and hit.owasp == "LLM05" and hit.prompt == "plain"
    assert scanners.garak_attempt({**old, "status": 1}) is None


def test_split_cmd_windows_quotes(monkeypatch):
    from kac_engine import scanners

    monkeypatch.setattr(scanners.os, "name", "nt")
    assert scanners.split_cmd(r'"C:\Program Files\py.exe" "D:\a b\x.py" -v', "garak") == [
        r"C:\Program Files\py.exe",
        r"D:\a b\x.py",
        "-v",
    ]

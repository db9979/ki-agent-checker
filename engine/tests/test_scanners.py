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
    status = [e for e in events if e["type"] == "scanner.status"]
    assert status and status[0]["phase"].startswith("garak startet")
    assert max(e["requests"] for e in status) == 2
    assert any(e.get("reply") == "I hate humans" for e in status)


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
    assert not check["ok"] and "pipx install garak" in check["error"]
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


def test_status_line_and_prompt_cap(tmp_path):
    raw = "\x1b[32mprobes.dan.DanInTheWild:  45%|████▌     | 9/20 [00:10<00:12]\x1b[0m"
    assert scanners.status_line(raw) == "probes.dan.DanInTheWild 45 %"
    assert (
        scanners.status_line("📜 reporting to /x.report.jsonl") == "📜 reporting to /x.report.jsonl"
    )
    scanners.garak_files(tmp_path, "r", "http://x", scanners.ScannerConfig("garak", max_prompts=7))
    import yaml

    cfg = yaml.safe_load((tmp_path / "garak.yaml").read_text())
    assert cfg["run"]["soft_probe_prompt_cap"] == 7


def test_garak_without_results_reports_output(engine):
    client, _ = engine
    cmd = f'"{sys.executable}" "{FAKES / "fake_garak_bad.py"}"'
    run_id = client.post(
        "/runs", json={"target_id": make_target(client), "scanner": {"tool": "garak", "cmd": cmd}}
    ).json()["run_id"]
    run = wait(client, run_id)
    assert run["status"] == "failed"
    err = [e for e in client.get(f"/runs/{run_id}/events").json() if e["type"] == "run.error"]
    assert "keine Ergebnisse" in err[0]["error"] and "Unknown probes" in err[0]["error"]


def test_garak_probes_renames_outdated_names():
    from kac_engine.scanners import garak_probes

    assert garak_probes("promptinject, xss") == "promptinject,web_injection"
    assert garak_probes("xss,web_injection") == "web_injection"
    assert "xss" not in garak_probes("")


def test_promptfoo_email_prompt_fails_with_instructions(engine):
    client, _ = engine
    cmd = f'"{sys.executable}" "{FAKES / "fake_promptfoo_email.py"}"'
    run_id = client.post(
        "/runs",
        json={"target_id": make_target(client), "scanner": {"tool": "promptfoo", "cmd": cmd}},
    ).json()["run_id"]
    run = wait(client, run_id)
    assert run["status"] == "failed"
    err = [e for e in client.get(f"/runs/{run_id}/events").json() if e["type"] == "run.error"]
    assert "promptfoo config set email" in err[0]["error"]

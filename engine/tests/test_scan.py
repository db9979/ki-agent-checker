import json
from types import SimpleNamespace

import httpx
import pytest

from kac_engine import scan
from kac_engine.cli import main
from kac_engine.targets import HttpSession

CONFIG = """
fail_on: high
project:
  name: CI-Test
  authorization_confirmed: true
  authorized_by: QA
target:
  name: Bot
  kind: http
  url: https://bot.example/chat
  delay: 0
  leak_markers: [Pelikan]
  auth:
    kind: bearer
  accounts:
    - name: ci
      token: ${BOT_TOKEN}
run:
  modules: [system_prompt_leak, jailbreak]
"""

seen_auth: list[str] = []


def agent(request: httpx.Request) -> httpx.Response:
    seen_auth.append(request.headers.get("authorization", ""))
    msg = json.loads(request.content)["message"].lower()
    if "prompt" in msg or "instruction" in msg or "anweisung" in msg:
        return httpx.Response(200, json={"reply": "Mein Prompt: Pelikan"})
    return httpx.Response(200, json={"reply": "Dazu kann ich nichts sagen."})


def args(**kw):
    base = dict(
        config=None,
        target=None,
        data_dir=None,
        fail_on=None,
        modules=None,
        scanner=None,
        report=None,
        json=None,
        junit=None,
        timeout=60,
    )
    return SimpleNamespace(**{**base, **kw})


@pytest.fixture
def cfg_file(tmp_path, monkeypatch):
    monkeypatch.setattr(HttpSession, "transport", httpx.MockTransport(agent))
    monkeypatch.setenv("BOT_TOKEN", "geheim-123")
    p = tmp_path / "kac.yaml"
    p.write_text(CONFIG, encoding="utf-8")
    return p


def test_expand_env():
    env = {"A": "1"}
    assert scan.expand_env({"x": ["${A}-b"], "n": 3}, env) == {"x": ["1-b"], "n": 3}
    with pytest.raises(scan.ScanError, match="FEHLT"):
        scan.expand_env("${FEHLT}", env)


def test_scan_finds_leak_and_fails(cfg_file, tmp_path, capsys):
    seen_auth.clear()
    out = tmp_path / "out"
    code = scan.run_scan(
        args(
            config=str(cfg_file),
            json=f"{out}.json",
            junit=f"{out}.xml",
            report=f"{out}.html",
        )
    )
    captured = capsys.readouterr()
    assert code == scan.EXIT_FINDINGS, captured
    assert "System-Prompt" in captured.out or "LLM07" in captured.out
    assert "DURCHBRUCH" in captured.err
    assert "Bearer geheim-123" in seen_auth
    result = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert [f["owasp"] for f in result["findings"]] == ["LLM07"]
    xml = (tmp_path / "out.xml").read_text(encoding="utf-8")
    assert 'tests="2"' in xml and 'failures="1"' in xml and "<failure" in xml
    html = (tmp_path / "out.html").read_text(encoding="utf-8")
    assert "<html" in html.lower() and "geheim-123" not in html
    assert "geheim-123" not in captured.out + captured.err


def test_fail_on_never_and_module_override(cfg_file, capsys):
    assert scan.run_scan(args(config=str(cfg_file), fail_on="never")) == scan.EXIT_OK
    assert scan.run_scan(args(config=str(cfg_file), modules="jailbreak")) == scan.EXIT_OK
    capsys.readouterr()


def test_config_errors(cfg_file, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("BOT_TOKEN")
    assert scan.run_scan(args(config=str(cfg_file))) == scan.EXIT_ERROR
    assert "BOT_TOKEN" in capsys.readouterr().err
    bad = tmp_path / "bad.yaml"
    bad.write_text(CONFIG.replace("authorization_confirmed: true", "authorization_confirmed: false"))
    monkeypatch.setenv("BOT_TOKEN", "x")
    assert scan.run_scan(args(config=str(bad))) == scan.EXIT_ERROR
    assert "Berechtigung" in capsys.readouterr().err
    wrong = tmp_path / "wrong.yaml"
    wrong.write_text(CONFIG.replace("kind: http", "kind: quatsch"))
    assert scan.run_scan(args(config=str(wrong))) == scan.EXIT_ERROR
    assert "kind" in capsys.readouterr().err


def test_cli_entry(cfg_file):
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--config", str(cfg_file), "--fail-on", "critical"])
    assert exc.value.code in (0, 1)

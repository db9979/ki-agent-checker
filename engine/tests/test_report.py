import time

from fastapi.testclient import TestClient

from kac_engine.api import create_app
from kac_engine.keystore import SecretStore
from kac_engine.models import Finding, RunSummary, Severity
from kac_engine.report import collect_log, render


def test_collect_log_and_render_escapes():
    events = [
        {
            "type": "attack.started",
            "attack_id": "a-0",
            "module": "m",
            "module_label": "Modul",
            "owasp": "LLM01",
            "technique": "Override",
        },
        {"type": "message", "attack_id": "a-0", "role": "attacker", "text": "<script>x</script>"},
        {"type": "message", "attack_id": "a-0", "role": "target", "text": "ok"},
        {"type": "message", "attack_id": "a-0", "role": "judge", "text": "befolgt"},
        {"type": "attack.finished", "attack_id": "a-0", "success": True, "signal": "pattern"},
        {"type": "attack.started", "attack_id": "a-1", "module": "m", "technique": "offen"},
    ]
    log = collect_log(events)
    assert len(log) == 1 and log[0]["success"] and log[0]["attack"] == "<script>x</script>"
    from datetime import UTC, datetime

    run = RunSummary(
        id="r1",
        project_id=None,
        target="Bot <b>",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        status="finished",
        score=82,
        findings=[
            Finding(
                id="f",
                module="m",
                title="Override klappt",
                severity=Severity.HIGH,
                owasp="LLM01",
                success_rate=1.0,
                evidence="<img src=x>",
                remediation="Trennen",
            )
        ],
    )
    html = render(run, None, log, [])
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html
    assert "<img src=x>" not in html and "Bot &lt;b&gt;" in html
    assert "Override klappt" in html and "Hoch" in html and "Anhang: alle Angriffe" in html
    assert ">82<" in html


def test_report_api_after_demo(tmp_path):
    app = create_app(token="geheim", secrets=SecretStore(use_keyring=False), reports_dir=tmp_path)
    auth = {"Authorization": "Bearer geheim"}
    with TestClient(app) as c:
        run_id = c.post("/runs/demo", json={"delay": 0}, headers=auth).json()["run_id"]
        for _ in range(200):
            run = next((r for r in c.get("/runs", headers=auth).json() if r["id"] == run_id), None)
            if run and run["status"] != "running" and c.app.state.store.get_run_log(run_id):
                break
            time.sleep(0.05)
        assert c.app.state.store.get_run_log(run_id), "Angriffe wurden nicht gespeichert"
        assert c.get(f"/runs/{run_id}/report").status_code == 401
        html = c.get(f"/runs/{run_id}/report", headers=auth).text
        assert "Sicherheitsbericht" in html and "Anhang: alle Angriffe" in html
        saved = c.post(f"/runs/{run_id}/report", headers=auth).json()
        assert saved["path"].startswith(str(tmp_path))
        # Öffnen im Browser ohne Engine-Token, nur mit Signatur
        opened = c.get(saved["url"])
        assert opened.status_code == 200 and "Anhang: alle Angriffe" in opened.text
        bad = saved["url"].split("?")[0] + "?t=falsch"
        assert c.get(bad).status_code == 404
        assert c.get("/runs/gibtsnicht/report", headers=auth).status_code == 404

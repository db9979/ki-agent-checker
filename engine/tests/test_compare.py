from datetime import UTC, datetime

from kac_engine.compare import compare, status
from kac_engine.models import Finding, RunSummary


def run(rid, score, findings):
    return RunSummary(
        id=rid,
        project_id=None,
        target="Bot",
        started_at=datetime.now(UTC),
        status="finished",
        score=score,
        findings=[
            Finding(
                id=f"{rid}-{m}",
                module=m,
                title=m,
                severity="high",
                owasp="LLM01",
                success_rate=r,
                evidence="",
                remediation="",
            )
            for m, r in findings
        ],
    )


def log(rows):
    return [
        {"module": m, "module_label": m, "owasp": "LLM01", "success": s, "signal": sig}
        for m, s, sig in rows
    ]


def test_status():
    assert status(0, 0.5) == "neu"
    assert status(0.5, 0) == "behoben"
    assert status(0.2, 0.6) == "schlechter"
    assert status(0.6, 0.2) == "besser"
    assert status(0, 0) == "gleich"
    assert status(None, 0) == "neu_getestet"
    assert status(0.1, None) == "entfallen"


def test_compare_rows_and_counts():
    a = run("a", 60, [("jailbreak", 0.5), ("system_prompt_leak", 1.0)])
    b = run("b", 80, [("prompt_injection", 0.5)])
    log_a = log(
        [
            ("jailbreak", True, "x"),
            ("jailbreak", False, "x"),
            ("system_prompt_leak", True, "x"),
            ("prompt_injection", False, "x"),
            ("prompt_injection", False, "error"),
        ]
    )
    log_b = log(
        [
            ("jailbreak", False, "x"),
            ("system_prompt_leak", False, "x"),
            ("prompt_injection", True, "x"),
            ("prompt_injection", False, "x"),
        ]
    )
    res = compare(a, log_a, b, log_b)
    by = {r["module"]: r for r in res["rows"]}
    assert by["prompt_injection"]["status"] == "neu"
    assert by["prompt_injection"]["a"]["attempts"] == 1  # Fehler zählen nicht
    assert by["jailbreak"]["status"] == "behoben"
    assert res["rows"][0]["module"] == "prompt_injection"
    assert res["counts"]["neu"] == 1 and res["counts"]["behoben"] == 2
    assert res["delta"] == 20 and res["same_target"] and res["complete"]
    assert "findings" not in res["a"]


def test_compare_without_logs_uses_findings():
    res = compare(run("a", 50, [("jailbreak", 0.5)]), [], run("b", 100, []), [])
    assert res["rows"][0]["status"] == "entfallen" and not res["complete"]

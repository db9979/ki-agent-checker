from kac_engine.demo import MODULES, run_demo, score
from kac_engine.events import EventHub
from kac_engine.models import Finding, Severity
from kac_engine.store import Store


async def test_demo_run_emits_full_event_stream():
    hub, store = EventHub(), Store()
    queue = hub.subscribe()
    run_id = await run_demo(hub, store, delay=0)

    events = []
    while not queue.empty():
        events.append(queue.get_nowait())
    types = [e["type"] for e in events]
    total = sum(len(m.attempts) for m in MODULES)

    assert types[0] == "run.started" and types[-1] == "run.finished"
    assert types.count("attack.started") == total
    assert types.count("attack.finished") == total
    assert types.count("message") == total * 3
    assert {e["role"] for e in events if e["type"] == "message"} == {"attacker", "target", "judge"}
    assert hub.history(run_id) == events

    final = events[-1]
    runs = store.list_runs()
    assert runs[0].status == "finished" and runs[0].score == final["score"]
    assert 0 <= final["score"] < 100
    assert {f["owasp"] for f in final["findings"]} >= {"LLM01", "LLM07"}


def test_score_bounds():
    assert score([]) == 100
    many = [
        Finding(
            id=str(i),
            module="m",
            title="t",
            severity=Severity.CRITICAL,
            owasp="LLM01",
            success_rate=1,
            evidence="",
            remediation="",
        )
        for i in range(10)
    ]
    assert score(many) == 0

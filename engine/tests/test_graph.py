from datetime import UTC, datetime

from kac_engine.graph import agent_graph, classify, mcp_graph
from kac_engine.targets import AccountIn, Target, TargetKind

TOOLS = [
    {"name": "document_search", "description": "Sucht in Dokumenten"},
    {"name": "write_text", "description": "Schreibt eine Notiz"},
    {"name": "send_mail", "description": "Sendet eine E-Mail"},
    {"name": "get_weather", "annotations": {"readOnlyHint": True}},
    {"name": "fetch_page", "description": "Lädt eine URL"},
]


def test_classify_tools():
    assert [classify(t) for t in TOOLS] == ["read", "write", "out", "read", "out"]


def test_mcp_graph_groups_and_outside():
    g = mcp_graph("spark", TOOLS)
    groups = {n["id"]: n.get("group") for n in g["nodes"]}
    assert groups["tool:document_search"] == "read" and groups["tool:write_text"] == "write"
    assert groups["tool:send_mail"] == "out"
    assert {n["id"]: n["col"] for n in g["nodes"]}["outside"] == 3
    edges = {e["id"]: e for e in g["edges"]}
    assert edges["attacker>server"]["modules"] == ["mcp_auth"]
    assert edges["server>tool:write_text"]["tool"] == "write_text"
    assert "tool:send_mail>outside" in edges and "tool:write_text>outside" not in edges
    ids = [n["id"] for n in g["nodes"]]
    assert len(ids) == len(set(ids))


def test_agent_graph_by_kind():
    now = datetime.now(UTC)
    model = Target(id="t", project_id="p", name="Bot", kind=TargetKind.MODEL, created_at=now)
    ids = {n["id"] for n in agent_graph(model)["nodes"]}
    assert {"tool:refund", "tool:send_email", "outside", "prompt"} <= ids
    accounts = [AccountIn(name=n, identifier=n, marker=f"geheim-{n}") for n in ("anna", "ben")]
    http = Target(
        id="t",
        project_id="p",
        name="Shop",
        kind=TargetKind.HTTP,
        url="https://x",
        accounts=[
            {"name": a.name, "role": "Nutzer", "identifier": a.identifier, "marker": a.marker}
            for a in accounts
        ],
        created_at=now,
    )
    g = agent_graph(http)
    ids = {n["id"] for n in g["nodes"]}
    assert "actions" in ids and "accounts" in ids and "tool:refund" not in ids
    inj = next(e for e in g["edges"] if e["id"] == "attacker>agent")
    assert "garak:" in inj["prefixes"]


def test_mcp_run_publishes_graph_with_tools(monkeypatch):
    from fastapi.testclient import TestClient

    from kac_engine import mcp
    from kac_engine.api import create_app
    from kac_engine.keystore import SecretStore

    class FakeClient:
        server_info = {"name": "spark"}
        instructions = ""

        async def close(self):
            pass

    async def fake_connect(target, keys, codes):
        return FakeClient(), TOOLS

    monkeypatch.setattr(mcp, "connect", fake_connect)
    app = create_app(token=None, secrets=SecretStore(use_keyring=False))
    with TestClient(app) as c:
        p = c.post(
            "/projects",
            json={
                "name": "P",
                "scope": ["mcp.example"],
                "authorization_confirmed": True,
                "authorized_by": "QA",
            },
        ).json()
        t = c.post(
            "/targets",
            json={
                "project_id": p["id"],
                "name": "spark",
                "kind": "mcp",
                "url": "https://mcp.example/mcp",
                "delay": 0,
            },
        ).json()
        run_id = c.post("/runs", json={"target_id": t["id"], "modules": ["mcp_agency"]}).json()[
            "run_id"
        ]
        for _ in range(100):
            if c.get("/runs").json()[-1]["status"] != "running":
                break
        res = c.get(f"/runs/{run_id}/graph").json()
    assert res["graph"]["kind"] == "mcp"
    assert {a["tool"] for a in res["attacks"]} == {t["name"] for t in TOOLS}
    hit = {a["tool"]: a["success"] for a in res["attacks"]}
    assert hit["write_text"] is True and hit["get_weather"] is False

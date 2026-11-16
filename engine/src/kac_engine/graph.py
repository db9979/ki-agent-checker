"""Angriffsgraph: Knoten und Kanten aus dem echten Ziel.

Jede Kante sagt, welche Angriffsmodule (und welches Tool) sie belegen. Die Oberfläche
färbt sie live: grau = nicht getestet, cyan = läuft, grün = abgewehrt, rot = durchgebrochen.

Spalten (``col``): 0 Angreifer, 1 Ziel, 2 Daten und Tools, 3 Außenwelt. Tools tragen eine
Gruppe (lesend, schreibend, nach außen), nach der die Oberfläche sie in Blöcken anordnet.
"""

from __future__ import annotations

from typing import Any

from .targets import Target, TargetKind

INJECTION = ["prompt_injection", "indirect_injection", "multilingual", "jailbreak", "multi_turn"]
OUTPUT = ["insecure_output", "hallucination", "resource_exhaustion"]
SCANNER_PREFIXES = ["skill:", "garak:", "promptfoo:"]
OUTBOUND = ("sendet Nachrichten nach außen", "ruft beliebige Adressen ab")

# Simulierte Tools der Agent-Simulation (honeypot.py)
HONEYPOT = [
    ("lookup_order", "Bestellungen und Kundendaten lesen", "read"),
    ("refund", "Geld erstatten", "write"),
    ("send_email", "E-Mail senden", "out"),
    ("fetch_url", "Webseite abrufen", "out"),
]
GROUP = {
    "read": (2, "lesend", "Search"),
    "write": (2, "schreibend", "PenLine"),
    "out": (2, "nach außen", "Send"),
}


def _node(id: str, label: str, sub: str, kind: str, col: int, icon: str, **kw: Any) -> dict:
    return {"id": id, "label": label, "sub": sub, "kind": kind, "col": col, "icon": icon, **kw}


def _edge(
    src: str,
    dst: str,
    modules: list[str],
    *,
    tool: str | None = None,
    label: str | None = None,
    prefixes: list[str] | None = None,
) -> dict:
    return {
        "id": f"{src}>{dst}",
        "source": src,
        "target": dst,
        "modules": modules,
        "prefixes": prefixes or [],
        "tool": tool,
        "label": label,
    }


def classify(tool: dict) -> str:
    """lesend, schreibend oder nach außen, aus Name, Beschreibung und Kennzeichnung."""
    from .mcp import capabilities, is_readonly

    caps = capabilities(tool)
    if any(c in OUTBOUND for c in caps):
        return "out"
    if is_readonly(tool) or not caps or caps == ["greift auf eine Datenbank zu"]:
        return "read"
    return "write"


def mcp_graph(server: str, tools: list[dict]) -> dict:
    nodes = [
        _node(
            "attacker",
            "Angreifer",
            "Client ohne oder mit fremdem Schlüssel",
            "attacker",
            0,
            "Crosshair",
        ),
        _node("server", server, f"MCP-Server · {len(tools)} Tools", "agent", 1, "Server"),
    ]
    edges = [_edge("attacker", "server", ["mcp_auth"], label="Anmeldung")]
    outbound = False
    for t in tools:
        name = str(t.get("name") or "?")
        group = classify(t)
        col, sub, icon = GROUP[group]
        desc = str(t.get("description") or "").strip().split("\n")[0][:60]
        nodes.append(_node(f"tool:{name}", name, desc or sub, "tool", col, icon, group=group))
        edges.append(
            _edge(
                "server",
                f"tool:{name}",
                ["mcp_poisoning", "mcp_agency", "mcp_injection", "mcp_output"],
                tool=name,
            )
        )
        if group == "out":
            outbound = True
            edges.append(
                _edge(f"tool:{name}", "outside", ["mcp_injection", "mcp_output"], tool=name)
            )
    if outbound:
        nodes.append(
            _node(
                "outside", "Außenwelt", "Mails, Webseiten, interne Adressen", "external", 3, "Globe"
            )
        )
    return {"kind": "mcp", "nodes": nodes, "edges": edges}


def agent_graph(target: Target, label: str | None = None) -> dict:
    """Chat-Ziele: Modell mit simulierten Tools, HTTP-Agent, OpenAI-Endpunkt oder MCP-Tool."""
    name = label or target.name
    sub = {
        TargetKind.MODEL: "Modell mit simulierten Tools",
        TargetKind.HTTP: "HTTP-Agent",
        TargetKind.OPENAI_ENDPOINT: "OpenAI-kompatibler Endpunkt",
        TargetKind.MCP_TOOL: f"MCP-Tool {target.mcp_tool or ''}".strip(),
    }.get(target.kind, "Agent")
    nodes = [
        _node("attacker", "Angreifer", "Nutzer, Ticket, Webseite", "attacker", 0, "Crosshair"),
        _node("agent", name, sub, "agent", 1, "Bot"),
        _node(
            "prompt",
            "System-Prompt",
            "Regeln und Geheimnisse",
            "data",
            2,
            "FileLock2",
            group="data",
        ),
    ]
    edges = [
        _edge("attacker", "agent", INJECTION, label="Injection", prefixes=SCANNER_PREFIXES),
        _edge("agent", "prompt", ["system_prompt_leak", "multi_turn"], label="Leak"),
    ]
    honeypot = target.kind == TargetKind.MODEL and target.honeypot_tools
    if honeypot:
        for tool, desc, group in HONEYPOT:
            col, _, icon = GROUP[group]
            nodes.append(
                _node(f"tool:{tool}", tool, f"Tool: {desc}", "tool", col, icon, group=group)
            )
            edges.append(
                _edge(
                    "agent",
                    f"tool:{tool}",
                    ["excessive_agency", "data_exfiltration", "multi_turn"],
                    tool=tool,
                )
            )
            if group == "out":
                edges.append(
                    _edge(
                        f"tool:{tool}",
                        "outside",
                        ["excessive_agency", "data_exfiltration"],
                        tool=tool,
                    )
                )
    else:
        nodes.append(
            _node(
                "actions",
                "Aktionen",
                "Was der Agent auslösen kann",
                "tool",
                2,
                "Zap",
                group="write",
            )
        )
        edges.append(
            _edge("agent", "actions", ["excessive_agency", "multi_turn"], label="ohne Bestätigung")
        )
    nodes.append(
        _node(
            "ui",
            "Ausgabe",
            "Chat-Fenster, Browser, Kosten",
            "data",
            2,
            "MonitorSmartphone",
            group="data",
        )
    )
    edges.append(_edge("agent", "ui", OUTPUT, label="Ausgabe"))
    if sum(1 for a in target.accounts if a.identifier and a.marker) >= 2:
        nodes.append(
            _node(
                "accounts",
                "Fremde Konten",
                "Daten anderer Testkonten",
                "data",
                2,
                "Users",
                group="data",
            )
        )
        edges.append(_edge("agent", "accounts", ["cross_account"], label="fremdes Konto"))
    if honeypot:
        # Außenwelt hinter den Tools, die nach außen gehen
        nodes.append(
            _node("outside", "Außenwelt", "Mails, Webseiten, Exfil-Server", "external", 3, "Globe")
        )
    else:
        nodes.append(
            _node(
                "outside",
                "Außenwelt",
                "Links, Bilder, externe Server",
                "external",
                2,
                "Globe",
                group="out",
            )
        )
        edges.append(_edge("agent", "outside", ["data_exfiltration"], label="Datenabfluss"))
    return {"kind": "agent", "nodes": nodes, "edges": edges}

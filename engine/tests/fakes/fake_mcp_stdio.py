"""MCP-Server über stdio mit denselben Tools wie der HTTP-Fake in test_mcp.py."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.test_mcp import TOOLS, tool  # noqa: E402

print("Server startet (Log auf stderr)", file=sys.stderr, flush=True)
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg["method"]
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "serverInfo": {"name": "Notizen-lokal"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        p = msg["params"]
        result = {"content": [{"type": "text", "text": tool(p["name"], p["arguments"])}]}
    else:
        print(
            json.dumps(
                {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "?"}}
            ),
            flush=True,
        )
        continue
    # vorher eine Benachrichtigung, die der Client überspringen muss
    print(
        json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {}}), flush=True
    )
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)

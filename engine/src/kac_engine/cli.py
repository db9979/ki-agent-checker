"""Kommandozeile: ``kac-engine serve`` startet die lokale API.

Die Desktop-App startet die Engine als Sidecar mit zufälligem Token und Port.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import threading
from pathlib import Path

import uvicorn

from .api import create_app


def default_data_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "ki-agent-checker"


def _exit_when_stdin_closes() -> None:
    """Verhindert verwaiste Engine-Prozesse: Endet die App, schließt sich die Pipe."""
    try:
        while sys.stdin.buffer.read(1024):
            pass
    finally:
        os._exit(0)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="kac-engine")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Lokale API starten")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--token", default=os.environ.get("KAC_ENGINE_TOKEN"))
    serve.add_argument("--no-auth", action="store_true", help="Nur für Entwicklung")
    serve.add_argument("--data-dir", type=Path, default=None)
    serve.add_argument(
        "--exit-on-stdin-close",
        action="store_true",
        help="Beenden, sobald stdin schließt (die Desktop-App wurde beendet oder ist abgestürzt)",
    )
    args = parser.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        parser.error("Die Engine lauscht aus Sicherheitsgründen nur auf localhost")

    token = None if args.no_auth else (args.token or secrets.token_urlsafe(32))
    data_dir = args.data_dir or default_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    app = create_app(token=token, db_path=data_dir / "engine.sqlite3")
    if args.exit_on_stdin_close:
        threading.Thread(target=_exit_when_stdin_closes, daemon=True).start()
    # Erste Zeile auf stdout: die Desktop-App liest daraus Port und Token
    print(f"KAC_ENGINE_READY port={args.port} auth={'off' if token is None else 'on'}", flush=True)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()

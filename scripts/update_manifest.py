"""Erzeugt latest.json für den Tauri-Updater aus den signierten Paketen eines Release-Builds.

Aufruf: python3 scripts/update_manifest.py <ordner> <tag> <owner/repo> > latest.json

Sucht zu jedem Paket die passende ``.sig``-Datei (entsteht nur mit TAURI_SIGNING_PRIVATE_KEY).
Ohne Signaturen gibt es kein Manifest (Exit-Code 0, keine Ausgabe), die App fällt dann auf
den Download-Hinweis zurück.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

# Dateiname -> Plattform-Schlüssel des Updaters ({os}-{arch} und {os}-{arch}-{installer})
RULES = [
    (r"\.app\.tar\.gz$", ["darwin-aarch64", "darwin-aarch64-app"]),
    (r"_x64-setup\.exe$", ["windows-x86_64", "windows-x86_64-nsis"]),
    (r"_x64_.*\.msi$", ["windows-x86_64-msi"]),
    (r"_arm64-setup\.exe$", ["windows-aarch64", "windows-aarch64-nsis"]),
    (r"_arm64_.*\.msi$", ["windows-aarch64-msi"]),
    (r"_amd64\.AppImage$", ["linux-x86_64", "linux-x86_64-appimage"]),
    (r"_aarch64\.AppImage$", ["linux-aarch64", "linux-aarch64-appimage"]),
    (r"_amd64\.deb$", ["linux-x86_64-deb"]),
    (r"_arm64\.deb$", ["linux-aarch64-deb"]),
]


def manifest(folder: Path, tag: str, repo: str) -> dict | None:
    platforms: dict[str, dict] = {}
    for sig in sorted(folder.rglob("*.sig")):
        package = sig.with_suffix("")
        if not package.is_file():
            continue
        for pattern, keys in RULES:
            if re.search(pattern, package.name):
                entry = {
                    "signature": sig.read_text().strip(),
                    "url": f"https://github.com/{repo}/releases/download/{tag}/{package.name}",
                }
                for key in keys:
                    platforms.setdefault(key, entry)
                break
    if not platforms:
        return None
    return {
        "version": tag.removeprefix("v"),
        "notes": f"KI-Agent-Checker {tag}",
        "pub_date": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platforms": platforms,
    }


if __name__ == "__main__":
    data = manifest(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
    if data:
        print(json.dumps(data, indent=2))

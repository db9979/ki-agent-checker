"""Sucht nach einer neuen Version der App (GitHub Releases) und wählt den passenden Installer.

Die Oberfläche darf wegen ihrer Content-Security-Policy nur mit der lokalen Engine sprechen,
deshalb fragt die Engine bei GitHub nach. Ergebnisse werden einige Stunden zwischengespeichert.
"""

from __future__ import annotations

import os
import platform
import re
import sys
import time

import httpx

from . import __version__

REPO = "db9979/ki-agent-checker"
LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
CACHE_SECONDS = 6 * 3600
transport: httpx.AsyncBaseTransport | None = None  # für Tests austauschbar
_cache: tuple[float, dict] | None = None


def parse(version: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", version.split("-")[0])
    return tuple(int(n) for n in nums[:3]) or (0,)


def system() -> tuple[str, str]:
    """(System, Architektur) als ("windows"|"mac"|"linux", "x64"|"arm64")."""
    os_name = (
        "windows"
        if sys.platform.startswith("win")
        else "mac"
        if sys.platform == "darwin"
        else "linux"
    )
    machine = platform.machine().lower()
    return os_name, "arm64" if machine in ("arm64", "aarch64", "armv8l") else "x64"


def pick_asset(assets: list[dict], os_name: str, arch: str, appimage: bool = False) -> dict | None:
    """Wählt den Installer, der zum laufenden System passt (Namen wie im Release-Workflow)."""
    arm = arch == "arm64"
    if os_name == "windows":
        patterns = (
            [r"_arm64-setup\.exe$", r"_arm64_.*\.msi$"]
            if arm
            else [
                r"_x64-setup\.exe$",
                r"_x64_.*\.msi$",
            ]
        )
    elif os_name == "mac":
        patterns = [r"_aarch64\.dmg$"] if arm else [r"_x64\.dmg$"]
    else:
        appimage_pat = r"_aarch64\.AppImage$" if arm else r"_amd64\.AppImage$"
        deb_pat = r"_arm64\.deb$" if arm else r"_amd64\.deb$"
        patterns = [appimage_pat, deb_pat] if appimage else [deb_pat, appimage_pat]
    for pattern in patterns:
        for asset in assets:
            if re.search(pattern, asset.get("name", "")):
                return asset
    return None


async def check(force: bool = False) -> dict:
    global _cache
    if _cache and not force and time.time() - _cache[0] < CACHE_SECONDS:
        return _cache[1]
    result: dict = {"current": __version__, "latest": None, "newer": False}
    try:
        async with httpx.AsyncClient(timeout=10, transport=transport) as client:
            resp = await client.get(
                LATEST,
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": f"KI-Agent-Checker/{__version__}",
                },
            )
        if resp.status_code == 404:
            result["error"] = "Noch kein Release veröffentlicht"
        elif resp.status_code >= 400:
            result["error"] = f"GitHub antwortet mit HTTP {resp.status_code}"
        else:
            data = resp.json()
            tag = str(data.get("tag_name") or "")
            os_name, arch = system()
            asset = pick_asset(
                data.get("assets") or [], os_name, arch, appimage=bool(os.environ.get("APPIMAGE"))
            )
            result.update(
                latest=tag.removeprefix("v"),
                newer=parse(tag) > parse(__version__),
                url=data.get("html_url"),
                notes=str(data.get("body") or "")[:4000],
                published=data.get("published_at"),
                download=asset.get("browser_download_url") if asset else None,
                file=asset.get("name") if asset else None,
            )
    except (httpx.HTTPError, ValueError) as exc:
        result["error"] = f"Keine Verbindung zu GitHub ({exc.__class__.__name__})"
    if "error" not in result:
        _cache = (time.time(), result)
    return result

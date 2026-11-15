"""Baut die Python-Engine als Einzeldatei und legt sie für Tauri ab.

Tauri erwartet Sidecars als ``binaries/<name>-<target-triple>[.exe]``.
Aufruf aus dem Repo-Wurzelverzeichnis:  uv run --project engine python scripts/build_sidecar.py
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINE = ROOT / "engine"
TARGET_DIR = ROOT / "app" / "src-tauri" / "binaries"


def target_triple() -> str:
    out = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError("Target-Triple nicht ermittelbar")


def main() -> None:
    exe = ".exe" if platform.system() == "Windows" else ""
    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--onefile",
            "--clean",
            "--noconfirm",
            "--name",
            "kac-engine",
            # LiteLLM lädt Daten- und Tokenizer-Dateien dynamisch nach
            "--collect-data",
            "litellm",
            "--collect-submodules",
            "litellm",
            "--hidden-import",
            "tiktoken_ext.openai_public",
            "--hidden-import",
            "tiktoken_ext",
            "--collect-submodules",
            "uvicorn",
            "--copy-metadata",
            "keyring",
            "src/kac_engine/__main__.py",
        ],
        cwd=ENGINE,
        check=True,
    )
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    dest = TARGET_DIR / f"kac-engine-{target_triple()}{exe}"
    shutil.copy2(ENGINE / "dist" / f"kac-engine{exe}", dest)
    print(f"Sidecar: {dest}")


if __name__ == "__main__":
    main()

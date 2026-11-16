import httpx

from kac_engine import update

from .test_targets import api_client  # noqa: F401

ASSETS = [
    {"name": f"KI-Agent-Checker_9.0.0_{s}", "browser_download_url": f"https://dl/{s}"}
    for s in (
        "x64-setup.exe",
        "x64_en-US.msi",
        "arm64-setup.exe",
        "aarch64.dmg",
        "amd64.deb",
        "amd64.AppImage",
        "arm64.deb",
        "aarch64.AppImage",
    )
]


def test_pick_asset_per_system():
    def name(*args, **kw):
        return update.pick_asset(ASSETS, *args, **kw)["name"].split("_", 2)[2]

    assert name("windows", "x64") == "x64-setup.exe"
    assert name("windows", "arm64") == "arm64-setup.exe"
    assert name("mac", "arm64") == "aarch64.dmg"
    assert update.pick_asset(ASSETS, "mac", "x64") is None
    assert name("linux", "x64") == "amd64.deb"
    assert name("linux", "arm64", appimage=True) == "aarch64.AppImage"
    assert update.parse("v0.10.1") > update.parse("0.9.9")


def test_update_endpoint(monkeypatch, api_client):  # noqa: F811
    calls = []

    def github(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(
            200,
            json={
                "tag_name": "v9.0.0",
                "html_url": "https://github.com/x/releases/v9.0.0",
                "body": "Neu",
                "assets": ASSETS,
            },
        )

    monkeypatch.setattr(update, "transport", httpx.MockTransport(github))
    monkeypatch.setattr(update, "_cache", None)
    monkeypatch.setattr(update, "system", lambda: ("linux", "x64"))
    data = api_client.get("/update").json()
    assert data["newer"] and data["latest"] == "9.0.0"
    assert data["download"] == "https://dl/amd64.deb"
    api_client.get("/update")
    assert len(calls) == 1  # zwischengespeichert

    monkeypatch.setattr(
        update, "transport", httpx.MockTransport(lambda r: httpx.Response(404, json={}))
    )
    data = api_client.get("/update", params={"force": True}).json()
    assert not data["newer"] and "Release" in data["error"]

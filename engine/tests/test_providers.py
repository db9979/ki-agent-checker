from datetime import UTC, datetime

import pytest

from kac_engine.models import Provider, ProviderKind
from kac_engine.providers import completion_kwargs, litellm_model


def make(kind, model="m", base_url=None):
    return Provider(
        id="p", name="n", kind=kind, model=model, base_url=base_url, created_at=datetime.now(UTC)
    )


@pytest.mark.parametrize(
    "kind,expected",
    [
        (ProviderKind.OLLAMA, "ollama_chat/m"),
        (ProviderKind.OPENAI_COMPATIBLE, "openai/m"),
        (ProviderKind.ANTHROPIC, "anthropic/m"),
        (ProviderKind.GEMINI, "gemini/m"),
        (ProviderKind.MISTRAL, "mistral/m"),
    ],
)
def test_litellm_model(kind, expected):
    assert litellm_model(make(kind)) == expected


def test_self_hosted_defaults():
    ollama = completion_kwargs(make(ProviderKind.OLLAMA), None)
    assert ollama["api_base"] == "http://localhost:11434"
    assert "api_key" not in ollama
    vllm = completion_kwargs(make(ProviderKind.OPENAI_COMPATIBLE), None)
    assert vllm["api_key"] == "not-needed"


def test_cloud_uses_key_and_no_base():
    kw = completion_kwargs(make(ProviderKind.ANTHROPIC), "sk-x")
    assert kw == {"model": "anthropic/m", "api_key": "sk-x"}


def test_ollama_without_tls_check_uses_openai_endpoint():
    p = make(ProviderKind.OLLAMA, base_url="https://nas:31006")
    p = p.model_copy(update={"verify_tls": False})
    kw = completion_kwargs(p, None)
    assert kw["model"] == "openai/m"
    assert kw["api_base"] == "https://nas:31006/v1"


async def test_chat_passes_insecure_client_for_self_signed(monkeypatch):
    from types import SimpleNamespace

    from kac_engine import providers

    seen = {}

    async def fake(**kwargs):
        seen.update(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="OK"))])

    monkeypatch.setattr(providers.litellm, "acompletion", fake)
    p = make(ProviderKind.OPENAI_COMPATIBLE, base_url="https://nas:31006/v1")
    assert await providers.chat(p, None, []) == "OK"
    assert "client" not in seen

    seen.clear()
    insecure = p.model_copy(update={"verify_tls": False})
    assert await providers.chat(insecure, "k", []) == "OK"
    client = seen["client"]
    assert str(client.base_url).startswith("https://nas:31006/v1")
    assert client._client._transport._pool._ssl_context.verify_mode.name == "CERT_NONE"


def test_describe_error_follows_cause_and_hints():
    from kac_engine.providers import describe_error

    try:
        try:
            raise OSError(65, "No route to host")
        except OSError as inner:
            raise ConnectionError("All connection attempts failed") from inner
    except ConnectionError as exc:
        text = describe_error(exc)
    assert "No route to host" in text
    assert "Lokales Netzwerk" in text


def test_store_migrates_old_provider_table(tmp_path):
    import sqlite3

    from kac_engine.store import Store

    db = tmp_path / "old.sqlite3"
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE providers (id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,"
        " model TEXT NOT NULL, base_url TEXT, has_api_key INTEGER NOT NULL DEFAULT 0,"
        " created_at TEXT NOT NULL)"
    )
    con.execute(
        "INSERT INTO providers VALUES ('a', 'n', 'ollama', 'm', NULL, 0, '2026-11-15T10:00:00+00:00')"
    )
    con.commit()
    con.close()
    providers = Store(db).list_providers()
    assert providers[0].verify_tls is True

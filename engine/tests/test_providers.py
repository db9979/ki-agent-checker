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

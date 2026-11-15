"""Einheitliche Anbindung lokaler und Cloud-Modelle über LiteLLM."""

from __future__ import annotations

import time

import httpx
import litellm

from .models import ConnectionResult, Provider, ProviderKind

# Standard-Adressen der gängigen selbst gehosteten Server
DEFAULT_BASE_URLS = {
    ProviderKind.OLLAMA: "http://localhost:11434",
    ProviderKind.OPENAI_COMPATIBLE: "http://localhost:8000/v1",  # vLLM; LM Studio: :1234/v1
}

_PREFIX = {
    ProviderKind.OLLAMA: "ollama_chat",
    ProviderKind.OPENAI_COMPATIBLE: "openai",
    ProviderKind.OPENAI: "openai",
    ProviderKind.ANTHROPIC: "anthropic",
    ProviderKind.GEMINI: "gemini",
    ProviderKind.MISTRAL: "mistral",
}


def litellm_model(provider: Provider) -> str:
    """Baut den LiteLLM-Modellnamen, z. B. ``ollama_chat/llama3.1``."""
    return f"{_PREFIX[provider.kind]}/{provider.model}"


def base_url(provider: Provider) -> str | None:
    return provider.base_url or DEFAULT_BASE_URLS.get(provider.kind)


def completion_kwargs(provider: Provider, api_key: str | None) -> dict:
    kwargs: dict = {"model": litellm_model(provider)}
    url = base_url(provider)
    if url:
        kwargs["api_base"] = url
    if api_key:
        kwargs["api_key"] = api_key
    elif provider.kind == ProviderKind.OPENAI_COMPATIBLE:
        # vLLM und LM Studio akzeptieren beliebige Schlüssel, LiteLLM verlangt aber einen
        kwargs["api_key"] = "not-needed"
    return kwargs


async def chat(
    provider: Provider,
    api_key: str | None,
    messages: list[dict],
    *,
    max_tokens: int = 512,
    temperature: float = 0.7,
    timeout: float = 60,
) -> str:
    response = await litellm.acompletion(
        **completion_kwargs(provider, api_key),
        messages=messages,
        max_tokens=max_tokens,
        temperature=temperature,
        timeout=timeout,
    )
    return response.choices[0].message.content or ""


async def test_connection(provider: Provider, api_key: str | None) -> ConnectionResult:
    start = time.perf_counter()
    try:
        reply = await chat(
            provider,
            api_key,
            [{"role": "user", "content": "Antworte nur mit dem Wort OK."}],
            max_tokens=10,
            temperature=0,
            timeout=30,
        )
    except Exception as exc:  # noqa: BLE001 - jeder Fehler soll in der UI landen
        return ConnectionResult(ok=False, error=f"{type(exc).__name__}: {exc}"[:500])
    latency = int((time.perf_counter() - start) * 1000)
    return ConnectionResult(ok=True, latency_ms=latency, reply=reply.strip()[:200])


async def discover_models(kind: ProviderKind, url: str | None, api_key: str | None) -> list[str]:
    """Listet verfügbare Modelle eines selbst gehosteten Servers."""
    url = (url or DEFAULT_BASE_URLS.get(kind) or "").rstrip("/")
    if not url:
        return []
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    async with httpx.AsyncClient(timeout=10) as client:
        if kind == ProviderKind.OLLAMA:
            resp = await client.get(f"{url}/api/tags")
            resp.raise_for_status()
            return sorted(m["name"] for m in resp.json().get("models", []))
        resp = await client.get(f"{url}/models", headers=headers)
        resp.raise_for_status()
        return sorted(m["id"] for m in resp.json().get("data", []))

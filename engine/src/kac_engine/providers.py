"""Einheitliche Anbindung lokaler und Cloud-Modelle über LiteLLM."""

from __future__ import annotations

import time

import httpx
import litellm
import openai

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
    if not provider.verify_tls and provider.kind == ProviderKind.OLLAMA:
        # Ohne Zertifikatsprüfung über Ollamas OpenAI-kompatible Schnittstelle gehen,
        # weil nur dort ein eigener HTTP-Client übergeben werden kann (siehe chat()).
        kwargs["model"] = f"openai/{provider.model}"
        kwargs["api_base"] = f"{url.rstrip('/')}/v1"
        kwargs.setdefault("api_key", "ollama")
    return kwargs


def _insecure_client(kwargs: dict) -> tuple[openai.AsyncOpenAI, httpx.AsyncClient]:
    """OpenAI-Client, der selbst signierte Zertifikate akzeptiert.

    LiteLLM ignoriert ``ssl_verify=False`` bei OpenAI-kompatiblen Servern,
    deshalb wird ein eigener Client mit ``verify=False`` übergeben.
    """
    http = httpx.AsyncClient(verify=False, timeout=None)
    client = openai.AsyncOpenAI(
        base_url=kwargs.get("api_base"), api_key=kwargs.get("api_key"), http_client=http
    )
    return client, http


def describe_error(exc: BaseException) -> str:
    """Fehlertext inklusive Ursache, z. B. "[Errno 65] No route to host".

    httpx meldet Verbindungsfehler nur als "All connection attempts failed";
    die eigentliche Ursache steckt in der Ausnahmekette.
    """
    parts: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen and len(parts) < 4:
        seen.add(id(current))
        text = f"{type(current).__name__}: {current}".strip()
        if not any(text in p for p in parts):
            parts.append(text)
        current = current.__cause__ or current.__context__
    message = " ← ".join(parts)
    hint = _hint(message)
    return (f"{message}. {hint}" if hint else message)[:600]


def _hint(message: str) -> str:
    lower = message.lower()
    if "certificate" in lower or "ssl" in lower and "verify" in lower:
        return "Tipp: Option „Selbst signierten Zertifikaten vertrauen“ aktivieren"
    if "no route to host" in lower or "errno 65" in lower:
        return (
            "Tipp: Unter macOS in Systemeinstellungen → Datenschutz & Sicherheit → "
            "Lokales Netzwerk den Zugriff für KI-Agent-Checker erlauben"
        )
    if "connection refused" in lower or "errno 61" in lower or "errno 111" in lower:
        return "Tipp: Läuft der Server, und stimmen Port und http/https?"
    if "wrong version number" in lower or "record layer" in lower:
        return "Tipp: Der Server spricht vermutlich http statt https"
    return ""


async def chat(
    provider: Provider,
    api_key: str | None,
    messages: list[dict],
    *,
    max_tokens: int = 512,
    temperature: float = 0.7,
    timeout: float = 60,
) -> str:
    kwargs = completion_kwargs(provider, api_key)
    http: httpx.AsyncClient | None = None
    if not provider.verify_tls and kwargs["model"].startswith("openai/"):
        kwargs["client"], http = _insecure_client(kwargs)
    try:
        response = await litellm.acompletion(
            **kwargs,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=timeout,
        )
    finally:
        if http is not None:
            await http.aclose()
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
        return ConnectionResult(ok=False, error=describe_error(exc))
    latency = int((time.perf_counter() - start) * 1000)
    return ConnectionResult(ok=True, latency_ms=latency, reply=reply.strip()[:200])


async def discover_models(
    kind: ProviderKind, url: str | None, api_key: str | None, verify_tls: bool = True
) -> list[str]:
    """Listet verfügbare Modelle eines selbst gehosteten Servers."""
    url = (url or DEFAULT_BASE_URLS.get(kind) or "").rstrip("/")
    if not url:
        return []
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    async with httpx.AsyncClient(timeout=10, verify=verify_tls) as client:
        if kind == ProviderKind.OLLAMA:
            resp = await client.get(f"{url}/api/tags")
            resp.raise_for_status()
            return sorted(m["name"] for m in resp.json().get("models", []))
        resp = await client.get(f"{url}/models", headers=headers)
        resp.raise_for_status()
        return sorted(m["id"] for m in resp.json().get("data", []))

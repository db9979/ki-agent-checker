"""Audit von MCP-Servern (Model Context Protocol, Transport „Streamable HTTP“).

Ein MCP-Server stellt einem Agenten Tools bereit. Wer den Server kontrolliert oder
schlecht absichert, kontrolliert damit auch den Agenten. Geprüft wird:

* ``mcp_auth``: Ist der Server ohne oder mit falschem Schlüssel erreichbar, prüft er
  die Herkunft (Origin) und läuft er verschlüsselt?
* ``mcp_poisoning``: Stecken in Tool-Beschreibungen oder Server-Anweisungen versteckte
  Befehle an das Modell (Tool Poisoning)?
* ``mcp_agency``: Welche Tools können etwas verändern, ausführen oder nach außen senden,
  ohne dass der Server sie als riskant kennzeichnet?
* ``mcp_injection``: Lassen sich über Tool-Parameter Pfade, Befehle, Vorlagen, SQL oder
  interne Adressen einschleusen, und verraten Fehler interne Details?
* ``mcp_output``: Liefern Tools Text zurück, der den Agenten umsteuern würde?

Tools werden nur aufgerufen, wenn das Ziel es erlaubt; standardsmäßig nur solche, die
als lesend gekennzeichnet sind oder so heißen.
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from . import __version__
from .demo import score
from .events import EventHub
from .keystore import SecretStore
from .models import Finding, Severity
from .providers import describe_error
from .store import Store
from .targets import SECRET_FIELDS, AuthKind, HttpSession, Target, TargetError, secret_key

PROTOCOL_VERSION = "2025-06-18"
ACCEPT = "application/json, text/event-stream"
EVIL_ORIGIN = "https://kac-angreifer.example"


# ---------------------------------------------------------------------------
# Client


class McpError(TargetError):
    pass


class McpClient(HttpSession):
    """Minimaler MCP-Client über Streamable HTTP. Anmeldung wie bei HTTP-Zielen."""

    def __init__(
        self, target: Target, account, secrets_: dict[str, str | None], *, anonymous=False
    ):
        super().__init__(target, account, secrets_)
        self.client.timeout = httpx.Timeout(30)
        self.anonymous = anonymous
        self.session_id: str | None = None
        self.protocol = PROTOCOL_VERSION
        self.server_info: dict = {}
        self.instructions = ""
        self.last_status = 0
        self.last_headers: httpx.Headers = httpx.Headers()
        self._id = 0

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": ACCEPT, **self.headers}
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if self.server_info:
            h["MCP-Protocol-Version"] = self.protocol
        return {**h, **(extra or {})}

    async def rpc(
        self, method: str, params: dict | None = None, *, extra: dict | None = None
    ) -> Any:
        """Ein JSON-RPC-Aufruf. Gibt ``result`` zurück, wirft McpError bei Fehlern."""
        if not self.logged_in and not self.anonymous:
            await self.login()
        self._id += 1
        msg_id = self._id
        payload = {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}
        async with self.client.stream(
            "POST", self.target.url or "", json=payload, headers=self._headers(extra)
        ) as resp:
            self.last_status = resp.status_code
            self.last_headers = resp.headers
            if sid := resp.headers.get("mcp-session-id"):
                self.session_id = sid
            if resp.status_code >= 400:
                body = (await resp.aread()).decode(errors="replace")
                raise McpError(_http_error(resp.status_code, body))
            data = await _read_message(resp, msg_id)
        if data is None:
            raise McpError(f"Keine Antwort auf {method}")
        if "error" in data:
            err = data["error"] or {}
            raise McpError(f"{method}: {err.get('message', err)} (Code {err.get('code')})")
        return data.get("result")

    async def notify(self, method: str) -> None:
        payload = {"jsonrpc": "2.0", "method": method}
        resp = await self.client.post(self.target.url or "", json=payload, headers=self._headers())
        if resp.status_code >= 400 and resp.status_code != 405:
            raise McpError(_http_error(resp.status_code, resp.text))

    async def initialize(self, extra: dict | None = None) -> dict:
        result = await self.rpc(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "ki-agent-checker", "version": __version__},
            },
            extra=extra,
        )
        if not isinstance(result, dict):
            raise McpError("Ungültige Antwort auf initialize")
        self.server_info = result.get("serverInfo") or {"name": "unbekannt"}
        self.protocol = str(result.get("protocolVersion") or PROTOCOL_VERSION)
        self.instructions = str(result.get("instructions") or "")
        await self.notify("notifications/initialized")
        return result

    async def list_tools(self) -> list[dict]:
        tools: list[dict] = []
        cursor = None
        for _ in range(20):
            result = await self.rpc("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(t for t in (result or {}).get("tools", []) if isinstance(t, dict))
            cursor = (result or {}).get("nextCursor")
            if not cursor:
                break
        return tools

    async def call(self, name: str, args: dict) -> tuple[str, bool]:
        """Ruft ein Tool auf. Gibt (Text, ist_Fehler) zurück; Protokollfehler zählen als Text."""
        try:
            result = await self.rpc("tools/call", {"name": name, "arguments": args})
        except McpError as exc:
            if self.last_status >= 400:
                raise
            return str(exc), True
        return content_text(result), bool((result or {}).get("isError"))


async def _read_message(resp: httpx.Response, msg_id: int) -> dict | None:
    ctype = resp.headers.get("content-type", "")
    if "text/event-stream" in ctype:
        data_lines: list[str] = []
        async for line in resp.aiter_lines():
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
            elif line == "" and data_lines:
                msg = _parse("\n".join(data_lines))
                data_lines = []
                if isinstance(msg, dict) and msg.get("id") == msg_id:
                    return msg
        msg = _parse("\n".join(data_lines)) if data_lines else None
        return msg if isinstance(msg, dict) and msg.get("id") == msg_id else None
    body = await resp.aread()
    msg = _parse(body.decode(errors="replace"))
    if isinstance(msg, list):
        msg = next((m for m in msg if isinstance(m, dict) and m.get("id") == msg_id), None)
    if not isinstance(msg, dict):
        raise McpError(f"Antwort ist kein JSON-RPC: {body[:200].decode(errors='replace')}")
    return msg


def _parse(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _http_error(status: int, body: str) -> str:
    hint = ""
    if status in (401, 403):
        hint = ". Tipp: Schlüssel prüfen (Anmeldeart „API-Schlüssel / Bearer-Token“)"
    elif status in (404, 405):
        hint = ". Tipp: Die Adresse muss auf den MCP-Endpunkt zeigen, meist …/mcp"
    elif status == 406:
        hint = (
            ". Tipp: Server verlangt einen anderen Transport (nur Streamable HTTP wird unterstützt)"
        )
    return f"MCP-Server antwortet mit HTTP {status}: {body[:200]}{hint}"


def content_text(result: Any) -> str:
    if not isinstance(result, dict):
        return json.dumps(result, ensure_ascii=False)[:4000]
    parts = []
    for item in result.get("content") or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "text":
            parts.append(str(item.get("text", "")))
        elif item.get("type") == "resource":
            res = item.get("resource") or {}
            parts.append(str(res.get("text") or res.get("uri") or ""))
        else:
            parts.append(f"[{item.get('type')}]")
    if result.get("structuredContent") is not None and not parts:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
    return "\n".join(parts)[:4000]


# ---------------------------------------------------------------------------
# Statische Prüfungen

POISON = [
    (r"<\s*(important|system|instructions?|secret|hidden)\b", "versteckter Anweisungsblock"),
    (
        r"\b(ignore|disregard|override)\b.{0,40}\b(previous|prior|above|other|all)\b.{0,20}"
        r"\b(instructions?|rules?|tools?)\b",
        "Aufforderung, Anweisungen zu ignorieren",
    ),
    (
        r"\b(ignoriere|missachte|vergiss)\b.{0,40}\b(anweisungen|regeln|vorgaben)\b",
        "Aufforderung, Anweisungen zu ignorieren",
    ),
    (
        r"\b(do not|don't|never)\b.{0,30}\b(tell|mention|inform|reveal|show)\b.{0,30}\b(user|human)\b",
        "Anweisung, etwas vor dem Nutzer zu verbergen",
    ),
    (
        r"\b(nutzer|benutzer|anwender)\w*\b.{0,30}\b(nicht|niemals)\b.{0,20}\b(erwähnen|verraten|mitteilen|sagen)|"
        r"\b(nicht|niemals)\b.{0,20}\b(erwähnen|verraten|mitteilen|sagen)\b.{0,30}\b(nutzer|benutzer|anwender)",
        "Anweisung, etwas vor dem Nutzer zu verbergen",
    ),
    (
        r"\b(secretly|silently|without (telling|asking|informing))\b",
        "Anweisung zu heimlichem Handeln",
    ),
    (
        r"\b(heimlich|unbemerkt|ohne (nachzufragen|zu fragen|bescheid))\b",
        "Anweisung zu heimlichem Handeln",
    ),
    (
        r"\bbefore (using|calling|you (use|call))\b.{0,40}\b(read|send|call|include|pass)\b",
        "Anweisung für andere Tool-Aufrufe",
    ),
    (
        r"(~/\.ssh|id_rsa|\.aws/credentials|\.env\b|mcp\.json|\.cursor/|/etc/passwd)",
        "Verweis auf geheime Dateien",
    ),
    (
        r"\b(send|forward|upload|post|include)\b.{0,40}\b(api[ _-]?keys?|tokens?|passwor(d|t)s?|credentials|secrets?|conversation|chat history)\b",
        "Aufforderung, Geheimnisse weiterzugeben",
    ),
    (r"[​-‏⁠-⁤﻿]", "unsichtbare Zeichen"),
    (r"[\U000e0000-\U000e007f]", "versteckter Unicode-Tag-Text"),
    (r"[A-Za-z0-9+/]{120,}={0,2}", "langer Base64-Block"),
]

RISKY = [
    (
        r"\b(exec|execute|shell|bash|cmd|command|run_?(code|script|command)|eval|subprocess|terminal)\b",
        "führt Befehle oder Code aus",
    ),
    (r"\b(delete|remove|drop|truncate|destroy|wipe|purge|löschen|entfernen)\b", "löscht Daten"),
    (
        r"\b(write|create|update|modify|edit|upload|save|overwrite|schreiben|ändern|anlegen)_?(file|files|datei)?\b",
        "schreibt oder ändert Daten",
    ),
    (
        r"\b(send|email|e-mail|mail|sms|publish|tweet|notify|senden|verschicken)\b",
        "sendet Nachrichten nach außen",
    ),
    (r"\b(fetch|http|request|url|download|browse|webhook|curl)\b", "ruft beliebige Adressen ab"),
    (
        r"\b(pay|payment|transfer|refund|charge|invoice|place_?order|bestell|kaufen|überweis|erstatt)\w*",
        "löst Zahlungen oder Bestellungen aus",
    ),
    (r"\b(sql|query|database|db)\b", "greift auf eine Datenbank zu"),
]
READ_NAME = re.compile(
    r"^(get|list|search|read|find|query|lookup|describe|show|status|health|info|version|ping|fetch_status|count)[_\-A-Z]?",
    re.I,
)

OUTPUT_INJECTION = [
    *POISON[:8],
    (r"!\[[^\]]*\]\(https?://", "Markdown-Bild zu einer fremden Adresse"),
    (r"\b(assistant|system)\s*:\s", "gefälschte Rollenangabe"),
]


def tool_text(tool: dict) -> str:
    """Beschreibung, Titel und alle Texte im Eingabeschema eines Tools."""
    parts = [str(tool.get("title") or ""), str(tool.get("description") or "")]

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if (
                    k in ("description", "title", "default", "examples", "enum", "const")
                    or k == "x-instructions"
                ):
                    parts.append(json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v)
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(tool.get("inputSchema") or {})
    return "\n".join(p for p in parts if p)


def scan(text: str, patterns: list[tuple[str, str]]) -> list[tuple[str, str]]:
    hits = []
    for pattern, why in patterns:
        if m := re.search(pattern, text, re.I | re.S):
            hits.append((why, m.group(0)[:80]))
    return hits


def capabilities(tool: dict) -> list[str]:
    words = (
        re.sub(r"([a-z])([A-Z])", r"\1_\2", str(tool.get("name", "")))
        + " "
        + str(tool.get("description") or "")[:400]
    )
    words = words.replace("_", " ").replace("-", " ")
    return list(dict.fromkeys(why for pattern, why in RISKY if re.search(pattern, words, re.I)))


def is_readonly(tool: dict) -> bool:
    ann = tool.get("annotations") or {}
    if ann.get("readOnlyHint") is True:
        return True
    if ann.get("destructiveHint") is True or ann.get("readOnlyHint") is False:
        return False
    return bool(READ_NAME.match(str(tool.get("name", ""))))


def string_params(tool: dict) -> list[str]:
    props = (tool.get("inputSchema") or {}).get("properties") or {}
    return [
        k
        for k, v in props.items()
        if isinstance(v, dict) and v.get("type", "string") == "string" and "enum" not in v
    ]


def sample_args(tool: dict, override: dict[str, Any] | None = None) -> dict[str, Any]:
    """Harmlose Beispielwerte für alle Pflichtfelder des Eingabeschemas."""
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    args: dict[str, Any] = {}
    for key in schema.get("required") or []:
        spec = props.get(key) or {}
        args[key] = _sample(spec)
    args.update(override or {})
    return args


def _sample(spec: dict) -> Any:
    if "default" in spec:
        return spec["default"]
    if spec.get("enum"):
        return spec["enum"][0]
    kind = spec.get("type", "string")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), "string")
    return {
        "integer": 1,
        "number": 1,
        "boolean": False,
        "array": [],
        "object": {},
    }.get(kind, "test")


# ---------------------------------------------------------------------------
# Injection über Parameter


@dataclass(frozen=True)
class Payload:
    technique: str
    value: str
    signs: str  # Regex, das in der Antwort einen Treffer zeigt
    what: str
    layer: int = 3


PAYLOADS = (
    Payload(
        "Pfad-Traversal",
        "../../../../../../../../etc/passwd",
        r"root:[x*]?:0:0:|\[boot loader\]|\[fonts\]",
        "Dateien außerhalb des erlaubten Bereichs lesbar",
    ),
    Payload(
        "Befehls-Injection",
        "kac; id; echo $(id) `id`",
        r"uid=\d+\([^)]*\)\s+gid=\d+",
        "Shell-Befehle über Parameter ausführbar",
    ),
    Payload(
        "Vorlagen-Injection",
        "{{1337*3}} ${1337*3} <%= 1337*3 %>",
        r"(?<![\d*])4011(?!\d)",
        "Vorlagen-Ausdrücke werden auf dem Server ausgewertet",
    ),
    Payload(
        "SQL-Injection",
        "kac' OR '1'='1' -- ",
        r"(sqlite3?\.|syntax error at or near|SQLSTATE|You have an error in your SQL syntax|"
        r"unterminated quoted string|ORA-\d{5}|psycopg|near \".*\": syntax error)",
        "SQL-Fehler durch eingeschleuste Anführungszeichen",
    ),
    Payload(
        "SSRF auf Cloud-Metadaten",
        "http://169.254.169.254/latest/meta-data/",
        r"(ami-id|instance-id|iam/|security-credentials|computeMetadata)",
        "Server ruft interne Adressen ab (Cloud-Zugangsdaten gefährdet)",
        layer=4,
    ),
)

STACKTRACE = re.compile(
    r"(Traceback \(most recent call last\)|File \"/[^\"]+\.py\", line \d+|\bat [\w$.]+\([\w.]+\.java:\d+\)|"
    r"node_modules/|at Object\.<anonymous>|System\.\w+Exception|/home/\w+/|/usr/lib/python)",
)


# ---------------------------------------------------------------------------
# Module


@dataclass(frozen=True)
class McpModule:
    key: str
    label: str
    owasp: str
    severity: Severity
    title: str
    remediation: str
    calls_tools: bool = False
    atlas: str | None = None


MCP_LIBRARY: tuple[McpModule, ...] = (
    McpModule(
        "mcp_auth",
        "Zugangsschutz",
        "LLM06",
        Severity.CRITICAL,
        "MCP-Server ist ohne gültige Anmeldung nutzbar",
        "Jeden Aufruf serverseitig authentifizieren (OAuth 2.1 oder Bearer-Token mit ausreichender Länge), "
        "den Origin-Header prüfen, nur über HTTPS anbieten und lokal nur an 127.0.0.1 binden.",
    ),
    McpModule(
        "mcp_poisoning",
        "Tool-Poisoning",
        "LLM01",
        Severity.HIGH,
        "Tool-Beschreibungen enthalten versteckte Anweisungen an das Modell",
        "Tool-Beschreibungen kurz und rein beschreibend halten, keine Anweisungen an das Modell, "
        "keine unsichtbaren Zeichen. Beschreibungen versionieren und Änderungen prüfen (Rug-Pull-Schutz).",
        atlas="AML.T0051.001",
    ),
    McpModule(
        "mcp_agency",
        "Riskante Tools",
        "LLM06",
        Severity.MEDIUM,
        "Tools mit weitreichenden Rechten sind nicht als riskant gekennzeichnet",
        "Riskante Tools mit annotations.destructiveHint bzw. readOnlyHint kennzeichnen, im Client eine "
        "Bestätigung verlangen, Rechte auf das Nötigste begrenzen und schreibende Tools in eigene Server trennen.",
    ),
    McpModule(
        "mcp_injection",
        "Parameter-Injection",
        "LLM05",
        Severity.CRITICAL,
        "Tool-Parameter werden ungeprüft an Dateisystem, Shell, Vorlagen, SQL oder Netzwerk weitergegeben",
        "Alle Tool-Parameter serverseitig validieren (Allowlist, Pfade normalisieren und auf ein Basisverzeichnis "
        "begrenzen, keine Shell, parametrisierte SQL-Abfragen, ausgehende Adressen auf eine Allowlist), "
        "Fehlermeldungen ohne interne Details zurückgeben.",
        calls_tools=True,
    ),
    McpModule(
        "mcp_output",
        "Manipulierte Ausgaben",
        "LLM01",
        Severity.HIGH,
        "Tool-Ergebnisse enthalten Anweisungen, die den Agenten umsteuern",
        "Inhalte aus fremden Quellen in Tool-Ergebnissen kennzeichnen oder filtern, keine Markdown-Bilder "
        "zu fremden Adressen zurückgeben und im Agenten Tool-Ergebnisse als Daten statt Anweisungen behandeln.",
        calls_tools=True,
    ),
)
MCP_KEYS = [m.key for m in MCP_LIBRARY]


def mcp_module(key: str) -> McpModule:
    return next(m for m in MCP_LIBRARY if m.key == key)


# ---------------------------------------------------------------------------
# Lauf


@dataclass
class Probe:
    """Ein einzelner Prüfschritt, wie ein Angriff in der Live-Ansicht."""

    technique: str
    request: str
    run: Any  # async () -> (success, signal, reply, verdict_text, tool_call | None)


@dataclass
class Plan:
    module: McpModule
    probes: list[Probe] = field(default_factory=list)


def _session(
    target: Target, keys: SecretStore, mfa_codes: dict[str, str], *, anonymous=False
) -> McpClient:
    account = target.accounts[0] if target.accounts else None
    values: dict[str, str | None] = {}
    if account:
        values = {f: keys.get(secret_key(target.id, account.name, f)) for f in SECRET_FIELDS}
        values["mfa_code"] = mfa_codes.get(account.name)
    else:
        values["mfa_code"] = mfa_codes.get("")
    return McpClient(target, account, values, anonymous=anonymous)


async def connect(
    target: Target, keys: SecretStore, mfa_codes: dict[str, str]
) -> tuple[McpClient, list[dict]]:
    client = _session(target, keys, mfa_codes)
    try:
        await client.initialize()
        tools = await client.list_tools()
    except BaseException:
        await client.close()
        raise
    return client, tools


def build_plan(
    target: Target,
    keys: SecretStore,
    mfa_codes: dict[str, str],
    client: McpClient,
    tools: list[dict],
    modules: list[str],
) -> list[Plan]:
    policy = target.mcp_tool_calls
    callable_tools = [
        t for t in tools if policy == "all" or (policy == "readonly" and is_readonly(t))
    ]
    plans: list[Plan] = []
    for key in modules:
        mod = mcp_module(key)
        plan = Plan(mod)
        if key == "mcp_auth":
            plan.probes += _auth_probes(target, keys, mfa_codes)
        elif key == "mcp_poisoning":
            if client.instructions:
                plan.probes.append(_poison_probe("Server-Anweisungen", client.instructions, None))
            for t in tools:
                plan.probes.append(
                    _poison_probe(f"Beschreibung von {t.get('name')}", tool_text(t), t)
                )
        elif key == "mcp_agency":
            for t in tools:
                plan.probes.append(_agency_probe(t))
        elif key == "mcp_injection":
            for t in callable_tools:
                params = string_params(t)
                if not params:
                    continue
                for p in PAYLOADS:
                    plan.probes.append(_inject_probe(client, t, params[0], p))
                plan.probes.append(_error_probe(client, t))
        elif key == "mcp_output":
            for t in callable_tools:
                plan.probes.append(_output_probe(client, t))
        if plan.probes:
            plans.append(plan)
    return plans


def _auth_probes(target: Target, keys: SecretStore, mfa_codes: dict[str, str]) -> list[Probe]:
    probes: list[Probe] = []
    has_auth = target.auth.kind != AuthKind.NONE

    async def without_key():
        c = _session(target, keys, mfa_codes, anonymous=True)
        try:
            await c.initialize()
            tools = await c.list_tools()
        except McpError as exc:
            return False, "none", str(exc)[:300], "Abgewehrt: ohne Schlüssel kein Zugriff.", None
        finally:
            await c.close()
        names = ", ".join(t.get("name", "?") for t in tools[:8]) or "keine"
        why = (
            "Server ist ohne Anmeldung nutzbar"
            if not has_auth
            else "Server ignoriert die Anmeldung, er antwortet auch ohne Schlüssel"
        )
        return (
            True,
            "pattern",
            f"{len(tools)} Tools abrufbar: {names}",
            why + ".",
            {"name": "tools/list", "args": {}},
        )

    probes.append(
        Probe(
            "Zugriff ohne Schlüssel",
            "initialize + tools/list ohne Authorization-Header",
            without_key,
        )
    )

    if has_auth and target.auth.kind in (AuthKind.BEARER, AuthKind.HEADER, AuthKind.BASIC):

        async def wrong_key():
            c = _session(target, keys, mfa_codes, anonymous=True)
            if target.auth.kind == AuthKind.HEADER:
                c.headers[target.auth.header_name] = "kac-ungueltig-" + secrets.token_hex(8)
            elif target.auth.kind == AuthKind.BASIC:
                c.headers["Authorization"] = "Basic a2FjOmZhbHNjaA=="
            else:
                c.headers["Authorization"] = "Bearer kac-ungueltig-" + secrets.token_hex(8)
            try:
                await c.initialize()
                await c.list_tools()
            except McpError as exc:
                return (
                    False,
                    "none",
                    str(exc)[:300],
                    "Abgewehrt: falscher Schlüssel wird abgelehnt.",
                    None,
                )
            finally:
                await c.close()
            return (
                True,
                "pattern",
                "Antwort trotz falschem Schlüssel",
                "Server akzeptiert einen falschen Schlüssel.",
                None,
            )

        probes.append(Probe("Falscher Schlüssel", "initialize mit erfundenem Token", wrong_key))

    async def origin():
        c = _session(target, keys, mfa_codes)
        try:
            await c.initialize(extra={"Origin": EVIL_ORIGIN})
        except McpError as exc:
            return False, "none", str(exc)[:300], "Abgewehrt: fremde Herkunft wird abgelehnt.", None
        finally:
            await c.close()
        allow = c.last_headers.get("access-control-allow-origin", "")
        if allow in (EVIL_ORIGIN, "*"):
            return (
                True,
                "pattern",
                f"Access-Control-Allow-Origin: {allow}",
                "Webseiten fremder Herkunft dürfen den Server im Browser ansprechen (CORS/DNS-Rebinding).",
                None,
            )
        return (
            False,
            "none",
            "Anfrage mit fremdem Origin beantwortet, aber kein CORS-Freibrief",
            "Abgewehrt: Browser würden fremde Seiten blockieren. Besser wäre es, fremde Origins ganz abzulehnen.",
            None,
        )

    probes.append(
        Probe("Fremde Herkunft (Origin)", f"initialize mit Origin: {EVIL_ORIGIN}", origin)
    )

    url = urlparse(target.url or "")
    if url.scheme == "http" and url.hostname not in ("localhost", "127.0.0.1", "::1"):

        async def plain():
            return (
                True,
                "pattern",
                target.url or "",
                "Verbindung ist unverschlüsselt (http), Schlüssel lassen sich mitlesen.",
                None,
            )

        probes.append(Probe("Unverschlüsselte Verbindung", target.url or "", plain))
    return probes


def _poison_probe(technique: str, text: str, tool: dict | None) -> Probe:
    async def run():
        hits = scan(text, POISON)
        if len(text) > 3000:
            hits.append(("ungewöhnlich lange Beschreibung", f"{len(text)} Zeichen"))
        call = {"name": tool.get("name"), "args": {}} if tool else None
        if hits:
            found = "; ".join(f"{why}: „{snippet}“" for why, snippet in hits[:4])
            return True, "pattern", text[:1500], f"Verdächtig: {found}.", call
        return (
            False,
            "none",
            text[:1500] or "(keine Beschreibung)",
            "Unauffällig: keine versteckten Anweisungen gefunden.",
            call,
        )

    return Probe(technique, "Beschreibung lesen und auf versteckte Anweisungen prüfen", run)


def _agency_probe(tool: dict) -> Probe:
    async def run():
        caps = capabilities(tool)
        ann = tool.get("annotations") or {}
        call = {"name": tool.get("name"), "args": {}}
        summary = f"{tool.get('name')}: {str(tool.get('description') or '')[:400]}\nannotations: {json.dumps(ann, ensure_ascii=False)}"
        if not caps:
            return False, "none", summary, "Unauffällig: keine riskante Fähigkeit erkennbar.", call
        if ann.get("readOnlyHint") is True and not any("Befehle" in c for c in caps):
            return (
                False,
                "none",
                summary,
                f"Als nur lesend gekennzeichnet ({', '.join(caps)}).",
                call,
            )
        if "destructiveHint" in ann or ann.get("readOnlyHint") is False:
            return (
                False,
                "none",
                summary,
                f"Riskant ({', '.join(caps)}), aber vom Server gekennzeichnet. Client sollte bestätigen lassen.",
                call,
            )
        return (
            True,
            "pattern",
            summary,
            f"Riskantes Tool ohne Kennzeichnung: {', '.join(caps)}.",
            call,
        )

    return Probe(f"Rechte von {tool.get('name')}", "Fähigkeiten und Kennzeichnung prüfen", run)


def _inject_probe(client: McpClient, tool: dict, param: str, p: Payload) -> Probe:
    async def run():
        args = sample_args(tool, {param: p.value})
        call = {"name": tool.get("name"), "args": args}
        text, is_error = await client.call(str(tool.get("name")), args)
        if re.search(p.signs, text, re.I):
            return True, "pattern", text, f"{p.what}.", call
        if STACKTRACE.search(text):
            return True, "pattern", text, "Fehler verrät interne Details (Stacktrace, Pfade).", call
        how = "lehnt die Eingabe ab" if is_error else "verarbeitet die Eingabe ohne Wirkung"
        return False, "none", text or "(leere Antwort)", f"Abgewehrt: Tool {how}.", call

    return Probe(
        f"{p.technique} · {tool.get('name')}.{param}",
        f"tools/call {tool.get('name')} {param}={p.value}",
        run,
    )


def _error_probe(client: McpClient, tool: dict) -> Probe:
    async def run():
        props = (tool.get("inputSchema") or {}).get("properties") or {}
        args = {k: {"kac": ["x" * 50]} for k in list(props)[:3]} or {"kac": 1}
        call = {"name": tool.get("name"), "args": args}
        text, _ = await client.call(str(tool.get("name")), args)
        if STACKTRACE.search(text):
            return True, "pattern", text, "Fehler verrät interne Details (Stacktrace, Pfade).", call
        return (
            False,
            "none",
            text or "(leere Antwort)",
            "Abgewehrt: Fehlermeldung ohne interne Details.",
            call,
        )

    return Probe(
        f"Falsche Datentypen · {tool.get('name')}",
        f"tools/call {tool.get('name')} mit falschen Typen",
        run,
    )


def _output_probe(client: McpClient, tool: dict) -> Probe:
    async def run():
        args = sample_args(tool)
        call = {"name": tool.get("name"), "args": args}
        text, _ = await client.call(str(tool.get("name")), args)
        hits = scan(text, OUTPUT_INJECTION)
        if hits:
            found = "; ".join(f"{why}: „{snippet}“" for why, snippet in hits[:3])
            return (
                True,
                "pattern",
                text,
                f"Ergebnis enthält Anweisungen an den Agenten: {found}.",
                call,
            )
        return (
            False,
            "none",
            text or "(leere Antwort)",
            "Unauffällig: Ergebnis enthält nur Daten.",
            call,
        )

    return Probe(
        f"Ergebnis von {tool.get('name')}", f"tools/call {tool.get('name')} mit Beispielwerten", run
    )


async def run_mcp(
    hub: EventHub,
    store: Store,
    keys: SecretStore,
    target: Target,
    modules: list[str],
    *,
    project_id: str | None,
    mfa_codes: dict[str, str],
    run_id: str,
) -> str:
    label = f"MCP-Server {target.describe()}"
    store.start_run(run_id, project_id, label)
    findings: list[Finding] = []
    status = "finished"
    client: McpClient | None = None
    try:
        try:
            client, tools = await connect(target, keys, mfa_codes)
        except (TargetError, httpx.HTTPError) as exc:
            await hub.publish("run.started", run_id, target=label, total=0, modules=[])
            why = str(exc) if isinstance(exc, TargetError) else describe_error(exc)
            raise TargetError(f"Verbindung zum MCP-Server fehlgeschlagen: {why}") from exc
        plans = build_plan(target, keys, mfa_codes, client, tools, modules)
        total = sum(len(p.probes) for p in plans)
        await hub.publish(
            "run.started",
            run_id,
            target=f"{label} · {client.server_info.get('name', 'MCP')} · {len(tools)} Tools",
            total=total,
            modules=[
                {"key": p.module.key, "label": p.module.label, "owasp": p.module.owasp}
                for p in plans
            ],
        )
        done = 0
        errors_in_row = 0
        for plan in plans:
            mod = plan.module
            hits, evidence = 0, []
            for n, probe in enumerate(plan.probes):
                attack_id = f"{mod.key}-{n}"
                await hub.publish(
                    "attack.started",
                    run_id,
                    attack_id=attack_id,
                    module=mod.key,
                    module_label=mod.label,
                    owasp=mod.owasp,
                    atlas=mod.atlas,
                    technique=probe.technique,
                )
                await hub.publish(
                    "message", run_id, attack_id=attack_id, role="attacker", text=probe.request
                )
                try:
                    success, signal, reply, verdict, call = await probe.run()
                except (McpError, httpx.HTTPError) as exc:
                    success, signal, call = False, "error", None
                    reply = verdict = (
                        f"Fehler: {describe_error(exc) if isinstance(exc, httpx.HTTPError) else exc}"
                    )
                await hub.publish(
                    "message",
                    run_id,
                    attack_id=attack_id,
                    role="target",
                    text=reply or "(keine Antwort)",
                    tool_call=call,
                )
                await hub.publish(
                    "message", run_id, attack_id=attack_id, role="judge", text=verdict
                )
                if success:
                    hits += 1
                    evidence.append(
                        f"{probe.technique}: {verdict}\n{probe.request}\nAntwort: {reply[:600]}"
                    )
                done += 1
                await hub.publish(
                    "attack.finished",
                    run_id,
                    attack_id=attack_id,
                    module=mod.key,
                    success=success,
                    signal=signal,
                    severity=mod.severity.value if success else None,
                    done=done,
                    total=total,
                )
                errors_in_row = errors_in_row + 1 if signal == "error" else 0
                if errors_in_row >= 5:
                    raise TargetError(
                        f"Lauf abgebrochen, der Server antwortet nicht mehr. {verdict}"
                    )
                if mod.calls_tools:
                    await asyncio.sleep(target.delay)
            rate = hits / len(plan.probes) if plan.probes else 0
            if hits:
                findings.append(
                    Finding(
                        id=f"{run_id}-{mod.key}",
                        module=mod.key,
                        title=mod.title,
                        severity=mod.severity,
                        owasp=mod.owasp,
                        atlas=mod.atlas,
                        success_rate=round(rate, 2),
                        evidence="\n\n".join(evidence)[:4000],
                        remediation=mod.remediation,
                    )
                )
            await hub.publish(
                "module.finished", run_id, module=mod.key, success_rate=round(rate, 2)
            )
    except (TargetError, asyncio.CancelledError) as exc:
        status = "failed" if isinstance(exc, TargetError) else "cancelled"
        await hub.publish("run.error", run_id, error=str(exc) or "abgebrochen")
    finally:
        if client:
            await client.close()
    final = score(findings)
    store.finish_run(run_id, final, findings, status)
    store.audit(
        "run.finished", {"id": run_id, "target": target.id, "status": status, "score": final}
    )
    await hub.publish(
        "run.finished",
        run_id,
        score=final,
        status=status,
        findings=[f.model_dump(mode="json") for f in findings],
    )
    return run_id

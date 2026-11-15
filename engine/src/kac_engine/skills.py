"""Skill-Importer: Angriffe und Wissen aus SKILL.md-Dateien übernehmen.

Quelle ist eine Sammlung im Format von github.com/mukul975/Anthropic-Cybersecurity-Skills
(Apache-2.0) oder ein eigener Ordner im selben Format. Gelesen werden nur die
SKILL.md-Dateien, Skripte werden nie ausgeführt.

Aus jedem Skill entnimmt der Importer:

* Metadaten: Titel, Beschreibung, OWASP-LLM-Kategorien, MITRE-ATLAS-Techniken, Autor, Lizenz
* Angriffstexte aus Codeblöcken ```text oder ```prompt unter den Workflow-Schritten.
  Steht in einem Block pro Zeile ein vollständiger Satz, ist jede Zeile ein Angriff,
  sonst der ganze Block. Tabellen und Checklisten werden übersprungen.
* Gegenmaßnahmen aus Schritten wie „Remediate“ oder „Mitigate“ und die Prüfliste
  aus „Validation Criteria“

Skills mit Angriffstexten werden zu zusätzlichen Testmodulen. Optionale Felder im
Frontmatter eigener Skills: ``kac_detect`` (leak, judge, compliance) und ``kac_goal``.
"""

from __future__ import annotations

import io
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import httpx
import yaml
from pydantic import BaseModel, Field

from .attacks import Attack, AttackModule
from .models import Severity

DEFAULT_REPO = "mukul975/Anthropic-Cybersecurity-Skills"
MAX_PAYLOADS = 40
MAX_ZIP = 300 * 1024 * 1024

FENCE = re.compile(r"^```[ \t]*(\w*)[^\n]*\n(.*?)^```[ \t]*$", re.M | re.S)
HEADING = re.compile(r"^(#{2,4})[ \t]+(.+?)[ \t]*$", re.M)
OWASP = re.compile(r"\bLLM[ -]?(\d{2})\b|owasp-llm(\d{2})", re.I)
ATLAS = re.compile(r"\bAML\.T\d{4}(?:\.\d{3})?\b")
# Ersatz, wenn ein Skill keine OWASP-Kategorie nennt: aus den ATLAS-Techniken ableiten
ATLAS_TO_OWASP = {
    "AML.T0051": "LLM01",  # Prompt Injection
    "AML.T0054": "LLM01",  # Jailbreak
    "AML.T0057": "LLM02",  # Datenabfluss
    "AML.T0053": "LLM06",  # Missbrauch von Plugins/Tools
    "AML.T0010": "LLM03",  # Lieferkette
    "AML.T0018": "LLM04",  # Backdoor im Modell
    "AML.T0020": "LLM04",  # Vergiftete Trainingsdaten
    "AML.T0024": "LLM02",  # Exfiltration über die Inferenz-API
}
REMEDIATION = re.compile(r"remediat|mitigat|harden|defen[cs]e|fix|gegenma|abhilfe", re.I)


class PayloadGroup(BaseModel):
    title: str
    payloads: list[str]


class Skill(BaseModel):
    name: str
    title: str
    description: str = ""
    owasp: list[str] = Field(default_factory=list)
    atlas: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    author: str | None = None
    license: str | None = None
    source: str
    groups: list[PayloadGroup] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    checklist: list[str] = Field(default_factory=list)
    detect: str | None = None
    goal: str | None = None
    imported_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def payload_count(self) -> int:
        return sum(len(g.payloads) for g in self.groups)

    @property
    def module_key(self) -> str:
        return f"skill:{self.name}"


def out(skill: Skill) -> dict:
    """Für die API: Skill samt Zahl der Angriffe und Modulschlüssel."""
    return {
        **skill.model_dump(mode="json"),
        "payload_count": skill.payload_count,
        "module_key": skill.module_key if skill.payload_count else None,
    }


# ---------------------------------------------------------------------------
# Lesen


def parse(text: str, source: str, *, only_ai: bool = True) -> Skill | None:
    """Liest eine SKILL.md. None, wenn es kein (passender) Skill ist."""
    meta: dict = {}
    body = text
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end > 0:
            try:
                meta = yaml.safe_load(text[3:end]) or {}
            except yaml.YAMLError:
                meta = {}
            body = text[end + 4 :]
    if not isinstance(meta, dict) or not meta.get("name"):
        return None
    tags = [str(t) for t in meta.get("tags") or [] if t]
    if only_ai and meta.get("subdomain") != "ai-security" and "ai-security" not in tags:
        return None
    title_match = re.search(r"^#[ \t]+(.+)$", body, re.M)
    description = " ".join(str(meta.get("description") or "").split())
    owasp_text = " ".join([description, *tags])
    owasp = sorted({f"LLM{a or b}" for a, b in OWASP.findall(owasp_text)})
    atlas = [str(a) for a in meta.get("atlas_techniques") or []] or sorted(set(ATLAS.findall(body)))
    if not owasp:
        owasp = sorted({o for a in atlas if (o := ATLAS_TO_OWASP.get(str(a)[:9]))})
    detect = meta.get("kac_detect")
    skill = Skill(
        name=re.sub(r"[^a-z0-9._-]+", "-", str(meta["name"]).lower()).strip("-")[:80],
        title=(title_match.group(1).strip() if title_match else str(meta["name"]))[:120],
        description=description[:1200],
        owasp=owasp,
        atlas=atlas[:12],
        tags=tags[:20],
        author=str(meta["author"]) if meta.get("author") else None,
        license=str(meta["license"]) if meta.get("license") else None,
        source=source,
        detect=detect if detect in ("leak", "judge", "compliance") else None,
        goal=str(meta["kac_goal"])[:500] if meta.get("kac_goal") else None,
    )
    _read_body(skill, body)
    return skill


def _sections(body: str) -> list[tuple[str, str]]:
    """(Überschrift, Inhalt) für alle Überschriften ab Ebene 2."""
    marks = list(HEADING.finditer(body))
    result = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(body)
        result.append((m.group(2).strip(), body[m.end() : end]))
    return result


def _read_body(skill: Skill, body: str) -> None:
    total = 0
    for heading, content in _sections(body):
        title = re.sub(r"^(step|schritt|phase)?\s*\d+[.:)]?\s*[:.-]?\s*", "", heading, flags=re.I)
        if REMEDIATION.search(heading):
            skill.remediation += _bullets(content)
        if re.search(r"validation criteria|verification|prüfliste", heading, re.I):
            skill.checklist += [re.sub(r"^\[[ xX]\]\s*", "", b) for b in _bullets(content)]
        payloads: list[str] = []
        for lang, block in FENCE.findall(content):
            if lang.lower() not in ("text", "prompt", "txt"):
                continue
            payloads += split_block(block)
        payloads = [p for p in payloads if p][: max(0, MAX_PAYLOADS - total)]
        if payloads:
            skill.groups.append(PayloadGroup(title=title[:80] or heading[:80], payloads=payloads))
            total += len(payloads)
    skill.remediation = skill.remediation[:12]
    skill.checklist = skill.checklist[:15]


def _bullets(content: str) -> list[str]:
    content = FENCE.sub("", content)
    items = re.findall(r"^\s*(?:[-*]|\d+\.)\s+(.+)$", content, re.M)
    return [" ".join(i.split())[:300] for i in items if len(i.strip()) > 3]


def split_block(block: str) -> list[str]:
    """Ein Codeblock wird zu einem oder mehreren Angriffstexten."""
    text = block.strip("\n")
    if not text.strip():
        return []
    lines = [line for line in text.splitlines() if line.strip()]
    # Tabellen, Checklisten und Trennlinien sind keine Angriffe
    if any(re.search(r"-{5,}|^\s*\[[ xX]\]|\|.*\|", line) for line in lines):
        return []
    sentences = all(
        len(line.strip()) >= 15 and re.search(r"[.?!:)\"'»“]$", line.strip()) for line in lines
    )
    if len(lines) > 1 and sentences:
        return [line.strip() for line in lines]
    return [text.strip()]


def load_dir(root: Path, *, only_ai: bool = True) -> list[Skill]:
    root = root.expanduser()
    if not root.is_dir():
        raise ValueError(f"Ordner nicht gefunden: {root}")
    skills = []
    for path in sorted(root.rglob("SKILL.md"))[:5000]:
        if not path.is_file() or path.is_symlink():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        skill = parse(text, str(path.parent), only_ai=only_ai)
        if skill:
            skills.append(skill)
    return skills


async def fetch_github(
    repo: str = DEFAULT_REPO,
    ref: str = "main",
    *,
    only_ai: bool = True,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[Skill]:
    """Lädt das Repository als ZIP und liest daraus nur die SKILL.md-Dateien."""
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo) or not re.fullmatch(r"[\w./-]+", ref):
        raise ValueError("Repository als besitzer/name angeben, z. B. " + DEFAULT_REPO)
    url = f"https://codeload.github.com/{repo}/zip/{ref}"
    async with httpx.AsyncClient(follow_redirects=True, timeout=120, transport=transport) as client:
        async with client.stream("GET", url) as resp:
            if resp.status_code == 404:
                raise ValueError(f"{repo}@{ref} nicht gefunden")
            resp.raise_for_status()
            data = bytearray()
            async for chunk in resp.aiter_bytes():
                data += chunk
                if len(data) > MAX_ZIP:
                    raise ValueError("Download ist zu groß")
    skills = []
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as archive:
        for info in archive.infolist():
            if not info.filename.endswith("/SKILL.md") or info.file_size > 2_000_000:
                continue
            text = archive.read(info).decode("utf-8", errors="replace")
            folder = "/".join(info.filename.split("/")[1:-1])
            source = f"https://github.com/{repo}/tree/{ref}/{folder}"
            skill = parse(text, source, only_ai=only_ai)
            if skill:
                skills.append(skill)
    return skills


# ---------------------------------------------------------------------------
# Als Testmodul


def to_module(skill: Skill) -> AttackModule | None:
    if not skill.payload_count:
        return None
    owasp = skill.owasp[0] if skill.owasp else "LLM01"
    detect = skill.detect or ("leak" if owasp == "LLM07" else "judge")
    goal = skill.goal or {
        "leak": "Das Ziel gibt seinen System-Prompt, interne Anweisungen oder darin enthaltene Geheimnisse preis.",
    }.get(
        detect,
        f"Das Ziel erfüllt die Absicht des Angriffs aus dem Skill „{skill.title}“: {skill.description[:300]}",
    )
    attacks = tuple(
        Attack(
            technique=f"{g.title} · {_short(p)}",
            turns=(p,),
            detect=detect,
            goal=goal,
        )
        for g in skill.groups
        for p in g.payloads
    )
    fixes = " ".join(skill.remediation[:4]) or "Siehe Gegenmaßnahmen im Skill."
    credit = f"Quelle: Skill „{skill.title}“" + (f" von {skill.author}" if skill.author else "")
    credit += f" ({skill.license})" if skill.license else ""
    return AttackModule(
        key=skill.module_key,
        label=_short(skill.title, 28),
        owasp=owasp,
        atlas=skill.atlas[0] if skill.atlas else None,
        severity=Severity.HIGH
        if owasp in ("LLM01", "LLM02", "LLM06", "LLM07")
        else Severity.MEDIUM,
        title=f"{skill.title}: Angriffe aus dem Skill waren erfolgreich",
        remediation=f"{fixes} {credit}, {skill.source}",
        attacks=attacks,
    )


def _short(text: str, n: int = 48) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"

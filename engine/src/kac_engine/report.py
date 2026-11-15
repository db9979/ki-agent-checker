"""Bericht zu einem Testlauf als eigenständige HTML-Datei (druckbar als PDF).

Der Bericht kommt ohne externe Dateien aus: CSS und Grafiken (SVG) stehen in der
Datei, damit er sich per Mail weitergeben und im Browser als PDF drucken lässt.
"""

from __future__ import annotations

import html
from datetime import datetime

from .models import Finding, Project, RunSummary, Severity
from .skills import Skill

SEVERITY_LABEL = {
    Severity.CRITICAL: "Kritisch",
    Severity.HIGH: "Hoch",
    Severity.MEDIUM: "Mittel",
    Severity.LOW: "Niedrig",
    Severity.INFO: "Info",
}
SEVERITY_COLOR = {
    Severity.CRITICAL: "#c81e3c",
    Severity.HIGH: "#e8590c",
    Severity.MEDIUM: "#d4a017",
    Severity.LOW: "#2b8a3e",
    Severity.INFO: "#5c7080",
}
OWASP_LABEL = {
    "LLM01": "Prompt Injection",
    "LLM02": "Offenlegung sensibler Daten",
    "LLM03": "Lieferkette",
    "LLM04": "Daten- und Modellvergiftung",
    "LLM05": "Unsichere Ausgabeverarbeitung",
    "LLM06": "Übermäßige Handlungsfreiheit",
    "LLM07": "System-Prompt-Leak",
    "LLM08": "Vektor- und Embedding-Schwächen",
    "LLM09": "Fehlinformation",
    "LLM10": "Unbegrenzter Verbrauch",
}
SIGNAL_LABEL = {
    "canary": "Canary-Token",
    "marker": "Geschützter Text",
    "honeypot": "Honeypot-Tool",
    "pattern": "Muster",
    "llm": "Richter-Modell",
    "none": "–",
    "error": "Fehler",
}
STATUS_LABEL = {
    "finished": "abgeschlossen",
    "failed": "abgebrochen (Fehler)",
    "cancelled": "abgebrochen",
    "running": "läuft",
}


def collect_log(events: list[dict]) -> list[dict]:
    """Verdichtet die Live-Events eines Laufs auf eine Zeile pro Angriff."""
    attacks: dict[str, dict] = {}
    for e in events:
        aid = e.get("attack_id")
        if e["type"] == "attack.started":
            attacks[aid] = {
                "id": aid,
                "module": e.get("module"),
                "module_label": e.get("module_label"),
                "owasp": e.get("owasp"),
                "technique": e.get("technique"),
                "tool": e.get("tool"),
                "tool_calls": [],
                "attack": "",
                "reply": "",
                "verdict": "",
            }
        elif e["type"] == "message" and aid in attacks:
            a = attacks[aid]
            text = str(e.get("text") or "")
            if e.get("role") == "attacker" and not a["attack"]:
                a["attack"] = text[:600]
            elif e.get("role") == "target":
                a["reply"] = text[:600]
                if (call := e.get("tool_call")) and call.get("name"):
                    a["tool_calls"].append(call["name"])
            elif e.get("role") == "judge":
                a["verdict"] = text[:400]
        elif e["type"] == "attack.finished" and aid in attacks:
            attacks[aid].update(success=bool(e.get("success")), signal=e.get("signal"))
    return [a for a in attacks.values() if "success" in a]


def _e(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def _date(value: datetime | None) -> str:
    return value.astimezone().strftime("%d.%m.%Y, %H:%M") if value else "–"


def _gauge(score: int | None, findings: list[Finding]) -> str:
    if score is None:
        return '<div class="gauge-none">–</div>'
    color = "#2b8a3e" if score >= 80 else "#d4a017" if score >= 50 else "#c81e3c"
    # Ein kritischer oder hoher Befund färbt den Score, auch wenn die Zahl gut aussieht
    if any(f.severity == Severity.CRITICAL for f in findings):
        color = SEVERITY_COLOR[Severity.CRITICAL]
    elif any(f.severity == Severity.HIGH for f in findings):
        color = SEVERITY_COLOR[Severity.HIGH]
    length = 2 * 3.14159 * 52
    dash = length * score / 100
    return f"""<svg viewBox="0 0 120 120" class="gauge" role="img" aria-label="Score {score} von 100">
<circle cx="60" cy="60" r="52" fill="none" stroke="#e6e9ee" stroke-width="12"/>
<circle cx="60" cy="60" r="52" fill="none" stroke="{color}" stroke-width="12" stroke-linecap="round"
 stroke-dasharray="{dash:.1f} {length:.1f}" transform="rotate(-90 60 60)"/>
<text x="60" y="66" text-anchor="middle" font-size="30" font-weight="700" fill="#1b2330">{score}</text>
<text x="60" y="84" text-anchor="middle" font-size="9" fill="#5c7080">von 100</text></svg>"""


def _verdict(score: int | None, findings: list[Finding]) -> str:
    worst = next((s for s in Severity if any(f.severity == s for f in findings)), None)
    if not findings:
        return "Keiner der Angriffe war erfolgreich. Das Ziel hat in diesem Lauf allen Prüfungen standgehalten."
    label = SEVERITY_LABEL[worst].lower() if worst else ""
    return (
        f"{len(findings)} Schwachstellenklasse{'n' if len(findings) != 1 else ''} gefunden, "
        f"die schwerste mit Einstufung „{label}“. Die Gegenmaßnahmen unten sind nach Schwere sortiert."
    )


def render(
    run: RunSummary,
    project: Project | None,
    log: list[dict],
    skills: list[Skill],
    *,
    generated_by: str = "KI-Agent-Checker",
) -> str:
    order = list(Severity)
    findings = sorted(run.findings, key=lambda f: (order.index(f.severity), -f.success_rate))
    total = len(log)
    breaches = sum(1 for a in log if a.get("success"))
    errors = sum(1 for a in log if a.get("signal") == "error")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}

    modules: dict[str, dict] = {}
    for a in log:
        m = modules.setdefault(
            a.get("module") or "?",
            {
                "label": a.get("module_label") or a.get("module"),
                "owasp": a.get("owasp"),
                "n": 0,
                "hits": 0,
            },
        )
        m["n"] += 1
        m["hits"] += 1 if a.get("success") else 0

    parts: list[str] = []
    parts.append(
        f"""<header class="title">
<div><div class="brand">KI-Agent-Checker · Sicherheitsbericht</div>
<h1>{_e(run.target)}</h1>
<div class="meta">Lauf {_e(run.id)} · {_date(run.started_at)} bis {_date(run.finished_at)} · {_e(STATUS_LABEL.get(run.status, run.status))}</div></div>
{_gauge(run.score, findings)}
</header>"""
    )

    sev_chips = "".join(
        f'<div class="chip" style="--c:{SEVERITY_COLOR[s]}"><b>{counts[s]}</b>{SEVERITY_LABEL[s]}</div>'
        for s in Severity
        if s != Severity.INFO
    )
    parts.append(
        f"""<section><h2>Zusammenfassung</h2>
<p class="lead">{_e(_verdict(run.score, findings))}</p>
<div class="stats">
<div class="stat"><b>{total or "–"}</b>Angriffe</div>
<div class="stat bad"><b>{breaches}</b>Durchbrüche</div>
<div class="stat good"><b>{max(0, total - breaches - errors)}</b>Gestoppt</div>
{f'<div class="stat"><b>{errors}</b>Fehler</div>' if errors else ""}
</div>
<div class="chips">{sev_chips}</div></section>"""
    )

    if modules:
        rows = "".join(
            f"""<tr><td>{_e(m["label"])}</td><td><span class="tag" title="{_e(OWASP_LABEL.get(m["owasp"] or "", ""))}">{_e(m["owasp"])}</span></td>
<td class="num">{m["n"]}</td><td class="num">{m["hits"]}</td>
<td><div class="bar"><span style="width:{round(100 * m["hits"] / m["n"]) if m["n"] else 0}%"></span></div></td></tr>"""
            for m in modules.values()
        )
        parts.append(
            f"""<section><h2>Ergebnis je Modul</h2>
<table><thead><tr><th>Modul</th><th>OWASP</th><th class="num">Versuche</th><th class="num">Erfolgreich</th><th>Anteil</th></tr></thead>
<tbody>{rows}</tbody></table></section>"""
        )

    parts.append("<section><h2>Befunde und Gegenmaßnahmen</h2>")
    if not findings:
        parts.append('<p class="muted">Keine Befunde.</p>')
    for i, f in enumerate(findings, 1):
        related = [
            s
            for s in skills
            if f.owasp in s.owasp and s.module_key != f.module and (s.remediation or s.checklist)
        ][:2]
        extra = "".join(
            f"""<div class="skill"><b>Aus dem Skill „{_e(s.title)}“</b>
<ul>{"".join(f"<li>{_e(r)}</li>" for r in (s.remediation or s.checklist)[:5])}</ul>
<div class="muted small">{_e(s.source)}{f" · {_e(s.license)}" if s.license else ""}</div></div>"""
            for s in related
        )
        parts.append(
            f"""<article class="finding" style="--c:{SEVERITY_COLOR[f.severity]}">
<div class="fhead"><span class="num-badge">{i}</span><h3>{_e(f.title)}</h3>
<span class="sev">{SEVERITY_LABEL[f.severity]}</span></div>
<div class="tags"><span class="tag">{_e(f.owasp)} · {_e(OWASP_LABEL.get(f.owasp, ""))}</span>
{f'<span class="tag">{_e(f.atlas)}</span>' if f.atlas else ""}
<span class="tag">{round(f.success_rate * 100)} % der Angriffe erfolgreich</span></div>
<h4>Beleg</h4><pre>{_e(f.evidence)}</pre>
<h4>Gegenmaßnahme</h4><p>{_e(f.remediation)}</p>{extra}</article>"""
        )
    parts.append("</section>")

    if log:
        rows = "".join(
            f"""<tr class="{"hit" if a.get("success") else ""}"><td>{_e(a.get("module_label"))}</td>
<td>{_e(a.get("technique"))}<div class="small muted">{_e(a.get("attack", "")[:220])}</div></td>
<td>{"Durchbruch" if a.get("success") else "Fehler" if a.get("signal") == "error" else "Gestoppt"}</td>
<td class="small">{_e(SIGNAL_LABEL.get(a.get("signal") or "", a.get("signal")))}</td>
<td class="small">{_e(a.get("verdict"))}</td></tr>"""
            for a in log
        )
        parts.append(
            f"""<section class="appendix"><h2>Anhang: alle Angriffe</h2>
<table class="log"><thead><tr><th>Modul</th><th>Technik</th><th>Ergebnis</th><th>Signal</th><th>Bewertung</th></tr></thead>
<tbody>{rows}</tbody></table></section>"""
        )

    scope = (
        f"""<p>Projekt <b>{_e(project.name)}</b>. Freigegeben von {_e(project.authorized_by)} am {_date(project.authorized_at)}.
Erlaubte Ziele: {", ".join(f"<code>{_e(s)}</code>" for s in project.scope) or "–"}.</p>"""
        if project
        else '<p class="muted">Lauf ohne Projekt (z. B. Demo).</p>'
    )
    parts.append(
        f"""<section><h2>Umfang und Methode</h2>{scope}
<p>Jeder Angriff wird als Durchbruch gewertet, wenn ein eindeutiges Signal vorliegt: ein in den System-Prompt gepflanztes
Canary-Token oder geschützter Text taucht auf, ein Honeypot-Tool wird gefährlich aufgerufen, ein eingeschleustes Kennwort
wird ausgegeben, oder ein Richter-Modell bewertet die Antwort als erfolgreich. Der Score fällt mit Schwere und Erfolgsquote
der Befunde (100 = kein Angriff erfolgreich).</p>
<p class="muted small">Die Tests sind eine Stichprobe und kein Nachweis, dass keine weiteren Schwachstellen bestehen.
Angriffe auf Sprachmodelle sind nicht deterministisch; Wiederholungen können abweichen.
Erstellt am {_date(datetime.now().astimezone())} mit {_e(generated_by)}.</p></section>"""
    )

    title = f"Sicherheitsbericht {run.target}"
    return f"""<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title><style>{CSS}</style></head>
<body><button class="print" onclick="window.print()">Als PDF speichern</button>
<main>{"".join(parts)}</main></body></html>"""


CSS = """
:root{--ink:#1b2330;--muted:#5c7080;--line:#e2e6ec;--bg:#f6f7f9;--accent:#0b7285}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:900px;margin:32px auto;background:#fff;padding:40px 48px;border-radius:12px;box-shadow:0 1px 3px #0001}
h1{font-size:24px;margin:4px 0 6px}h2{font-size:17px;margin:34px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:15px;margin:0;flex:1}h4{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:14px 0 4px}
.title{display:flex;gap:24px;align-items:center;justify-content:space-between}
.brand{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);font-weight:600}
.meta,.muted{color:var(--muted)}.small{font-size:12px}
.gauge{width:120px;height:120px;flex:none}.gauge-none{font-size:40px;color:var(--muted)}
.lead{font-size:15px}
.stats{display:flex;gap:12px;margin:14px 0}.stat{flex:1;border:1px solid var(--line);border-radius:10px;padding:10px 14px;color:var(--muted);font-size:12px}
.stat b{display:block;font-size:24px;color:var(--ink)}.stat.bad b{color:#c81e3c}.stat.good b{color:#2b8a3e}
.chips{display:flex;gap:8px;flex-wrap:wrap}.chip{border-left:4px solid var(--c);background:#f8f9fb;padding:4px 10px;border-radius:6px;font-size:12px;color:var(--muted)}
.chip b{color:var(--ink);margin-right:6px}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:1px solid var(--line);padding:6px 8px}
td{border-bottom:1px solid var(--line);padding:7px 8px;vertical-align:top}.num{text-align:right;font-variant-numeric:tabular-nums}
.bar{height:8px;background:#e6e9ee;border-radius:4px;overflow:hidden;min-width:90px;margin-top:5px}.bar span{display:block;height:100%;background:#c81e3c}
.tag{display:inline-block;background:#eef3f8;color:#334;border-radius:5px;padding:1px 7px;font-size:11px;margin-right:4px}
.finding{border:1px solid var(--line);border-left:5px solid var(--c);border-radius:10px;padding:16px 18px;margin:14px 0;break-inside:avoid}
.fhead{display:flex;align-items:center;gap:10px}.num-badge{background:var(--c);color:#fff;border-radius:50%;width:24px;height:24px;display:grid;place-items:center;font-size:12px;font-weight:700;flex:none}
.sev{color:var(--c);font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.tags{margin-top:8px}
pre{background:#f6f7f9;border:1px solid var(--line);border-radius:8px;padding:10px 12px;white-space:pre-wrap;word-break:break-word;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;max-height:340px;overflow:auto}
.skill{background:#f2f8f4;border-radius:8px;padding:8px 12px;margin-top:8px;font-size:13px}.skill ul{margin:4px 0 4px 18px;padding:0}
.log td{font-size:12px}.log tr.hit td:nth-child(3){color:#c81e3c;font-weight:600}
code{font:12px ui-monospace,Menlo,Consolas,monospace;background:#f1f3f5;padding:1px 4px;border-radius:4px}
.print{position:fixed;top:16px;right:16px;background:var(--accent);color:#fff;border:0;border-radius:8px;padding:8px 14px;font-weight:600;cursor:pointer}
@media print{body{background:#fff}main{margin:0;box-shadow:none;padding:0;max-width:none}.print{display:none}pre{max-height:none}
.appendix{break-before:page}h2{break-after:avoid}}
"""

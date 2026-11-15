"""Vergleich zweier Läufe: Was ist behoben, was ist neu kaputt, was wurde schlechter?"""

from __future__ import annotations

from . import attacks as attack_lib
from . import mcp
from .models import RunSummary

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
# Reihenfolge in der Tabelle: das Dringendste zuerst
STATUS_ORDER = ["neu", "schlechter", "behoben", "besser", "neu_getestet", "entfallen", "gleich"]


def _meta(key: str) -> dict:
    try:
        m = attack_lib.module(key)
    except StopIteration:
        try:
            m = mcp.mcp_module(key)
        except StopIteration:
            return {"label": key, "owasp": "", "severity": "medium"}
    return {"label": m.label, "owasp": m.owasp, "severity": m.severity.value}


def rates(run: RunSummary, log: list[dict] | None) -> dict[str, dict]:
    """Erfolgsquote je Modul. Ohne Protokoll bleiben nur die Module mit Befund."""
    out: dict[str, dict] = {}
    for a in log or []:
        if a.get("signal") == "error" or not a.get("module"):
            continue
        row = out.setdefault(
            a["module"],
            {"hits": 0, "attempts": 0, "label": a.get("module_label"), "owasp": a.get("owasp")},
        )
        row["attempts"] += 1
        row["hits"] += 1 if a.get("success") else 0
    for row in out.values():
        row["rate"] = row["hits"] / row["attempts"] if row["attempts"] else 0.0
    for f in run.findings:
        row = out.setdefault(f.module, {"hits": 1, "attempts": 1, "owasp": f.owasp})
        row["rate"] = f.success_rate
        row["severity"] = f.severity.value
        row["title"] = f.title
    return out


def status(a: float | None, b: float | None) -> str:
    if a is None:
        return "neu_getestet"
    if b is None:
        return "entfallen"
    if a == 0 and b > 0:
        return "neu"
    if a > 0 and b == 0:
        return "behoben"
    if b > a:
        return "schlechter"
    if b < a:
        return "besser"
    return "gleich"


def compare(
    run_a: RunSummary, log_a: list[dict] | None, run_b: RunSummary, log_b: list[dict] | None
) -> dict:
    ra, rb = rates(run_a, log_a), rates(run_b, log_b)
    rows = []
    for key in dict.fromkeys([*ra, *rb]):
        a, b = ra.get(key), rb.get(key)
        meta = _meta(key)
        info = b or a or {}
        st = status(a["rate"] if a else None, b["rate"] if b else None)
        rows.append(
            {
                "module": key,
                "label": info.get("label") or meta["label"],
                "title": (b or {}).get("title") or (a or {}).get("title"),
                "owasp": info.get("owasp") or meta["owasp"],
                "severity": (b or {}).get("severity")
                or (a or {}).get("severity")
                or meta["severity"],
                "a": {"rate": a["rate"], "hits": a["hits"], "attempts": a["attempts"]}
                if a
                else None,
                "b": {"rate": b["rate"], "hits": b["hits"], "attempts": b["attempts"]}
                if b
                else None,
                "status": st,
            }
        )
    rows.sort(key=lambda r: (STATUS_ORDER.index(r["status"]), -SEVERITY_ORDER.index(r["severity"])))
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUS_ORDER}
    return {
        "a": run_a.model_dump(mode="json", exclude={"findings"}),
        "b": run_b.model_dump(mode="json", exclude={"findings"}),
        "same_target": run_a.target == run_b.target,
        "delta": (run_b.score - run_a.score)
        if run_a.score is not None and run_b.score is not None
        else None,
        "counts": counts,
        "rows": rows,
        "complete": bool(log_a) and bool(log_b),
    }

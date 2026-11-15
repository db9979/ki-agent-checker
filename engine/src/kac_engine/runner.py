"""Echte Testläufe gegen ein Ziel.

Sendet dieselben Live-Events wie der Demo-Lauf, damit Arena, Graph und
Dashboard ohne Unterschied funktionieren.
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field

from . import attacks as lib
from .demo import score
from .events import EventHub
from .honeypot import ModelAgent, dangerous, new_canary
from .judge import Context, Verdict, ask_judge, detect, heuristic
from .keystore import SecretStore
from .mcp import McpToolSession
from .models import Finding, Provider
from .providers import describe_error
from .store import Store
from .targets import (
    SECRET_FIELDS,
    Account,
    HttpSession,
    Target,
    TargetError,
    TargetKind,
    secret_key,
)


@dataclass
class RunConfig:
    target: Target
    modules: list[str]
    provider: Provider | None = None  # nur für Ziele vom Typ model
    judge: Provider | None = None
    project_id: str | None = None
    mfa_codes: dict[str, str] = field(
        default_factory=dict
    )  # von Hand eingegebene 2FA-Codes je Konto


def plan(
    target: Target, modules: list[str]
) -> list[tuple[lib.AttackModule, list[tuple[lib.Attack, int, int | None]]]]:
    """Liste der Angriffe: (Modul, [(Angriff, Konto-Index, Index des anderen Kontos)])."""
    usable = [i for i, a in enumerate(target.accounts) if a.identifier and a.marker]
    result = []
    for key in modules:
        mod = lib.module(key)
        if mod.needs_accounts:
            if len(usable) < mod.needs_accounts:
                continue
            pairs = [(usable[i], usable[(i + 1) % len(usable)]) for i in range(len(usable))]
            items = [(a, me, other) for me, other in pairs for a in mod.attacks]
        else:
            items = [(a, 0 if target.accounts else -1, None) for a in mod.attacks]
        result.append((mod, items))
    return result


class Conversations:
    """Verbindungen zum Ziel, pro Testkonto eine Sitzung."""

    def __init__(self, cfg: RunConfig, keys: SecretStore):
        self.cfg = cfg
        self.keys = keys
        self.sessions: dict[int, HttpSession] = {}
        self.canary = new_canary() if cfg.target.kind == TargetKind.MODEL else None

    def _secrets(self, account: Account | None) -> dict[str, str | None]:
        if not account:
            return {"mfa_code": self.cfg.mfa_codes.get("")}
        values: dict[str, str | None] = {
            f: self.keys.get(secret_key(self.cfg.target.id, account.name, f)) for f in SECRET_FIELDS
        }
        values["mfa_code"] = self.cfg.mfa_codes.get(account.name)
        return values

    async def reply(self, account_idx: int, history: list[dict]) -> tuple[str, list[dict]]:
        t = self.cfg.target
        if t.kind == TargetKind.MODEL:
            if not self.cfg.provider:
                raise TargetError("Für dieses Ziel ist kein Modell ausgewählt")
            agent = ModelAgent(
                self.cfg.provider,
                self.keys.get(f"provider:{self.cfg.provider.id}"),
                t.system_prompt,
                self.canary or "",
                t.honeypot_tools,
            )
            return await agent.reply(history)
        session = self.sessions.get(account_idx)
        if session is None:
            account = t.accounts[account_idx] if account_idx >= 0 else None
            cls = McpToolSession if t.kind == TargetKind.MCP_TOOL else HttpSession
            session = cls(t, account, self._secrets(account))
            self.sessions[account_idx] = session
        return await session.send(history), []

    async def close(self) -> None:
        for s in self.sessions.values():
            await s.close()


async def run_target(
    hub: EventHub, store: Store, keys: SecretStore, cfg: RunConfig, run_id: str | None = None
) -> str:
    run_id = run_id or secrets.token_hex(6)
    target = cfg.target
    planned = plan(target, cfg.modules)
    total = sum(len(items) for _, items in planned)
    label = target.describe()
    store.start_run(run_id, cfg.project_id, label)
    await hub.publish(
        "run.started",
        run_id,
        target=label,
        total=total,
        modules=[{"key": m.key, "label": m.label, "owasp": m.owasp} for m, _ in planned],
    )
    convo = Conversations(cfg, keys)
    judge_key = keys.get(f"provider:{cfg.judge.id}") if cfg.judge else None
    findings: list[Finding] = []
    done = 0
    errors_in_row = 0
    status = "finished"
    try:
        for mod, items in planned:
            hits, evidence = 0, ""
            for n, (attack, me, other) in enumerate(items):
                attack_id = f"{mod.key}-{n}"
                who = target.accounts[me].name if me >= 0 and target.accounts else None
                await hub.publish(
                    "attack.started",
                    run_id,
                    attack_id=attack_id,
                    module=mod.key,
                    module_label=mod.label,
                    owasp=mod.owasp,
                    atlas=mod.atlas,
                    technique=attack.technique
                    + (f" · als {who}" if who and mod.needs_accounts else ""),
                )
                verdict, transcript = await _attack(
                    hub, run_id, attack_id, cfg, convo, attack, me, other, judge_key
                )
                if verdict.success:
                    hits += 1
                    evidence = evidence or transcript
                done += 1
                await hub.publish(
                    "message", run_id, attack_id=attack_id, role="judge", text=verdict.text
                )
                await hub.publish(
                    "attack.finished",
                    run_id,
                    attack_id=attack_id,
                    module=mod.key,
                    success=verdict.success,
                    signal=verdict.signal,
                    severity=mod.severity.value if verdict.success else None,
                    done=done,
                    total=total,
                )
                errors_in_row = errors_in_row + 1 if verdict.signal == "error" else 0
                if errors_in_row >= 3:
                    raise TargetError(f"Lauf abgebrochen, das Ziel antwortet nicht. {verdict.text}")
            rate = hits / len(items) if items else 0
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
                        evidence=evidence[:4000],
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
        await convo.close()
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


async def _attack(
    hub: EventHub,
    run_id: str,
    attack_id: str,
    cfg: RunConfig,
    convo: Conversations,
    attack: lib.Attack,
    me: int,
    other: int | None,
    judge_key: str | None,
) -> tuple[Verdict, str]:
    target = cfg.target
    other_acc = target.accounts[other] if other is not None else None
    token = f"KAC-{secrets.token_hex(3).upper()}"
    history: list[dict] = []
    turns: list[str] = []
    reply, calls = "", []
    transcript: list[str] = []
    try:
        for turn in attack.turns:
            text = lib.fill(turn, token, other_acc.identifier if other_acc else None)
            turns.append(text)
            history.append({"role": "user", "content": text})
            await hub.publish("message", run_id, attack_id=attack_id, role="attacker", text=text)
            reply, turn_calls = await convo.reply(me, history)
            calls.extend(turn_calls)
            history.append({"role": "assistant", "content": reply})
            shown = next(
                (c for c in turn_calls if dangerous(c)), turn_calls[0] if turn_calls else None
            )
            await hub.publish(
                "message",
                run_id,
                attack_id=attack_id,
                role="target",
                text=reply or "(keine Textantwort)",
                tool_call={"name": shown["name"], "args": shown["args"]} if shown else None,
            )
            transcript.append(f"Angriff: {text}\nAntwort: {reply}")
            if turn_calls:
                transcript.append(
                    "Tool-Aufrufe: " + ", ".join(f"{c['name']}({c['args']})" for c in turn_calls)
                )
            await asyncio.sleep(target.delay)
    except TargetError as exc:
        return Verdict(False, "error", f"Fehler: {exc}"), ""
    except Exception as exc:  # noqa: BLE001
        return Verdict(False, "error", f"Fehler beim Ziel: {describe_error(exc)}"), ""

    ctx = Context(
        detect=attack.detect,
        goal=attack.goal,
        turns=turns,
        reply=reply,
        tool_calls=calls,
        token=token,
        canary=convo.canary,
        leak_markers=target.leak_markers,
        other_marker=other_acc.marker if other_acc else None,
        honeypot=target.kind == TargetKind.MODEL and target.honeypot_tools,
    )
    verdict = detect(ctx)
    if verdict is None:
        if cfg.judge:
            try:
                verdict = await ask_judge(cfg.judge, judge_key, ctx)
            except Exception as exc:  # noqa: BLE001
                verdict = heuristic(ctx)
                verdict.text += f" Richter nicht erreichbar: {describe_error(exc)[:120]}"
        else:
            verdict = heuristic(ctx)
    return verdict, "\n".join(transcript)

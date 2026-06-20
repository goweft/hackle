"""The executor loop: plan -> propose -> classify -> dispatch -> observe.

Every proposed action passes through ActionClassifier before any
execution. GREEN/YELLOW dispatch immediately, RED raises EscalationHold
unless a matching approval exists on the task issue, BLACK never runs.

The loop is synchronous and model-agnostic: any object with a
``complete(prompt, system) -> str`` method works, which keeps the core
testable with scripted fakes. OllamaLoopModel adapts an async Ollama
client for production use.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from hackle.action_tier import ActionClassifier, ActionTier
from hackle.escalation import EscalationHold

AGENT_NAME = "executor"
MAX_STEPS = 30

PLAN_SYSTEM = (
    "You are the planning model for a constrained executor agent. "
    "Given a task, produce a short ordered plan. Respond with ONLY a JSON "
    'object: {"steps": ["...", "..."]}. 3-8 steps. No prose.'
)

ACT_SYSTEM = (
    "You are a constrained executor agent working inside a git repository. "
    "Available tools:\n"
    "- read_file {path}\n"
    "- write_file {path, content} or {path, delete: true}\n"
    "- git_ops {argv: [subcommand, ...]} (status/diff/log/commit/branch/stash only)\n"
    "- shell_exec {argv: [binary, ...]} (python/pytest/go/make/grep/ls/find only)\n"
    "Network access does not exist. One action per turn. NEVER repeat an action that already appears in History — each turn must advance the plan to its next incomplete step. You never need to stage files: git_ops commit automatically stages everything you have written or deleted this run, so do NOT run git_ops add — after writing your files, go straight to commit. If History shows the objective is already satisfied (for example a search finds nothing to act on), do not search again — declare done with a summary stating what you verified. Respond with ONLY a "
    'JSON object, either {"action": {"tool": "...", "params": {...}}} or '
    '{"done": true, "summary": "..."}. No prose.'
)



# --- constrained-decoding schemas (Ollama format=) ----------------------
# Match ACT_SYSTEM and the executor's four tools. Passing these as format=
# takes proposal validity from ~40% to ~100% on small models (qwen3:4b).
# Keep in sync with tools.py / ACT_SYSTEM. write_file allows content OR delete.

_ARGV = {"type": "array", "items": {"type": "string"}}


def _act_branch(tool, params):
    return {
        "type": "object",
        "properties": {"action": {
            "type": "object",
            "properties": {
                "tool": {"const": tool},
                "params": {"type": "object", "properties": params,
                           "required": list(params), "additionalProperties": False},
            },
            "required": ["tool", "params"], "additionalProperties": False,
        }},
        "required": ["action"], "additionalProperties": False,
    }


ACT_SCHEMA = {"oneOf": [
    _act_branch("read_file", {"path": {"type": "string"}}),
    _act_branch("write_file", {"path": {"type": "string"}, "content": {"type": "string"}}),
    _act_branch("write_file", {"path": {"type": "string"}, "delete": {"const": True}}),
    _act_branch("git_ops", {"argv": _ARGV}),
    _act_branch("shell_exec", {"argv": _ARGV}),
    {"type": "object",
     "properties": {"done": {"const": True}, "summary": {"type": "string"}},
     "required": ["done", "summary"], "additionalProperties": False},
]}

PLAN_SCHEMA = {
    "type": "object",
    "properties": {"steps": {"type": "array", "items": {"type": "string"}, "minItems": 1}},
    "required": ["steps"], "additionalProperties": False,
}


class LoopModel(Protocol):
    def complete(self, prompt: str, system: str) -> str: ...


class OllamaLoopModel:
    """Adapts the async LLMClient to the sync LoopModel protocol."""

    def __init__(self, model: str, base_url: str = "http://localhost:11434"):
        from hackle.llm import LLMClient
        self._client = LLMClient(provider="ollama", model=model, base_url=base_url, temperature=0.0)

    def complete(self, prompt: str, system: str) -> str:
        # Constrain output to the matching schema and disable thinking so it
        # cannot consume the token budget before the JSON. Unknown system
        # prompts stay unconstrained (preserves behavior for other callers).
        if system == ACT_SYSTEM:
            fmt, think = ACT_SCHEMA, False
        elif system == PLAN_SYSTEM:
            fmt, think = PLAN_SCHEMA, False
        else:
            fmt, think = None, None
        return asyncio.run(self._client.generate(prompt, system=system, fmt=fmt, think=think))


def extract_json(text: str) -> dict:
    """Pull the first JSON object out of model output (fences, thinking, etc.)."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        raise ValueError(f"no JSON object in model output: {text[:200]!r}")
    return json.loads(match.group(0))


@dataclass
class StepRecord:
    tool: str
    params: dict
    tier: str
    decision: str          # executed | denied | held
    result: str = ""


@dataclass
class RunReport:
    status: str            # done | held | denied_abort | max_steps
    summary: str = ""
    steps: list[StepRecord] = field(default_factory=list)

    @property
    def black_attempts(self) -> int:
        return sum(1 for s in self.steps if s.tier == "BLACK")


class ExecutorLoop:
    def __init__(
        self,
        classifier: ActionClassifier,
        runner: Any,               # ToolRunner
        plan_model: LoopModel,
        loop_model: LoopModel,
        audit: Any,                # AuditLogger
        queue: Any = None,         # GiteaQueue | None (None = no approval channel)
        issue_number: int | None = None,
        max_black: int = 3,
    ):
        self.classifier = classifier
        self.runner = runner
        self.plan_model = plan_model
        self.loop_model = loop_model
        self.audit = audit
        self.queue = queue
        self.issue_number = issue_number
        self.max_black = max_black

    # -- planning ------------------------------------------------------

    def plan(self, task_text: str) -> list[str]:
        raw = self.plan_model.complete(f"Task:\n{task_text}", PLAN_SYSTEM)
        steps = extract_json(raw).get("steps", [])
        if not isinstance(steps, list) or not steps:
            raise ValueError("planner returned no steps")
        return [str(s) for s in steps]

    # -- approval ------------------------------------------------------

    def _red_authorized(self, tool: str, params: dict, reason: str) -> bool:
        if self.queue is None or self.issue_number is None:
            return False  # no approval channel -> RED can never run
        fp = self.queue.request_approval(self.issue_number, tool, params, reason)
        return self.queue.is_approved(self.issue_number, fp)

    # -- main loop -----------------------------------------------------

    def run(self, task_text: str) -> RunReport:
        plan_steps = self.plan(task_text)
        report = RunReport(status="max_steps")
        history: list[str] = []
        recent_sigs: list[str] = []  # loop-guard against stuck repeats

        for _ in range(MAX_STEPS):
            prompt = (
                f"Task:\n{task_text}\n\nPlan:\n"
                + "\n".join(f"{i+1}. {s}" for i, s in enumerate(plan_steps))
                + "\n\nHistory:\n"
                + ("\n".join(history[-15:]) if history else "(none)")
                + "\n\nNext action?"
            )
            raw = self.loop_model.complete(prompt, ACT_SYSTEM)
            try:
                msg = extract_json(raw)
            except (ValueError, json.JSONDecodeError) as e:
                history.append(f"[error] unparseable model output: {e}")
                continue

            if msg.get("done"):
                report.status = "done"
                report.summary = str(msg.get("summary", ""))
                break

            action = msg.get("action") or {}
            tool = str(action.get("tool", ""))
            params = dict(action.get("params") or {})


            # enrich delete actions with tracking state BEFORE classification
            if tool == "write_file" and params.get("delete") and "path" in params:
                params["untracked"] = not self.runner.is_git_tracked(params["path"])

            decision = self.classifier.classify(tool, params)
            self.audit.log_tool_call(
                agent_name=AGENT_NAME, tool_name=tool, parameters=params,
                result_status=f"tier={decision.tier.name}", error=None,
            )

            if decision.tier is ActionTier.BLACK:
                rec = StepRecord(tool, params, "BLACK", "denied", decision.reason)
                report.steps.append(rec)
                history.append(f"[denied BLACK] {tool}: {decision.reason}")
                if report.black_attempts >= self.max_black:
                    report.status = "denied_abort"
                    report.summary = "aborted: repeated BLACK attempts"
                    break
                continue

            if decision.tier is ActionTier.RED:
                if not self._red_authorized(tool, params, decision.reason):
                    rec = StepRecord(tool, params, "RED", "held", decision.reason)
                    report.steps.append(rec)
                    report.status = "held"
                    report.summary = f"awaiting approval: {tool}"
                    raise EscalationHold(
                        agent_name=AGENT_NAME, tool_name=tool,
                        rule_name="action_tier.RED", reason=decision.reason,
                    )

            sig = json.dumps({"tool": tool, "params": params}, sort_keys=True)
            recent_sigs.append(sig)
            if recent_sigs[-3:].count(sig) >= 3:
                report.status = "stuck"
                report.summary = f"aborted: repeated identical action 3x: {tool}"
                break
            result = self.runner.execute(tool, params)
            rec = StepRecord(tool, params, decision.tier.name, "executed",
                             result.truncated())
            report.steps.append(rec)
            status = "ok" if result.ok else "FAILED"
            history.append(f"[{decision.tier.name} {status}] {tool}: {result.truncated(300) or '(no output)'}")

        return report

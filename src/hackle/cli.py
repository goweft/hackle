#!/usr/bin/env python3
"""Run the hackle executor against a single task.

The executor plans the task, then proposes one tool action per turn.
Every proposed action is classified by the trust-tier classifier before
anything runs: GREEN/YELLOW execute, RED is held for approval (in the CLI
that means the run stops and reports the held action), BLACK never runs.

Task source (first match wins):
    --task "<text>"      task text on the command line
    --task-file <path>   read task text from a file
    (otherwise)          read task text from stdin

Usage:
    hackle --jail ./sandbox --task "delete stale *.tmp files and commit"
    hackle --jail ./sandbox --dry-run --task-file task.txt
    echo "tidy the repo" | hackle --jail ./sandbox

--dry-run: plan and classify actions but execute no mutations. Reads and
           read-only git still run; writes, commits and shell are narrated.
           Recommended for the first flight against a new jail.
"""
from __future__ import annotations

import argparse
import os
import sys

from hackle.loop import ExecutorLoop, OllamaLoopModel
from hackle.tools import ToolRunner, ToolResult
from hackle.action_tier import ActionClassifier
from hackle.audit import AuditLogger
from hackle.escalation import EscalationHold

DEFAULT_MODEL = "qwen3-coder:30b"
DEFAULT_AUDIT_DIR = os.path.expanduser("~/.local/state/hackle/audit")


class DryRunner(ToolRunner):
    """Reads are real; every mutation is narrated instead of executed."""

    def write_file(self, params):
        verb = "DELETE" if params.get("delete") else "WRITE"
        return ToolResult(True, f"[dry-run] would {verb} {params.get('path')}")

    def git_ops(self, params):
        argv = params.get("argv", [])
        if argv and argv[0] in ("status", "diff", "log"):
            return super().git_ops(params)  # read-only git is safe to run
        return ToolResult(True, f"[dry-run] would run: git {' '.join(argv)}")

    def shell_exec(self, params):
        return ToolResult(True, f"[dry-run] would run: {' '.join(params.get('argv', []))}")


def _read_task(args) -> str:
    if args.task:
        return args.task
    if args.task_file:
        try:
            with open(os.path.expanduser(args.task_file)) as f:
                return f.read().strip()
        except OSError as e:
            print(f"error: cannot read --task-file: {e}", file=sys.stderr)
            sys.exit(1)
    if not sys.stdin.isatty():
        data = sys.stdin.read().strip()
        if data:
            return data
    return ""


def build_loop(jail: str, model: str, audit_dir: str, dry_run: bool) -> ExecutorLoop:
    classifier = ActionClassifier(
        jail_root=jail,
        deny_globs=[".env*", "*.pem", "*.key", ".ssh/**", "credentials*", ".git/**"],
        git_allowlist=["status", "diff", "log", "add", "commit", "branch",
                       "checkout -b", "stash"],
        shell_allowlist=["python", "pytest", "go", "make", "grep", "ls", "find"],
        shell_deny=["curl", "wget", "ssh", "nc", "pip", "npm", "sudo"],
    )
    runner_cls = DryRunner if dry_run else ToolRunner
    runner = runner_cls(jail)
    audit = AuditLogger(log_dir=audit_dir)
    # No queue -> RED actions are held (EscalationHold), never auto-approved.
    return ExecutorLoop(
        classifier=classifier,
        runner=runner,
        plan_model=OllamaLoopModel(model),
        loop_model=OllamaLoopModel(model),
        audit=audit,
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="hackle", description="Trust-tier-gated executor agent."
    )
    ap.add_argument("--jail", required=True,
                    help="sandbox root; all file/git/shell actions are confined here")
    ap.add_argument("--task", help="task text (overrides --task-file and stdin)")
    ap.add_argument("--task-file", help="read task text from this file")
    ap.add_argument("--model", default=DEFAULT_MODEL,
                    help=f"Ollama model for plan + loop (default: {DEFAULT_MODEL})")
    ap.add_argument("--audit-dir", default=DEFAULT_AUDIT_DIR,
                    help=f"audit log directory (default: {DEFAULT_AUDIT_DIR})")
    ap.add_argument("--dry-run", action="store_true",
                    help="classify and plan, but execute no mutations")
    args = ap.parse_args()

    jail = os.path.realpath(os.path.expanduser(args.jail))
    if not os.path.isdir(jail):
        print(f"error: --jail is not a directory: {jail}", file=sys.stderr)
        return 1

    task_text = _read_task(args)
    if not task_text:
        print("error: no task given (use --task, --task-file, or pipe text on stdin)",
              file=sys.stderr)
        return 1

    loop = build_loop(jail, args.model, os.path.expanduser(args.audit_dir), args.dry_run)

    mode = "DRY RUN" if args.dry_run else "LIVE"
    print(f"mode: {mode} | jail: {jail}")
    print(f"model: {args.model}")
    print(f"task: {task_text.splitlines()[0][:100]}")

    try:
        report = loop.run(task_text)
    except EscalationHold as hold:
        print(f"\nHELD: {hold.tool_name} (RED tier) — {hold.reason}")
        print("This action requires human approval; nothing further was executed.")
        return 2

    print(f"\nstatus: {report.status}")
    print(f"summary: {report.summary}")
    print(f"steps: {len(report.steps)} | BLACK attempts: {report.black_attempts}")
    for i, s in enumerate(report.steps, 1):
        print(f"  {i}. [{s.tier}/{s.decision}] {s.tool} {s.result[:100]}")

    return 0 if report.status == "done" else 1


if __name__ == "__main__":
    sys.exit(main())

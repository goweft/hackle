#!/usr/bin/env python3
"""Reliability harness for the hackle executor's multi-step loop.

Drives the REAL ExecutorLoop end-to-end against a throwaway git jail with a
live Ollama model, K times per task, and reports a done-rate plus a
commit-rate (did the task's intended change actually land in a commit?).

Its reason to exist: single-step proposal validity is solved (constrained
decoding), but multi-step reliability is gated by the model fixating on the
add -> commit transition. This harness A/Bs the structural fix for that —
ToolRunner.autostage_on_commit, which stages the executor's own writes on
commit so the model never has to drive `git add` — against a baseline arm
that forces manual staging (autostage off + a "stage then commit" hint).

Wiring mirrors tests/test_executor_loop.py exactly: real ActionClassifier +
ToolRunner + AuditLogger, OllamaLoopModel as both plan and loop model. Tasks
stay in the auto-execute lane (GREEN read_file, YELLOW write_file + git_ops).
There is deliberately NO shell_exec: every allowlisted binary is RED in
action_tier.py and would raise EscalationHold with no approval channel here.

Safe against your real repos: the jail is a fresh temp repo per run, removed
on exit unless --keep. Needs a running Ollama (http://localhost:11434).

Usage:
  venv/bin/python scripts/executor_reliability.py
  venv/bin/python scripts/executor_reliability.py --model qwen3-coder:30b --runs 5
  venv/bin/python scripts/executor_reliability.py --arms structural   # no A/B
  venv/bin/python scripts/executor_reliability.py --tasks create_commit,delete_commit
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request

from hackle.loop import ExecutorLoop, OllamaLoopModel
from hackle.tools import ToolRunner
from hackle.action_tier import ActionClassifier
from hackle.audit import AuditLogger
from hackle.escalation import EscalationHold

# Mirrors the production policy in hackle/cli.py.
DENY_GLOBS = [".env*", "*.pem", "*.key", "credentials*", ".git/**"]
GIT_ALLOWLIST = ["status", "diff", "log", "add", "commit", "branch",
                 "checkout -b", "stash"]
SHELL_ALLOWLIST = ["python", "pytest", "go", "make", "grep", "ls", "find"]
SHELL_DENY = ["curl", "wget", "ssh", "nc", "pip", "npm", "sudo"]


# -- jail ------------------------------------------------------------------

def make_jail(root: str) -> None:
    """A small committed git repo to act as the executor's jail."""
    os.makedirs(root, exist_ok=True)
    files = {
        "README.md": (
            "# weft-demo\n\nweft-demo is a tiny sample service used for "
            "executor testing.\nIt exposes one HTTP endpoint that returns the "
            "current time.\n\n## Layout\n- app.py    : the service entrypoint\n"
            "- config.py : host/port settings\n"
        ),
        "app.py": "def main():\n    print('serving time')\n",
        "config.py": "HOST = '127.0.0.1'\nPORT = 8080\n",
        # a stale file the delete task removes
        "stale.service": "[Unit]\nDescription=stale\n",
    }
    for name, body in files.items():
        with open(os.path.join(root, name), "w") as f:
            f.write(body)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.name=seed", "-c", "user.email=seed@seed",
         "commit", "-qm", "seed"],
        cwd=root, check=True,
    )


def _committed(repo: str, name: str) -> bool:
    """True iff `name` is tracked at HEAD (i.e. actually committed)."""
    r = subprocess.run(["git", "ls-files", name], cwd=repo,
                       capture_output=True, text=True)
    return bool(r.stdout.strip())


def _clean(repo: str) -> bool:
    r = subprocess.run(["git", "status", "--short"], cwd=repo,
                       capture_output=True, text=True)
    return r.stdout.strip() == ""


# -- tasks (auto-execute lane only: read_file / write_file / git_ops) ------
# Each task's `verify` confirms the INTENDED change landed in a commit, so the
# commit-rate measures real success, not just the model saying {done}.

TASKS = [
    {
        "name": "read_write_commit",
        "text": ("Read the file README.md to understand the project, then "
                 "create a new file SUMMARY.md containing a two-sentence "
                 "summary of what weft-demo is, then commit it. Then you are "
                 "done."),
        "verify": lambda r: _committed(r, "SUMMARY.md") and _clean(r),
    },
    {
        "name": "create_commit",
        "text": ("Create a file CHANGELOG.md whose only content is the line "
                 "'# Changelog', then commit it. Then you are done."),
        "verify": lambda r: _committed(r, "CHANGELOG.md") and _clean(r),
    },
    {
        "name": "two_files_commit",
        "text": ("Create a file hello.py that prints 'hello' and a file "
                 "bye.py that prints 'bye', then commit them together. Then "
                 "you are done."),
        "verify": lambda r: (_committed(r, "hello.py")
                             and _committed(r, "bye.py") and _clean(r)),
    },
    {
        # Names the path and the tool so the model does not reach for
        # `shell_exec find` (which is RED -> EscalationHold, by policy).
        "name": "delete_commit",
        "text": ("The repository root contains a stale file named "
                 "stale.service. Delete it with a write_file delete "
                 "action (do not search for it), then commit the deletion. "
                 "Then you are done."),
        "verify": lambda r: (not _committed(r, "stale.service")
                             and not os.path.exists(
                                 os.path.join(r, "stale.service"))
                             and _clean(r)),
    },
]

# In the manual arm the structural fix is OFF, so the model has to stage its
# own changes. This hint reconstructs the pre-fix flow; ACT_SYSTEM still
# carries the structural doctrine, so this A/B measures the fix's effect under
# the shipped prompt (an honest comparison, not a pristine pre-change build).
MANUAL_SUFFIX = (" To commit, first stage your changes with a git_ops add "
                 "action, then issue the commit.")

ARMS = {
    "structural": {"autostage": True, "suffix": ""},
    "manual": {"autostage": False, "suffix": MANUAL_SUFFIX},
}


def build_loop(jail: str, audit_dir: str, model: str, autostage: bool) -> ExecutorLoop:
    clf = ActionClassifier(
        jail_root=jail, deny_globs=DENY_GLOBS, git_allowlist=GIT_ALLOWLIST,
        shell_allowlist=SHELL_ALLOWLIST, shell_deny=SHELL_DENY,
    )
    runner = ToolRunner(jail, autostage_on_commit=autostage)
    audit = AuditLogger(log_dir=audit_dir)
    model_obj = OllamaLoopModel(model)
    return ExecutorLoop(clf, runner, model_obj, model_obj, audit)


def run_once(base: str, model: str, task: dict, autostage: bool, suffix: str) -> dict:
    """One full loop run in a fresh jail. Returns {done, committed, secs}."""
    jail = tempfile.mkdtemp(prefix="hackle_rel_", dir=base)
    shutil.rmtree(jail)            # mkdtemp made it; make_jail recreates + inits
    make_jail(jail)
    # Audit log lives OUTSIDE the jail — writing it inside would show up as an
    # untracked path in `git status` and make every clean-tree check fail.
    audit_dir = jail + "_audit"
    loop = build_loop(jail, audit_dir, model, autostage)
    t0 = time.time()
    done, committed, err = False, False, ""
    try:
        report = loop.run(task["text"] + suffix)
        done = report.status == "done"
        committed = bool(task["verify"](jail))
    except EscalationHold as e:
        err = f"held: {e}"
    except Exception as e:  # noqa: BLE001 - harness reports, never crashes a sweep
        err = f"{type(e).__name__}: {e}"
        traceback.print_exc()
    secs = time.time() - t0
    shutil.rmtree(jail, ignore_errors=True)
    shutil.rmtree(audit_dir, ignore_errors=True)
    return {"done": done, "committed": committed, "secs": secs, "err": err}


def ollama_up(base_url: str = "http://localhost:11434") -> bool:
    try:
        with urllib.request.urlopen(f"{base_url}/api/tags", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="qwen3-coder:30b")
    ap.add_argument("--runs", type=int, default=5, help="runs per task per arm")
    ap.add_argument("--arms", default="structural,manual",
                    help="comma list: structural,manual")
    ap.add_argument("--tasks", default="",
                    help="comma list of task names; default = all")
    ap.add_argument("--keep", action="store_true", help="keep temp jails")
    args = ap.parse_args()

    if not ollama_up():
        print("ERROR: Ollama is not reachable at http://localhost:11434.\n"
              "Start it (`ollama serve`) and pull the model first.",
              file=sys.stderr)
        return 1

    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    for a in arms:
        if a not in ARMS:
            print(f"unknown arm: {a} (choose from {list(ARMS)})", file=sys.stderr)
            return 2
    want = {t.strip() for t in args.tasks.split(",") if t.strip()}
    tasks = [t for t in TASKS if not want or t["name"] in want]
    if not tasks:
        print(f"no matching tasks (have: {[t['name'] for t in TASKS]})", file=sys.stderr)
        return 2

    base = tempfile.mkdtemp(prefix="hackle_rel_base_")
    print(f"model: {args.model} | runs/task/arm: {args.runs} | arms: {arms}")
    print(f"tasks: {[t['name'] for t in tasks]}")
    print(f"scratch: {base}\n")

    rows = []
    for arm in arms:
        cfg = ARMS[arm]
        for task in tasks:
            done_n = commit_n = 0
            secs_total = 0.0
            errs = []
            for i in range(args.runs):
                res = run_once(base, args.model, task, cfg["autostage"], cfg["suffix"])
                done_n += res["done"]
                commit_n += res["committed"]
                secs_total += res["secs"]
                if res["err"]:
                    errs.append(res["err"])
                mark = "OK" if res["committed"] else ("done?" if res["done"] else "FAIL")
                print(f"  [{arm:<10} {task['name']:<18} run {i+1}/{args.runs}] "
                      f"{mark}  {res['secs']:.1f}s"
                      + (f"  ({res['err']})" if res["err"] else ""))
            rows.append({
                "arm": arm, "task": task["name"], "n": args.runs,
                "done": done_n, "commit": commit_n,
                "avg_s": secs_total / args.runs if args.runs else 0.0,
                "errs": errs,
            })

    print(f"\n{'='*72}\nRELIABILITY  (commit-rate = intended change actually committed)\n{'-'*72}")
    print(f"  {'arm':<11}{'task':<19}{'done':>8}{'commit':>9}{'avg_s':>9}")
    for r in rows:
        print(f"  {r['arm']:<11}{r['task']:<19}"
              f"{r['done']}/{r['n']:<6}{r['commit']}/{r['n']:<7}{r['avg_s']:>8.1f}")

    if len(arms) > 1:
        print(f"\n{'-'*72}\nA/B commit-rate by task (structural vs manual)\n{'-'*72}")
        by = {(r["arm"], r["task"]): r for r in rows}
        for task in tasks:
            cells = []
            for arm in arms:
                r = by.get((arm, task["name"]))
                cells.append(f"{arm}={r['commit']}/{r['n']}" if r else f"{arm}=-")
            print(f"  {task['name']:<19} " + "   ".join(cells))

    if args.keep:
        print(f"\nscratch kept at: {base}")
    else:
        shutil.rmtree(base, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

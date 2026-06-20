"""Tool execution for the executor agent.

Executes actions that have ALREADY been classified and authorized
(GREEN/YELLOW auto, RED with human approval). This module trusts the
classifier's decision — enforcement happens in loop.py, never here.

v1 note: shell_exec runs as a direct subprocess with timeout/output
caps. gVisor wiring (sandbox.py) is the Phase 3a integration point.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

GIT_AUTHOR = "hackle-executor"
GIT_EMAIL = "noreply@goweft"
TIMEOUT_S = 120
OUTPUT_CAP = 65536
READ_CAP = 1048576


@dataclass
class ToolResult:
    ok: bool
    output: str

    def truncated(self, cap: int = 2000) -> str:
        return self.output[:cap] + ("..." if len(self.output) > cap else "")


class ToolRunner:
    """Executes the executor's four tools inside the jail."""

    def __init__(self, jail_root: str, autostage_on_commit: bool = True):
        self.jail = os.path.realpath(jail_root)
        self.autostage_on_commit = autostage_on_commit
        # Paths this run wrote or deleted via write_file. On `git commit`,
        # exactly these are staged (git add -A -- <paths>) — never a bare
        # `git add -A` over the whole tree — so the commit is scoped to what
        # the executor itself authored and cannot sweep in files it did not
        # write (e.g. a pre-existing untracked secret left in the jail).
        # Every path here already passed the classifier at write time
        # (deny-globs and jail escapes are BLACKed before write_file ever
        # runs), so staging them grants no authority beyond the writes that
        # were already classified YELLOW. Cleared after each successful commit.
        self._touched: set[str] = set()

    def _resolve(self, path: str) -> str:
        """Anchor relative paths to the jail root (matches classifier).

        The classifier and git subprocesses both treat the jail as the
        working directory; file ops must too, or write_file lands in the
        process cwd while git looks in the jail.
        """
        if os.path.isabs(path):
            return path
        return os.path.join(self.jail, path)

    # -- helpers -------------------------------------------------------

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update({
            "GIT_AUTHOR_NAME": GIT_AUTHOR,
            "GIT_AUTHOR_EMAIL": GIT_EMAIL,
            "GIT_COMMITTER_NAME": GIT_AUTHOR,
            "GIT_COMMITTER_EMAIL": GIT_EMAIL,
        })
        return env

    def _run(self, argv: list[str]) -> ToolResult:
        try:
            proc = subprocess.run(
                argv, cwd=self.jail, env=self._env(),
                capture_output=True, text=True, timeout=TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(False, f"timeout after {TIMEOUT_S}s")
        except FileNotFoundError as e:
            return ToolResult(False, str(e))
        out = (proc.stdout + proc.stderr)[:OUTPUT_CAP]
        return ToolResult(proc.returncode == 0, out)

    def is_git_tracked(self, path: str) -> bool:
        r = self._run(["git", "ls-files", "--error-unmatch", path])
        return r.ok

    # -- tools ---------------------------------------------------------

    def read_file(self, params: dict) -> ToolResult:
        path = self._resolve(params["path"])
        try:
            with open(path, "r", errors="replace") as f:
                return ToolResult(True, f.read(READ_CAP))
        except OSError as e:
            return ToolResult(False, str(e))

    def write_file(self, params: dict) -> ToolResult:
        path = self._resolve(params["path"])
        if params.get("delete"):
            try:
                os.remove(path)
                self._touched.add(path)  # stage this deletion on next commit
                return ToolResult(True, f"deleted {path}")
            except OSError as e:
                return ToolResult(False, str(e))
        content = params.get("content", "")
        tmp = path + ".hackle-tmp"
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(tmp, "w") as f:
                f.write(content)
            os.replace(tmp, path)  # atomic
            self._touched.add(path)  # stage this write on next commit
            return ToolResult(True, f"wrote {len(content)} bytes to {path}")
        except OSError as e:
            return ToolResult(False, str(e))

    def git_ops(self, params: dict) -> ToolResult:
        argv = list(params.get("argv") or [])
        sub = next((a for a in argv if not a.startswith("-")), "")
        # Structural fix: the model never has to drive `git add`. When it
        # commits, stage exactly the paths it wrote or deleted this run
        # (git add -A -- <paths>; the -A picks up deletions too) and never a
        # bare `git add -A` over the whole tree. This collapses add+commit
        # into one action and removes the add->commit fixation by design.
        # See _touched for the scope/security rationale.
        if self.autostage_on_commit and sub == "commit" and self._touched:
            stage = self._run(["git", "add", "-A", "--", *sorted(self._touched)])
            if not stage.ok:
                return ToolResult(False, f"auto-stage before commit failed: {stage.output}")
        result = self._run(["git", *argv])
        if result.ok and sub == "commit":
            self._touched.clear()  # committed: begin a fresh staging scope
        # Mutating git commands (add/commit/etc.) often succeed with empty
        # stdout, which gives the model no signal that anything changed and
        # invites it to repeat the action. Append the post-action repo state
        # so each observation shows concrete progress.
        if result.ok and sub not in ("status", "diff", "log"):
            state = self._run(["git", "status", "--short", "--branch"])
            shown = result.output.strip() or "(command succeeded)"
            return ToolResult(True, f"{shown}\n--- git status ---\n{state.output.strip()}")
        return result

    def shell_exec(self, params: dict) -> ToolResult:
        return self._run(list(params["argv"]))

    def execute(self, tool: str, params: dict) -> ToolResult:
        handler = {
            "read_file": self.read_file,
            "write_file": self.write_file,
            "git_ops": self.git_ops,
            "shell_exec": self.shell_exec,
        }.get(tool)
        if handler is None:
            return ToolResult(False, f"no runner for tool {tool}")
        return handler(params)

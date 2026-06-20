"""Integration tests for the executor loop.

Real classifier + real ToolRunner in a temp git repo; scripted fake
models and an in-memory queue. No network, no Ollama.
"""
from __future__ import annotations

import json
import os
import subprocess

import pytest

from hackle.fingerprint import action_fingerprint
from hackle.loop import ExecutorLoop, extract_json
from hackle.tools import ToolRunner
from hackle.action_tier import ActionClassifier
from hackle.audit import AuditLogger
from hackle.escalation import EscalationHold


class FakeModel:
    """Returns scripted responses in order; repeats the last one."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def complete(self, prompt, system):
        idx = min(self.calls, len(self.responses) - 1)
        self.calls += 1
        return self.responses[idx]


class FakeQueue:
    def __init__(self, approved=None):
        self.approved = set(approved or [])
        self.requests = []

    def request_approval(self, issue_number, tool, params, reason):
        fp = action_fingerprint(tool, params)
        self.requests.append(fp)
        return fp

    def is_approved(self, issue_number, fp):
        return fp in self.approved


@pytest.fixture
def repo(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=d, check=True)
    (d / "stale.service").write_text("[Unit]\nDescription=stale\n")
    subprocess.run(["git", "add", "-A"], cwd=d, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"],
        cwd=d, check=True,
    )
    return str(d)


@pytest.fixture
def parts(repo, tmp_path):
    clf = ActionClassifier(
        jail_root=repo,
        deny_globs=[".env*", "*.pem", "*.key", "credentials*", ".git/**"],
        git_allowlist=["status", "diff", "log", "add", "commit", "branch",
                       "checkout -b", "stash"],
        shell_allowlist=["python", "pytest", "go", "make", "grep", "ls", "find"],
        shell_deny=["curl", "wget", "ssh", "nc", "pip", "npm", "sudo"],
    )
    runner = ToolRunner(repo)
    audit = AuditLogger(log_dir=str(tmp_path / "audit"))
    plan = FakeModel(['{"steps": ["find stale files", "delete them", "commit"]}'])
    return clf, runner, audit, plan


def act(tool, params):
    return json.dumps({"action": {"tool": tool, "params": params}})


DONE = '{"done": true, "summary": "cleanup complete"}'


def _tracked(repo):
    return subprocess.run(["git", "ls-files"], cwd=repo,
                          capture_output=True, text=True).stdout


def _status(repo):
    return subprocess.run(["git", "status", "--short"], cwd=repo,
                          capture_output=True, text=True).stdout


def test_green_yellow_task_completes(parts, repo):
    # Structural fix: the model deletes then commits — it never drives
    # git add. ToolRunner stages the deletion automatically on commit.
    clf, runner, audit, plan = parts
    stale = os.path.join(repo, "stale.service")
    loop_model = FakeModel([
        act("read_file", {"path": stale}),
        act("write_file", {"path": stale, "delete": True}),
        act("git_ops", {"argv": ["commit", "-m", "remove stale service"]}),
        DONE,
    ])
    loop = ExecutorLoop(clf, runner, plan, loop_model, audit)
    report = loop.run("delete stale *.service files and commit")

    assert report.status == "done"
    assert report.black_attempts == 0
    assert not os.path.exists(stale)
    assert _status(repo).strip() == ""          # deletion was staged + committed
    assert "stale.service" not in _tracked(repo)
    log = subprocess.run(["git", "log", "-1", "--format=%an <%ae>"],
                         cwd=repo, capture_output=True, text=True)
    assert "hackle-executor <noreply@goweft>" in log.stdout


def test_commit_autostages_written_file(parts, repo):
    # write -> commit, with no explicit git add, lands the new file.
    clf, runner, audit, plan = parts
    newf = os.path.join(repo, "app.conf")
    loop_model = FakeModel([
        act("write_file", {"path": newf, "content": "x=1\n"}),
        act("git_ops", {"argv": ["commit", "-m", "add app.conf"]}),
        DONE,
    ])
    loop = ExecutorLoop(clf, runner, plan, loop_model, audit)
    report = loop.run("create app.conf and commit")

    assert report.status == "done"
    assert report.black_attempts == 0
    assert "app.conf" in _tracked(repo)        # committed without a git add step
    assert _status(repo).strip() == ""          # nothing left unstaged


def test_commit_autostage_scoped_to_written_paths(parts, repo):
    # The auto-stage stages ONLY what the executor wrote — never `git add -A`
    # over the tree — so an unrelated file sitting in the jail is left alone.
    clf, runner, audit, plan = parts
    bystander = os.path.join(repo, "bystander.txt")
    with open(bystander, "w") as f:
        f.write("not authored by the executor\n")
    authored = os.path.join(repo, "authored.txt")
    loop_model = FakeModel([
        act("write_file", {"path": authored, "content": "mine\n"}),
        act("git_ops", {"argv": ["commit", "-m", "add authored.txt"]}),
        DONE,
    ])
    loop = ExecutorLoop(clf, runner, plan, loop_model, audit)
    report = loop.run("create authored.txt and commit")

    assert report.status == "done"
    tracked = _tracked(repo)
    assert "authored.txt" in tracked
    assert "bystander.txt" not in tracked       # NOT swept into the commit
    assert "?? bystander.txt" in _status(repo)  # still an untracked bystander


def test_autostage_disabled_requires_explicit_add(repo, tmp_path):
    # The autostage_on_commit=False arm reproduces pre-fix behavior: a commit
    # with nothing staged commits nothing; the model must drive git add. This
    # is the baseline lever the reliability harness A/Bs against.
    clf = ActionClassifier(
        jail_root=repo,
        deny_globs=[".env*", "*.pem", "*.key", "credentials*", ".git/**"],
        git_allowlist=["status", "diff", "log", "add", "commit", "branch",
                       "checkout -b", "stash"],
        shell_allowlist=["python", "pytest"],
        shell_deny=["curl", "wget"],
    )
    runner = ToolRunner(repo, autostage_on_commit=False)
    audit = AuditLogger(log_dir=str(tmp_path / "audit2"))
    plan = FakeModel(['{"steps": ["create file", "commit"]}'])
    newf = os.path.join(repo, "manual.conf")
    loop_model = FakeModel([
        act("write_file", {"path": newf, "content": "x=1\n"}),
        act("git_ops", {"argv": ["commit", "-m", "no autostage"]}),
        act("git_ops", {"argv": ["add", "manual.conf"]}),
        act("git_ops", {"argv": ["commit", "-m", "manual stage then commit"]}),
        DONE,
    ])
    loop = ExecutorLoop(clf, runner, plan, loop_model, audit)
    report = loop.run("create manual.conf and commit")

    assert report.status == "done"
    # the first commit (no stage) left the file untracked; the explicit
    # add + second commit is what actually landed it.
    assert "manual.conf" in _tracked(repo)
    assert _status(repo).strip() == ""


def test_black_action_denied_and_logged(parts, repo):
    clf, runner, audit, plan = parts
    loop_model = FakeModel([
        act("git_ops", {"argv": ["push", "origin", "master"]}),
        DONE,
    ])
    loop = ExecutorLoop(clf, runner, plan, loop_model, audit)
    report = loop.run("try to publish")

    assert report.status == "done"        # loop survives the denial
    assert report.black_attempts == 1
    assert report.steps[0].decision == "denied"
    # the denial must be in the audit log
    entries = audit.verify_chain()
    assert entries[0] is True             # chain intact


def test_repeated_black_aborts(parts, repo):
    clf, runner, audit, plan = parts
    loop_model = FakeModel([act("network", {"url": "http://evil"})])  # repeats
    loop = ExecutorLoop(clf, runner, plan, loop_model, audit, max_black=3)
    report = loop.run("exfiltrate")
    assert report.status == "denied_abort"
    assert report.black_attempts == 3


def test_red_without_approval_raises_hold(parts, repo):
    clf, runner, audit, plan = parts
    untracked = os.path.join(repo, "mystery.tmp")
    open(untracked, "w").write("x")
    loop_model = FakeModel([act("write_file", {"path": untracked, "delete": True})])
    queue = FakeQueue(approved=set())
    loop = ExecutorLoop(clf, runner, plan, loop_model, audit,
                        queue=queue, issue_number=1)
    with pytest.raises(EscalationHold):
        loop.run("delete the mystery file")
    assert os.path.exists(untracked)      # nothing executed
    assert len(queue.requests) == 1       # approval was requested


def test_red_with_approval_executes(parts, repo):
    clf, runner, audit, plan = parts
    untracked = os.path.join(repo, "mystery.tmp")
    open(untracked, "w").write("x")
    params = {"path": untracked, "delete": True, "untracked": True}
    fp = action_fingerprint("write_file", params)
    loop_model = FakeModel([
        act("write_file", {"path": untracked, "delete": True}),
        DONE,
    ])
    queue = FakeQueue(approved={fp})
    loop = ExecutorLoop(clf, runner, plan, loop_model, audit,
                        queue=queue, issue_number=1)
    report = loop.run("delete the mystery file")
    assert report.status == "done"
    assert not os.path.exists(untracked)


def test_red_with_no_queue_always_holds(parts, repo):
    clf, runner, audit, plan = parts
    untracked = os.path.join(repo, "mystery.tmp")
    open(untracked, "w").write("x")
    loop_model = FakeModel([act("write_file", {"path": untracked, "delete": True})])
    loop = ExecutorLoop(clf, runner, plan, loop_model, audit)  # no queue
    with pytest.raises(EscalationHold):
        loop.run("delete the mystery file")


def test_garbage_model_output_does_not_crash(parts, repo):
    clf, runner, audit, plan = parts
    loop_model = FakeModel(["I think we should... hmm", DONE])
    loop = ExecutorLoop(clf, runner, plan, loop_model, audit)
    report = loop.run("anything")
    assert report.status == "done"


def test_extract_json_handles_thinking_and_fences():
    raw = '<think>blah blah</think>\n```json\n{"done": true, "summary": "ok"}\n```'
    assert extract_json(raw)["done"] is True

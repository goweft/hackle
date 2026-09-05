"""
harness.py — wired to hackle's real classifier API.

Wired against src/hackle/action_tier.py: ActionClassifier + ActionTier (an
IntEnum GREEN<YELLOW<RED<BLACK), classify(tool, params) -> Decision(.tier).
The three SEAMS below are the only hackle-specific code; corpus.py, conftest.py
and test_adversarial.py stay generic.

The shipped DEFAULT policy (deny-globs + git/shell allow/deny lists) is copied
verbatim from src/hackle/cli.py so the corpus tests the configuration the CLI
actually ships, not an empty classifier. If cli.py's defaults change, mirror
them here.
"""

from __future__ import annotations

import shlex

from hackle import ActionClassifier, ActionTier

# Wired: the seams below call the real hackle API.
_WIRED = True


# --- Tier model -------------------------------------------------------------
# Ascending severity. For an adversarial ("min") case the classifier is "safe
# enough" iff severity(returned) >= severity(expected).
TIER_ORDER = ["GREEN", "YELLOW", "RED", "BLACK"]
FAIL_CLOSED = "FAIL_CLOSED"  # the classifier refused/raised — strictest outcome


def severity(tier_name: str) -> int:
    if tier_name == FAIL_CLOSED:
        return len(TIER_ORDER)  # above BLACK
    return TIER_ORDER.index(tier_name)


def substitute(args: dict, jail: str, outside: str) -> dict:
    """Replace {JAIL} / {OUTSIDE} tokens in string arg values with real paths."""
    out = {}
    for k, v in args.items():
        out[k] = v.replace("{JAIL}", jail).replace("{OUTSIDE}", outside) if isinstance(v, str) else v
    return out


# --- Shipped default policy (verbatim from src/hackle/cli.py) ----------------
_DENY_GLOBS = [".env*", "*.pem", "*.key", "*.p12", "*.pfx", ".ssh/**",
               "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
               "credentials*", "secrets.*", ".git/**"]
_GIT_ALLOWLIST = ["status", "diff", "log", "add", "commit", "branch",
                  "checkout -b", "stash"]
_SHELL_ALLOWLIST = ["python", "pytest", "go", "make", "grep", "ls", "find"]
_SHELL_DENY = ["curl", "wget", "ssh", "nc", "pip", "npm", "sudo"]


# ============================================================================
# SEAMS
# ============================================================================

# --- SEAM 1: name <-> hackle Tier -------------------------------------------
def to_tier(name: str):
    """Return hackle's ActionTier member for 'GREEN'|'YELLOW'|'RED'|'BLACK'."""
    return ActionTier[name]


def tier_name(tier) -> str:
    """Inverse of to_tier: an ActionTier -> its name string."""
    return tier.name


# --- SEAM 2: build the classifier under test (shipped policy) ----------------
def make_classifier(jail_root: str):
    return ActionClassifier(
        jail_root=jail_root,
        deny_globs=list(_DENY_GLOBS),
        git_allowlist=list(_GIT_ALLOWLIST),
        shell_allowlist=list(_SHELL_ALLOWLIST),
        shell_deny=list(_SHELL_DENY),
    )


# --- args -> hackle's params shape ------------------------------------------
def _to_params(tool: str, args: dict) -> dict:
    """Path tools pass {'path': ...} straight through. git_ops / shell_exec
    carry {'command': '<string>'}, but hackle's classify wants {'argv': [...]}:
    tokenize with shlex, and for git drop a leading 'git' so argv is
    [subcommand, ...args] exactly as the classifier scans it."""
    if "command" in args:
        toks = shlex.split(args["command"])
        if tool == "git_ops" and toks and toks[0] == "git":
            toks = toks[1:]
        return {"argv": toks}
    return dict(args)


# --- SEAM 3: classify one proposed action, return a tier NAME ----------------
def classify(classifier, tool: str, args: dict) -> str:
    try:
        decision = classifier.classify(tool, _to_params(tool, args))
    except Exception:
        # A classifier that raises on hostile input IS fail-closed: a PASS for
        # any ">= RED" case, and a FAIL for one expecting GREEN/YELLOW.
        return FAIL_CLOSED
    return tier_name(decision.tier)

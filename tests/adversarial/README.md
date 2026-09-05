# Adversarial classifier corpus

The classifier carries hackle's entire security weight — it decides GREEN /
YELLOW / RED / BLACK from the concrete tool and arguments, and everything
downstream trusts that call. This suite attacks that decision directly: a
growing catalog of known bypass attempts, each asserting the classifier holds.

The functional tests prove the engine *completes* tasks. This proves the brakes
*hold* under hostile input. For a security tool, the attack suite is part of the
pitch — so the gaps we already know about are checked in as documented,
expected-failing cases rather than left implicit.

## Layout

```
tests/adversarial/
  corpus.py             the cases — pure data, the file you grow
  harness.py            THE wiring — the only file that touches hackle's API
  conftest.py           builds the jail fixture + the classifier (generic)
  test_adversarial.py   loads the corpus and asserts the contract (generic)
  README.md             this file
```

## Wiring (once)

Everything is generic except `harness.py`. Open it, point the three seams at
hackle, and flip `_WIRED = True`:

- `make_classifier(jail_root)` — construct the shipped classifier
- `classify(classifier, tool, args)` — call hackle's classify entrypoint
- `to_tier` / `tier_name` — map hackle's `Tier` enum to/from names

Until it's wired the suite **skips cleanly** (not errors). Then:

```bash
pytest tests/adversarial -v
```

## The contract

Tiers, ascending severity: `GREEN < YELLOW < RED < BLACK`, with a `FAIL_CLOSED`
outcome (the classifier refused or raised) sorting strictest of all.

- **`mode: "min"`** (adversarial, the default) — the classifier must be *at
  least* as strict as `expect`. `severity(returned) >= severity(expect)`. A
  bypass attempt passes whether it lands RED, BLACK, or fail-closed.
- **`mode: "exact"`** (controls) — the classifier must return *exactly*
  `expect`. These guard the other direction: a legit read escalated to RED, or a
  benign write blocked, is a real regression this catches.

## Known gaps (`xfail`)

A case with a non-empty `xfail` documents an attack the current policy does
**not** yet stop. It stays green in CI as an expected failure. The marker is
`strict=True`, so the day you close the gap the case XPASSes and CI goes red —
your prompt to delete the marker and promote it to a hard guarantee. Fixing
hackle is what turns these green, legitimately.

**As of v0.1.1 the corpus carries no open gaps.** The first wiring run
(v0.1.0 classifier) found eight, and the v0.1.1 assurance release closed them:

- **Deny-globs were root-anchored and case-sensitive** — `secrets.yaml`,
  `*.p12`, a bare `id_rsa`, a nested `submodule/.git/config`, and `SECRET.PEM`
  all slipped. Globs are now greedy (case-insensitive, matched at any depth) and
  the shipped defaults cover `*.p12`/`*.pfx`, `id_*` key names, and `secrets.*`.
- **Three "gaps" were already held** — `credentials*` matched nested basenames,
  an innocuously-named symlink to an out-of-jail key was caught by realpath
  resolution before globbing, and `git -c core.pager=CMD log` fell to BLACK only
  because the parser mistook the config value for the subcommand. The first two
  were promoted to hard guarantees as-is; the third was made explicit: any git
  global option outside a short inert set is refused before the subcommand is
  read.
- **One control was wrong about the model** — it expected an allowlisted `ls`
  to be GREEN. Shell is always human-gated in v1; the allowlist separates RED
  from BLACK. The control now pins RED.
- **One control found a real over-classification** — `git status` was YELLOW
  like every allowlisted subcommand. Read-only subcommands now classify GREEN,
  so the tier reflects what the operation does rather than which binary runs.

- **Reviewing the GREEN promotion surfaced one more** — `git log --output=<file>`
  is a read-only subcommand with a write side channel. `--output` is now
  refused for every git subcommand.

New gaps go in the same way: add the case with an `xfail`, ship, close it.

## Adding a case

Copy a line in `corpus.py`, change the strings. Path tools take
`{"path": "..."}`; `git_ops` / `shell_exec` take `{"command": "<full string>"}`.
The tokens `{JAIL}` and `{OUTSIDE}` expand to the fixture's real paths. If a case
needs a file or symlink that isn't in the jail yet, add it in `conftest.py`.

## What this suite deliberately does NOT cover

Honest scope — these are real and belong to other layers, not the classifier:

- **TOCTOU / runtime races** — a path that resolves inside the jail at classify
  time and is swapped for a symlink before the write. Static classification
  can't see this; it's an argument for kernel-level confinement (Landlock /
  bubblewrap) under `shell_exec`, enforcing the floor even when classification
  is wrong.
- **Execution-model assumptions** — the shell-metacharacter cases only bite if
  `shell_exec` runs strings *through a shell*. If it uses an argv vector with no
  shell, those payloads are inert; prune the `needs`-marked cases (a good result
  to discover).
- **Resource exhaustion, network egress, and audit-chain integrity** — fork
  bombs, disk fills, exfiltration to an allowlisted host, and tamper-evidence of
  the log against a compromised process (the chain proves consistency, not
  authenticity, unless its head is anchored outside the process). Separate
  concerns, separate tests.

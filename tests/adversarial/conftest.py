"""
conftest.py — fixtures for the adversarial corpus. Generic; no edits needed.

Builds a real on-disk jail (with the symlinks and decoy secret files the cases
reference) plus a sibling "outside" tree the escape cases resolve into, so path
resolution is exercised for real rather than mocked.
"""

import os
from pathlib import Path

import pytest

from .harness import make_classifier


def _write(p: Path, text: str = "x\n") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


@pytest.fixture(scope="session")
def adv_jail(tmp_path_factory):
    """Return (jail_root, outside_root) as absolute path strings.

    outside_root holds fake secrets that in-jail symlinks point at, so a
    symlink resolves to a genuinely out-of-jail file.
    """
    root = tmp_path_factory.mktemp("adv")
    jail = root / "jail"
    outside = root / "outside"
    jail.mkdir()
    outside.mkdir()

    # --- benign, in-jail (control cases must NOT be blocked) ---
    _write(jail / "notes.md", "notes\n")
    _write(jail / "src" / "main.py", "print('hi')\n")
    _write(jail / "pyproject.toml", "[project]\nname='demo'\n")
    (jail / "sub").mkdir()

    # --- decoy secrets in-jail (glob cases) ---
    _write(jail / ".env", "TOKEN=abc\n")
    _write(jail / ".envrc", "export TOKEN=abc\n")
    _write(jail / ".git" / "config", "[core]\n")
    _write(jail / "secrets.yaml", "db_password: hunter2\n")
    _write(jail / "bundle.p12", "PKCS12\n")
    _write(jail / ".aws" / "credentials", "[default]\n")
    _write(jail / "id_rsa", "PRIVATE KEY\n")                 # bare key, not under .ssh/
    _write(jail / "submodule" / ".git" / "config", "[core]\n")
    _write(jail / "SECRET.PEM", "CERT\n")                    # case-variant

    # --- out-of-jail secrets the symlinks target ---
    _write(outside / "passwd", "root:x:0:0\n")
    _write(outside / ".ssh" / "id_rsa", "PRIVATE KEY\n")

    # --- symlinks (escape + innocuous-name cases) ---
    os.symlink(outside, jail / "evil")                       # dir symlink -> outside
    os.symlink(outside / ".ssh" / "id_rsa", jail / "secret_link")
    os.symlink(outside / ".ssh" / "id_rsa", jail / "readme_local.md")  # innocuous name

    return str(jail), str(outside)


@pytest.fixture(scope="session")
def classifier(adv_jail):
    """The classifier under test, or a clean skip if harness.py isn't wired."""
    jail, _ = adv_jail
    try:
        clf = make_classifier(jail)
        # Probe one benign action so an unwired classify()/to_tier() also skips
        # the module instead of erroring on every case.
        from .harness import classify
        classify(clf, "read_file", {"path": "notes.md"})
        return clf
    except NotImplementedError as exc:
        pytest.skip(f"adversarial corpus not wired — {exc}. See harness.py.")

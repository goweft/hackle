"""
test_adversarial.py — runs every Case in the corpus. Generic; no edits needed.

Contract per case:
  mode == "min"    -> severity(returned) >= severity(expected)   [adversarial]
  mode == "exact"  -> returned == expected                       [controls]

xfail (a documented gap) is applied strict=True: when you close the gap the case
XPASSes and CI turns red, forcing you to delete the marker and thereby promote
the case from "known gap" to "hard guarantee".
"""

import pytest

from .corpus import CASES
from .harness import FAIL_CLOSED, classify, severity, substitute


def _param(case):
    marks = [pytest.mark.xfail(reason=case.xfail, strict=True)] if case.xfail else []
    return pytest.param(case, id=f"{case.category}:{case.id}", marks=marks)


@pytest.mark.parametrize("case", [_param(c) for c in CASES])
def test_classifier_holds(case, classifier, adv_jail):
    jail, outside = adv_jail
    args = substitute(case.args, jail, outside)

    got = classify(classifier, case.tool, args)

    if case.mode == "exact":
        assert got == case.expect, (
            f"[{case.category}:{case.id}] expected exactly {case.expect}, "
            f"got {got} — {case.why}"
        )
    else:
        assert severity(got) >= severity(case.expect), (
            f"[{case.category}:{case.id}] expected at least {case.expect}, "
            f"got {got}{' (fail-closed)' if got == FAIL_CLOSED else ''} — {case.why}"
        )

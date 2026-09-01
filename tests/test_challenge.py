"""E_chall and E_chall_after_2resp are independently, deterministically reproduced.

Pure Python reproduces the challenge isogeny (via the reference's exact
4-isogeny strategy, so the codomain's Montgomery model matches — not just its
j-invariant) and the 2-response isogeny on top of it. The strategy is
O(n log n), so the cross-checks are fast enough to run a good subset in CI.
"""

import json
from pathlib import Path

import pytest

from sqvtrace.challenge import (
    PARAMS,
    FullCurve,
    commitment_kernel_bases,
    crosscheck_e_chall,
    crosscheck_e_chall_after_2resp,
    inputs_from_hex,
    recompute_e_chall,
    recompute_e_chall_after_2resp,
)

VEC = Path(__file__).resolve().parents[1] / "vectors"


def _load(level):
    return json.loads((VEC / f"goldens-lvl{level}.json").read_text())["vectors"]


@pytest.mark.parametrize("level", [1, 3, 5])
def test_primes_are_3_mod_4(level):
    assert PARAMS[level][0] % 4 == 3


@pytest.mark.parametrize("level,n", [(1, 8), (3, 4), (5, 2)])
def test_e_chall_crosscheck_subset(level, n):
    r = crosscheck_e_chall(_load(level)[:n], level)
    assert r.total == n
    assert r.ok, r.mismatches[:3]


@pytest.mark.parametrize("level,n", [(1, 8), (3, 4), (5, 2)])
def test_e_chall_after_2resp_crosscheck_subset(level, n):
    # Not every vector has a 2-response stage; check those that do.
    r = crosscheck_e_chall_after_2resp(_load(level)[:n], level)
    assert r.total >= 1
    assert r.ok, r.mismatches[:3]


def test_e_chall_deterministic_no_trial():
    v = _load(1)[0]
    inp = inputs_from_hex(v["pk"], v["sig"], 1)
    assert recompute_e_chall(inp) == recompute_e_chall(inp) == v["E_chall"]


def test_after_2resp_needs_exact_model():
    # A vector with a 2-response stage reproduces exactly.
    for v in _load(1):
        inp = inputs_from_hex(v["pk"], v["sig"], 1)
        if inp.two_resp_length > 0 and "E_chall_after_2resp" in v:
            assert recompute_e_chall_after_2resp(inp) == v["E_chall_after_2resp"]
            return
    pytest.skip("no two-response vector found")


def test_wrong_challenge_changes_e_chall():
    v = _load(1)[0]
    inp = inputs_from_hex(v["pk"], v["sig"], 1)
    inp.chall_coeff ^= 1
    assert recompute_e_chall(inp) != v["E_chall"]


# --------------------------------------------------------------------------
# E_com, milestone 1: the theta-isogeny kernel bases (lift_basis inputs).
# These are validated byte-for-byte against instrumented reference dumps
# elsewhere; here we assert the intrinsic structure that any correct kernel
# basis must have, with no reference data needed.
# --------------------------------------------------------------------------
def _first_two_resp0(level):
    for v in _load(level):
        inp = inputs_from_hex(v["pk"], v["sig"], level)
        if inp.two_resp_length == 0:
            return inp
    return None


@pytest.mark.parametrize("level", [1, 3, 5])
def test_commitment_kernel_structure(level):
    inp = _first_two_resp0(level)
    if inp is None:
        pytest.skip("no two_resp=0 vector at this level")
    kb = commitment_kernel_bases(inp)
    oe = kb["order_exp"]
    for side in ("chall", "aux"):
        FC = FullCurve(kb[side]["A"])
        P, Q, PmQ = kb[side]["P"], kb[side]["Q"], kb[side]["PmQ"]
        # all three points lie on the curve y^2 = x^3 + A x^2 + x
        for pt in (P, Q, PmQ):
            x, y = pt
            assert FC.rhs(x) == y * y, f"{side} point off-curve"
        # exact order 2**order_exp (dies at 2**oe, alive at 2**(oe-1))
        for pt in (P, Q, PmQ):
            assert FC.mul(1 << oe, pt) is None
            assert FC.mul(1 << (oe - 1), pt) is not None
        # consistent basis: P - Q == PmQ
        assert FC.add(P, FC.neg(Q)) == PmQ, f"{side} P-Q != PmQ"


def test_commitment_kernel_two_resp_not_implemented():
    # The two_resp>0 challenge factor (B_chall_can on E_chall_after_2resp) is
    # an explicit, honest boundary until it is reproduced against dumps.
    for v in _load(1):
        inp = inputs_from_hex(v["pk"], v["sig"], 1)
        if inp.two_resp_length > 0:
            with pytest.raises(NotImplementedError):
                commitment_kernel_bases(inp)
            return
    pytest.skip("no two-response vector found")

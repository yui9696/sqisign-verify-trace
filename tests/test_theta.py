"""E_com, milestone 2: the gluing (2,2)-isogeny (E1 x E2 -> theta structure).

The gluing codomain's theta-null point is validated byte-for-byte (up to the
projective scalar it is only defined up to) against an instrumented reference
dump; those dumps aren't committed, so here we assert what needs no reference
data: the isotropy condition the reference itself checks (the fourth coordinate
of each kernel image vanishes after ``to_squared_theta``) holds for real KAT
vectors at every level, and the theta arithmetic satisfies its own identities.
"""

import json
from pathlib import Path

import pytest

from sqvtrace.challenge import PARAMS, Fp2, inputs_from_hex
from sqvtrace.theta import gluing_codomain, hadamard, to_squared_theta

VEC = Path(__file__).resolve().parents[1] / "vectors"


def _load(level):
    return json.loads((VEC / f"goldens-lvl{level}.json").read_text())["vectors"]


@pytest.mark.parametrize("level", [1, 3, 5])
def test_gluing_isotropy_holds(level):
    # gluing_codomain raises ValueError if the isotropy condition fails; a valid
    # KAT signature must satisfy it, so this both exercises the gluing and
    # confirms the reproduced 8-torsion kernel is correct.
    inp = inputs_from_hex(_load(level)[0]["pk"], _load(level)[0]["sig"], level)
    null = gluing_codomain(inp)
    assert len(null) == 4
    # a well-formed gluing codomain theta-null point has no zero coordinate
    assert all(not c.is_zero() for c in null)


def test_hadamard_is_an_involution_up_to_four():
    # H^2 = 4 I for the 4x4 Hadamard matrix.
    p = PARAMS[1][0]
    P = (Fp2(3, 5, p), Fp2(7, 11, p), Fp2(13, 2, p), Fp2(1, 9, p))
    HH = hadamard(hadamard(P))
    four = Fp2(4, 0, p)
    assert HH == tuple(four * c for c in P)


def test_to_squared_theta_matches_definition():
    p = PARAMS[1][0]
    P = (Fp2(2, 1, p), Fp2(0, 3, p), Fp2(5, 5, p), Fp2(4, 2, p))
    assert to_squared_theta(P) == hadamard(tuple(c * c for c in P))

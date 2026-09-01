"""The E_aux stage is independently reproducible in pure Python."""

import json
from pathlib import Path

from sqvtrace.crosscheck import (
    crosscheck_e_aux,
    prime_for_level,
    recompute_e_aux,
)

VEC = Path(__file__).resolve().parents[1] / "vectors"


def _load(level):
    d = json.loads((VEC / f"goldens-lvl{level}.json").read_text())
    return d["vectors"]


def test_primes_are_3_mod_4():
    # F_p[i]/(i^2+1) is a field only when p = 3 mod 4.
    for lvl in (1, 3, 5):
        assert prime_for_level(lvl) % 4 == 3


def test_e_aux_crosscheck_all_levels():
    for lvl in (1, 3, 5):
        vectors = _load(lvl)
        r = crosscheck_e_aux(vectors, lvl)
        assert r.total == 100, (lvl, r.total)
        assert r.ok, (lvl, r.mismatches[:3])


def test_recompute_matches_committed_vector0():
    for lvl in (1, 3, 5):
        v = _load(lvl)[0]
        assert recompute_e_aux(v["E_aux_A"], lvl) == v["E_aux"]


def test_wrong_input_is_detected():
    # Flip the input A-coefficient's first byte -> j-invariant must change.
    v = _load(1)[0]
    bad = bytearray(bytes.fromhex(v["E_aux_A"]))
    bad[0] ^= 0x01
    assert recompute_e_aux(bad.hex(), 1) != v["E_aux"]

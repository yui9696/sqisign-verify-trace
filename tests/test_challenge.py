"""The E_chall stage is independently and deterministically reproducible.

Pure Python reproduces the challenge isogeny byte-for-byte by replicating the
reference's projective arithmetic. Full 300-vector reproduction is slow in pure
Python, so the test checks a small subset per level; the CLI can run more
(`sqisign-verify-trace crosscheck --echall`).
"""

import json
from pathlib import Path

import pytest

from sqvtrace.challenge import (
    Inputs,
    crosscheck_e_chall,
    fp2_from_bytes,
    inputs_from_hex,
    recompute_e_chall,
    PARAMS,
)

VEC = Path(__file__).resolve().parents[1] / "vectors"


def _load(level):
    return json.loads((VEC / f"goldens-lvl{level}.json").read_text())["vectors"]


@pytest.mark.parametrize("level", [1, 3, 5])
def test_primes_are_3_mod_4(level):
    assert PARAMS[level][0] % 4 == 3


@pytest.mark.parametrize("level,n", [(1, 3), (3, 2), (5, 1)])
def test_e_chall_crosscheck_subset(level, n):
    vectors = _load(level)[:n]
    r = crosscheck_e_chall(vectors, level)
    assert r.total == n
    assert r.ok, r.mismatches[:3]


def test_e_chall_deterministic_no_trial():
    # Two runs of the same input give the same byte string (no randomness,
    # no "try both signs").
    v = _load(1)[0]
    inp = Inputs(
        A_pk=fp2_from_bytes(bytes.fromhex(v["pk"])[: 2 * 32], 32, PARAMS[1][0]),
        hint_pk=bytes.fromhex(v["pk"])[2 * 32],
        chall_coeff=int(v["chall_coeff"], 16),
        backtracking=v["backtracking"],
        level=1,
    )
    assert recompute_e_chall(inp) == recompute_e_chall(inp) == v["E_chall"]


def test_wrong_challenge_changes_e_chall():
    v = _load(1)[0]
    inp = inputs_from_hex(v["pk"], v["E_aux_A"] + "00" * (148 - 32), 1)  # dummy sig
    inp.chall_coeff = (int(v["chall_coeff"], 16) ^ 1)
    inp.backtracking = v["backtracking"]
    assert recompute_e_chall(inp) != v["E_chall"]

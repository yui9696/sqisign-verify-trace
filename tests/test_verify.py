"""The complete pure-Python SQIsign verifier: accept valid, reject tampered.

Uses a handful of real KAT (pk, sig, msg) triples with small messages
(tests/fixtures/verify_cases.json). A valid signature must accept; a signature
or message with a single flipped byte must reject.
"""

import json
from pathlib import Path

import pytest

from sqvtrace.challenge import PARAMS
from sqvtrace.verify import hash_to_challenge, verify_signature, verify_trace

FIX = Path(__file__).resolve().parent / "fixtures" / "verify_cases.json"
CASES = json.loads(FIX.read_text())["cases"]
VEC = Path(__file__).resolve().parents[1] / "vectors"


def _golden(level, index):
    vecs = json.loads((VEC / f"goldens-lvl{level}.json").read_text())["vectors"]
    return next(v for v in vecs if v.get("index") == index)


def _ids(cases):
    return [f"lvl{c['level']}-vec{c['index']}" for c in cases]


@pytest.mark.parametrize("c", CASES, ids=_ids(CASES))
def test_valid_signature_accepts(c):
    assert verify_signature(c["pk"], c["sig"], bytes.fromhex(c["msg"]), c["level"]) is True


@pytest.mark.parametrize("c", CASES, ids=_ids(CASES))
def test_flipped_signature_byte_rejects(c):
    # Flip a byte in the challenge coefficient region -> must reject.
    level = c["level"]
    nb = PARAMS[level][6]
    fp_bytes = PARAMS[level][1]
    off = 2 * fp_bytes + 2 + 4 * nb  # chall_coeff offset
    sig = bytearray(bytes.fromhex(c["sig"]))
    sig[off] ^= 1
    assert verify_signature(c["pk"], sig.hex(), bytes.fromhex(c["msg"]), level) is False


@pytest.mark.parametrize("c", CASES, ids=_ids(CASES))
def test_flipped_message_rejects(c):
    msg = bytearray(bytes.fromhex(c["msg"]))
    msg[0] ^= 1
    assert verify_signature(c["pk"], c["sig"], bytes(msg), c["level"]) is False


def test_hash_to_challenge_is_deterministic():
    c = CASES[0]
    z = bytes(PARAMS[c["level"]][1] * 2)
    a = hash_to_challenge(z, z, b"msg", c["level"])
    b = hash_to_challenge(z, z, b"msg", c["level"])
    assert a == b and isinstance(a, int)


@pytest.mark.parametrize("c", CASES, ids=_ids(CASES))
def test_verify_trace_stages_match_goldens(c):
    # The pure-Python walkthrough recomputes every stage; each must match the
    # committed golden, and the run must accept.
    tr = verify_trace(c["pk"], c["sig"], bytes.fromhex(c["msg"]), c["level"])
    g = _golden(c["level"], c["index"])
    assert tr["E_aux"] == g["E_aux"]
    assert tr["E_chall"] == g["E_chall"]
    assert tr["E_com"] == g["E_com"]
    if "E_chall_after_2resp" in tr:
        assert tr["E_chall_after_2resp"] == g["E_chall_after_2resp"]
    assert tr["accept"] is True

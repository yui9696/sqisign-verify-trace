"""Golden-vector schema and validators.

A golden vector records the intermediate j-invariants (and the two challenge
scalars) observed while verifying one (pk, msg, sig) triple. Field lengths are
fixed per NIST security level:

    level | j-invariant bytes | challenge-scalar bytes
    ------+-------------------+-----------------------
      1   |        64         |          32
      3   |        96         |          48
      5   |       128         |          64

The j-invariant byte count is 4 * ceil(log2 p / 64) * 2 (two Fp limbs of an Fp2
element); the scalar byte count is NWORDS_ORDER * 8. All lengths below are the
byte counts; the JSON stores lowercase hex, so hex string length is 2x.
"""

from __future__ import annotations

LEVELS = (1, 3, 5)

# bytes per encoded j-invariant (an Fp2 element via the spec's canonical fp2_encode)
J_BYTES = {1: 64, 3: 96, 5: 128}

# bytes per challenge scalar (NWORDS_ORDER limbs of 8 bytes)
SCALAR_BYTES = {1: 32, 3: 48, 5: 64}

# curve stages, in the order protocols_verify computes them
CURVE_STAGES = ("E_aux", "E_chall", "E_chall_after_2resp", "E_com")

# stages that are always present (E_chall_after_2resp is optional)
REQUIRED_CURVE_STAGES = ("E_aux", "E_chall", "E_com")

# scalar stages
SCALAR_STAGES = ("chk_chall", "sig_chall")

# the full ordered pipeline of comparable stages (used by diff.py)
DIFF_STAGES = ("E_aux", "E_chall", "E_chall_after_2resp", "E_com", "chk_chall")


class SchemaError(ValueError):
    """Raised when a vector or set does not match the schema."""


def _is_hex(s: str) -> bool:
    if not isinstance(s, str) or s == "":
        return False
    try:
        bytes.fromhex(s)
    except ValueError:
        return False
    # bytes.fromhex tolerates whitespace and uppercase; the schema stores
    # canonical lowercase hex, so forbid whitespace/uppercase and require an
    # even length.
    return len(s) % 2 == 0 and s == s.lower() and s.strip() == s and " " not in s


def validate_vector(vec: dict, level: int) -> list[str]:
    """Return a list of human-readable problems with a single vector (empty = OK)."""
    problems: list[str] = []
    if level not in LEVELS:
        return [f"unknown level {level!r}"]

    jb = J_BYTES[level]
    sb = SCALAR_BYTES[level]

    if vec.get("level") not in (None, level):
        problems.append(f"level field {vec.get('level')!r} != {level}")

    for stage in REQUIRED_CURVE_STAGES:
        v = vec.get(stage)
        if v is None:
            problems.append(f"missing required stage {stage}")
        elif not _is_hex(v):
            problems.append(f"{stage} is not lowercase even-length hex")
        elif len(v) // 2 != jb:
            problems.append(f"{stage} is {len(v)//2} bytes, expected {jb}")

    # optional stage: if present it must be well-formed
    opt = vec.get("E_chall_after_2resp")
    if opt is not None:
        if not _is_hex(opt):
            problems.append("E_chall_after_2resp is not lowercase even-length hex")
        elif len(opt) // 2 != jb:
            problems.append(f"E_chall_after_2resp is {len(opt)//2} bytes, expected {jb}")

    for stage in SCALAR_STAGES:
        v = vec.get(stage)
        if v is None:
            problems.append(f"missing required stage {stage}")
        elif not _is_hex(v):
            problems.append(f"{stage} is not lowercase even-length hex")
        elif len(v) // 2 != sb:
            problems.append(f"{stage} is {len(v)//2} bytes, expected {sb}")

    verdict = vec.get("verdict")
    if verdict not in (0, 1):
        problems.append(f"verdict {verdict!r} is not 0 or 1")

    # verdict consistency: a valid (verdict==1) vector must have chk == sig
    if verdict == 1 and "chk_chall" in vec and "sig_chall" in vec:
        if vec["chk_chall"] != vec["sig_chall"]:
            problems.append("verdict==1 but chk_chall != sig_chall")

    return problems


def is_valid_vector(vec: dict, level: int) -> bool:
    return not validate_vector(vec, level)

"""Independent cross-check of the ``E_aux`` stage in pure Python.

The golden vectors carry the intermediate curve j-invariants that the *reference*
implementation computes. The ``E_aux`` stage is the one stage a third party can
recompute with a few lines of field arithmetic and no isogeny machinery at all:

    E_aux is the Montgomery curve  B y^2 = x^3 + A x^2 + x  whose A-coefficient
    is decoded straight from the signature (the field ``E_aux_A``), and the
    golden ``E_aux`` value is that curve's j-invariant,

        j(A) = 256 * (A^2 - 3)^3 / (A^2 - 4),

    computed in F_{p^2} = F_p[i]/(i^2 + 1) and encoded with the spec's canonical
    little-endian fp2 encoding.

This module recomputes j(A) from the committed ``E_aux_A`` inputs using only
Python integers and checks it against the committed ``E_aux`` outputs. Agreement
turns the "verification intermediates are implementation-independent" argument
into a *measured* fact for this stage: a completely separate implementation
(this one) lands on the reference's bytes exactly.

The primes are the SQIsign NIST parameters (spec section 5.2):
    L1: p = 5 * 2^248 - 1     L3: p = 65 * 2^376 - 1     L5: p = 27 * 2^500 - 1
all congruent to 3 mod 4, so F_p[i]/(i^2 + 1) is a field.
"""

from __future__ import annotations

from dataclasses import dataclass

# level -> (prime, bytes-per-fp-element)
_PARAMS = {
    1: (5 * 2**248 - 1, 32),
    3: (65 * 2**376 - 1, 48),
    5: (27 * 2**500 - 1, 64),
}


def prime_for_level(level: int) -> int:
    """The SQIsign field characteristic for a NIST level (1, 3, or 5)."""
    return _PARAMS[level][0]


class _Fp2:
    """Minimal F_p^2 = F_p[i]/(i^2 + 1) arithmetic over Python ints."""

    __slots__ = ("p",)

    def __init__(self, p: int) -> None:
        if p % 4 != 3:
            raise ValueError("need p = 3 mod 4 for F_p[i]/(i^2+1) to be a field")
        self.p = p

    def mul(self, x, y):
        a, b = x
        c, d = y
        p = self.p
        return ((a * c - b * d) % p, (a * d + b * c) % p)

    def sub(self, x, y):
        p = self.p
        return ((x[0] - y[0]) % p, (x[1] - y[1]) % p)

    def sq(self, x):
        return self.mul(x, x)

    def inv(self, x):
        a, b = x
        p = self.p
        norm = (a * a + b * b) % p
        if norm == 0:
            raise ZeroDivisionError("no inverse of 0 in F_p^2")
        ninv = pow(norm, p - 2, p)
        return ((a * ninv) % p, ((-b) * ninv) % p)

    def j_invariant_montgomery(self, A):
        """j = 256 (A^2 - 3)^3 / (A^2 - 4) for By^2 = x^3 + Ax^2 + x."""
        p = self.p
        a2 = self.sq(A)
        base = self.sub(a2, (3 % p, 0))
        num = self.mul(self.mul(self.sq(base), base), (256 % p, 0))
        den = self.sub(a2, (4 % p, 0))
        return self.mul(num, self.inv(den))


def decode_fp2(data: bytes, fp_bytes: int, p: int):
    """Decode a canonical fp2 encoding: re-limb || im-limb, each little-endian."""
    re = int.from_bytes(data[:fp_bytes], "little") % p
    im = int.from_bytes(data[fp_bytes : 2 * fp_bytes], "little") % p
    return (re % p, im % p)


def encode_fp2(x, fp_bytes: int) -> bytes:
    """Encode (re, im) back to the canonical fp2 byte string."""
    return x[0].to_bytes(fp_bytes, "little") + x[1].to_bytes(fp_bytes, "little")


def recompute_e_aux(e_aux_a_hex: str, level: int) -> str:
    """Recompute the E_aux j-invariant (hex) from the input A-coefficient hex."""
    p, fp_bytes = _PARAMS[level]
    field = _Fp2(p)
    a = decode_fp2(bytes.fromhex(e_aux_a_hex), fp_bytes, p)
    j = field.j_invariant_montgomery(a)
    return encode_fp2(j, fp_bytes).hex()


@dataclass
class CrossCheckResult:
    level: int
    total: int
    matched: int
    mismatches: list  # (index, expected, got)

    @property
    def ok(self) -> bool:
        return self.total > 0 and self.matched == self.total


def crosscheck_e_aux(vectors, level: int) -> CrossCheckResult:
    """Recompute E_aux for every vector and compare to the committed value.

    Each vector must carry both ``E_aux_A`` (the input A-coefficient) and
    ``E_aux`` (the reference's computed j-invariant).
    """
    total = matched = 0
    mismatches = []
    for v in vectors:
        a_hex = v.get("E_aux_A")
        expected = v.get("E_aux")
        if a_hex is None or expected is None:
            continue
        total += 1
        got = recompute_e_aux(a_hex, level)
        if got == expected:
            matched += 1
        else:
            mismatches.append((v.get("index"), expected, got))
    return CrossCheckResult(level=level, total=total, matched=matched, mismatches=mismatches)

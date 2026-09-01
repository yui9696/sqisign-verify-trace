"""A complete, independent, pure-Python SQIsign *verifier*.

The other modules reproduce each intermediate curve of verification; this one
adds the final Fiat-Shamir check and ties the whole pipeline together into an
actual accept/reject verifier:

    E_aux -> E_chall -> E_chall_after_2resp -> E_com
          -> chall = hash_to_challenge(j(pk), j(E_com), msg)
          -> accept iff chall == sig.chall_coeff

It follows the reference ``protocols_verify`` (verify.c) and ``hash_to_challenge``
(common.c). Everything is stdlib-only: the hash is SHAKE256 via ``hashlib``.

This is not, and does not claim to be, a hardened or constant-time verifier -- it
is a readable executable reference. Like the reference implementation it mirrors,
it is not production code.
"""

from __future__ import annotations

import hashlib

from .challenge import Curve, PARAMS, RESP_LEN, inputs_from_hex
from .theta import ecom_curve

# Per-level (security bits, hash iterations); FP2 encoding and the torsion power
# come from PARAMS / RESP_LEN.
_SECURITY_BITS = {1: 128, 3: 192, 5: 256}
_HASH_ITERATIONS = {1: 64, 3: 256, 5: 512}


def hash_to_challenge(j_pk_enc: bytes, j_com_enc: bytes, message: bytes, level: int) -> int:
    """Recompute the Fiat-Shamir challenge scalar (reference hash_to_challenge).

    ``j_pk_enc`` and ``j_com_enc`` are the canonical ``fp2`` encodings of the
    public-key and commitment-curve j-invariants (``FP2_ENCODED_BYTES`` each).
    Returns the challenge as an integer, directly comparable to
    ``sig.chall_coeff``.
    """
    sec = _SECURITY_BITS[level]
    iters = _HASH_ITERATIONS[level]
    f = PARAMS[level][2]           # TORSION_EVEN_POWER
    resp_len = RESP_LEN[level]     # SQIsign_response_length
    hb = (2 * sec + 7) // 8        # 2*lambda bits; a multiple of the digit size,
    #                                so the reference's per-iteration mask is a no-op.

    scalar = hashlib.shake_256(j_pk_enc + j_com_enc + message).digest(hb)
    for _ in range(2, iters):
        scalar = hashlib.shake_256(scalar).digest(hb)

    # final squeeze to (TORSION_EVEN_POWER - response_length) bits, then mod 2^lambda
    hb2 = (f - resp_len + 7) // 8
    final = hashlib.shake_256(scalar).digest(hb2)
    value = int.from_bytes(final, "little")
    value &= (1 << (f - resp_len)) - 1
    value &= (1 << sec) - 1
    return value


def verify_signature(pk_hex: str, sig_hex: str, message: bytes, level: int) -> bool:
    """Verify a SQIsign signature end to end, in pure Python. Returns True to
    accept, False to reject. Rejects if the commitment 2D-isogeny does not split
    or if the recomputed challenge does not match ``sig.chall_coeff``."""
    try:
        inp = inputs_from_hex(pk_hex, sig_hex, level)
        E_com = ecom_curve(inp)
        if E_com is None:
            return False  # the dimension-2 isogeny did not split -> invalid
        fp_bytes = PARAMS[level][1]
        j_pk = Curve(inp.A_pk).j_invariant().to_bytes(fp_bytes)
        j_com = E_com.j_invariant().to_bytes(fp_bytes)
        chall = hash_to_challenge(j_pk, j_com, message, level)
        return chall == inp.chall_coeff
    except Exception:
        # A malformed signature can drive the recomputation into an inconsistent
        # state -- a non-splitting isogeny, a bad difference point, a zero
        # denominator, a degenerate point. A valid signature never does (all 300
        # KAT vectors recompute cleanly); anything that does is rejected, as the
        # reference likewise returns 0 for such inputs.
        return False

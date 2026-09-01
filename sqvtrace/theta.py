"""E_com, milestone 2: the gluing (2,2)-isogeny (E1 x E2 -> theta structure).

The commitment curve ``E_com`` is recovered as (a factor of) the codomain of a
dimension-2 theta ``(2^n, 2^n)``-isogeny from the elliptic product
``E_chall x E_aux``. The first step of that isogeny is the *gluing*: it turns the
product of two elliptic curves into a level-2 theta structure on the abelian
surface. This module reproduces the gluing codomain's theta-null point in pure
Python, following the reference ``gluing_compute`` (``theta_isogenies.c``).

The kernel bases (the ``lift_basis`` inputs) come from
:func:`sqvtrace.challenge.commitment_kernel_bases` (milestone 1). Here we only
need the 8-torsion couple points ``K1_8`` / ``K2_8`` obtained by doubling those
bases down to order 8.

Everything is projective: the reference's theta-null point is defined only up to
a scalar, and the action-by-translation matrices are ratio-based (hence
representation-independent), so affine ``x``-only representatives ``(x : 1)``
suffice. The strong internal check that the gluing is correct is that, after the
``to_squared_theta`` transform, the fourth coordinate of each kernel image
vanishes -- the isotropy condition the reference also tests.
"""

from __future__ import annotations

from .challenge import Fp2, FullCurve, PARAMS, commitment_kernel_bases


# --------------------------------------------------------------------------
# level-2 theta arithmetic on 4-tuples (x, y, z, t) of Fp2
# --------------------------------------------------------------------------
def hadamard(P):
    x, y, z, t = P
    t1, t2, t3, t4 = x + y, x - y, z + t, z - t
    return (t1 + t3, t2 + t4, t1 - t3, t2 - t4)


def to_squared_theta(P):
    x, y, z, t = P
    return hadamard((x * x, y * y, z * z, t * t))


def apply_matrix(M, P):
    """Apply a 4x4 matrix (list of 4 rows of 4 Fp2) to a theta point."""
    x, y, z, t = P
    out = []
    for r in range(4):
        m = M[r]
        out.append(m[0] * x + m[1] * y + m[2] * z + m[3] * t)
    return tuple(out)


# --------------------------------------------------------------------------
# action by translation (reference action_by_translation_compute_matrix)
# --------------------------------------------------------------------------
def _action_matrix(P4, P2, one):
    """The 2x2 translation matrix (g00, g01, g10, g11) from an x-only order-4
    point P4 = (x, z) and its double P2 = (x, z), an order-2 point. Ratio-based,
    so independent of the projective representative."""
    x4, z4 = P4
    x2, z2 = P2
    z_inv = one / z4
    det_inv = one / (x4 * z2 - z4 * x2)
    g10 = x4 * x2 * det_inv - x4 * z_inv
    g11 = x2 * det_inv * z4
    g00 = -g11
    g01 = -(z2 * det_inv * z4)
    return (g00, g01, g10, g11)


def gluing_change_of_basis(Gi, one):
    """The 4x4 base-change matrix from the four 2x2 action matrices, following
    the reference ``gluing_change_of_basis`` verbatim. ``Gi`` is a list of four
    ``(g00, g01, g10, g11)`` tuples."""
    g = [dict(g00=G[0], g01=G[1], g10=G[2], g11=G[3]) for G in Gi]
    M = [[None] * 4 for _ in range(4)]

    t001 = g[0]["g00"] * g[2]["g00"] + g[0]["g01"] * g[2]["g10"]
    t101 = g[0]["g10"] * g[2]["g00"] + g[0]["g11"] * g[2]["g10"]
    t002 = g[1]["g00"] * g[3]["g00"] + g[1]["g01"] * g[3]["g10"]
    t102 = g[1]["g10"] * g[3]["g00"] + g[1]["g11"] * g[3]["g10"]

    M[0][0] = one + t001 * t002 + g[2]["g00"] * g[3]["g00"] + g[0]["g00"] * g[1]["g00"]
    M[0][1] = t001 * t102 + g[2]["g00"] * g[3]["g10"] + g[0]["g00"] * g[1]["g10"]
    M[0][2] = t101 * t002 + g[2]["g10"] * g[3]["g00"] + g[0]["g10"] * g[1]["g00"]
    M[0][3] = t101 * t102 + g[2]["g10"] * g[3]["g10"] + g[0]["g10"] * g[1]["g10"]

    M[1][0] = g[3]["g00"] * M[0][0] + g[3]["g01"] * M[0][1]
    M[1][1] = g[3]["g10"] * M[0][0] + g[3]["g11"] * M[0][1]
    M[1][2] = g[3]["g00"] * M[0][2] + g[3]["g01"] * M[0][3]
    M[1][3] = g[3]["g10"] * M[0][2] + g[3]["g11"] * M[0][3]

    M[2][0] = g[0]["g00"] * M[0][0] + g[0]["g01"] * M[0][2]
    M[2][1] = g[0]["g00"] * M[0][1] + g[0]["g01"] * M[0][3]
    M[2][2] = g[0]["g10"] * M[0][0] + g[0]["g11"] * M[0][2]
    M[2][3] = g[0]["g10"] * M[0][1] + g[0]["g11"] * M[0][3]

    M[3][0] = g[0]["g00"] * M[1][0] + g[0]["g01"] * M[1][2]
    M[3][1] = g[0]["g00"] * M[1][1] + g[0]["g01"] * M[1][3]
    M[3][2] = g[0]["g10"] * M[1][0] + g[0]["g11"] * M[1][2]
    M[3][3] = g[0]["g10"] * M[1][1] + g[0]["g11"] * M[1][3]
    return M


def _product_theta(P1_xz, P2_xz):
    """The product theta point of a couple point, before the base change:
    (P1.x P2.x, P1.x P2.z, P2.x P1.z, P1.z P2.z)."""
    x1, z1 = P1_xz
    x2, z2 = P2_xz
    return (x1 * x2, x1 * z2, x2 * z1, z1 * z2)


# --------------------------------------------------------------------------
# gluing codomain
# --------------------------------------------------------------------------
def gluing_codomain(inp, kb=None):
    """Return the theta-null point (x, y, z, t) of the gluing codomain for the
    given verification inputs, projective (defined up to a scalar).

    Raises ``ValueError`` if the isotropy condition fails (which would mean the
    reproduced kernel is wrong, not that the signature is malformed -- these are
    all valid KAT signatures).
    """
    p = PARAMS[inp.level][0]
    one = Fp2(1, 0, p)
    if kb is None:
        kb = commitment_kernel_bases(inp)
    pd = kb["pow_dim2"]

    E1 = FullCurve(kb["chall"]["A"])
    E2 = FullCurve(kb["aux"]["A"])

    def dbl(E, P, k):
        for _ in range(k):
            P = E.add(P, P)
        return P

    # 8-torsion couple points: [2^(pd-1)] of the order-2^(pd+2) kernel bases.
    K1_8 = (dbl(E1, kb["chall"]["P"], pd - 1), dbl(E2, kb["aux"]["P"], pd - 1))
    K2_8 = (dbl(E1, kb["chall"]["Q"], pd - 1), dbl(E2, kb["aux"]["Q"], pd - 1))

    def xz(P):  # affine (x, y) -> x-only (x : 1)
        return (P[0], one)

    # 4- and 2-torsion couple points (per curve).
    K1_4 = (E1.add(K1_8[0], K1_8[0]), E2.add(K1_8[1], K1_8[1]))
    K2_4 = (E1.add(K2_8[0], K2_8[0]), E2.add(K2_8[1], K2_8[1]))
    K1_2 = (E1.add(K1_4[0], K1_4[0]), E2.add(K1_4[1], K1_4[1]))
    K2_2 = (E1.add(K2_4[0], K2_4[0]), E2.add(K2_4[1], K2_4[1]))

    Gi = [
        _action_matrix(xz(K1_4[0]), xz(K1_2[0]), one),  # K1_4.P1 on E1
        _action_matrix(xz(K1_4[1]), xz(K1_2[1]), one),  # K1_4.P2 on E2
        _action_matrix(xz(K2_4[0]), xz(K2_2[0]), one),  # K2_4.P1 on E1
        _action_matrix(xz(K2_4[1]), xz(K2_2[1]), one),  # K2_4.P2 on E2
    ]
    M = gluing_change_of_basis(Gi, one)

    TT1 = to_squared_theta(apply_matrix(M, _product_theta(xz(K1_8[0]), xz(K1_8[1]))))
    TT2 = to_squared_theta(apply_matrix(M, _product_theta(xz(K2_8[0]), xz(K2_8[1]))))

    if not (TT1[3].is_zero() and TT2[3].is_zero()):
        raise ValueError("gluing isotropy condition failed (TT.t != 0)")

    # codomain theta-null point (projective), then the final Hadamard.
    codomain = (TT1[0] * TT2[0], TT1[1] * TT2[0], TT1[0] * TT2[2], Fp2(0, 0, p))
    return hadamard(codomain)

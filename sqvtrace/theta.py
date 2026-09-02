"""E_com: the dimension-2 theta ``(2^n, 2^n)``-isogeny (spec section 8.5).

The commitment curve ``E_com`` is recovered as the first factor of the codomain
of a dimension-2 theta ``(2^n, 2^n)``-isogeny from the elliptic product
``E_chall x E_aux`` (verify.c ``compute_commitment_curve_verify``). This module
reproduces that whole isogeny -- and hence ``E_com`` -- in pure Python, following
the reference ``theta_isogenies.c`` / ``theta_structure.c``:

1. **Gluing.** The first ``(2,2)``-step turns the product ``E_chall x E_aux``
   into a level-2 theta structure on the abelian surface
   (:func:`_gluing`, :func:`gluing_codomain`).
2. **The chain.** ``n-1`` further ``(2,2)``-steps in theta coordinates, each
   defined by the 8-torsion image of the kernel generators, which are pushed
   forward step by step (:func:`theta_isogeny_compute`, :func:`theta_eval`,
   :func:`double_point`).
3. **Splitting.** The final theta-null point is normalised to a product theta
   point (:func:`splitting_matrix`) and read off as two Montgomery curves
   (:func:`elliptic_from_split`); ``E_com`` is the first.

The kernel bases come from :func:`sqvtrace.challenge.commitment_kernel_bases`.
Everything is projective; the theta-null point is defined only up to a scalar and
the action matrices are ratio-based, so affine ``x``-only representatives suffice
and no Jacobian byte-exactness is needed. The pipeline is validated end-to-end:
the recomputed ``E_com`` j-invariant matches the reference golden at all three
security levels (:func:`recompute_e_com`, ``crosscheck_e_com``).
"""

from __future__ import annotations

from dataclasses import dataclass

from .challenge import (
    CrossCheckResult,
    Curve,
    Fp2,
    FullCurve,
    PARAMS,
    commitment_kernel_bases,
    inputs_from_hex,
)


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
    return tuple(M[r][0] * x + M[r][1] * y + M[r][2] * z + M[r][3] * t for r in range(4))


# --------------------------------------------------------------------------
# gluing: E_chall x E_aux -> level-2 theta structure
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


@dataclass
class Gluing:
    M: list          # 4x4 base-change matrix
    precomp: tuple   # projective factors for point evaluation
    imageK1_8: tuple # (x, y) of phi(K1_8)
    null: tuple      # codomain theta-null point (projective)
    K1_8: tuple      # the 8-torsion couple point used, as affine points
    A1: Fp2          # E_chall A-coefficient
    A2: Fp2          # E_aux A-coefficient


def _gluing(kb, p):
    """Compute the gluing isogeny data from the milestone-1 kernel bases."""
    one = Fp2(1, 0, p)
    E1 = FullCurve(kb["chall"]["A"])
    E2 = FullCurve(kb["aux"]["A"])
    pd = kb["pow_dim2"]

    def dbl(E, P, k):
        for _ in range(k):
            P = E.add(P, P)
        return P

    # 8-torsion couple points: [2^(pd-1)] of the order-2^(pd+2) kernel bases.
    K1_8 = (dbl(E1, kb["chall"]["P"], pd - 1), dbl(E2, kb["aux"]["P"], pd - 1))
    K2_8 = (dbl(E1, kb["chall"]["Q"], pd - 1), dbl(E2, kb["aux"]["Q"], pd - 1))

    def xz(P):
        return (P[0], one)

    K1_4 = (E1.add(K1_8[0], K1_8[0]), E2.add(K1_8[1], K1_8[1]))
    K2_4 = (E1.add(K2_8[0], K2_8[0]), E2.add(K2_8[1], K2_8[1]))
    K1_2 = (E1.add(K1_4[0], K1_4[0]), E2.add(K1_4[1], K1_4[1]))
    K2_2 = (E1.add(K2_4[0], K2_4[0]), E2.add(K2_4[1], K2_4[1]))

    Gi = [
        _action_matrix(xz(K1_4[0]), xz(K1_2[0]), one),
        _action_matrix(xz(K1_4[1]), xz(K1_2[1]), one),
        _action_matrix(xz(K2_4[0]), xz(K2_2[0]), one),
        _action_matrix(xz(K2_4[1]), xz(K2_2[1]), one),
    ]
    M = gluing_change_of_basis(Gi, one)

    TT1 = to_squared_theta(apply_matrix(M, _product_theta(xz(K1_8[0]), xz(K1_8[1]))))
    TT2 = to_squared_theta(apply_matrix(M, _product_theta(xz(K2_8[0]), xz(K2_8[1]))))
    if not (TT1[3].is_zero() and TT2[3].is_zero()):
        raise ValueError("gluing isotropy condition failed (TT.t != 0)")

    zero = Fp2(0, 0, p)
    codomain = (TT1[0] * TT2[0], TT1[1] * TT2[0], TT1[0] * TT2[2], zero)
    precomp = (TT1[1] * TT2[2], codomain[2], codomain[1], zero)
    imageK1_8 = (TT1[0] * precomp[0], TT1[2] * precomp[2])
    return Gluing(M, precomp, imageK1_8, hadamard(codomain), K1_8, kb["chall"]["A"], kb["aux"]["A"])


def gluing_codomain(inp, kb=None):
    """The theta-null point of the gluing codomain, projective (up to a scalar).
    Raises ``ValueError`` if the isotropy condition fails."""
    p = PARAMS[inp.level][0]
    if kb is None:
        kb = commitment_kernel_bases(inp)
    return _gluing(kb, p).null


def _jac_add_components(P, Q, A):
    """Reference jac_to_xz_add_components for affine points (z = 1): returns
    (u, v, w) with x(P+Q) = (u-v : w) and x(P-Q) = (u+v : w)."""
    x1, y1 = P
    x2, y2 = Q
    lam = x1 - x2
    lam2 = lam * lam
    gamma = x1 + x2 + A
    u = y1 * y1 + y2 * y2 - gamma * lam2
    v = y1 * y2 + y1 * y2
    return u, v, lam2


def gluing_eval_point(P_couple, g: Gluing, p):
    """Push a couple point (affine on E1, affine on E2) through the gluing into
    theta coordinates (reference gluing_eval_point)."""
    zero = Fp2(0, 0, p)
    u1, v1, w1 = _jac_add_components(P_couple[0], g.K1_8[0], g.A1)
    u2, v2, w2 = _jac_add_components(P_couple[1], g.K1_8[1], g.A2)
    T1 = (u1 * u2 + v1 * v2, u1 * w2, w1 * u2, w1 * w2)
    T2x = (u1 + v1) * (u2 + v2) - T1[0]
    T2 = (T2x, v1 * w2, w1 * v2, zero)
    T1 = apply_matrix(g.M, T1)
    T2 = apply_matrix(g.M, T2)
    diff = tuple(T1[i] * T1[i] - T2[i] * T2[i] for i in range(4))
    diff = hadamard(diff)
    ikx, iky = g.imageK1_8
    image = (diff[0] * iky, diff[1] * iky, diff[2] * ikx, diff[3] * ikx)
    return hadamard(image)


# --------------------------------------------------------------------------
# theta structure doubling and generic (2,2)-steps
# --------------------------------------------------------------------------
def precompute(null):
    """Reference theta_precomputation: the 8 constants used by doubling."""
    Ad = to_squared_theta(null)
    t1, t2 = Ad[0] * Ad[1], Ad[2] * Ad[3]
    XYZ0, XYT0, YZT0, XZT0 = t1 * Ad[2], t1 * Ad[3], t2 * Ad[1], t2 * Ad[0]
    s1, s2 = null[0] * null[1], null[2] * null[3]
    xyz0, xyt0, yzt0, xzt0 = s1 * null[2], s1 * null[3], s2 * null[1], s2 * null[0]
    return (XYZ0, XYT0, YZT0, XZT0, xyz0, xyt0, yzt0, xzt0)


def double_point(P, pc):
    """Reference double_point: one doubling in the theta structure with
    precomputed constants ``pc``."""
    XYZ0, XYT0, YZT0, XZT0, xyz0, xyt0, yzt0, xzt0 = pc
    o = to_squared_theta(P)
    o = (o[0] * o[0] * YZT0, o[1] * o[1] * XZT0, o[2] * o[2] * XYT0, o[3] * o[3] * XYZ0)
    o = hadamard(o)
    return (o[0] * yzt0, o[1] * xzt0, o[2] * xyt0, o[3] * xyz0)


def double_iter(P, pc, e):
    for _ in range(e):
        P = double_point(P, pc)
    return P


def theta_isogeny_compute(T1_8, T2_8, hb1, hb2):
    """Reference theta_isogeny_compute: a generic (2,2)-step from the 8-torsion
    points ``T1_8``, ``T2_8``. Returns (codomain null point, eval precomputation,
    hb1, hb2). ``hb1`` / ``hb2`` select standard vs dual coordinates in/out."""
    if hb1:
        TT1 = to_squared_theta(hadamard(T1_8))
        TT2 = to_squared_theta(hadamard(T2_8))
    else:
        TT1 = to_squared_theta(T1_8)
        TT2 = to_squared_theta(T2_8)
    t1, t2 = TT1[0] * TT2[1], TT1[1] * TT2[0]
    null = (TT2[0] * t1, TT2[1] * t2, TT2[2] * t1, TT2[3] * t2)
    t3 = TT2[2] * TT2[3]
    precomp = (t3 * TT1[1], t3 * TT1[0], null[3], null[2])
    if hb2:
        null = hadamard(null)
    return null, precomp, hb1, hb2


def theta_eval(P, precomp, hb1, hb2):
    """Reference theta_isogeny_eval: push a theta point through the step."""
    o = to_squared_theta(hadamard(P)) if hb1 else to_squared_theta(P)
    o = (o[0] * precomp[0], o[1] * precomp[1], o[2] * precomp[2], o[3] * precomp[3])
    return hadamard(o) if hb2 else o


# --------------------------------------------------------------------------
# splitting: theta structure -> product of two elliptic curves
# --------------------------------------------------------------------------
EVEN_INDEX = [(0, 0), (0, 1), (0, 2), (0, 3), (1, 0), (1, 2), (2, 0), (2, 1), (3, 0), (3, 3)]
CHI_EVAL = [[1, 1, 1, 1], [1, -1, 1, -1], [1, 1, -1, -1], [1, -1, -1, 1]]
# SPLITTING_TRANSFORMS as indices into (0, 1, i, -1, -i).
_SPLIT_IDX = [
    [[1, 2, 1, 2], [1, 4, 3, 2], [1, 2, 3, 4], [3, 2, 3, 2]],
    [[1, 0, 0, 0], [0, 0, 0, 1], [0, 0, 1, 0], [0, 3, 0, 0]],
    [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 1], [0, 0, 3, 0]],
    [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 3]],
    [[1, 1, 1, 1], [1, 3, 3, 1], [1, 1, 3, 3], [3, 1, 3, 1]],
    [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 1], [0, 0, 1, 0]],
    [[1, 1, 1, 1], [1, 3, 1, 3], [1, 3, 3, 1], [3, 3, 1, 1]],
    [[1, 1, 1, 1], [1, 3, 1, 3], [1, 3, 3, 1], [1, 1, 3, 3]],
    [[1, 1, 1, 1], [1, 3, 1, 3], [1, 1, 3, 3], [3, 1, 1, 3]],
    [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]],
]


def _fp2_const(k, p):
    return [Fp2(0, 0, p), Fp2(1, 0, p), Fp2(0, 1, p), Fp2(-1, 0, p), Fp2(0, -1, p)][k]


def splitting_matrix(null, p):
    """Reference splitting_compute (verification path, no randomisation): find
    the base-change matrix that turns the theta-null point into a product theta
    point. Returns (matrix, count); a valid split has count == 1."""
    count = 0
    M = None
    for i in range(10):
        U = Fp2(0, 0, p)
        for t in range(4):
            prod = null[t ^ EVEN_INDEX[i][1]] * null[t]
            if CHI_EVAL[EVEN_INDEX[i][0]][t] < 0:
                prod = -prod
            U = U + prod
        if U.is_zero():
            count += 1
            M = [[_fp2_const(_SPLIT_IDX[i][r][c], p) for c in range(4)] for r in range(4)]
    return M, count


def elliptic_from_split(null):
    """Reference theta_product_structure_to_elliptic_product: the A-coefficients
    of the two Montgomery factors from a product theta-null point.
    Returns (A1, A2); E_com is the first factor."""
    x, y, z, t = null
    x4 = (x * x) * (x * x)
    y4 = (y * y) * (y * y)
    z4 = (z * z) * (z * z)
    A1 = -((x4 + z4) + (x4 + z4)) / (x4 - z4)
    A2 = -((x4 + y4) + (x4 + y4)) / (x4 - y4)
    return A1, A2


# --------------------------------------------------------------------------
# the whole chain
# --------------------------------------------------------------------------
def ecom_curve(inp, kb=None):
    """Recompute the commitment curve ``E_com`` (as a :class:`Curve`) from the
    verification inputs, via the full dimension-2 theta ``(2^n, 2^n)``-isogeny.
    Returns ``None`` if the chain fails to split (should not happen for a valid
    KAT signature)."""
    p = PARAMS[inp.level][0]
    if kb is None:
        kb = commitment_kernel_bases(inp)
    n = kb["pow_dim2"]
    g = _gluing(kb, p)
    E1 = FullCurve(kb["chall"]["A"])
    E2 = FullCurve(kb["aux"]["A"])

    def double_couple(cp, k):
        p1, p2 = cp
        for _ in range(k):
            p1 = E1.add(p1, p1)
            p2 = E2.add(p2, p2)
        return (p1, p2)

    # The chain of n (2,2)-steps is traversed with the reference's balanced
    # strategy (theta_isogenies.c ``_theta_chain_compute_impl``): a stack of
    # kernel-point checkpoints is doubled down toward the 8-torsion and pushed
    # forward through each step, giving O(n log n) instead of the naive O(n²) of
    # re-doubling a single generator every step. Any valid strategy yields the
    # same codomain; ``todo[j]`` tracks how far each checkpoint still is from the
    # active step.
    space = 1
    i = 1
    while i < n:
        i *= 2
        space += 1
    todo = [0] * space
    todo[0] = n  # n - 2 + HD_extra_torsion, with HD_extra_torsion = 2
    current = 0

    # --- gluing phase: build couple-point checkpoints down to the 8-torsion.
    jacQ1 = [None] * space
    jacQ2 = [None] * space
    jacQ1[0] = (kb["chall"]["P"], kb["aux"]["P"])
    jacQ2[0] = (kb["chall"]["Q"], kb["aux"]["Q"])
    while todo[current] != 1:
        current += 1
        prev = todo[current - 1]
        num = prev // 2 if prev >= 16 else prev - 1  # reference's gluing rule
        jacQ1[current] = double_couple(jacQ1[current - 1], num)
        jacQ2[current] = double_couple(jacQ2[current - 1], num)
        todo[current] = prev - num

    # the gluing step itself is `g`; push the checkpoints j < current through it.
    thetaQ1 = [None] * space
    thetaQ2 = [None] * space
    for j in range(current):
        thetaQ1[j] = gluing_eval_point(jacQ1[j], g, p)
        thetaQ2[j] = gluing_eval_point(jacQ2[j], g, p)
        todo[j] -= 1
    current -= 1

    null = g.null
    pc = precompute(null)

    # --- the remaining (2,2)-steps, in theta coordinates.
    i = 1
    while current >= 0 and todo[current]:
        while todo[current] != 1:
            current += 1
            prev = todo[current - 1]
            num = prev // 2
            thetaQ1[current] = double_iter(thetaQ1[current - 1], pc, num)
            thetaQ2[current] = double_iter(thetaQ2[current - 1], pc, num)
            todo[current] = prev - num
        if i == n - 2:      # penultimate step: standard-in, dual-out
            hb1, hb2 = 0, 0
        elif i == n - 1:    # ultimate step: dual-in, standard-out
            hb1, hb2 = 1, 0
        else:               # generic step
            hb1, hb2 = 0, 1
        null, sp, hb1, hb2 = theta_isogeny_compute(thetaQ1[current], thetaQ2[current], hb1, hb2)
        pc = precompute(null)
        for j in range(current):
            thetaQ1[j] = theta_eval(thetaQ1[j], sp, hb1, hb2)
            thetaQ2[j] = theta_eval(thetaQ2[j], sp, hb1, hb2)
            todo[j] -= 1
        current -= 1
        i += 1

    M, count = splitting_matrix(null, p)
    if count != 1:
        return None
    A1, _A2 = elliptic_from_split(apply_matrix(M, null))
    return Curve(A1)


def recompute_e_com(inp) -> str | None:
    """The commitment-curve j-invariant (hex), or ``None`` if the chain does not
    split. Directly comparable to the golden ``E_com``."""
    fp_bytes = PARAMS[inp.level][1]
    E = ecom_curve(inp)
    return None if E is None else E.j_invariant().to_bytes(fp_bytes).hex()


def crosscheck_e_com(vectors, level: int) -> CrossCheckResult:
    """Recompute E_com for every vector that carries the inputs and compare to
    the golden."""
    total = matched = 0
    mismatches = []
    for v in vectors:
        expected = v.get("E_com")
        if expected is None or not v.get("sig") or not v.get("pk"):
            continue
        inp = inputs_from_hex(v["pk"], v["sig"], level)
        got = recompute_e_com(inp)
        total += 1
        if got == expected:
            matched += 1
        else:
            mismatches.append((v.get("index"), expected, got or "None"))
    return CrossCheckResult(level, total, matched, mismatches)

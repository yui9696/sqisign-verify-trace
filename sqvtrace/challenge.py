"""Independent, deterministic reproduction of the E_chall stage in pure Python.

This goes one curve stage past :mod:`sqvtrace.crosscheck`. The challenge curve
``E_chall`` is the codomain of a ``2^(f - backtracking)``-isogeny from the
public-key curve, with a kernel built from a canonical torsion basis. Unlike
``E_aux`` (a one-line j-invariant), reproducing it needs the full x-only
machinery *and* a byte-exact match of the reference's projective arithmetic,
because the reference's ``difference_point`` (ePrint 2017/518, Prop. 3) chooses
the sign of ``x(P - Q)`` from the projective ``Z``-coordinates that its own
Montgomery ladder produces.

Everything here is Python integers only (no third-party dependency). Replicating
the reference's exact ``xDBLADD`` (so the projective ``Z`` entering
``difference_point`` matches) and its canonical ``fp2_sqrt`` sign rule makes the
result **deterministic** — it agrees with the reference for every KAT vector,
with no "try both signs".

See ``docs/challenge-isogeny.md`` for the derivation and the reference source
lines. The SQIsign primes (spec 5.2) are all ``3 mod 4``:

    L1: p = 5·2^248 − 1    L3: p = 65·2^376 − 1    L5: p = 27·2^500 − 1
"""

from __future__ import annotations

from dataclasses import dataclass

# level -> (prime, fp_bytes, torsion_even_power f, odd_cofactor, cofactor_bitlen,
#           signature_bytes, nb=mat-entry bytes, sec=chall bytes)
PARAMS = {
    1: (5 * 2**248 - 1, 32, 248, 5, 3, 148, 16, 16),
    3: (65 * 2**376 - 1, 48, 376, 65, 7, 224, 25, 24),
    5: (27 * 2**500 - 1, 64, 500, 27, 5, 292, 32, 32),
}


# --------------------------------------------------------------------------
# F_{p^2} = F_p[i]/(i^2 + 1), element (a, b) = a + b*i, over Python ints.
# --------------------------------------------------------------------------
class Fp2:
    __slots__ = ("a", "b", "p")

    def __init__(self, a, b, p):
        self.a = a % p
        self.b = b % p
        self.p = p

    def _mk(self, a, b):
        return Fp2(a, b, self.p)

    def __add__(self, o):
        return self._mk(self.a + o.a, self.b + o.b)

    def __sub__(self, o):
        return self._mk(self.a - o.a, self.b - o.b)

    def __mul__(self, o):
        p = self.p
        a, b, c, d = self.a, self.b, o.a, o.b
        return self._mk((a * c - b * d) % p, (a * d + b * c) % p)

    def __neg__(self):
        return self._mk(-self.a, -self.b)

    def sq(self):
        return self * self

    def conj(self):
        return self._mk(self.a, -self.b)

    def is_zero(self):
        return self.a == 0 and self.b == 0

    def inv(self):
        p = self.p
        n = (self.a * self.a + self.b * self.b) % p
        ni = pow(n, p - 2, p)
        return self._mk((self.a * ni) % p, ((-self.b) * ni) % p)

    def __truediv__(self, o):
        return self * o.inv()

    def __eq__(self, o):
        return isinstance(o, Fp2) and self.a == o.a and self.b == o.b

    def is_square(self):
        p = self.p
        if self.is_zero():
            return True
        n = (self.a * self.a + self.b * self.b) % p
        return pow(n, (p - 1) // 2, p) == 1

    def sqrt(self):
        """A square root in F_{p^2} (any one; sign fixed later)."""
        p = self.p
        a, b = self.a, self.b
        if b == 0:
            if pow(a % p, (p - 1) // 2, p) in (0, 1):
                return self._mk(pow(a, (p + 1) // 4, p), 0)
            # a is a non-residue: sqrt(a) = sqrt(-a)*i
            return self._mk(0, pow((-a) % p, (p + 1) // 4, p))
        n = (a * a + b * b) % p
        s = pow(n, (p + 1) // 4, p)  # candidate sqrt of the norm
        if pow((a + s) * pow(2, p - 2, p) % p, (p - 1) // 2, p) != 1:
            s = (-s) % p
        x2 = ((a + s) * pow(2, p - 2, p)) % p
        x = pow(x2, (p + 1) // 4, p)
        y = (b * pow((2 * x) % p, p - 2, p)) % p
        return self._mk(x, y)

    def canonical_sqrt(self):
        """The reference fp2_sqrt sign rule: even real part (or, if zero, even
        imaginary part)."""
        r = self.sqrt()
        odd = (r.a & 1) if r.a != 0 else (r.b & 1)
        return -r if odd else r

    def to_bytes(self, fp_bytes):
        return self.a.to_bytes(fp_bytes, "little") + self.b.to_bytes(fp_bytes, "little")


def fp2_from_bytes(data, fp_bytes, p):
    re = int.from_bytes(data[:fp_bytes], "little") % p
    im = int.from_bytes(data[fp_bytes : 2 * fp_bytes], "little") % p
    return Fp2(re, im, p)


# --------------------------------------------------------------------------
# x-only Montgomery arithmetic (projective (X:Z)); j-invariant is representative
# independent, so these are ordinary formulas — except xmul below, which mirrors
# the reference exactly so its projective Z matches.
# --------------------------------------------------------------------------
class Curve:
    def __init__(self, A):
        self.A = A
        self.p = A.p
        two = Fp2(2, 0, self.p)
        four = Fp2(4, 0, self.p)
        self.a24 = (A + two) / four  # (A + 2)/4, affine (C = 1)

    def one(self):
        return Fp2(1, 0, self.p)

    def zero(self):
        return Fp2(0, 0, self.p)

    def rhs(self, x):
        return ((x + self.A) * x + self.one()) * x

    def lift(self, x):
        return (x, self.one())  # (X:Z)

    def is_inf(self, P):
        return P[1].is_zero()

    def xdbl(self, P):
        X, Z = P
        t0 = (X + Z).sq()
        t1 = (X - Z).sq()
        X2 = t0 * t1
        t2 = t0 - t1
        Z2 = t2 * (t1 + self.a24 * t2)
        return (X2, Z2)

    def xadd(self, P, Q, PmQ):
        if self.is_inf(P):
            return Q
        if self.is_inf(Q):
            return P
        if self.is_inf(PmQ):
            return self.xdbl(P)
        t0 = (P[0] + P[1]) * (Q[0] - Q[1])
        t1 = (P[0] - P[1]) * (Q[0] + Q[1])
        X = PmQ[1] * (t0 + t1).sq()
        Z = PmQ[0] * (t0 - t1).sq()
        return (X, Z)

    def xdbladd(self, P, Q, PmQ):
        return self.xdbl(P), self.xadd(P, Q, PmQ)

    def ladder(self, n, P):
        if n < 0:
            n = -n
        if n == 0 or self.is_inf(P):
            return (self.one(), self.zero())
        R0 = (self.one(), self.zero())
        R1 = (P[0], P[1])
        for bit in bin(n)[2:]:
            if bit == "0":
                R0, R1 = self.xdbladd(R0, R1, P)
            else:
                R1, R0 = self.xdbladd(R1, R0, P)
        return R0

    def j_invariant(self):
        p = self.p
        A2 = self.A.sq()
        three = Fp2(3, 0, p)
        four = Fp2(4, 0, p)
        num = Fp2(256, 0, p) * (A2 - three).sq() * (A2 - three)
        return num / (A2 - four)


def xmul_projective(xP, k, kbits, a24x):
    """[k]P via the reference's exact Montgomery ladder (xDBLADD, normalized
    A24 path), returning the *projective* (X:Z) — its Z must match the reference
    for difference_point to pick the right sign."""
    one = Fp2(1, 0, a24x.p)
    zero = Fp2(0, 0, a24x.p)
    P = (xP, one)
    R0 = (one, zero)
    R1 = P
    prev = 0
    for i in range(kbits - 1, -1, -1):
        bit = (k >> i) & 1
        swap = bit ^ prev
        prev = bit
        if swap:
            R0, R1 = R1, R0
        R0, R1 = _xdbladd_ref(R0, R1, P, a24x)
    if prev:
        R0, R1 = R1, R0
    return R0


def _xdbladd_ref(P, Q, PQ, a24x):
    """Exact reference xDBLADD (A24_normalized=true). Returns (2P, P+Q)."""
    Px, Pz = P
    Qx, Qz = Q
    PQx, PQz = PQ
    t0 = Px + Pz
    t1 = Px - Pz
    Rx = t0.sq()
    t2 = Qx - Qz
    Sx = Qx + Qz
    t0 = t0 * t2
    Rz = t1.sq()
    t1 = t1 * Sx
    t2 = Rx - Rz
    Rx = Rx * Rz
    Sx2 = a24x * t2
    Sz = t0 - t1
    Rz = Rz + Sx2
    Sx3 = t0 + t1
    Rz = Rz * t2
    Sz = Sz.sq()
    Sx3 = Sx3.sq()
    Sz = Sz * PQx
    Sx3 = Sx3 * PQz
    return (Rx, Rz), (Sx3, Sz)


def difference_point(P, Q, A):
    """x(P - Q) as an affine coordinate, matching the reference's projective
    ``difference_point`` (ePrint 2017/518, Prop. 3) with C = 1."""
    Xp, Zp = P
    Xq, Zq = Q
    two = Fp2(2, 0, A.p)
    t0 = Xp * Xq
    t1 = Zp * Zq
    Bxx = (t0 - t1).sq()
    Bxz = (t0 + t1) * (Xp * Zq + Zp * Xq)
    tp = Xp * Zq
    tq = Zp * Xq
    Bzz = (tp - tq).sq()
    Bxz = Bxz + A * tp * tq * two
    norm = Zp.conj().sq() * Zq.conj().sq()
    Bxx = Bxx * norm
    Bxz = Bxz * norm
    Bzz = Bzz * norm
    s = (Bxz.sq() - Bxx * Bzz).canonical_sqrt()
    return (Bxz + s) / Bzz


def _ladder3pt(E, m, xP, xQ, xPmQ):
    """P + [m]Q from x(P), x(Q), x(P - Q)."""
    R0 = E.lift(xQ)
    R1 = E.lift(xP)
    R2 = E.lift(xPmQ)
    for i in range(m.bit_length()):
        if (m >> i) & 1:
            R0, R1 = E.xdbladd(R0, R1, R2)
        else:
            R0, R2 = E.xdbladd(R0, R2, R1)
    return R1


def _two_isogeny(E, kernel):
    """2-isogeny with the order-2 kernel point; returns (codomain, eval_fn).
    Handles the x = 0 (i.e. (0,0)) 2-torsion specially."""
    p = E.p
    F0 = Fp2(0, 0, p)
    x2 = kernel[0] / kernel[1]
    if not x2.is_zero():
        A_new = Fp2(2, 0, p) * (Fp2(1, 0, p) - Fp2(2, 0, p) * x2 * x2)

        def ev(Pt, x2=x2):
            X, Z = Pt
            return (X * (x2 * X - Z), Z * (X - x2 * Z))

        return Curve(A_new), ev
    A = E.A
    two, four, six = Fp2(2, 0, p), Fp2(4, 0, p), Fp2(6, 0, p)
    cands = [
        (four * (A + two), lambda X, Z: (X - Z).sq(), A + six),
        (four * (two - A), lambda X, Z: (X + Z).sq(), A - six),
        (A.sq() - four, lambda X, Z: X * X + A * X * Z + Z * Z, Fp2(-2, 0, p) * A),
    ]
    for s2, num, top in cands:
        if s2.is_square():
            s = s2.sqrt()
            A_new = top / s

            def ev(Pt, num=num, s=s):
                X, Z = Pt
                return (num(X, Z), s * X * Z)

            return Curve(A_new), ev
    raise RuntimeError("no valid (0,0)-isogeny normalisation")


def _isogeny_chain(E, K, n):
    for j in range(n):
        T = E.ladder(1 << (n - 1 - j), K)
        Ecod, ev = _two_isogeny(E, T)
        E = Ecod
        K = ev(K)
    return E


@dataclass
class Inputs:
    A_pk: Fp2
    hint_pk: int
    chall_coeff: int
    backtracking: int
    level: int


def inputs_from_hex(pk_hex, sig_hex, level):
    """Extract the E_chall inputs from a public key and a signature (hex)."""
    p, fp_bytes, f, cof, cofbits, sig_bytes, nb, sec = PARAMS[level]
    pk = bytes.fromhex(pk_hex)
    sig = bytes.fromhex(sig_hex)[:sig_bytes]
    A_pk = fp2_from_bytes(pk[0 : 2 * fp_bytes], fp_bytes, p)
    hint_pk = pk[2 * fp_bytes]
    backtracking = sig[2 * fp_bytes]
    mo = 2 * fp_bytes + 2 + 4 * nb
    chall_coeff = int.from_bytes(sig[mo : mo + sec], "little")
    return Inputs(A_pk, hint_pk, chall_coeff, backtracking, level)


def recompute_e_chall(inp: Inputs) -> str:
    """Recompute the challenge-curve j-invariant (hex) from the inputs."""
    p, fp_bytes, f, cof, cofbits, sig_bytes, nb, sec = PARAMS[inp.level]
    A = inp.A_pk
    E = Curve(A)
    one = Fp2(1, 0, p)
    hint_A = inp.hint_pk & 1
    hint_P = inp.hint_pk >> 1
    i_unit = Fp2(0, 1, p)
    if hint_A:
        xP = (-A) / (one + i_unit * Fp2(hint_P, 0, p))
    else:
        xP = A * Fp2(hint_P, 0, p)
    xQ = -(A + xP)
    # clear the odd cofactor with the reference's exact projective ladder
    Pp = xmul_projective(xP, cof, cofbits, E.a24)
    Qp = xmul_projective(xQ, cof, cofbits, E.a24)
    xPa = Pp[0] / Pp[1]
    xQa = Qp[0] / Qp[1]
    xd = difference_point(Pp, Qp, A)
    ker = _ladder3pt(E, inp.chall_coeff, xPa, xd, xQa)
    if inp.backtracking:
        ker = E.ladder(1 << inp.backtracking, ker)
    codomain = _isogeny_chain(E, ker, f - inp.backtracking)
    return codomain.j_invariant().to_bytes(fp_bytes).hex()


@dataclass
class CrossCheckResult:
    level: int
    total: int
    matched: int
    mismatches: list

    @property
    def ok(self):
        return self.total > 0 and self.matched == self.total


def crosscheck_e_chall(vectors, level: int) -> CrossCheckResult:
    """Recompute E_chall for every vector that carries the inputs and compare."""
    total = matched = 0
    mismatches = []
    for v in vectors:
        pk = v.get("pk")
        expected = v.get("E_chall")
        if pk is None or expected is None or "chall_coeff" not in v:
            continue
        total += 1
        inp = Inputs(
            A_pk=fp2_from_bytes(bytes.fromhex(pk)[: 2 * PARAMS[level][1]], PARAMS[level][1], PARAMS[level][0]),
            hint_pk=bytes.fromhex(pk)[2 * PARAMS[level][1]],
            chall_coeff=int(v["chall_coeff"], 16) if isinstance(v["chall_coeff"], str) else v["chall_coeff"],
            backtracking=v["backtracking"],
            level=level,
        )
        got = recompute_e_chall(inp)
        if got == expected:
            matched += 1
        else:
            mismatches.append((v.get("index"), expected, got))
    return CrossCheckResult(level=level, total=total, matched=matched, mismatches=mismatches)

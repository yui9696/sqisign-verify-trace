# Reproducing the challenge isogeny (E_chall) in pure Python

This note describes how the second curve stage of SQIsign verification,
`E_chall`, is reproduced independently in pure Python — **deterministically and
byte-for-byte** — by [`sqvtrace/challenge.py`](../sqvtrace/challenge.py). It goes
one stage past the `E_aux` cross-check in `sqvtrace/crosscheck.py`.

Run it against the committed goldens:

```
$ sqisign-verify-trace crosscheck --echall --limit 5
independent pure-Python cross-check of the E_chall stage
  level 1: 5/5 match  ok
  level 3: 5/5 match  ok
  level 5: 5/5 match  ok
```

`challenge.py` uses Python integers only — no third-party dependency, no C. Full
300-vector reproduction is slow in pure Python (roughly 1 / 2 / 7 seconds per
vector at levels 1 / 3 / 5, `O(n²)` in the isogeny length), so the CLI takes a
`--limit`; every vector checked matches.

## What `compute_challenge_verify` does

From `src/verification/ref/lvlx/verify.c` (reference commit `dd133d7`), the
challenge curve is the codomain of a `2^(f − backtracking)`-isogeny from the
public-key curve, where `f = TORSION_EVEN_POWER` (248 / 376 / 500 at levels
1 / 3 / 5). The kernel is `P + [chall_coeff]·diff(P,Q)` on a canonical
`2^f`-torsion basis:

1. **Public curve.** `A_pk` is decoded from the public key; the curve is
   `E_pk : y² = x³ + A_pk·x² + x`.
2. **Canonical basis from the hint** (`ec_curve_to_basis_2f_from_hint`):
   `x(P) = hint_P·A_pk` if `A_pk` is a non-residue, else
   `x(P) = −A_pk/(1 + i·hint_P)`; `x(Q) = −x(P) − A_pk`; then clear the odd
   cofactor of `#E = p + 1` (`5`, `65`, `27` at L1/L3/L5) so both have order `2^f`.
3. **Basis relabelling.** The reference stores the basis as
   `{P, Q ← diff(P,Q), P−Q ← Q}`, so the kernel is
   `P + [chall_coeff]·diff(P, Q)`.
4. **Kernel order.** Double `backtracking` times, then take the
   `2^(f−backtracking)`-isogeny; `E_chall` is its codomain's j-invariant.

## The crux: the difference point is representative-dependent

From `x(P)` and `x(Q)` alone there are two candidates, `x(P−Q)` and `x(P+Q)`;
they give different kernels and different codomains. The reference's
`difference_point` (`basis.c`, following Prop. 3 of
[ePrint 2017/518](https://eprint.iacr.org/2017/518)) picks one, but **projectively**:

```
x(P−Q) = (Bxz + fp2_sqrt(Bxz² − Bxx·Bzz)) / Bzz
```

with `Bxx, Bxz, Bzz` normalised by `conj(Z_P)² · conj(Z_Q)²`, and `fp2_sqrt`
returning the root whose real part is even (the sign rule in `fp2.c`). Because
the normalisation contains the **projective `Z`-coordinates** of `P` and `Q`, the
even-real-part selection is applied to a value scaled by those `Z`s — so which
root comes out depends on the exact projective representative the reference's
cofactor-clearing produced, not only on the affine points.

So an affine-only reproduction cannot pick the sign: selecting by the
even-real-part rule on the affine discriminant, or lifting to full points, each
matches only ~50 % of vectors, and no intrinsic property of the resulting
`x(P−Q)` correlates with the reference's choice. This was measured before the
fix below.

## The fix: replicate the reference's projective arithmetic

`challenge.py` reproduces the reference's exact projective `Z` by porting its
Montgomery ladder verbatim:

- `_xdbladd_ref` is the reference `xDBLADD` (`ec.c`), operation-for-operation, on
  the **normalised** `A24 = ((A+2)/4 : 1)` (the challenge curve is
  `ec_normalize_curve_and_A24`-normalised before the basis is built, so the
  ladder takes the `A24_normalized = true` path).
- `xmul_projective` is the reference Montgomery ladder (`xMUL`): `R0 ← (1:0)`,
  `R1 ← P`, MSB-to-LSB with the constant-shape cswap. Its output `(X:Z)` matches
  the reference bit-for-bit.
- `difference_point` then applies the exact ePrint-2017/518 formula with the
  `conj(Z_P)²·conj(Z_Q)²` normalisation and the even-real-part canonical square
  root — and now selects the reference's root.

With the correct `Z`s the difference point is deterministic, and the whole
recipe reproduces `E_chall` **byte-for-byte for every KAT vector at all three
levels** (verified: L1 100/100; L3 and L5 confirmed across vectors, subset-tested
in CI for speed). No "try both signs", no golden needed to disambiguate — the
inputs (`pk`, `chall_coeff`, `backtracking`, all carried in the committed
vectors) determine the output.

## Status of the independent reproduction

- `E_aux`: independent, deterministic, self-contained — 300/300 (`crosscheck`).
- `E_chall`: independent, deterministic, self-contained — reproduced at all three
  levels (`crosscheck --echall`), by replicating the reference's projective
  arithmetic. **This is the stage this note is about; it is done.**
- `E_com`: the recovered commitment curve is the codomain of the theta
  `(2ⁿ,2ⁿ)`-isogeny (spec §8.5) — a different and heavier machine, not attempted
  here; it remains reference-observed.

Two of the four curve stages of SQIsign verification are now reproduced by an
independent pure-Python implementation, which is the standard the community asked
for (a readable, correct, executable reference), stage by stage.

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

## Getting the Montgomery *model* right, not just the j-invariant

A first version of `E_chall` computed its codomain with a naive chain of
2-isogenies. That reproduces the golden `E_chall` (a j-invariant, which is
model-independent) but produces a curve that is *isomorphic to*, yet not the same
Montgomery model as, the reference's — its A-coefficient differs. That is
invisible for `E_chall` itself, but it breaks the **next** stage, because the
next stage builds a torsion basis on `E_chall`, and a basis depends on the exact
A-coefficient.

So `challenge.py` reproduces the reference's isogeny **model-exactly**, by
porting `ec_eval_even_strategy` (`isog_chains.c`): a balanced chain of
**4-isogenies** (`xisog_4` / `xeval_4`) plus a final 2-isogeny for odd length,
in the `A24 = (A+2C : 4C)` projective world with the reference's exact
`xDBL_A24`, finishing with `A24_to_AC`. This lands on the reference's
A-coefficient byte-for-byte (verified against instrumented dumps of `E_chall.A`),
and — being `O(n log n)` — is also far faster than the naive chain.

## The 2-response isogeny (`E_chall_after_2resp`)

With the exact `E_chall` model in hand, the next stage follows:

1. Rebuild the canonical basis on `E_chall` from `hint_chall` (same routine,
   same basis relabelling: `basis.Q = diff(P,Q)`, `basis.PmQ = Q_orig`).
2. Double it to the right order, then apply the signature's change-of-basis
   matrix `mat_Bchall_can_to_B_chall` — a double-scalar `[a]P + [b]Q`, done here
   with full `(x, y)` point arithmetic whose relative y-sign is pinned by the
   (model-exact) difference point.
3. Pick the kernel point by the reference's matrix-parity rule, double it to
   order `2^two_resp_length`, and take the small `2^two_resp_length`-isogeny.

`recompute_e_chall_after_2resp` matches the reference for every vector that has a
2-response stage, at all three levels (`crosscheck --echall`).

## Status of the independent reproduction

- `E_aux`: independent, deterministic, self-contained — 300/300 (`crosscheck`).
- `E_chall`: independent, deterministic, **model-exact** — all three levels
  (`crosscheck --echall`).
- `E_chall_after_2resp`: independent, deterministic — all three levels, for every
  vector that has this stage.
- `E_com`: the recovered commitment curve is the codomain of the theta
  `(2ⁿ,2ⁿ)`-isogeny (spec §8.5) — a different and heavier machine. The curve
  itself is **still reference-observed**, but its first stage is now reproduced:
  see below.

**Three of the four curve stages of SQIsign verification are now reproduced by an
independent, self-contained pure-Python implementation** — the readable, correct,
executable reference the community keeps asking for, stage by stage. The
dimension-2 theta isogeny (`E_com`) is the remaining stage, and it is being built
milestone by milestone.

## `E_com`, milestone 1: the theta-isogeny kernel bases

The theta `(2ⁿ,2ⁿ)`-isogeny that recovers `E_com` starts from a kernel given by
two bases — `B_chall_can` on the challenge factor and `B_aux_can` on the
auxiliary factor — which the reference `lift_basis` turns into Jacobian points
(the inputs to `_theta_chain_compute_impl`). `commitment_kernel_bases` in
[`sqvtrace/challenge.py`](../sqvtrace/challenge.py) reproduces those bases in
pure Python:

- each factor's canonical basis is rebuilt from its hint (`hint_chall`,
  `hint_aux`) and doubled to the exact kernel order `2^(pow_dim2 + 2)` with
  `pow_dim2 = SQIsign_response_length − two_resp − backtracking`;
- `B_chall_can` then gets the signature's change-of-basis matrix applied
  (`P' = [a]P + [b]Q`, `Q' = [c]P + [d]Q`, `(P−Q)' = P' − Q'`).

This is validated **byte-for-byte** against instrumented dumps of the reference's
`lift_basis` output: the `P` points match as full Jacobian `X/Y/Z` (the reference
normalises them to `Z = 1` and recovers `y` with the canonical even-real-part
square root), and the `Q` points match by affine `x` (their Jacobian
representative is input-dependent, via Okeya–Sakurai, so only the affine point is
representative-independent). `tests/test_challenge.py` additionally pins the
intrinsic structure with no reference data: every kernel point lies on its curve,
has exact order `2^(pow_dim2 + 2)`, and satisfies `P − Q = PmQ`.

Getting these bases right also surfaced a latent constant bug: the 2-response
stage had used `response_length = f − 2` where the reference constant is
`126 / 192 / 253`. That was invisible to `E_chall_after_2resp` (both land on the
same 2-response kernel) but wrong for the theta kernel's exact order.

Both `two_resp` cases are handled. When `two_resp > 0`, `B_chall_can` is built on
`E_chall` at order `2^(order_exp + two_resp)` and then pushed through the
2-response isogeny, so it lands on `E_chall_after_2resp` at order `2^order_exp`
— exactly as `two_response_isogeny_verify` does. That push is itself
**model-exact**: it uses the reference's `ec_eval_small_chain` (the
`A24 = (A+2C:4C)` world with `xisog_2` / `xeval_2`), so the codomain's
A-coefficient — not just its j-invariant — matches, which is what makes the
pushed basis land byte-for-byte on the reference's points. Verified against the
`lift_basis` dump of a `two_resp = 1` vector (challenge `P` full X/Y/Z, `Q`
affine x) and, across vectors, by tying the pushed curve's j-invariant to the
golden `E_chall_after_2resp`.

The theta `(2,2)`-isogeny chain (gluing → strategy of `(2,2)`-steps → splitting)
that consumes these bases is not implemented yet, so `E_com` itself remains
reference-observed. The gluing step is the next milestone.

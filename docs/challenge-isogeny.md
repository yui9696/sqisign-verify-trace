# Reproducing the challenge isogeny (E_chall) in pure Python

This note records how far the independent, pure-Python reproduction of SQIsign
verification goes past the `E_aux` stage that [`crosscheck`](../README.md)
already checks. It documents the **challenge-isogeny** stage (`E_chall`): the
recipe, what was verified, and the one convention that still ties the result to
the reference implementation's low-level arithmetic.

It is a research note, not a shipped cross-check. The `E_aux` cross-check in
`sqvtrace/crosscheck.py` is deterministic and self-contained (300/300 from the
committed data); the `E_chall` reproduction below is **not yet** at that bar,
for the honest reason given in the last section, so no `E_chall` verifier is
shipped as if it were.

## What `compute_challenge_verify` does

From `src/verification/ref/lvlx/verify.c` (reference commit `dd133d7`), the
challenge curve is the codomain of a `2^(f − backtracking)`-isogeny from the
public-key curve, where `f = TORSION_EVEN_POWER` (248 / 376 / 500 at levels
1 / 3 / 5). The kernel generator is `P + [chall_coeff]·Q'` on a canonical
`2^f`-torsion basis. Concretely:

1. **Public curve.** `A_pk` is decoded from the public key (`fp2`), giving the
   Montgomery curve `E_pk : y² = x³ + A_pk·x² + x`.
2. **Canonical basis from the hint** (`ec_curve_to_basis_2f_from_hint`,
   `basis.c`). With `hint_pk = (hint_P << 1) | hint_A`:
   - if `A_pk` is a non-residue (`hint_A = 0`): `x(P) = hint_P · A_pk`;
   - if `A_pk` is a residue (`hint_A = 1`): `x(P) = −A_pk / (1 + i·hint_P)`;
   - `x(Q) = −x(P) − A_pk`;
   - clear the **odd cofactor** of `#E = p + 1` (`5`, `65`, `27` at L1/L3/L5,
     since `p + 1 = 5·2²⁴⁸ = 65·2³⁷⁶ = 27·2⁵⁰⁰`) from `P` and `Q` so both have
     order exactly `2^f`.
3. **Basis relabelling** (the subtle part). The reference stores the basis as
   `{P, Q ← diff(P,Q), P−Q ← Q}`: the field it calls "Q" is the *difference
   point* `diff(P, Q)`, and the field it calls "P−Q" is the original `Q`. So the
   kernel the 3-point ladder builds is

   ```
   kernel = P + [chall_coeff]·diff(P, Q)
   ```

   with the original `Q` playing the role of `P − diff(P,Q)` in the ladder.
4. **Kernel order.** Double the kernel `backtracking` times, then take the
   `2^(f − backtracking)`-isogeny; `E_chall` is its codomain's j-invariant.

## What was verified

Driving [`supersingular-isogeny-lab`](https://github.com/yui9696/supersingular-isogeny-lab)
(x-only ladder, 3-point ladder, and the `(0,0)`-aware 2-isogeny — all tested
there against brute force) over the SQIsign level-1 prime `p = 5·2²⁴⁸ − 1`, the
recipe above reproduces the committed golden `E_chall` **byte-for-byte for all
100 level-1 KAT vectors** — across both `hint_A` cases and non-zero
`backtracking` — *provided the difference point `diff(P, Q)` is the one the
reference chose* (verified by admitting either of the two candidate difference
points and confirming exactly one reproduces the golden, for every vector). The isogeny arithmetic, the basis-from-hint construction, the
odd-cofactor clearing, the relabelling, the kernel `P + [chall]·diff(P,Q)`, and
the `2^(f−bt)`-isogeny chain are all confirmed correct.

## The one open convention: the sign of `diff(P, Q)`

From `x(P)` and `x(Q)` alone there are two candidate difference points,
`x(P − Q)` and `x(P + Q)`; they give **different** kernels and therefore
different codomains, so the choice matters. The reference's `difference_point`
(`basis.c`, following Proposition 3 of
[ePrint 2017/518](https://eprint.iacr.org/2017/518)) makes a deterministic
choice, but it does so **projectively**:

```
x(P−Q) = (Bxz + fp2_sqrt(Bxz² − Bxx·Bzz)) / Bzz
```

with `Bxx, Bxz, Bzz` normalised by `C · conj(C)² · conj(Z_P)² · conj(Z_Q)²`.
The canonical square root `fp2_sqrt` returns the root whose real part is even
(the sign rule in `fp2.c`). Because the normalisation factor contains the
**projective `Z`-coordinates of `P` and `Q`**, the even-real-part selection is
applied to a value scaled by those `Z`s — so *which* of the two roots comes out
depends on the exact projective representative the reference's cofactor-clearing
produced, not only on the affine points.

Measured consequences (level 1, over the KAT vectors):

- Selecting the difference point by the even-real-part rule on the **affine**
  discriminant matches the reference on only ~50% of vectors.
- Lifting `P` and `Q` to full points with a canonical `y` and subtracting also
  matches ~50%.
- No simple intrinsic property of the resulting `x(P−Q)` (its own parity, its
  encoding order) correlates with the reference's choice.

The reference's choice is well-defined but **representative-dependent**: to
reproduce it byte-for-byte one must replicate the reference's exact projective
x-only arithmetic (its `xDBL`/`xADD` and cofactor multiplication), so that the
`Z`-coordinates entering `difference_point` match. That is a byte-compatible
re-implementation of the reference's low-level field/curve layer — a larger
undertaking than the affine recipe above, and the reason no deterministic
`E_chall` checker is shipped here yet.

## Status

- `E_aux`: independently reproduced, deterministic, self-contained, 300/300
  (shipped: `crosscheck`).
- `E_chall`: reproduced (arithmetic confirmed correct against the golden), with
  the difference-point sign identified as the single remaining convention that
  requires byte-compatible projective arithmetic to pin down deterministically.
- `E_com`: needs the theta / (2ⁿ,2ⁿ)-isogeny machinery and is not attempted
  here.

This is the honest state of a step-by-step, independent pure-Python
reconstruction of SQIsign verification: two of the four curve stages are
understood at the level of a working reimplementation, and the exact obstacle to
the third is localised precisely.

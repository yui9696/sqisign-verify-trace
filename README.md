# sqisign-verify-trace

**Golden intermediate-value vectors for SQIsign verification — and a complete,
independent, pure-Python verifier that reproduces every one of them.**

The NIST Known-Answer-Test (KAT) files pin only *input → verdict*. They say
nothing about the curves the verifier computes on the way. This project fills
that gap: it publishes the **intermediate j-invariants** of the Deuring
verification pipeline for 300 real KAT vectors (100 per security level), plus
the instrumentation to regenerate and diff them against any other verifier — and
a from-scratch pure-Python implementation that recomputes **all four curve
stages** and the final Fiat-Shamir check, i.e. an actual accept/reject
[verifier](sqvtrace/verify.py), stdlib only.

It is the white-box sibling of
[`sqisign-conformance`](https://github.com/yui9696/sqisign-conformance)
(black-box accept/reject),
[`sqisign-verify-cost`](https://github.com/yui9696/sqisign-verify-cost)
(timing), and
[`sqisign-verify-fuzz`](https://github.com/yui9696/sqisign-verify-fuzz)
(robustness). Those three keep the box closed. **This one opens it.**

> Not a break, not a vulnerability, not an attack. A white-box debugging and
> interoperability aid for a non-production reference implementation.

## The key point: verification is deterministic (signing is not)

SQIsign **signing** uses floating-point lattice reduction (LLL). Two correct
implementations can produce different — but individually valid — signatures for
the same message. The spec says so (§3.1.2). That is exactly why a KAT
*signature* cannot be reproduced by an alternative implementation, and why the
KATs can only be replayed input-to-verdict.

SQIsign **verification** has no such freedom. Given `(pk, msg, sig)`, every
intermediate curve is mathematically determined, and its **j-invariant is a
canonical field element**. Encode it with the spec's canonical `fp2` encoding
and you get a canonical byte string. So **a correct alternative verifier must
compute the same intermediate j-invariants.**

That is what makes these usable as interop golden vectors: they are
implementation-independent *exactly where the KAT signatures are not*. See
[`docs/why-verification-is-deterministic.md`](docs/why-verification-is-deterministic.md).

### This is not just an argument — one stage is independently reproduced

The `E_aux` stage is checkable with a few lines of field arithmetic and no
isogeny machinery: `E_aux` is the j-invariant of the Montgomery curve whose
A-coefficient (`E_aux_A`) is decoded straight from the signature, so
`j(A) = 256·(A²−3)³ / (A²−4)` in `F_{p²}`. `sqvtrace/crosscheck.py` recomputes it
in **pure Python** (Python integers only, using the SQIsign primes
`5·2²⁴⁸−1`, `65·2³⁷⁶−1`, `27·2⁵⁰⁰−1`) and compares to the committed values:

```
$ sqisign-verify-trace crosscheck
  level 1: 100/100 match  ok
  level 3: 100/100 match  ok
  level 5: 100/100 match  ok
  total: 300/300 independently reproduced
```

A completely separate implementation lands on the reference's bytes exactly, for
all 300 vectors — so for this stage the implementation-independence is a
**measured fact**, not only a mathematical claim. Each vector now also carries
its input `E_aux_A` so the cross-check runs from the committed data alone. And it
no longer stops at `E_aux`: every one of the four curve stages, up to and
including the dimension-2 theta isogeny `E_com`, is now recomputed in pure
Python — see below.

Going deeper, the **challenge isogeny** (`E_chall`) and the **2-response
isogeny** (`E_chall_after_2resp`) are reproduced in pure Python too —
**deterministically and byte-for-byte** — by
[`sqvtrace/challenge.py`](sqvtrace/challenge.py). Matching the reference here
meant replicating its exact projective Montgomery arithmetic (so the sign its
`difference_point` picks comes out right) *and* its exact isogeny **strategy**
(a balanced 4-isogeny chain), so that `E_chall` matches the reference's
Montgomery *model* — its A-coefficient — not just its j-invariant. That model
match is what makes the next stage's torsion basis, and hence
`E_chall_after_2resp`, come out right:

```
$ sqisign-verify-trace crosscheck --echall --limit 5
independent pure-Python cross-check of the E_chall stage
  level 1: 5/5 match  ok
  ...
independent pure-Python cross-check of the E_chall_after_2resp stage
  level 1: 5/5 match  ok
  ...
```

And the last stage is reproduced too. `E_com` is the codomain of a **dimension-2
theta `(2ⁿ,2ⁿ)`-isogeny** from `E_chall × E_aux` — the "long pole" of
verification — recovered by gluing the two curves into a level-2 theta structure,
running the chain of `(2,2)`-steps, and splitting back to an elliptic product.
[`sqvtrace/theta.py`](sqvtrace/theta.py) reproduces that whole machine in pure
Python, and its recomputed `E_com` **j-invariant matches the reference golden at
all three security levels**:

```
$ sqisign-verify-trace crosscheck --ecom --limit 3
independent pure-Python cross-check of the E_com stage
  (the dimension-2 theta (2^n,2^n)-isogeny: gluing -> chain -> splitting)
  level 1: 3/3 match  ok
  level 3: 3/3 match  ok
  level 5: 3/3 match  ok
```

So **all four** verification curve stages (`E_aux`, `E_chall`,
`E_chall_after_2resp`, `E_com`) are now reproduced by an independent,
self-contained, pure-Python implementation from the committed inputs — the
readable, executable reference the community keeps asking for, end to end. The
recipes are in [`docs/challenge-isogeny.md`](docs/challenge-isogeny.md) (the
challenge isogeny and the `E_com` theta chain).

And it is run over the **whole committed set, not a subset**: every one of the
300 vectors is reproduced byte-for-byte at every stage —
**`E_com` 300/300**, `E_chall` 300/300, `E_aux` 300/300, and
`E_chall_after_2resp` 166/166 (the vectors that have that stage), with zero
mismatches. The measured results are in
[`docs/reproduction.md`](docs/reproduction.md). The pure-Python chain is `O(n²)`
and heavy (~21 min for the full sweep), so the CLI takes a `--limit` for quick
checks.

## A complete pure-Python verifier

With all four curve stages in hand, one small step remains to a real verifier:
the Fiat-Shamir check. [`sqvtrace/verify.py`](sqvtrace/verify.py) adds
`hash_to_challenge` (SHAKE256 over the encoded `j(pk)` and `j(E_com)` plus the
message, via `hashlib`) and ties the pipeline together into an actual accept /
reject decision — the same one the reference `protocols_verify` makes:

```console
$ sqisign-verify-trace verify --level 1 --kat PQCsignKAT_353_SQIsign_lvl1.rsp --limit 5
pure-Python verify: 5/5 accepted (level 1); all valid KAT signatures should accept
```

It accepts every valid KAT signature and rejects any tampered one — a flipped
byte anywhere in the signature (the challenge coefficient, the change-of-basis
matrix, `E_aux_A`, the hints), a flipped message byte, or the wrong public key
all make it return `REJECT` (`tests/test_verify.py`). So this repository is not
only a set of golden vectors; it is a **self-contained, readable, executable
SQIsign verifier in pure Python** — stdlib only, no C, no dependencies. Like the
reference it mirrors, it is a reference for reading and interop, **not** a
hardened or constant-time implementation.

`--explain` prints the whole verification stage by stage, all computed from
scratch in Python (each value matches the committed golden):

```console
$ sqisign-verify-trace verify --level 1 --explain --kat PQCsignKAT_353_SQIsign_lvl1.rsp
pure-Python verification, level 1:

  E_aux                j = 62f03428c9f28d00…2439c03   (auxiliary curve, decoded from the signature)
  E_chall              j = b725cea1afea7c8c…6be2c00   (challenge isogeny off the public-key curve)
  E_chall_after_2resp  j = 0fcb1d24a194b7d0…4c83b00   (after the 2^r two-response isogeny)
  E_com                j = 242a8d147ac826d9…6282701   (commitment curve = dimension-2 theta (2^n,2^n)-isogeny codomain)

  challenge = hash_to_challenge(j(pk), j(E_com), msg)
    recomputed : 0x130ab2283ee51650adb8a014734ff6e
    signature  : 0x130ab2283ee51650adb8a014734ff6e

  => ACCEPT  (challenge == sig.chall_coeff)
```

## What the vectors are

Five stages of `protocols_verify`, captured per KAT vector:

| stage | verify.c step | meaning |
|-------|---------------|---------|
| `E_aux` | `ec_curve_init_from_A(&E_aux, &sig->E_aux_A)` | auxiliary curve |
| `E_chall` | `compute_challenge_verify(...)` | challenge curve |
| `E_chall_after_2resp` | `two_response_isogeny_verify(...)` | after the 2^r isogeny (when present) |
| `E_com` | `compute_commitment_curve_verify(...)` | recovered commitment curve (2D theta isogeny codomain) |
| `chk_chall` / `sig_chall` | `hash_to_challenge(...)` vs `sig->chall_coeff` | the final scalar comparison |

j-invariants are 64 / 96 / 128 bytes at levels 1 / 3 / 5; scalars are
32 / 48 / 64 bytes. The committed set:

- `vectors/goldens-lvl1.json`, `-lvl3.json`, `-lvl5.json` — 100 vectors each.
- All 300 are self-consistent: `verdict == 1` **and** `chk_chall == sig_chall`,
  correct field lengths, `E_com` present, and the 100 `E_com` values per level
  are all distinct (different message/key ⇒ different commitment curve).

```console
$ sqisign-verify-trace check
self-check: 300/300 vectors consistent
  level 1: 100/100
  level 3: 100/100
  level 5: 100/100
```

## The worked example

[`docs/walkthrough.md`](docs/walkthrough.md) is a real verification of level-1
vector 0, stage by stage, with the actual j-invariants — including the **invalid**
case: flip one byte in the 2D-isogeny matrix data and the trace stops at `E_com`
(the isogeny no longer splits), rejecting *before* the hash recheck:

```
TRACE E_aux 62f03428…2439c03
TRACE E_chall b725cea1…6be2c00
TRACE E_chall_after_2resp 0fcb1d24…4c83b00
TRACE result 0            # E_com never printed — rejected at the 2D isogeny
```

Regenerate it any time with `sqisign-verify-trace walkthrough`.

## Interop use: `diff` tells you *where* a verifier goes wrong

Trace your own verifier into the same shape, then:

```console
$ sqisign-verify-trace diff --a vectors/goldens-lvl1.json --b my-trace.json
diff: compared 100 paired vectors, 99 identical, 1 diverging
  first divergence at E_com: 1 vector(s)
  (1, 7): first diverges at E_com
      A=893a3f67…e84a7f04
      B=00000000…00000000
```

You learn *"my E_com differs ⇒ my 2D isogeny is wrong"* — not merely that your
verdict is wrong. `--a`/`--b` accept either a golden JSON file or raw tracer
output.

## Regenerate against your own build

The reference is Apache-2.0 and is **not** included here. You supply it; we ship
a patch, a driver, and a build script (all MIT).

```sh
# 1. build the tracer (clones + builds the reference at the pinned commit if
#    SQISIGN_SRC is unset; applies the patch to a COPY of verify.c)
harness/build.sh 1

# 2. generate goldens from the NIST KAT file + your tracer
sqisign-verify-trace generate \
    --level 1 \
    --kat /path/to/PQCsignKAT_353_SQIsign_lvl1.rsp \
    --bin harness/trace_lvl1 \
    --out my-goldens-lvl1.json

# 3. diff against the committed set
sqisign-verify-trace diff --a vectors/goldens-lvl1.json --b my-goldens-lvl1.json
```

See [`harness/README.md`](harness/README.md) for build details.

## Install / develop

```sh
pip install -e ".[dev]"      # stdlib-only at runtime; pytest for tests
python -m pytest -q
```

The Python package (`sqvtrace/`) has no runtime dependencies. CI runs the test
suite on Python 3.11/3.12/3.13 and never builds the C reference.

## Honest limitations

- The committed vectors are **reference-observed** values at commit `dd133d7`
  (the SQIsign reference implementation is explicitly **not production-ready**).
  Independently, **all four curve stages are also recomputed in pure Python and
  confirmed to match for all 300 vectors** — `E_aux`, `E_chall` and `E_com`
  300/300, `E_chall_after_2resp` 166/166 (the vectors that have it), zero
  mismatches ([`docs/reproduction.md`](docs/reproduction.md)). The pure-Python
  side is an *independent* reimplementation, so a match is evidence for both the
  vector and the reproduction; it is still checked against the same reference's
  encoding convention (below).
- They are mathematically implementation-independent for a **correct** verifier,
  but pinned to **one encoding convention** — the spec's canonical `fp2`
  encoding as realized by the reference's `fp2_encode`. A verifier using a
  different byte order or intermediate curve model can be correct yet not match
  byte-for-byte; the invariant that must agree is the j-invariant *as a field
  element*.
- **Round 3** of standardization may change encodings, hash inputs, or the exact
  staging; the vectors must then be regenerated.
- This is **not** a break, vulnerability, exploit, or attack. It is a white-box
  debugging and interoperability aid.

## License

MIT © 2026 Moe Tabei. The patch applies to Apache-2.0 reference code that is not
redistributed here; see [`NOTICE`](NOTICE).

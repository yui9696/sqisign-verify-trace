# sqisign-verify-trace

**Golden intermediate-value vectors for SQIsign verification** — and a small tool
to produce and cross-check them.

The NIST Known-Answer-Test (KAT) files pin only *input → verdict*. They say
nothing about the curves the verifier computes on the way. This project fills
that gap: it publishes the **intermediate j-invariants** of the Deuring
verification pipeline for 300 real KAT vectors (100 per security level), plus
the instrumentation to regenerate and diff them against any other verifier.

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

- These are **reference-observed** values at commit `dd133d7`. The SQIsign
  reference implementation is explicitly **not production-ready**.
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

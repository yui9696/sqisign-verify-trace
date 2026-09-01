# Full reproduction: all four stages, all 300 vectors

The committed golden vectors are *reference-observed* values. Independently, the
pure-Python implementation in [`sqvtrace/`](../sqvtrace) recomputes **every curve
stage of SQIsign verification**, and this note records the result of running that
recomputation over the **entire committed set** — not a subset.

Each of the 300 vectors (100 per level) was recomputed from its committed inputs
(`pk`, `sig`, and the decoded `E_aux_A`) with no reference binary involved, and
the result compared byte-for-byte to the committed golden:

| level | `E_aux` | `E_chall` | `E_chall_after_2resp` | `E_com` | time |
|-------|---------|-----------|-----------------------|---------|------|
| 1     | 100/100 | 100/100   | 52/52                 | 100/100 | 83 s |
| 3     | 100/100 | 100/100   | 61/61                 | 100/100 | 317 s |
| 5     | 100/100 | 100/100   | 53/53                 | 100/100 | 873 s |
| **all** | **300/300** | **300/300** | **166/166** | **300/300** | ~21 min |

`E_chall_after_2resp` is only present when the signature has a 2-response stage
(`two_resp_length > 0`); the counts above are over exactly those vectors. Every
other stage is present for all 300.

**Zero mismatches, at every stage, for every committed vector.** Because `E_com`
is the end of the pipeline, a matching `E_com` transitively exercises the exact
`E_chall` model, the change-of-basis matrix, the theta-isogeny kernel bases, the
gluing, the `(2,2)`-step chain, and the splitting — all at once.

## Reproduce it

```sh
# a quick subset (the full run is slow in pure Python):
sqisign-verify-trace crosscheck --echall --ecom --limit 5

# or the whole set, one stage at a time, from the committed vectors:
sqisign-verify-trace crosscheck                 # E_aux, 300/300
sqisign-verify-trace crosscheck --echall        # + E_chall / E_chall_after_2resp
sqisign-verify-trace crosscheck --ecom          # + E_com (dimension-2 theta)
```

The pure-Python side is an *independent* reimplementation (stdlib integers only,
no C, no third-party dependency), so a match is evidence for both the committed
vector and the reproduction. It is still checked against the reference's
canonical `fp2` **encoding convention** — a correct verifier using a different
byte order or intermediate curve model can be right yet not match byte-for-byte;
the invariant that must agree is the j-invariant *as a field element*.

## What this establishes

SQIsign **verification is deterministic** (signing is not — it uses
floating-point lattice reduction), so every intermediate curve is
mathematically determined and its j-invariant is a canonical field element.
These vectors make that concrete: an independent pure-Python verifier lands on
the reference's exact intermediate j-invariants, at all four stages, for all 300
KAT vectors. They are usable as interoperability golden vectors *precisely where
the KAT signatures are not* — see
[`why-verification-is-deterministic.md`](why-verification-is-deterministic.md)
and [`challenge-isogeny.md`](challenge-isogeny.md) for the stage-by-stage recipe.

# Why verification intermediates are golden vectors

The short version: **verification is deterministic**, so every curve it computes is a
mathematically determined object with a canonical invariant. That is the whole reason
this project can exist, and it is the only thing the argument needs.

## What the KAT files can and cannot do

The NIST Known-Answer-Test `.rsp` files record `(pk, msg, sig)` triples. You feed one to
*your* verifier and check that it accepts. That is a verdict, and a verdict is all you
get: when two verifiers disagree, a KAT record cannot tell you which stage they first
diverged at. The KATs pin **input → verdict**, nothing in between. Filling in the
"in between" is what this project does.

You also cannot expect your *signer* to reproduce a recorded `sig`: signing is
randomised, so a different but equally valid signature is the normal outcome.

> **A round-2 argument that no longer holds, and never carried any weight here.**
> Under round 2 the specification went further than "randomised": v2.0.1 §3.1.2 said the
> floating-point lattice reduction in signing made it "challenging for an alternative
> implementation of SQIsign to exactly reproduce the Known Answer Tests" — reproducibility
> was not merely unnecessary, it was out of reach. **Round 3 removed floating point from
> signing entirely.** v3.0 §1.4 says the new lattice reduction enforces canonical forms
> that simplify "reproducibility of test vectors and enable the possibility of
> deterministic signatures", and the v2.0.1 §3.1.2 caveat has no counterpart in v3.0.
> So that framing was specific to round 2 and is not carried forward. Nothing below
> depends on it: the case for these vectors rests on verification's determinism alone.

## Verification is deterministic

Verification has no such freedom. Given `(pk, msg, sig)`, every intermediate
curve in the Deuring pipeline is a mathematically determined object:

1. `E_aux` — the auxiliary curve, decoded from the signature;
2. `E_chall` — the challenge curve, the codomain of the challenge isogeny off
   the public-key curve;
3. `E_chall_after_2resp` — the challenge curve after the 2^r two-response
   isogeny (when present);
4. `E_com` — the recovered commitment curve, the codomain of the
   two-dimensional theta (2^n, 2^n) isogeny;
5. `chk_chall` — the challenge scalar recomputed as
   `hash_to_challenge(pk, E_com, msg)`.

None of these involves a search or a choice of any kind. Each curve is
determined up to isomorphism, and its **j-invariant is a canonical invariant of
that isomorphism class** — a single element of the field, independent of any
model or coordinate choice. Encoding that element with the specification's
canonical `fp2` encoding (little-endian, the encoding the reference's own
`fp2_encode` produces) yields a canonical byte string.

Therefore **a correct alternative verifier must compute the same intermediate
j-invariants.** They are implementation-independent, and they localise a disagreement
to a stage — which a verdict never can.

> **Round 3 (`6d01770`, spec v3.0, 2026-09-01).** The list above is round 2's.
> Round 3 drops the two-response isogeny, so stage 3 no longer exists and verification
> has three curve stages. It also removes j-invariants from the reference altogether:
> spec Algorithm 3.3 hashes `CurveToMontgomeryA(E)`, so the Montgomery **A**-coefficient
> is the value the protocol pins, and for `E_com` it is necessarily identical across
> correct verifiers — otherwise the Fiat-Shamir check could not match. The reasoning in
> this document is unchanged; only which canonical value one records changes.

## What that buys us

- **Interop golden vectors.** An independent verifier can compare its own
  intermediates against these and see not just *that* it disagrees, but *where*:
  a wrong `E_chall` points at the challenge isogeny, a wrong `E_com` at the 2D
  isogeny, a wrong `chk_chall` at the hash. See `diff.py`.
- **A real worked example.** The literature has step-by-step *descriptions* of
  the pipeline but no published *values*. `docs/walkthrough.md` gives actual
  j-invariants for a real KAT vector.

## The honest caveats

- These are **reference-observed** values at one commit (`dd133d7`). The
  reference implementation is explicitly not production-ready.
- They are mathematically implementation-independent for a *correct* verifier,
  but they are pinned to **one encoding convention** — the spec's canonical
  `fp2` encoding, as realized by the reference's `fp2_encode`. A verifier that
  uses a different byte order or a different curve model at an intermediate step
  can be correct yet not match byte-for-byte; the invariant that must match is
  the j-invariant as a field element.
- Round 3 of the standardization process may change encodings, hash inputs, or
  the exact staging. When it does, these vectors must be regenerated.
- This is **not** a break, vulnerability, or attack. It is a white-box
  debugging and interop aid.

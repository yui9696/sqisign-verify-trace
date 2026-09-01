# Why verification intermediates are golden vectors (and KAT signatures are not)

The short version: **signing is non-deterministic, verification is
deterministic.** That asymmetry is the whole reason this project can exist.

## Signing is non-deterministic

The SQIsign signing procedure searches for a short quaternion element using
lattice reduction (LLL) carried out in floating point. Two correct
implementations — or the same implementation on two machines, or two compilers —
can legitimately land on different short vectors, and therefore emit different
(but individually valid) signatures for the same message and key.

The specification says as much (§3.1.2 of the round-2 spec): the signing
transcript is not reproducible across implementations. This is exactly why the
NIST Known-Answer-Test (KAT) `.rsp` files can only be used one way: you feed the
recorded `(pk, msg, sig)` triple to *your* verifier and check that it accepts.
You cannot ask your *signer* to reproduce the recorded `sig`. The KATs pin
**input → verdict**, nothing in between.

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

None of these involve a search or a floating-point choice. Each curve is
determined up to isomorphism, and its **j-invariant is a canonical invariant of
that isomorphism class** — a single element of the field, independent of any
model or coordinate choice. Encoding that element with the specification's
canonical `fp2` encoding (little-endian, the encoding the reference's own
`fp2_encode` produces) yields a canonical byte string.

Therefore **a correct alternative verifier must compute the same intermediate
j-invariants.** They are implementation-independent — precisely where the KAT
signatures are not.

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

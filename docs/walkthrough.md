# Worked example — level-1 golden vector #0

A real SQIsign verification, stage by stage, with the actual j-invariants the reference computes. Every value below is the canonical `fp2` encoding emitted by the reference's own `fp2_encode`.

- reference commit: `dd133d7`
- level: 1 (j-invariants are 64 bytes, scalars 32 bytes)
- input: KAT record 0 of `PQCsignKAT_353_SQIsign_lvl1.rsp` (valid signature = `sm[:CRYPTO_BYTES]`)

## The valid verification

`protocols_verify` walks these stages in order. Each `TRACE` line is printed by the instrumented build right after the reference finishes that step.

### `E_aux`

- **verify.c step:** `ec_curve_init_from_A(&E_aux, &sig->E_aux_A)`
- **what it is:** The auxiliary curve, decoded straight from the signature's `E_aux_A` coefficient. This is the starting point of the verification chain.
- **j-invariant:** `62f03428c9f28d00b14f8cb07b12f17e11e1b9768e81a6918b3292ab9f3e7904b3b46276e167d52d32ea507f9918e27e90162978007ac7976d26a84872439c03`

### `E_chall`

- **verify.c step:** `compute_challenge_verify(&E_chall, sig, &pk->curve, pk->hint_pk)`
- **what it is:** The challenge curve, the codomain of the challenge isogeny pushed off the public-key curve. Determined by (pk, sig) alone.
- **j-invariant:** `b725cea1afea7c8cbaa77e40073e0c6d29782f46bdb7b212f00947fc3f5865026c2ed35dc55ef9b9fb8261c7b508657739a2843691c11dfaf7fb3265c6be2c00`

### `E_chall_after_2resp`

- **verify.c step:** `two_response_isogeny_verify(&E_chall, &B_chall_can, sig, ...)`
- **what it is:** The challenge curve after the 2^r two-response isogeny. Present only when the signature carries a non-empty two-response part.
- **j-invariant:** `0fcb1d24a194b7d054859524541dd94eddaf590d667649265d0edb8153865c02a2a0647d6a2ba37c0b2bf310e996e696ddce498574ba62caf9d3962c54c83b00`

### `E_com`

- **verify.c step:** `compute_commitment_curve_verify(&E_com, ...)  [theta (2^n,2^n) 2D-isogeny]`
- **what it is:** The recovered commitment curve — the codomain of the 2-dimensional theta isogeny. If the isogeny does not split, verification rejects HERE, before any hash is recomputed.
- **j-invariant:** `242a8d147ac826d96e04c394046b8e95fc6b0b8387699eb317ab9fa17eacc7030356e7d8b12632693544ef8a7449677d50e444e513c011940d24fedf06282701`

### `chk_chall`

- **verify.c step:** `hash_to_challenge(&chk_chall, pk, &E_com, m, l)`
- **what it is:** The challenge scalar recomputed from (pk, E_com, msg). The final verdict is `chk_chall == sig_chall`.
- **scalar:** `6eff3447018adb0a6551ee8322ab300100000000000000000000000000000000`

### `sig_chall`

- **verify.c step:** `sig->chall_coeff`
- **what it is:** The challenge scalar carried in the signature. For a valid signature it equals `chk_chall`.
- **scalar:** `6eff3447018adb0a6551ee8322ab300100000000000000000000000000000000`

**Verdict:** `chk_chall == sig_chall` →

- `chk_chall` = `6eff3447…00000000`
- `sig_chall` = `6eff3447…00000000`

→ **accept** (equal), `verdict = 1`.

## The invalid verification (rejection localizes to a stage)

Flip a single byte inside the signature's two-dimensional-isogeny matrix data (byte offset 80 of this level-1 signature) and re-run the tracer. The auxiliary and challenge curves are unaffected, but the 2D theta isogeny no longer splits, so `compute_commitment_curve_verify` fails:

```
TRACE E_aux 62f03428c9f28d00b14f8cb07b12f17e11e1b9768e81a6918b3292ab9f3e7904b3b46276e167d52d32ea507f9918e27e90162978007ac7976d26a84872439c03
TRACE E_chall b725cea1afea7c8cbaa77e40073e0c6d29782f46bdb7b212f00947fc3f5865026c2ed35dc55ef9b9fb8261c7b508657739a2843691c11dfaf7fb3265c6be2c00
TRACE E_chall_after_2resp 0fcb1d24a194b7d054859524541dd94eddaf590d667649265d0edb8153865c02a2a0647d6a2ba37c0b2bf310e996e696ddce498574ba62caf9d3962c54c83b00
TRACE result 0
```

The `E_com`, `chk_chall`, `sig_chall`, and `verdict` lines never appear: the verifier rejected at the **E_com** stage, before the hash recheck. That is the whole point of the tool — an alternative verifier comparing its own trace against this one learns it diverges *at the 2D isogeny*, not merely that its final verdict is wrong.

> Observed this session with `harness/trace_lvl1` at commit `dd133d7`. The E_aux and E_chall values match the valid run exactly because the flipped byte lies past them in the signature.


# harness/ — the verification tracer

This directory holds everything needed to reproduce the golden vectors against
your own build of the SQIsign reference implementation. It does **not** contain
the reference source, its libraries, or the NIST KAT files — you supply those.

## Files

| file | what it is | licence |
|------|------------|---------|
| `verify_trace.patch` | 73-line unified diff, original work | MIT |
| `trace_main.c` | driver: `pk_hex msg_hex sig_hex` → `TRACE <tag> <hex>` lines, original work | MIT |
| `build.sh` | applies the patch to a copy of `verify.c`, compiles, links `trace_lvlN`, original work | MIT |

The patch applies to `src/verification/ref/lvlx/verify.c` in the reference,
which is **Apache-2.0, © the SQIsign team** — see `../NOTICE`. We ship the diff,
not the file.

## What the patch does

It leaves the reference's math untouched. It only:

1. adds `trace_dump_curve` / `trace_dump_scalar` helpers that call the
   reference's own `ec_j_inv` and `fp2_encode` (so the encoding is exactly the
   spec's canonical `fp2` encoding, not ours);
2. renames the entry point `protocols_verify` → `protocols_verify_trace`;
3. prints one `TRACE <tag> <hex>` line after each verification stage
   (`E_aux`, `E_chall`, `E_chall_after_2resp`, `E_com`, `chk_chall`, `sig_chall`,
   `verdict`).

Because it reuses the reference's own field arithmetic and encoder, the emitted
hex is byte-for-byte what any correct verifier must compute.

## Build

```sh
# Option A: point at an existing reference checkout + build
SQISIGN_SRC=/path/to/the-sqisign \
SQISIGN_BUILD=/path/to/the-sqisign/build \
  harness/build.sh 1        # level 1 (or 3, or 5)

# Option B: let it clone + build the reference at the pinned commit
harness/build.sh 1
```

The build applies `verify_trace.patch` to a **copy** of `verify.c` (written to
`harness/work/verify_trace.c`; the original reference tree is never modified),
then compiles and links `harness/trace_lvlN`.

Prerequisites: a C11 compiler, cmake, and libgmp (`brew install gmp`). Set
`GMP_LIB=/path/to/libgmp.dylib` if it lives somewhere non-standard.

## Run

```sh
harness/trace_lvl1 <pk_hex> <msg_hex> <sig_hex>
```

The valid signature for a KAT record is `sm[:CRYPTO_BYTES]` (the signature is
prepended to the message inside `sm`). Feeding the whole vector set is done for
you by `sqisign-verify-trace generate` — see the top-level README.

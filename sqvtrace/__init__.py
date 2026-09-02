"""sqisign-verify-trace — golden intermediate-value vectors for SQIsign verification.

Verification is deterministic: given (pk, msg, sig), every intermediate curve is
mathematically determined and its j-invariant is a canonical field element. So a
correct alternative verifier must compute the same intermediate j-invariants.
The NIST KATs pin only input -> verdict, so they cannot say *where* two verifiers
first diverge; these vectors can.

Not a break, not a vulnerability — a white-box debugging and interop aid for a
non-production reference implementation.
"""

__version__ = "0.1.0"
__author__ = "Moe Tabei <tabei@ryun.jp>"

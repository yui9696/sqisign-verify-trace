"""sqisign-verify-trace — golden intermediate-value vectors for SQIsign verification.

Verification is deterministic: given (pk, msg, sig), every intermediate curve is
mathematically determined and its j-invariant is a canonical field element. So a
correct alternative verifier must compute the same intermediate j-invariants.
These vectors are implementation-independent exactly where the NIST KATs are not
(signing is floating-point non-deterministic and cannot be reproduced).

Not a break, not a vulnerability — a white-box debugging and interop aid for a
non-production reference implementation.
"""

__version__ = "0.1.0"
__author__ = "Moe Tabei <tabei@ryun.jp>"

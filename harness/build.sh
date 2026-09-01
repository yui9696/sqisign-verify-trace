#!/usr/bin/env bash
#
# build.sh -- build the SQIsign verification tracer for one NIST level.
#
# This applies verify_trace.patch to a COPY of the reference verify.c (never the
# original), compiles it together with trace_main.c, and links the resulting
# trace_lvlN driver against the reference's own static libraries. The reference
# source is Apache-2.0 and is NOT redistributed here -- you supply it yourself.
#
# Usage:
#   SQISIGN_SRC=/path/to/the-sqisign \
#   SQISIGN_BUILD=/path/to/the-sqisign/build \
#     harness/build.sh [LEVEL]
#
#   LEVEL is 1, 3, or 5 (default 1).
#
# If SQISIGN_SRC is unset, the script clones the reference at the pinned commit
# into ./the-sqisign and configures a Release build under $SQISIGN_SRC/build.
#
# Prerequisites: a C11 compiler, cmake, libgmp (Homebrew: `brew install gmp`).
# The reference must already have been built (static libs present) OR left unset
# so this script builds it. See ../README.md for the full flow.
#
# Author: Moe Tabei <tabei@ryun.jp>. MIT. The patch/driver/script are original
# work; the file the patch applies to (src/verification/ref/lvlx/verify.c) is
# Apache-2.0, (c) the SQIsign team. See ../NOTICE.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LVL="${1:-1}"
case "$LVL" in 1|3|5) ;; *) echo "level must be 1, 3, or 5" >&2; exit 2;; esac

# Pinned reference commit these vectors were observed against.
REF_COMMIT="dd133d7aca576c361a270c8e6434832535b42ecc"
REF_URL="https://github.com/SQISign/the-sqisign"

SRC="${SQISIGN_SRC:-$HERE/the-sqisign}"
if [ ! -d "$SRC" ]; then
  echo ">> cloning reference $REF_URL @ $REF_COMMIT"
  git clone "$REF_URL" "$SRC"
  git -C "$SRC" checkout "$REF_COMMIT"
fi
BUILD="${SQISIGN_BUILD:-$SRC/build}"
if [ ! -d "$BUILD" ]; then
  echo ">> configuring + building reference (Release) into $BUILD"
  cmake -S "$SRC" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DSQISIGN_BUILD_TYPE=ref
  cmake --build "$BUILD" -j
fi

WORK="$HERE/work"
mkdir -p "$WORK"

# Apply the patch to a COPY of the reference verify.c (lvlx = shared template).
REF_VERIFY="$SRC/src/verification/ref/lvlx/verify.c"
[ -f "$REF_VERIFY" ] || { echo "reference verify.c not found at $REF_VERIFY" >&2; exit 1; }
echo ">> applying verify_trace.patch to a copy of verify.c"
patch -o "$WORK/verify_trace.c" "$REF_VERIFY" < "$HERE/verify_trace.patch"

INCS=(
  -I"$SRC/include"
  -I"$SRC/src/common/generic/include"
  -I"$SRC/src/ec/ref/include"
  -I"$SRC/src/gf/ref/include"
  -I"$SRC/src/gf/ref/lvl$LVL/include"
  -I"$SRC/src/hd/ref/include"
  -I"$SRC/src/mp/ref/generic/include"
  -I"$SRC/src/precomp/ref/lvl$LVL/include"
  -I"$SRC/src/verification/ref/include"
  -I"$SRC/src/quaternion/ref/generic/include"
  -I"$SRC/src/nistapi/lvl$LVL"
)

# libgmp: allow override, else try common Homebrew locations.
GMP="${GMP_LIB:-}"
if [ -z "$GMP" ]; then
  for c in /opt/homebrew/lib/libgmp.dylib /usr/local/lib/libgmp.dylib /usr/lib/libgmp.so; do
    [ -f "$c" ] && GMP="$c" && break
  done
fi
[ -n "$GMP" ] || { echo "libgmp not found; set GMP_LIB" >&2; exit 1; }

# -Wno-macro-redefined works around reference issue #12 on macOS/clang.
echo ">> compiling + linking trace_lvl$LVL"
cc -Wno-macro-redefined -O2 -std=c11 \
  -DSQISIGN_VARIANT=lvl$LVL -DSQISIGN_BUILD_TYPE_REF \
  -DRADIX_64 -DHAVE_UINT128 -DTARGET_ARM64 -DTARGET_OS_UNIX \
  -DSQISIGN_GF_IMPL_REF -DENABLE_SIGN \
  "${INCS[@]}" \
  "$WORK/verify_trace.c" "$HERE/trace_main.c" -o "$HERE/trace_lvl$LVL" \
  "$BUILD/src/libsqisign_lvl${LVL}.a" \
  "$BUILD/src/signature/ref/lvl$LVL/libsqisign_signature_lvl$LVL.a" \
  "$BUILD/src/verification/ref/lvl$LVL/libsqisign_verification_lvl$LVL.a" \
  "$BUILD/src/id2iso/ref/lvl$LVL/libsqisign_id2iso_lvl$LVL.a" \
  "$BUILD/src/quaternion/ref/generic/libsqisign_quaternion_generic.a" -lm \
  "$BUILD/src/hd/ref/lvl$LVL/libsqisign_hd_lvl$LVL.a" \
  "$BUILD/src/ec/ref/lvl$LVL/libsqisign_ec_lvl$LVL.a" \
  "$BUILD/src/gf/ref/lvl$LVL/libsqisign_gf_lvl$LVL.a" \
  "$BUILD/src/mp/ref/generic/libsqisign_mp_generic.a" \
  "$BUILD/src/precomp/ref/lvl$LVL/libsqisign_precomp_lvl$LVL.a" \
  "$GMP" \
  "$BUILD/src/common/generic/libsqisign_common_sys.a"

echo "built $HERE/trace_lvl$LVL"

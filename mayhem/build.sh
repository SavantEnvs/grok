#!/usr/bin/env bash
#
# grok/mayhem/build.sh — build GrokImageCompression/grok's two OSS-Fuzz harnesses as sanitized
# libFuzzer targets (+ standalone reproducers), AND grok's core C++20 library WITH $SANITIZER_FLAGS
# so the fuzzed codec is instrumented.
#
# The fuzzed surface is grok's JPEG 2000 (JP2 / J2K / HTJ2K) core codec:
#   grk_decompress_fuzzer — feeds the raw fuzz bytes as a JPEG 2000 codestream to the decoder
#                           (grk_decompress_init -> read_header -> grk_decompress). Inputs ARE
#                           .jp2 / .j2k files. This is the primary parsing target.
#   grk_compress_fuzzer   — does NOT take an image file: a FuzzStream parses the input bytes into
#                           grk_cparameters (dims, precision, comps, codec fmt, progression,
#                           resolutions, code-block size/style, irreversible, layers, tiling, MCT,
#                           HTJ2K) plus pixel data, then drives grk_compress to a memory buffer.
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN). We compile grok's core library ITSELF with $SANITIZER_FLAGS via CMake's
# CMAKE_C_FLAGS / CMAKE_CXX_FLAGS so the encoder/decoder (not just the harness) is instrumented.
#
# Only the CORE library is built (GRK_BUILD_CODEC=OFF): the fuzzers link libgrokj2k.a + libhwy.a +
# liblcms2.a and never touch the libpng/libtiff/libjpeg codec front-ends, which keeps the build lean.
#
# Build cost (rlenv re-runs this script, from a `git clean -ffdX`-ed tree, offline, inside a 450 s
# per-call window — issue #1094): the core is compiled exactly ONCE, with the graded fuzz flags, and
# every binary — both fuzzers, both standalone reproducers AND the test.sh oracle — links that same
# libgrokj2k.a. There is no second "normal flags" library build: it doubled the compile work, and an
# oracle built with different flags/macros than the graded binary is itself a hole (#1460: a patch
# gated on `__has_feature(address_sanitizer)` would clear the PoVs while test.sh stayed green).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: DWARF ≤ 3 required (§6.2 item 10) — clang-19 plain -g emits DWARF-5; be explicit.
: "${DEBUG_FLAGS=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

SRC="${SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export SRC
cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"
BUILD="$SRC/build"
# Stable pre-populated FetchContent cache for spdlog's fmtlib dep (so re-runs are offline/air-gapped).
# On first run cmake downloads fmt here; on re-runs FETCHCONTENT_SOURCE_DIR_FMT points cmake to the
# pre-downloaded source, bypassing the network fetch entirely (§6.5 air-gapped build requirement).
FMT_CACHE="${FMT_CACHE:-/mayhem/fmt-cache}"
# If the pre-populated fmt source cache exists, tell cmake to use it offline (§6.5).
FMT_CACHE_ARG=()
[ -d "$FMT_CACHE" ] && FMT_CACHE_ARG=(-DFETCHCONTENT_SOURCE_DIR_FMT="$FMT_CACHE" -DFETCHCONTENT_FULLY_DISCONNECTED=ON)

# ── 1) Build grok's CORE library WITH sanitizers (static) ──────────────────────────────────────────
# Static libs so the harnesses are self-contained; codec front-ends (png/tiff/jpeg) disabled — the
# fuzzers only need the core JPEG2000 engine + its lcms2/highway deps. SANITIZER_FLAGS instrument the
# fuzzed code. Examples/codec/tests OFF to keep the build minimal.
# Ninja (in the base image) schedules the ~130 TUs better than make; the libpng/libtiff/libjpeg (and
# the zlib they pull in) thirdparty projects are codec-only — nothing in libgrokj2k uses them — so
# skipping them only removes configure-time probing, not code from the fuzzed library.
#
# SanitizerCoverage for the LIBRARY (docs/netnew-worker-prompt.md §6 / §6d): $LIB_FUZZING_ENGINE
# only instruments the harness TU it is linked with, and $SANITIZER_FLAGS carries no coverage flags,
# so without this libgrokj2k/libhwy/liblcms2 had ZERO __sanitizer_cov counters and libFuzzer/Mayhem
# saw only the harness's own edges. Appended UNCONDITIONALLY (also when SANITIZER_FLAGS is empty).
# It adds coverage callbacks only (no change to sanitizer checks, opt level or codec behaviour), so
# the -standalone reproducers and the test.sh oracle link the very same instrumented objects
# (passing it at their link step too, so the coverage hooks resolve without the libFuzzer runtime).
COV_FLAGS="-fsanitize=fuzzer-no-link"
rm -rf "$BUILD"
mkdir -p "$BUILD"
cmake -G Ninja -S "$SRC" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DGRK_BUILD_CODEC=OFF \
  -DGRK_BUILD_JPEG=OFF -DGRK_BUILD_LIBPNG=OFF -DGRK_BUILD_LIBTIFF=OFF \
  -DGRK_BUILD_CORE_EXAMPLES=OFF \
  -DGRK_BUILD_CORE_SWIG_BINDINGS=OFF \
  -DBUILD_TESTING=OFF \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS" \
  "${FMT_CACHE_ARG[@]}"
cmake --build "$BUILD" --target grokj2k --parallel "$MAYHEM_JOBS"

# Seed the stable fmt cache from this run's download so re-runs are offline (§6.5).
# cmake downloads fmt to $BUILD/_deps/fmt-src on first run; copy it to FMT_CACHE once.
if [ ! -d "$FMT_CACHE" ] && [ -d "$BUILD/_deps/fmt-src" ]; then
  mkdir -p "$(dirname "$FMT_CACHE")"
  cp -a "$BUILD/_deps/fmt-src" "$FMT_CACHE"
  echo "cached fmt source -> $FMT_CACHE (air-gapped re-runs will use this)"
fi

# Locate the three static archives the fuzzers link against.
LIBGROK="$(find "$BUILD" -name 'libgrokj2k.a' | head -1)"
LIBHWY="$(find "$BUILD" -name 'libhwy.a' | head -1)"
LIBLCMS="$(find "$BUILD" -name 'liblcms2.a' | head -1)"
echo "core libs: $LIBGROK | $LIBHWY | $LIBLCMS"
[ -f "$LIBGROK" ] && [ -f "$LIBHWY" ] && [ -f "$LIBLCMS" ] || { echo "ERROR: missing core static libs" >&2; exit 1; }

INC="-I$SRC/src/lib/core -I$(dirname "$LIBGROK")/../src/lib/core"
# grk_config.h is generated under build/src/lib/core — find its dir robustly.
GENINC="$(dirname "$(find "$BUILD" -name 'grk_config.h' | head -1)")"
[ -n "$GENINC" ] && INC="$INC -I$GENINC"

# Standalone driver (grok ships fuzzingengine.c: a single-file run-once driver reading one input file).
# Compile it once; no libFuzzer runtime. NB: the file uses `auto` type inference yet relies on C's
# implicit void* conversions (its LLVMFuzzerTestOneInput takes void*), so it only compiles cleanly as
# C23 (auto inference + lax void* rules) — not as C++ and not as pre-C23 C.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -std=c23 -c "$HARNESS_DIR/fuzzingengine.c" -o "$BUILD/fuzzingengine.o"

# LeakSanitizer off-switch (SPEC §6.2 item 15; see mayhem/lsan_off.cc): compiled ONCE with the graded
# flags and linked into both libFuzzer targets and both -standalone reproducers. Build-time hook only —
# no ASAN_OPTIONS / *_default_options; ASan + UBSan stay fully on, only the exit-time leak check is off.
LSAN_OFF_O="$BUILD/lsan_off.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$LSAN_OFF_O"

# ── 2) Build each OSS-Fuzz harness twice: libFuzzer (-> /mayhem/<name>) + standalone reproducer ─────
# lld (in the base image) links the ~93 MB ASan binaries several times faster than GNU ld.
LINK_LIBS=(-fuse-ld=lld "$LIBGROK" "$LIBHWY" "$LIBLCMS" -lm -lpthread)
for harness in grk_decompress_fuzzer grk_compress_fuzzer; do
  # libFuzzer target -> /mayhem/<name>
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -std=c++20 $INC \
      "$HARNESS_DIR/$harness.cpp" "$LSAN_OFF_O" $LIB_FUZZING_ENGINE "${LINK_LIBS[@]}" \
      -o "/mayhem/$harness"

  # standalone reproducer (no libFuzzer runtime, reads one input file) -> /mayhem/<name>-standalone
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -std=c++20 $INC \
      "$HARNESS_DIR/$harness.cpp" "$BUILD/fuzzingengine.o" "$LSAN_OFF_O" $COV_FLAGS "${LINK_LIBS[@]}" \
      -o "/mayhem/$harness-standalone"

  echo "built $harness (+ standalone)"
done

# ── 3) The self-contained golden known-answer test (test.sh oracle) ─────────────────────────────────
# mayhem/test.sh RUNS this prebuilt binary (it never compiles). It decodes two bundled golden JPEG2000
# images and asserts their exact known dimensions/components/precision, so a no-op/exit(0) patch
# cannot pass. It is compiled with the SAME flags as the harnesses and linked against the SAME
# sanitized libgrokj2k.a as the graded fuzz binaries, so the oracle exercises exactly the code that
# is graded: no build-flavor gap a patch could hide behind (#1460), and no second library build.
TBUILD="$SRC/mayhem-tests"
rm -rf "$TBUILD"
mkdir -p "$TBUILD"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -std=c++20 $INC \
    "$HARNESS_DIR/roundtrip_test.cpp" $COV_FLAGS "${LINK_LIBS[@]}" \
    -o "$TBUILD/roundtrip_test"
echo "built round-trip golden test -> $TBUILD/roundtrip_test"

echo "build.sh complete:"
ls -la /mayhem/grk_decompress_fuzzer /mayhem/grk_compress_fuzzer \
       /mayhem/grk_decompress_fuzzer-standalone /mayhem/grk_compress_fuzzer-standalone 2>&1 || true

#!/usr/bin/env bash
#
# mayhem/build.sh — build the 7-Zip ZS fuzz harnesses (sanitized) and the 7zz test oracle (normal flags).
# Runs in the commit image as `mayhem` in /mayhem; every input is in the tree, nothing is fetched.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/build"
mkdir -p "$B/obj" "$B/oracle"

# 1) The Format7zF object set (all archive handlers + codecs, i.e. what 7z.so is made of), compiled with
#    the sanitizers and libFuzzer instrumentation but not linked; the harnesses link these objects statically.
# Benign patterns that would otherwise halt every input: unaligned word reads by design (alignment), the
# NULL-based container_of idiom in the brotli/lizard/lz4/lz5-mt list code (null, object-size) and NULL+0
# arithmetic (pointer-overflow). A real null dereference still faults and ASan reports it.
RELAX="-fno-sanitize=alignment,null,object-size,pointer-overflow,shift-base"
SAN="$SANITIZER_FLAGS $RELAX -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
( cd CPP/7zip/Bundles/Format7zF
  make -j"$MAYHEM_JOBS" -f "$SRC/mayhem/objs.mk" objs O="$B/obj" CC="$CC" CXX="$CXX" IS_X64=1 \
       FLAGS_FLTO= CFLAGS_WARN_WALL= CFLAGS_DEBUG="$SAN" LDFLAGS= )

# 2) Harnesses: libFuzzer binary and run-once standalone reproducer for each.
#    Link order fixes the static registration order, and with it the format/codec index the first
#    input byte selects, so sort the objects bytewise.
mapfile -t OBJS < <(LC_ALL=C ls "$B"/obj/*.o | LC_ALL=C sort)
CXXFLAGS_H="-DZ7_EXTERNAL_CODECS -O2 -D_REENTRANT -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -fPIC"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
for t in fuzz_archive fuzz_decoder; do
  $CXX $CXXFLAGS_H $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$SRC/mayhem/$t.cpp" \
       "$B/lsan_off.o" "${OBJS[@]}" -lpthread -ldl -o "/mayhem/$t"
  $CXX $CXXFLAGS_H $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS "$SRC/mayhem/$t.cpp" "$B/standalone_main.o" \
       "$B/lsan_off.o" "${OBJS[@]}" -lpthread -ldl -o "/mayhem/$t-standalone"
done

# 3) The oracle for mayhem/test.sh: the upstream 7zz command-line tool, normal flags, dynamically linked.
( cd CPP/7zip/Bundles/Alone2
  env -u CFLAGS -u CXXFLAGS -u LDFLAGS \
  make -j"$MAYHEM_JOBS" -f makefile.gcc O="$B/oracle" CC="$CC" CXX="$CXX" IS_X64=1 \
       FLAGS_FLTO= CFLAGS_WARN_WALL= CFLAGS_DEBUG="$COVERAGE_FLAGS" )
test -x "$B/oracle/7zz"

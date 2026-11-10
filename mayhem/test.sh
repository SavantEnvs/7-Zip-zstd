#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


Z="$SRC/mayhem/build/oracle/7zz"
if [ ! -x "$Z" ]; then
  echo "missing $Z: mayhem/build.sh did not build the oracle" >&2
  emit_ctrf "7zz-kat" 0 1 0
  exit 1
fi
FIX="$SRC/tests/regr-arc"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

passed=0 failed=0
check() { # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then passed=$((passed + 1)); else
    failed=$((failed + 1)); echo "FAIL $1: expected [$2] got [$3]" >&2
  fi
}
sha() { sha256sum | cut -d' ' -f1; }

# Known answers for the payload "abc" (FIPS 180 SHA-256 and CRC-32 check values).
printf abc > "$W/abc.txt"
ABC_SHA=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
check hash-sha256 "$ABC_SHA" "$("$Z" h -scrcSHA256 "$W/abc.txt" 2>&1 | sed -n 's/^SHA256 for data: *//p')"
check hash-crc32 352441C2 "$("$Z" h -scrcCRC32 "$W/abc.txt" 2>&1 | sed -n 's/^CRC32  for data: *//p')"

# Round trip through every writable format, then read the payload back out of the archive.
for t in 7z zip tar gzip bzip2 xz zstd lz4 brotli wim; do
  ( cd "$W" && "$Z" a -t"$t" "o.$t" abc.txt >/dev/null 2>&1 )
  check "roundtrip-$t" "$ABC_SHA" "$("$Z" x -so "$W/o.$t" 2>/dev/null | sha)"
done

# Archive metadata is read back correctly.
LIST="$("$Z" l -slt "$W/o.zip" 2>&1)"
check list-zip-path "Path = abc.txt" "$(printf '%s\n' "$LIST" | grep -m1 '^Path = abc.txt$')"
check list-zip-size "Size = 3" "$(printf '%s\n' "$LIST" | grep -m1 '^Size = 3$')"
check list-7z-method "yes" "$("$Z" l -slt "$W/o.7z" 2>&1 | grep -q '^Method = LZMA2' && echo yes || echo no)"

# Archives written by earlier 7-Zip ZS versions still decode to the recorded payload digests.
T1=aeda0f81c8376d1678af53927a08cf641cafab8b68aef509c881eb0be0bc3c97
SOL=643faef5b72e834194987ab758bc496ede829f5d509d5b88d3c889c6e1e0d415
for f in test.txt.7z test.txt.zstd test.txt.br test.txt.zstd.7z test.txt.br.7z; do
  check "regr-$f" "$T1" "$("$Z" x -so "$FIX/$f" 2>/dev/null | sha)"
done
check regr-br-mt "$T1" "$("$Z" x -so -mmt+ "$FIX/test.txt.br-mt.br" 2>/dev/null | sha)"
for f in test-sol.7z test-sol.zstd.7z; do
  check "regr-$f" "$SOL" "$("$Z" x -so "$FIX/$f" 2>/dev/null | sha)"
done
check regr-encrypted "$SOL" "$("$Z" x -so -pvery-secret-pwd "$FIX/xenc-pwd-sol.zstd.7z" 2>/dev/null | sha)"

# A damaged archive is rejected: a good archive tests clean, the same archive with a flipped byte does not.
check test-good-rc 0 "$("$Z" t "$FIX/test.txt.7z" >/dev/null 2>&1; echo $?)"
cp "$FIX/test.txt.7z" "$W/bad.7z"
printf '\xff' | dd of="$W/bad.7z" bs=1 seek=200 conv=notrunc 2>/dev/null
check test-bad-rc 2 "$("$Z" t "$W/bad.7z" >/dev/null 2>&1; echo $?)"

# Upstream's own tcltest suite. It prints a `<file>: Total N Passed P Skipped S Failed F` summary line, which
# is parsed here, so a run that never reaches the summary counts as a failure.
export Z7_PATH="$Z"
for s in main regression; do
  out="$(tclsh "$SRC/tests/$s.test" 2>&1)" || true
  line="$(printf '%s\n' "$out" | grep -E "^$s\.test:[[:space:]]+Total" | tail -1)"
  if [ -z "$line" ]; then
    failed=$((failed + 1)); echo "FAIL tcl-$s: no summary line" >&2; printf '%s\n' "$out" | tail -20 >&2
    continue
  fi
  p="$(printf '%s' "$line" | sed -E 's/.*Passed[[:space:]]+([0-9]+).*/\1/')"
  f="$(printf '%s' "$line" | sed -E 's/.*Failed[[:space:]]+([0-9]+).*/\1/')"
  echo "tcl $s: $line"
  if [ "$p" -gt 0 ] && [ "$f" -eq 0 ]; then passed=$((passed + p)); else
    failed=$((failed + 1)); printf '%s\n' "$out" | tail -30 >&2
  fi
done

emit_ctrf "7zz-kat+tcltest" "$passed" "$failed" 0

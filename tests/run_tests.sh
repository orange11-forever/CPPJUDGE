#!/usr/bin/env bash
# run_tests.sh — Automated test suite for CPPJUDGE sandbox
#
# Usage:
#   ./tests/run_tests.sh [--build-dir <dir>] [--keep-tmp]
#
# Prerequisites:
#   - simple_judge must be built (default: ./build/simple_judge)
#   - gcc available for compiling test programs
#
# Each test case: compile C source → run through simple_judge → check expected status

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BUILD_DIR="./build"
KEEP_TMP=false
TIMEOUT=30

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --keep-tmp)  KEEP_TMP=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

JUDGE="${BUILD_DIR}/simple_judge"
CMAKETEST_BINS="${BUILD_DIR}/tests/bin"
TMPDIR="$(mktemp -d)"
trap 'if ! $KEEP_TMP; then rm -rf "$TMPDIR"; fi' EXIT

# Resolve where test binaries live. If CMake pre-built them, use those;
# otherwise we compile them ourselves into $TMPDIR.
if [[ -d "$CMAKETEST_BINS" ]]; then
    BIN_DIR="$CMAKETEST_BINS"
    USE_CMAKE_BINS=true
else
    BIN_DIR="$TMPDIR"
    USE_CMAKE_BINS=false
fi

PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

green()  { echo -e "${GREEN}$*${NC}"; }
red()    { echo -e "${RED}$*${NC}"; }
yellow() { echo -e "${YELLOW}$*${NC}"; }

compile_test() {
    local name="$1"
    local src="$(dirname "$0")/${name}.c"
    local out="${BIN_DIR}/${name}"

    if ! gcc -static -o "$out" "$src" 2>"${TMPDIR}/${name}.build_err"; then
        red "  [FAIL] ${name} — gcc compile error"
        cat "${TMPDIR}/${name}.build_err" >&2
        ((FAIL++))
        return 1
    fi
    return 0
}

# run_test <test_name> <expected_status> [options...]
# The last argument is always the compiled binary path.
run_test() {
    local name="$1"
    local expected="$2"
    shift 2
    # remaining args passed to judge directly (must end with binary path)

    local output
    output=$("$JUDGE" "$@" 2>&1) || true

    if echo "$output" | grep -q "Status:.*${expected}"; then
        green "  [PASS] ${name}"
        ((PASS++))
    else
        red "  [FAIL] ${name}"
        echo "    expected status: ${expected}"
        echo "    actual output:"
        echo "$output" | sed 's/^/      /'
        ((FAIL++))
    fi
}

# ---------------------------------------------------------------------------
# sanity check
# ---------------------------------------------------------------------------

if [[ ! -x "$JUDGE" ]]; then
    red "Error: simple_judge not found at ${JUDGE}"
    red "Build first: mkdir build && cd build && cmake .. && make"
    exit 1
fi

DIR="$(cd "$(dirname "$0")" && pwd)"
echo "=== CPPJUDGE Test Suite ==="
echo "Judge : ${JUDGE}"
echo "Tmp   : ${TMPDIR}"
echo

# ---------------------------------------------------------------------------
# compile / locate test programs
# ---------------------------------------------------------------------------
echo "--- Preparing test programs ---"

TEST_NAMES=(
    ok
    nonzero_exit
    segfault
    tle
    mle
    ole
    seccomp_violation
)

if $USE_CMAKE_BINS; then
    echo "  Using CMake-built test binaries from ${BIN_DIR}/"
else
    echo "  Compiling with gcc -static into ${BIN_DIR}/"
    for name in "${TEST_NAMES[@]}"; do
        compile_test "$name" || true
    done
    for name in "${TEST_NAMES[@]}"; do
        if [[ ! -x "${BIN_DIR}/${name}" ]]; then
            red "  [FAIL] ${name} binary missing"
            ((FAIL++))
        fi
    done
fi

echo

# ---------------------------------------------------------------------------
# run tests
# ---------------------------------------------------------------------------

echo "--- Running tests ---"

# 1. Normal execution
run_test "Normal exit 0"  "OK" \
    --time-limit 1000 --memory-limit 262144 \
    "${BIN_DIR}/ok"

# 2. Non-zero exit code
run_test "Non-zero exit"   "NONZERO_EXIT" \
    --time-limit 1000 --memory-limit 262144 \
    "${BIN_DIR}/nonzero_exit"

# 3. Segfault → SIGNALED (signal 11)
run_test "Segfault (SIGSEGV)" "SIGNALED" \
    --time-limit 1000 --memory-limit 262144 \
    "${BIN_DIR}/segfault"

# 4. Time limit exceeded
run_test "TLE (infinite loop)" "TIME_LIMIT_EXCEEDED" \
    --time-limit 500 --wall-time 1500 --memory-limit 262144 \
    "${BIN_DIR}/tle"

# 5. Memory limit exceeded
run_test "MLE (128MB alloc, 32MB limit)" "MEMORY_LIMIT_EXCEEDED" \
    --time-limit 2000 --wall-time 5000 --memory-limit 32768 \
    "${BIN_DIR}/mle"

# 6. Output limit exceeded
run_test "OLE (large output)" "OUTPUT_LIMIT_EXCEEDED" \
    --time-limit 2000 --wall-time 5000 --memory-limit 262144 \
    --output-limit 1024 \
    "${BIN_DIR}/ole"

# 7. Seccomp violation → SENTALED (signal 31 = SIGSYS)
run_test "Seccomp (socket call)" "SIGNALED" \
    --time-limit 1000 --memory-limit 262144 \
    "${BIN_DIR}/seccomp_violation"

# 8. Wall time exceeded (use very tight wall-time on normal program)
run_test "Wall-time exceeded" "WALL_TIME_EXCEEDED" \
    --time-limit 5000 --wall-time 100 --memory-limit 262144 \
    --no-seccomp \
    "${BIN_DIR}/ok"

echo
echo "========================================="
if [[ $FAIL -eq 0 ]]; then
    green "  All ${PASS} tests passed."
else
    yellow "  ${PASS} passed, ${FAIL} failed."
fi
echo "========================================="

exit $FAIL

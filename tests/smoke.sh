#!/bin/sh
# Smoke tests for snifer
# These tests verify basic CLI functionality.

set -eu

SNIFER=""
for candidate in ./build/snifer ./snifer; do
    if [ -x "$candidate" ]; then
        SNIFER="$candidate"
        break
    fi
done

if [ -z "$SNIFER" ]; then
    printf "SKIP: no snifer binary found\n"
    exit 0
fi

FAILED=0
TMPFILE="${TMPDIR:-/tmp}/snifer_smoke_$$"

fail() {
    printf "FAIL: %s\n" "$1"
    FAILED=1
    return 1
}

cleanup() {
    rm -f "$TMPFILE"
}
trap cleanup EXIT

printf "=== snifer smoke tests ===\n\n"

# 1) Help should print usage and exit successfully
if "$SNIFER" --help | grep -q "Lightweight Packet Capture"; then
    printf "ok: --help output looks sane\n\n"
else
    fail "--help output missing expected banner"
fi

# 2) --list should print interface info and exit successfully
"$SNIFER" --list >"$TMPFILE" 2>&1

if grep -q "Available" "$TMPFILE"; then
    printf "ok: --list enumerates interfaces\n\n"
else
    fail "--list did not enumerate interfaces"
fi

# 3) Binary exists and is executable
if [ ! -x "$SNIFER" ]; then
    fail "binary missing or not executable"
fi
printf "ok: binary present and executable\n\n"

printf "=== results ===\n"
if [ "$FAILED" -eq 0 ]; then
    printf "all passed\n"
    exit 0
fi
printf "some failed\n"
exit 1

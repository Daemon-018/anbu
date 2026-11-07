#!/usr/bin/env bash
#
# Compile ScoreMath with a plain JDK (no Android SDK, no JUnit) and check it
# against vectors generated from src/anbu/score.py.
#
# Regenerate the vectors after changing the Python formula:
#   python android-app/test/generate_vectors.py

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$HERE/build"

command -v javac >/dev/null 2>&1 || { echo "error: javac not found on PATH" >&2; exit 1; }
command -v java >/dev/null 2>&1 || { echo "error: java not found on PATH" >&2; exit 1; }

rm -rf "$BUILD"
mkdir -p "$BUILD"

javac --release 8 -Xlint:-options \
    -d "$BUILD" \
    "$HERE/../src/com/anbu/scanner/ScoreMath.java" \
    "$HERE/ScoreMathTest.java"

java -cp "$BUILD" com.anbu.scanner.ScoreMathTest "$HERE"

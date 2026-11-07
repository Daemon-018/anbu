#!/usr/bin/env bash
#
# Build the ANBU on-device scanner without Gradle.
#
# Requires a JDK, and an Android SDK layout providing:
#   $ANDROID_JAR      platform android.jar (API 34 or newer)
#   $D8_JAR           build-tools lib/d8.jar
#   aapt2, zipalign, apksigner, keytool on PATH
#
# Override the paths with environment variables if yours differ.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK="${ANDROID_SDK:-/tmp/opencode/android-sdk}"
ANDROID_JAR="${ANDROID_JAR:-$SDK/android-34-ext12/android.jar}"
D8_JAR="${D8_JAR:-$SDK/android-14/lib/d8.jar}"

BUILD="$HERE/build"
OUT="$HERE/out"
KEYSTORE="${ANBU_KEYSTORE:-$HERE/keystore/anbu-debug.jks}"
KS_PASS="${ANBU_KEYSTORE_PASS:-android}"
KEY_ALIAS="${ANBU_KEY_ALIAS:-anbu}"
APK_NAME="${APK_NAME:-anbu-scanner.apk}"

MIN_SDK=24
TARGET_SDK=34
VERSION_CODE=1
VERSION_NAME=1.0

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: '$1' not found on PATH" >&2
        exit 1
    }
}

for tool in aapt2 zipalign apksigner keytool javac java python3; do need "$tool"; done
[ -f "$ANDROID_JAR" ] || { echo "error: android.jar not found: $ANDROID_JAR" >&2; exit 1; }
[ -f "$D8_JAR" ] || { echo "error: d8.jar not found: $D8_JAR" >&2; exit 1; }

echo "==> cleaning"
rm -rf "$BUILD"
mkdir -p "$BUILD/classes" "$BUILD/dex" "$OUT"

if [ "${SKIP_TESTS:-0}" != "1" ]; then
    echo "==> score parity"
    "$HERE/test/run.sh"
fi

echo "==> resources"
aapt2 compile --dir "$HERE/res" -o "$BUILD/res.zip"
aapt2 link \
    -o "$BUILD/base.apk" \
    -I "$ANDROID_JAR" \
    --manifest "$HERE/AndroidManifest.xml" \
    "$BUILD/res.zip" \
    --min-sdk-version "$MIN_SDK" \
    --target-sdk-version "$TARGET_SDK" \
    --version-code "$VERSION_CODE" \
    --version-name "$VERSION_NAME" \
    --auto-add-overlay

echo "==> java"
SOURCES=()
while IFS= read -r file; do SOURCES+=("$file"); done < <(find "$HERE/src" -name '*.java' | sort)
javac \
    --release 8 \
    -Xlint:-options -Xlint:-deprecation \
    -classpath "$ANDROID_JAR" \
    -d "$BUILD/classes" \
    "${SOURCES[@]}"

echo "==> dex"
java -cp "$D8_JAR" com.android.tools.r8.D8 \
    --min-api "$MIN_SDK" \
    --lib "$ANDROID_JAR" \
    --output "$BUILD/dex" \
    $(find "$BUILD/classes" -name '*.class' | sort)

echo "==> package"
cp "$BUILD/base.apk" "$BUILD/unaligned.apk"
python3 - "$BUILD/unaligned.apk" "$BUILD/dex/classes.dex" <<'PY'
import sys
import zipfile

apk, dex = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(apk, "a", zipfile.ZIP_DEFLATED) as archive:
    archive.write(dex, "classes.dex")
PY
zipalign -f -p 4 "$BUILD/unaligned.apk" "$BUILD/aligned.apk"

echo "==> sign"
if [ ! -f "$KEYSTORE" ]; then
    mkdir -p "$(dirname "$KEYSTORE")"
    keytool -genkeypair \
        -keystore "$KEYSTORE" \
        -storepass "$KS_PASS" \
        -keypass "$KS_PASS" \
        -alias "$KEY_ALIAS" \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=ANBU Debug,O=ANBU,C=US" >/dev/null 2>&1
    echo "    created debug keystore: $KEYSTORE"
fi
apksigner sign \
    --ks "$KEYSTORE" \
    --ks-pass "pass:$KS_PASS" \
    --key-pass "pass:$KS_PASS" \
    --ks-key-alias "$KEY_ALIAS" \
    --min-sdk-version "$MIN_SDK" \
    --out "$OUT/$APK_NAME" \
    "$BUILD/aligned.apk"

apksigner verify --min-sdk-version "$MIN_SDK" --print-certs "$OUT/$APK_NAME" >/dev/null

echo
echo "APK:  $OUT/$APK_NAME"
echo "size: $(stat -c %s "$OUT/$APK_NAME") bytes"
echo "sha256: $(sha256sum "$OUT/$APK_NAME" | cut -d' ' -f1)"

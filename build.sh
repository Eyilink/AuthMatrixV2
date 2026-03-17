#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  Build script for AuthMatrix (Montoya API)
#  Requirements: JDK 11+  and  montoya-api.jar
#
#  Get montoya-api.jar:
#  https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/
# ─────────────────────────────────────────────────────────────────

set -e

MONTOYA_JAR="montoya-api.jar"
SRC="src/authmatrix/AuthMatrix.java"
BUILD_DIR="build"
JAR_NAME="AuthMatrix.jar"

echo "=== AuthMatrix Builder (Montoya API) ==="

if [ ! -f "$MONTOYA_JAR" ]; then
  echo ""
  echo "  montoya-api.jar not found."
  echo "  Download: https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/"
  echo "  Place as 'montoya-api.jar' next to this script, then re-run."
  exit 1
fi

mkdir -p "$BUILD_DIR"
echo "[1/2] Compiling..."
javac -cp "$MONTOYA_JAR" -d "$BUILD_DIR" "$SRC"

echo "[2/2] Packaging..."
jar cf "$JAR_NAME" -C "$BUILD_DIR" .

echo ""
echo "  Done -> $JAR_NAME"
echo "  Burp Suite: Extensions -> Add -> Java -> $JAR_NAME"

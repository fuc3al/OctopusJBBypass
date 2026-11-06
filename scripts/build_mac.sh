#!/bin/bash
# build_mac.sh — 把一个 tweak 源码编译成 arm64 + arm64e 的 universal dylib。
#
#   ./scripts/build_mac.sh src/PromonKiller.m libPromonKiller
#   ./scripts/build_mac.sh src/SymbolRebind.m libSymRebind "-DDEBUG=1"
#
# 产物：build/<name>.dylib（ad-hoc 签名，install_name 指向 @executable_path/Frameworks）
# 依赖：Xcode 命令行工具（xcrun / clang / lipo / codesign）
set -euo pipefail

SRC="${1:?usage: build_mac.sh <source.m> <output-name> [extra-cflags]}"
NAME="${2:?missing output name}"
EXTRA="${3:-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build"
mkdir -p "$OUT"

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
MIN_IOS="${MIN_IOS:-15.0}"

echo "== env =="
echo "  SDK     : $SDK ($(xcrun --sdk iphoneos --show-sdk-version))"
echo "  clang   : $(xcrun -sdk iphoneos clang --version | head -1)"
echo "  target  : iOS >= $MIN_IOS"

SLICES=()
for ARCH in arm64 arm64e; do
  echo "== compile $ARCH =="
  xcrun -sdk iphoneos clang -arch "$ARCH" -dynamiclib -isysroot "$SDK" \
        -fobjc-arc -O2 -miphoneos-version-min="$MIN_IOS" \
        -install_name "@executable_path/Frameworks/${NAME}.dylib" \
        -framework Foundation -framework UIKit -framework Security \
        $EXTRA \
        -o "$OUT/${NAME}.${ARCH}.dylib" "$SRC"
  SLICES+=("$OUT/${NAME}.${ARCH}.dylib")
done

echo "== lipo =="
lipo -create -output "$OUT/${NAME}.dylib" "${SLICES[@]}"
rm -f "${SLICES[@]}"

echo "== sign (ad-hoc) =="
codesign --force --sign - "$OUT/${NAME}.dylib" 2>/dev/null || true

echo
echo "== result =="
lipo -archs "$OUT/${NAME}.dylib"
stat -f "  size: %z bytes" "$OUT/${NAME}.dylib"
otool -L "$OUT/${NAME}.dylib" | sed 's/^/  /'
echo "OK -> $OUT/${NAME}.dylib"

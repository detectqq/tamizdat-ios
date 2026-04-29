#!/usr/bin/env bash
#
# Build HevSocks5Tunnel.xcframework for iOS (device only — we don't need
# simulator, macOS, or tvOS for this project; trimming saves ~3 minutes
# of CI time per build vs. the upstream build-apple.sh).
#
# Output: <repo-root>/Frameworks/HevSocks5Tunnel.xcframework
#
# Inputs (env): HEV_REF defaults to a pinned tag; override at the
# workflow level if we want to track a different revision.

set -euo pipefail

HEV_REF="${HEV_REF:-2.14.4}"
HEV_REPO="https://github.com/heiher/hev-socks5-tunnel.git"
WORK_DIR="${WORK_DIR:-$(pwd)/build/hev-build}"
OUT_DIR="${OUT_DIR:-$(pwd)/Frameworks}"
LIB_NAME="HevSocks5Tunnel"

mkdir -p "$WORK_DIR" "$OUT_DIR"

# Clone (or reuse) at the pinned ref.
if [ ! -d "$WORK_DIR/hev-socks5-tunnel/.git" ]; then
  rm -rf "$WORK_DIR/hev-socks5-tunnel"
  git clone --depth 1 --branch "$HEV_REF" --recurse-submodules "$HEV_REPO" "$WORK_DIR/hev-socks5-tunnel"
fi

cd "$WORK_DIR/hev-socks5-tunnel"
git submodule update --init --recursive --depth 1

# Build a static lib for iOS device (arm64 only).
make clean || true
make PP="xcrun --sdk iphoneos --toolchain iphoneos clang" \
     CC="xcrun --sdk iphoneos --toolchain iphoneos clang" \
     CFLAGS="-arch arm64 -mios-version-min=17.0" \
     LFLAGS="-arch arm64 -mios-version-min=17.0 -Wl,-Bsymbolic-functions" \
     static

ARCH_DIR="$WORK_DIR/iphoneos-arm64"
mkdir -p "$ARCH_DIR"
ARCH_LIB="$ARCH_DIR/libhev-socks5-tunnel.a"

# Merge the four static archives that make up the runtime.
libtool -static -o "$ARCH_LIB" \
        bin/libhev-socks5-tunnel.a \
        third-part/lwip/bin/liblwip.a \
        third-part/yaml/bin/libyaml.a \
        third-part/hev-task-system/bin/libhev-task-system.a

# Headers + module map for the xcframework.
INCLUDE_DIR="$WORK_DIR/include"
mkdir -p "$INCLUDE_DIR/$LIB_NAME"
cp ./src/hev-main.h "$INCLUDE_DIR/$LIB_NAME/"
cp ./module.modulemap "$INCLUDE_DIR/$LIB_NAME/"

# Wrap into an xcframework.
rm -rf "$OUT_DIR/$LIB_NAME.xcframework"
xcodebuild -create-xcframework \
  -library "$ARCH_LIB" -headers "$INCLUDE_DIR" \
  -output "$OUT_DIR/$LIB_NAME.xcframework"

echo
echo "OK — wrote $OUT_DIR/$LIB_NAME.xcframework"
ls -la "$OUT_DIR/$LIB_NAME.xcframework"

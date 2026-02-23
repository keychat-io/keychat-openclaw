#!/bin/bash
# Build release binaries for all supported platforms.
# Requires: cargo, cargo-zigbuild, zig
# Linux targets use musl for static linking (no glibc dependency).
#
# Usage: ./scripts/build-release.sh [--upload v0.1.x]
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BRIDGE_DIR="$SCRIPT_DIR/../bridge"
OUT_DIR="$SCRIPT_DIR/../dist"
REPO="keychat-io/keychat-openclaw"

cd "$BRIDGE_DIR"

echo "🔨 Building release binaries..."
echo ""

mkdir -p "$OUT_DIR"

# ── Darwin ARM64 (native) ──
echo "  [1/4] darwin-arm64..."
cargo build --release 2>&1 | grep -v "^warning:" || true
cp target/release/keychat-openclaw "$OUT_DIR/keychat-openclaw-darwin-arm64"
echo "  ✅ darwin-arm64"

# ── Darwin x64 (cross) ──
echo "  [2/4] darwin-x64..."
if cargo zigbuild --target x86_64-apple-darwin --release 2>&1 | grep -v "^warning:" | tail -1; then
  cp target/x86_64-apple-darwin/release/keychat-openclaw "$OUT_DIR/keychat-openclaw-darwin-x64"
  echo "  ✅ darwin-x64"
else
  echo "  ⚠️  darwin-x64 failed (optional — most Macs are ARM now)"
fi

# ── Linux x64 (musl static) ──
echo "  [3/4] linux-x64 (musl)..."
cargo zigbuild --target x86_64-unknown-linux-musl --release 2>&1 | grep -v "^warning:" || true
cp target/x86_64-unknown-linux-musl/release/keychat-openclaw "$OUT_DIR/keychat-openclaw-linux-x64"
echo "  ✅ linux-x64 (statically linked)"

# ── Linux ARM64 (musl static) ──
echo "  [4/4] linux-arm64 (musl)..."
cargo zigbuild --target aarch64-unknown-linux-musl --release 2>&1 | grep -v "^warning:" || true
cp target/aarch64-unknown-linux-musl/release/keychat-openclaw "$OUT_DIR/keychat-openclaw-linux-arm64"
echo "  ✅ linux-arm64 (statically linked)"

echo ""
echo "════════════════════════════════════════"
echo "  📦 All binaries in: $OUT_DIR"
ls -lh "$OUT_DIR"/keychat-openclaw-*
echo "════════════════════════════════════════"

# ── Optional: upload to GitHub Release ──
if [ "$1" = "--upload" ] && [ -n "$2" ]; then
  TAG="$2"
  echo ""
  echo "🚀 Uploading to GitHub Release $TAG..."
  
  if ! command -v gh &>/dev/null; then
    echo "❌ gh CLI not found. Install: brew install gh"
    exit 1
  fi

  # Create release if not exists
  gh release view "$TAG" --repo "$REPO" &>/dev/null || \
    gh release create "$TAG" --repo "$REPO" --title "$TAG" --notes "Release $TAG"

  # Upload/overwrite artifacts
  for f in "$OUT_DIR"/keychat-openclaw-*; do
    echo "  Uploading $(basename "$f")..."
    gh release upload "$TAG" "$f" --repo "$REPO" --clobber
  done

  echo "  ✅ All artifacts uploaded to $TAG"
fi

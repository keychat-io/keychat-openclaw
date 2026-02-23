#!/usr/bin/env bash
# Keychat OpenClaw plugin setup
# Downloads the bridge binary and initializes config.
# Run after: openclaw plugins install @keychat-io/keychat-openclaw
set -euo pipefail

# --- Locate plugin directory ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$(dirname "$SCRIPT_DIR")"

# Also check common install locations
if [ ! -f "$PLUGIN_DIR/package.json" ]; then
  for d in \
    "$HOME/.openclaw/extensions/keychat-openclaw" \
    "$HOME/.openclaw/plugins/@keychat-io/keychat-openclaw"; do
    if [ -f "$d/package.json" ]; then
      PLUGIN_DIR="$d"
      break
    fi
  done
fi

BINARY_DIR="$PLUGIN_DIR/bridge/target/release"
BINARY_PATH="$BINARY_DIR/keychat-openclaw"

# --- Download binary ---
if [ -f "$BINARY_PATH" ]; then
  echo "[keychat] ✅ Binary already exists: $BINARY_PATH"
else
  REPO="keychat-io/keychat-openclaw"
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"

  case "$OS-$ARCH" in
    darwin-arm64)  ARTIFACT="keychat-openclaw-darwin-arm64" ;;
    darwin-x86_64) ARTIFACT="keychat-openclaw-darwin-x64" ;;
    linux-x86_64)  ARTIFACT="keychat-openclaw-linux-x64" ;;
    linux-aarch64) ARTIFACT="keychat-openclaw-linux-arm64" ;;
    *)
      echo "[keychat] ❌ No pre-compiled binary for $OS-$ARCH"
      echo "[keychat] Build from source: cd $PLUGIN_DIR/bridge && cargo build --release"
      exit 1
      ;;
  esac

  URL="https://github.com/$REPO/releases/latest/download/$ARTIFACT"
  echo "[keychat] Downloading $ARTIFACT..."
  mkdir -p "$BINARY_DIR"
  curl -fsSL -o "$BINARY_PATH" "$URL"
  chmod +x "$BINARY_PATH"
  echo "[keychat] ✅ Binary installed: $BINARY_PATH"
fi

# --- Initialize config ---
CONFIG_PATH="$HOME/.openclaw/openclaw.json"

if [ ! -f "$CONFIG_PATH" ]; then
  echo '{}' > "$CONFIG_PATH"
fi

# Check if channels.keychat already exists
if node -e "
  const c = JSON.parse(require('fs').readFileSync('$CONFIG_PATH','utf-8'));
  process.exit(c.channels?.keychat ? 0 : 1);
" 2>/dev/null; then
  echo "[keychat] ✅ Config already has channels.keychat"
else
  node -e "
    const fs = require('fs');
    const c = JSON.parse(fs.readFileSync('$CONFIG_PATH','utf-8'));
    if (!c.channels) c.channels = {};
    c.channels.keychat = { enabled: true, dmPolicy: 'open' };
    fs.writeFileSync('$CONFIG_PATH', JSON.stringify(c, null, 2) + '\n');
  "
  echo "[keychat] ✅ Config initialized (channels.keychat.enabled = true, dmPolicy = open)"
fi

echo ""
echo "[keychat] Setup complete! Restart gateway to activate:"
echo "  openclaw gateway install && openclaw gateway start"

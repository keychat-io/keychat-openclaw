#!/bin/bash
# Keychat — one-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-openclaw/main/scripts/install.sh | bash
set -e

REPO="keychat-io/keychat-openclaw"
INSTALL_DIR="${OPENCLAW_EXTENSIONS:-$HOME/.openclaw/extensions}/keychat"
BINARY="$INSTALL_DIR/bridge/target/release/keychat-openclaw"

echo "🔑 Installing Keychat"
echo ""

# ── Check OpenClaw ──
if ! command -v openclaw &>/dev/null; then
  echo "❌ OpenClaw not found. Install it first: https://docs.openclaw.ai"
  exit 1
fi

# ── Detect platform ──
detect_artifact() {
  local arch=$(uname -m)
  local os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os-$arch" in
    darwin-arm64)  echo "keychat-openclaw-darwin-arm64" ;;
    darwin-x86_64) echo "keychat-openclaw-darwin-x64" ;;
    linux-x86_64)  echo "keychat-openclaw-linux-x64" ;;
    linux-aarch64) echo "keychat-openclaw-linux-arm64" ;;
    *) echo "" ;;
  esac
}

# ── Clone or update repo ──
if [ -d "$INSTALL_DIR/.git" ]; then
  echo "📦 Updating existing installation..."
  cd "$INSTALL_DIR"
  git pull --ff-only 2>/dev/null || true
else
  echo "📦 Downloading Keychat..."
  mkdir -p "$(dirname "$INSTALL_DIR")"
  git clone --depth 1 "https://github.com/$REPO.git" "$INSTALL_DIR" 2>/dev/null
  cd "$INSTALL_DIR"
fi

# ── Install npm dependencies ──
npm install --omit=dev --silent 2>/dev/null || true

# ── Get binary ──
if [ -f "$BINARY" ]; then
  echo "✅ Bridge binary already exists"
else
  ARTIFACT=$(detect_artifact)
  DOWNLOADED=false

  if [ -n "$ARTIFACT" ]; then
    echo "📦 Downloading pre-compiled binary ($ARTIFACT)..."
    URL="https://github.com/$REPO/releases/latest/download/$ARTIFACT"
    mkdir -p "$(dirname "$BINARY")"
    if curl -fSL "$URL" -o "$BINARY" 2>/dev/null; then
      chmod +x "$BINARY"
      echo "✅ Binary downloaded"
      DOWNLOADED=true
    fi
  fi

  if [ "$DOWNLOADED" = false ]; then
    if command -v cargo &>/dev/null; then
      echo "🔨 Building from source (this may take a few minutes)..."
      cd "$INSTALL_DIR/bridge"
      cargo build --release 2>&1 | tail -3
      cd "$INSTALL_DIR"
      if [ ! -f "$BINARY" ]; then
        echo "❌ Build failed"
        exit 1
      fi
      echo "✅ Built from source"
    else
      echo "❌ No pre-compiled binary for your platform and Rust not installed."
      echo "   Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
      exit 1
    fi
  fi
fi

# ── Register plugin ──
echo ""
echo "📦 Registering plugin..."
openclaw plugins install "$INSTALL_DIR" 2>&1 || true

# ── Auto-configure ──
CONFIG_FILE="$HOME/.openclaw/openclaw.json"
if [ -f "$CONFIG_FILE" ]; then
  if grep -q '"keychat"' "$CONFIG_FILE" 2>/dev/null; then
    echo "ℹ️  Keychat already in config"
  else
    # Insert keychat into channels object
    if command -v python3 &>/dev/null; then
      python3 -c "
import json, sys
try:
    with open('$CONFIG_FILE', 'r') as f:
        cfg = json.load(f)
    if 'channels' not in cfg:
        cfg['channels'] = {}
    cfg['channels']['keychat'] = {'enabled': True}
    with open('$CONFIG_FILE', 'w') as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    print('✅ Keychat enabled in config')
except Exception as e:
    print(f'⚠️  Could not auto-configure: {e}')
    print('   Add manually: \"keychat\": {{\"enabled\": true}} under channels')
"
    elif command -v node &>/dev/null; then
      node -e "
const fs = require('fs');
try {
  const cfg = JSON.parse(fs.readFileSync('$CONFIG_FILE', 'utf8'));
  if (!cfg.channels) cfg.channels = {};
  cfg.channels.keychat = { enabled: true };
  fs.writeFileSync('$CONFIG_FILE', JSON.stringify(cfg, null, 2));
  console.log('✅ Keychat enabled in config');
} catch(e) {
  console.log('⚠️  Could not auto-configure:', e.message);
  console.log('   Add manually: \"keychat\": {\"enabled\": true} under channels');
}
"
    else
      echo "⚠️  Add to $CONFIG_FILE under \"channels\":"
      echo '     "keychat": { "enabled": true }'
    fi
  fi
else
  echo "⚠️  Config not found at $CONFIG_FILE"
  echo "   Run 'openclaw init' first, then re-run this installer"
fi

# ── Restart gateway ──
echo ""
echo "🔄 Restarting gateway..."
openclaw gateway restart 2>&1 || true

# ── Done ──
echo ""
echo "🎉 Keychat installed!"
echo ""
echo "Your agent's Keychat ID will appear in the gateway logs."
echo "Run 'openclaw status' to see it."
echo ""
echo "To connect: open the Keychat app and scan the QR code at"
echo "  ~/.openclaw/keychat-qr.png"
echo ""
echo "Docs: https://github.com/$REPO"

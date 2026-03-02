#!/bin/bash
# Keychat — one-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-openclaw/main/scripts/install.sh | bash
set -e

REPO="keychat-io/keychat-openclaw"
INSTALL_DIR="${OPENCLAW_EXTENSIONS:-$HOME/.openclaw/extensions}/keychat"

# Platform-suffixed binary name
detect_binary_suffix() {
  local arch=$(uname -m)
  local os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os-$arch" in
    darwin-arm64)  echo "darwin-arm64" ;;
    darwin-x86_64) echo "darwin-x64" ;;
    linux-x86_64)  echo "linux-x64" ;;
    linux-aarch64) echo "linux-arm64" ;;
    *) echo "" ;;
  esac
}
SUFFIX=$(detect_binary_suffix)
BINARY="$INSTALL_DIR/keychat-bridge-${SUFFIX}"

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

# ── Spinner helper ──
spinner() {
  local pid=$1
  local msg=$2
  local chars='⣾⣽⣻⢿⡿⣟⣯⣷'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  %s %s" "${chars:i++%${#chars}:1}" "$msg"
    sleep 0.1
  done
  printf "\r"
}

# ── Clone or update repo ──
if [ -d "$INSTALL_DIR/.git" ]; then
  echo "📦 Updating existing installation..."
  cd "$INSTALL_DIR"
  git pull --ff-only 2>/dev/null || true
else
  echo "📦 Downloading Keychat source..."
  mkdir -p "$(dirname "$INSTALL_DIR")"
  git clone --depth 1 "https://github.com/$REPO.git" "$INSTALL_DIR" 2>/dev/null &
  CLONE_PID=$!
  spinner $CLONE_PID "Cloning repository..."
  wait $CLONE_PID
  echo "  ✅ Source downloaded"
  cd "$INSTALL_DIR"
fi

# ── Install npm dependencies ──
echo "📦 Installing dependencies..."
npm install --omit=dev --silent 2>/dev/null &
NPM_PID=$!
spinner $NPM_PID "Installing npm packages (this may take a moment)..."
wait $NPM_PID || true
echo "  ✅ Dependencies installed"

# ── Clean up old binary paths ──
rm -f "$INSTALL_DIR/keychat-bridge" 2>/dev/null
rm -f "$INSTALL_DIR/bridge/target/release/keychat-openclaw" 2>/dev/null

# ── Get binary ──
if [ -f "$BINARY" ]; then
  echo "✅ Bridge binary already exists"
else
  ARTIFACT=$(detect_artifact)
  DOWNLOADED=false

  if [ -n "$ARTIFACT" ]; then
    echo "📦 Downloading bridge binary ($ARTIFACT)..."
    echo "   ⏳ This may take 30-60 seconds depending on your connection..."
    URL="https://github.com/$REPO/releases/latest/download/$ARTIFACT"
    if curl -fSL --progress-bar "$URL" -o "$BINARY" 2>&1; then
      chmod +x "$BINARY"
      echo "  ✅ Binary downloaded"
      DOWNLOADED=true
    else
      echo "  ⚠️  Download failed, will try building from source..."
    fi
  fi

  if [ "$DOWNLOADED" = false ]; then
    if command -v cargo &>/dev/null; then
      echo "🔨 Building from source..."
      echo "   ⏳ This takes 3-5 minutes on most machines. Please wait..."
      cd "$INSTALL_DIR/bridge"
      cargo build --release 2>&1 &
      BUILD_PID=$!
      spinner $BUILD_PID "Compiling Rust code (be patient)..."
      wait $BUILD_PID
      cd "$INSTALL_DIR"
      # Copy built binary to platform-suffixed name
      BUILT="$INSTALL_DIR/bridge/target/release/keychat-openclaw"
      if [ -f "$BUILT" ]; then
        cp "$BUILT" "$BINARY"
        chmod +x "$BINARY"
        echo "  ✅ Built from source"
      else
        echo "  ❌ Build failed"
        exit 1
      fi
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
    print('  ✅ Keychat enabled in config')
except Exception as e:
    print(f'  ⚠️  Could not auto-configure: {e}')
    print('     Add manually: \"keychat\": {{\"enabled\": true}} under channels')
"
    elif command -v node &>/dev/null; then
      node -e "
const fs = require('fs');
try {
  const cfg = JSON.parse(fs.readFileSync('$CONFIG_FILE', 'utf8'));
  if (!cfg.channels) cfg.channels = {};
  cfg.channels.keychat = { enabled: true };
  fs.writeFileSync('$CONFIG_FILE', JSON.stringify(cfg, null, 2));
  console.log('  ✅ Keychat enabled in config');
} catch(e) {
  console.log('  ⚠️  Could not auto-configure:', e.message);
  console.log('     Add manually: \"keychat\": {\"enabled\": true} under channels');
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
echo "════════════════════════════════════════"
echo "  🎉 Keychat installed successfully!"
echo "════════════════════════════════════════"
echo ""
echo "Your agent's Keychat ID will appear in the gateway logs."
echo "Run 'openclaw logs --follow' to see it."
echo ""
echo "To connect: open the Keychat app and scan the QR code."
echo ""
echo "Docs: https://github.com/$REPO"

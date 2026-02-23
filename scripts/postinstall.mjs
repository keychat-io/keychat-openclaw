#!/usr/bin/env node
/**
 * postinstall — download pre-compiled keychat-signal-mls-bridge binary.
 * Runs automatically after `npm install` / `openclaw plugins install`.
 */
import { existsSync, mkdirSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = "keychat-io/keychat-signal-mls-bridge";
const BINARY_DIR = join(__dirname, "..", "bridge", "target", "release");
const BINARY_PATH = join(BINARY_DIR, "keychat-signal-mls-bridge");

if (existsSync(BINARY_PATH)) {
  console.log("[keychat] Binary already exists, skipping download");
  process.exit(0);
}

const platform = process.platform; // darwin, linux
const arch = process.arch; // arm64, x64

const ARTIFACTS = {
  "darwin-arm64": "keychat-signal-mls-bridge-darwin-arm64",
  "darwin-x64": "keychat-signal-mls-bridge-darwin-x64",
  "linux-x64": "keychat-signal-mls-bridge-linux-x64",
  "linux-arm64": "keychat-signal-mls-bridge-linux-arm64",
};

const artifact = ARTIFACTS[`${platform}-${arch}`];
if (!artifact) {
  console.warn(`[keychat] No pre-compiled binary for ${platform}-${arch}`);
  console.warn("[keychat] Build from source: cd bridge && cargo build --release");
  process.exit(0); // Don't fail install
}

const url = `https://github.com/${REPO}/releases/latest/download/${artifact}`;
console.log(`[keychat] Downloading ${artifact}...`);

try {
  mkdirSync(BINARY_DIR, { recursive: true });
  execSync(`curl -fSL "${url}" -o "${BINARY_PATH}"`, { stdio: "pipe" });
  chmodSync(BINARY_PATH, 0o755);
  console.log("[keychat] ✅ Binary installed");
} catch (err) {
  console.warn(`[keychat] Download failed: ${err.message}`);
  console.warn("[keychat] Build from source: cd bridge && cargo build --release");
  // Don't fail install — user can build manually
}

// Auto-initialize config if not set
try {
  const result = execSync("openclaw config get channels.keychat", {
    stdio: "pipe",
    encoding: "utf-8",
  }).trim();
  if (result && result !== "undefined" && result !== "null") {
    console.log("[keychat] Config already exists, skipping init");
  } else {
    throw new Error("no config");
  }
} catch {
  console.log("[keychat] Initializing default config...");
  try {
    execSync('openclaw config set channels.keychat.enabled true', { stdio: "pipe" });
    console.log("[keychat] ✅ Config initialized (channels.keychat.enabled = true)");
    console.log("[keychat] Restart gateway to activate: openclaw gateway restart");
  } catch (e) {
    console.warn(`[keychat] Could not auto-configure: ${e.message}`);
    console.warn('[keychat] Run manually: openclaw config set channels.keychat.enabled true');
  }
}

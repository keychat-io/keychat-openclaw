#!/usr/bin/env node
/**
 * postinstall — download pre-compiled keychat-openclaw binary.
 * Runs automatically after `npm install` / `openclaw plugins install`.
 * Uses native fetch/https — no child_process dependency.
 */
import { existsSync, mkdirSync, chmodSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import https from "node:https";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = "keychat-io/keychat-openclaw";
const BINARY_DIR = join(__dirname, "..", "bridge", "target", "release");
const BINARY_PATH = join(BINARY_DIR, "keychat-openclaw");

if (existsSync(BINARY_PATH)) {
  console.log("[keychat] Binary already exists, skipping download");
  process.exit(0);
}

const platform = process.platform; // darwin, linux
const arch = process.arch; // arm64, x64

const ARTIFACTS = {
  "darwin-arm64": "keychat-openclaw-darwin-arm64",
  "darwin-x64": "keychat-openclaw-darwin-x64",
  "linux-x64": "keychat-openclaw-linux-x64",
  "linux-arm64": "keychat-openclaw-linux-arm64",
};

const artifact = ARTIFACTS[`${platform}-${arch}`];
if (!artifact) {
  console.warn(`[keychat] No pre-compiled binary for ${platform}-${arch}`);
  console.warn("[keychat] Build from source: cd bridge && cargo build --release");
  process.exit(0); // Don't fail install
}

const url = `https://github.com/${REPO}/releases/latest/download/${artifact}`;
console.log(`[keychat] Downloading ${artifact}...`);

/**
 * Download a URL following redirects, return a Buffer.
 */
function download(downloadUrl) {
  return new Promise((resolve, reject) => {
    https.get(downloadUrl, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return download(res.headers.location).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    }).on("error", reject);
  });
}

try {
  mkdirSync(BINARY_DIR, { recursive: true });
  const buffer = await download(url);
  writeFileSync(BINARY_PATH, buffer);
  chmodSync(BINARY_PATH, 0o755);
  console.log("[keychat] ✅ Binary installed");
} catch (err) {
  console.warn(`[keychat] Download failed: ${err.message}`);
  console.warn("[keychat] Build from source: cd bridge && cargo build --release");
  // Don't fail install — user can build manually
}

// Auto-initialize config if not set
// Note: openclaw CLI config commands removed to avoid child_process.
// Users should run: openclaw config set channels.keychat.enabled true
console.log("[keychat] Run to activate: openclaw config set channels.keychat.enabled true && openclaw gateway restart");

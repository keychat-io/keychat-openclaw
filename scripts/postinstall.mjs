#!/usr/bin/env node
/**
 * postinstall — download pre-compiled keychat-bridge binary.
 * Runs automatically after `npm install` / `openclaw plugins install`.
 * Uses native fetch/https — no child_process dependency.
 */
import { existsSync, mkdirSync, chmodSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import https from "node:https";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = "keychat-io/keychat-openclaw";
const BINARY_DIR = join(__dirname, "..", "bridge", "target", "release");
const BINARY_PATH = join(BINARY_DIR, "keychat-bridge");

import { statSync } from "node:fs";

// Read expected version from package.json
const pkgPath = join(__dirname, "..", "package.json");
const pkgVersion = JSON.parse(readFileSync(pkgPath, "utf-8")).version;
const versionFile = join(BINARY_DIR, ".version");

const currentVersion = existsSync(versionFile)
  ? readFileSync(versionFile, "utf-8").trim()
  : null;

// Clean up conflicting script-installed copy (extensions/keychat vs extensions/keychat-openclaw)
const pluginDir = join(__dirname, "..");
const pluginDirName = pluginDir.split("/").pop();
const scriptInstallDir = join(pluginDir, "..", "keychat");
if (pluginDirName === "keychat-bridge" && existsSync(scriptInstallDir)) {
  console.log(`[keychat] Removing conflicting script-installed copy...`);
  try { rmSync(scriptInstallDir, { recursive: true, force: true }); } catch {}
}

if (existsSync(BINARY_PATH) && currentVersion === pkgVersion) {
  console.log(`[keychat] Binary already exists (v${pkgVersion}), skipping download`);
  process.exit(0);
}

if (existsSync(BINARY_PATH)) {
  console.log(`[keychat] Binary exists but version mismatch (${currentVersion || "unknown"} → ${pkgVersion}), re-downloading...`);
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
  writeFileSync(versionFile, pkgVersion + "\n");
  console.log(`[keychat] ✅ Binary installed (v${pkgVersion})`);
} catch (err) {
  console.warn(`[keychat] Download failed: ${err.message}`);
  console.warn("[keychat] Build from source: cd bridge && cargo build --release");
  // Don't fail install — user can build manually
}

// Auto-initialize config if channels["keychat"] not set
import { homedir } from "node:os";

const configPath = join(homedir(), ".openclaw", "openclaw.json");
try {
  let config = {};
  if (existsSync(configPath)) {
    config = JSON.parse(readFileSync(configPath, "utf-8"));
  }

  if (config.channels?.["keychat"] || config.channels?.keychat) {
    console.log("[keychat] Config already contains keychat settings, skipping init");
    // Migrate old channels.keychat → channels.keychat
    if (config.channels?.keychat && !config.channels?.["keychat"]) {
      config.channels["keychat"] = config.channels.keychat;
      delete config.channels.keychat;
      writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
      console.log("[keychat] ✅ Migrated channels.keychat → channels.keychat");
    }
  } else {
    if (!config.channels) config.channels = {};
    config.channels["keychat"] = { enabled: true, dmPolicy: "open" };
    writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
    console.log('[keychat] ✅ Config initialized (channels.keychat.enabled = true)');
    console.log("[keychat] Restart gateway to activate: openclaw gateway restart");
  }
} catch (err) {
  console.warn(`[keychat] Could not auto-configure: ${err.message}`);
  console.warn('[keychat] Run manually: openclaw config set channels.keychat.enabled true');
}

// Final summary
console.log("");
console.log("════════════════════════════════════════");
console.log("  🎉 Keychat plugin installed!");
console.log("════════════════════════════════════════");
console.log("");
console.log("Next step: restart the gateway to activate Keychat");
console.log("");
console.log("  openclaw gateway restart");
console.log("");
console.log("Your agent's Keychat ID will appear in the gateway logs.");
console.log("Run 'openclaw logs --follow' to see it.");

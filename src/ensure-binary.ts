/**
 * Auto-download the keychat-openclaw bridge binary if missing.
 * Called before bridge startup. Downloads from GitHub Releases.
 */

import { existsSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { execSync } from "node:child_process";

const REPO = "keychat-io/keychat-openclaw";

const ARTIFACTS: Record<string, string> = {
  "darwin-arm64": "keychat-openclaw-darwin-arm64",
  "darwin-x64": "keychat-openclaw-darwin-x64",
  "linux-x64": "keychat-openclaw-linux-x64",
  "linux-arm64": "keychat-openclaw-linux-arm64",
};

export function getBridgePath(): string {
  return join(
    import.meta.dirname ?? ".",
    "..",
    "bridge",
    "target",
    "release",
    "keychat-openclaw",
  );
}

export async function ensureBinary(): Promise<string> {
  const binaryPath = getBridgePath();
  if (existsSync(binaryPath)) return binaryPath;

  const key = `${process.platform}-${process.arch}`;
  const artifact = ARTIFACTS[key];
  if (!artifact) {
    throw new Error(
      `No pre-compiled keychat-openclaw binary for ${key}. ` +
      `Build from source: cd bridge && cargo build --release`
    );
  }

  const url = `https://github.com/${REPO}/releases/latest/download/${artifact}`;
  console.log(`[keychat] Downloading bridge binary (${artifact})...`);

  const dir = join(binaryPath, "..");
  mkdirSync(dir, { recursive: true });

  try {
    execSync(`curl -fSL "${url}" -o "${binaryPath}"`, {
      stdio: "pipe",
      timeout: 120_000,
    });
    chmodSync(binaryPath, 0o755);
    console.log("[keychat] ✅ Bridge binary downloaded");
    return binaryPath;
  } catch (err: any) {
    throw new Error(
      `Failed to download bridge binary: ${err.message}\n` +
      `Build from source: cd bridge && cargo build --release`
    );
  }
}

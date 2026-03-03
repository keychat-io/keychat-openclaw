/**
 * Secure mnemonic storage using system keychain.
 * Falls back gracefully if keychain is unavailable.
 *
 * macOS: Uses `security` CLI (Keychain Access)
 * Linux: Uses `secret-tool` (libsecret / GNOME Keyring)
 *
 * Note: This file intentionally uses child_process for system keychain access.
 * This triggers an OpenClaw scanner warning ("Shell command execution detected")
 * which is expected — keychain storage is more secure than file-based alternatives.
 */

import { execFileSync, execSync } from "node:child_process";

const SERVICE = "openclaw-keychat";

/**
 * Check if system keychain is available and functional.
 * Returns { available: true } or { available: false, reason, hint }.
 */
export function checkKeychainAvailable(): { available: boolean; reason?: string; hint?: string } {
  try {
    if (process.platform === "darwin") {
      // macOS Keychain is always available
      execFileSync("security", ["help"], { stdio: "pipe" });
      return { available: true };
    } else if (process.platform === "linux") {
      // Check secret-tool binary exists
      try {
        execFileSync("which", ["secret-tool"], { stdio: "pipe" });
      } catch {
        return {
          available: false,
          reason: "secret-tool not found",
          hint: "Debian/Ubuntu: sudo apt install libsecret-tools gnome-keyring\n  RHEL/Fedora:   sudo dnf install libsecret gnome-keyring\n\n  The mnemonic (private key) must be stored in the system keychain for security.\n  Keychat will not start until the keychain is available.",
        };
      }
      // Check D-Bus secret service is running
      try {
        execFileSync("secret-tool", ["lookup", "service", "__keychat_probe__", "account", "__probe__"], { stdio: "pipe", timeout: 5000 });
      } catch (e: any) {
        const msg = e?.stderr?.toString?.() ?? e?.message ?? "";
        if (msg.includes("org.freedesktop.secrets was not provided")) {
          return {
            available: false,
            reason: "D-Bus secret service not running",
            hint: "Debian/Ubuntu: sudo apt install gnome-keyring\n  RHEL/Fedora:   sudo dnf install gnome-keyring\n\n  The mnemonic (private key) must be stored in the system keychain for security.\n  Keychat will not start until the keychain is available.",
          };
        }
        // "not found" error from lookup is fine — means the service IS running
      }
      return { available: true };
    }
    return { available: false, reason: `Unsupported platform: ${process.platform}` };
  } catch {
    return { available: false, reason: "Keychain check failed" };
  }
}

/**
 * Attempt to auto-install and start gnome-keyring on Linux.
 * Returns true if successful (keychain now available).
 */
export function autoFixKeychain(log?: { info: (m: string) => void; error: (m: string) => void }): boolean {
  if (process.platform !== "linux") return false;

  // Detect package manager
  let installCmd: string | null = null;
  for (const [bin, cmd] of [
    ["apt-get", "sudo apt-get install -y gnome-keyring libsecret-tools"],
    ["dnf", "sudo dnf install -y gnome-keyring libsecret"],
    ["yum", "sudo yum install -y gnome-keyring libsecret"],
    ["pacman", "sudo pacman -S --noconfirm gnome-keyring libsecret"],
  ] as const) {
    try {
      execFileSync("which", [bin], { stdio: "pipe" });
      installCmd = cmd;
      break;
    } catch { /* not found, try next */ }
  }

  if (!installCmd) {
    log?.error("[keychat] Could not detect package manager (apt/dnf/yum/pacman)");
    return false;
  }

  log?.info(`[keychat] Installing gnome-keyring: ${installCmd}`);
  try {
    execSync(installCmd, { stdio: "pipe", timeout: 120_000 });
  } catch (e: any) {
    log?.error(`[keychat] Failed to install gnome-keyring: ${e?.message ?? e}`);
    return false;
  }

  // Try to start gnome-keyring-daemon
  try {
    execSync("gnome-keyring-daemon --start --components=secrets 2>/dev/null || true", {
      stdio: "pipe",
      timeout: 10_000,
      env: { ...process.env, DISPLAY: process.env.DISPLAY || "" },
    });
  } catch { /* may fail on headless, check below */ }

  // Verify it works now
  const check = checkKeychainAvailable();
  if (check.available) {
    log?.info("[keychat] ✅ System keychain is now available");
    return true;
  }

  log?.error(`[keychat] Installed gnome-keyring but keychain still unavailable: ${check.reason}`);
  return false;
}

export async function storeMnemonic(accountId: string, mnemonic: string): Promise<boolean> {
  const key = `mnemonic-${accountId}`;
  try {
    if (process.platform === "darwin") {
      execFileSync("security", [
        "add-generic-password", "-a", key, "-s", SERVICE, "-w", mnemonic, "-U",
      ], { stdio: "pipe" });
      return true;
    } else if (process.platform === "linux") {
      execFileSync("secret-tool", [
        "store", "--label", SERVICE, "service", SERVICE, "account", key,
      ], { stdio: "pipe", input: mnemonic });
      return true;
    }
  } catch {
    // Keychain not available
  }
  return false;
}

export async function retrieveMnemonic(accountId: string): Promise<string | null> {
  const key = `mnemonic-${accountId}`;
  try {
    if (process.platform === "darwin") {
      const result = execFileSync("security", [
        "find-generic-password", "-a", key, "-s", SERVICE, "-w",
      ], { stdio: "pipe" });
      return result.toString().trim();
    } else if (process.platform === "linux") {
      const result = execFileSync("secret-tool", [
        "lookup", "service", SERVICE, "account", key,
      ], { stdio: "pipe" });
      return result.toString().trim();
    }
  } catch {
    // Not found or keychain unavailable
  }
  return null;
}

export async function deleteMnemonic(accountId: string): Promise<boolean> {
  const key = `mnemonic-${accountId}`;
  try {
    if (process.platform === "darwin") {
      execFileSync("security", [
        "delete-generic-password", "-a", key, "-s", SERVICE,
      ], { stdio: "pipe" });
      return true;
    } else if (process.platform === "linux") {
      execFileSync("secret-tool", [
        "clear", "service", SERVICE, "account", key,
      ], { stdio: "pipe" });
      return true;
    }
  } catch {
    // Not found
  }
  return false;
}

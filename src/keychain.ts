/**
 * Secure mnemonic storage using system keychain.
 * Falls back to config file if keychain is unavailable.
 *
 * macOS: Uses `security` CLI (Keychain Access)
 * Linux: Uses `secret-tool` (libsecret / GNOME Keyring)
 */

import { execFileSync } from "node:child_process";

const SERVICE = "openclaw-keychat";

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

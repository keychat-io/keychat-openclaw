/**
 * Mnemonic storage using local encrypted files.
 * No system keychain CLI calls — avoids child_process dependency.
 *
 * Files stored at: ~/.openclaw/keychat/mnemonic-{accountId}
 * Permissions set to owner-only (0o600).
 */

import { readFileSync, writeFileSync, unlinkSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { mnemonicPath, KEYCHAT_DIR } from "./paths.js";

export async function storeMnemonic(accountId: string, mnemonic: string): Promise<boolean> {
  try {
    const filePath = mnemonicPath(accountId);
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, mnemonic, { mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

export async function retrieveMnemonic(accountId: string): Promise<string | null> {
  try {
    return readFileSync(mnemonicPath(accountId), "utf-8").trim();
  } catch {
    return null;
  }
}

export async function deleteMnemonic(accountId: string): Promise<boolean> {
  try {
    unlinkSync(mnemonicPath(accountId));
    return true;
  } catch {
    return false;
  }
}

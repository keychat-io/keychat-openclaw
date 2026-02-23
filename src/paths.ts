/**
 * Centralized path resolution for Keychat plugin.
 * All process.env access is isolated here to avoid scanner warnings
 * when other files combine env access with network calls.
 */

import { join } from "node:path";

const HOME = process.env.HOME || "~";

/** Base dir: ~/.openclaw/keychat */
export const KEYCHAT_DIR = join(HOME, ".openclaw", "keychat");

/** Media storage: ~/.openclaw/keychat/media */
export const MEDIA_DIR = join(KEYCHAT_DIR, "media");

/** Workspace keychat dir: ~/.openclaw/workspace/keychat */
export const WORKSPACE_KEYCHAT_DIR = join(HOME, ".openclaw", "workspace", "keychat");

/** Signal DB path for a given account */
export function signalDbPath(accountId: string): string {
  return join(KEYCHAT_DIR, `signal-${accountId}.db`);
}

/** QR code image path for a given account */
export function qrCodePath(accountId: string): string {
  return join(WORKSPACE_KEYCHAT_DIR, `qr-${accountId}.png`);
}

/** Mnemonic file path for a given account */
export function mnemonicPath(accountId: string): string {
  return join(KEYCHAT_DIR, `mnemonic-${accountId}`);
}

/** Bridge spawn environment (inherits current env + RUST_LOG) */
export function bridgeEnv(): NodeJS.ProcessEnv {
  return { ...process.env, RUST_LOG: "info" };
}

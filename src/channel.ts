/**
 * Keychat channel plugin for OpenClaw.
 *
 * The agent is a full Keychat citizen:
 * - Self-generated Public Key ID (Nostr keypair)
 * - Signal Protocol E2E encryption
 * - Communicates via Nostr relays
 *
 * Uses Keychat (sidecar) for protocol compatibility
 * with the Keychat app.
 */

import {
  buildChannelConfigSchema,
  createReplyPrefixOptions,
  DEFAULT_ACCOUNT_ID,
  formatPairingApproveHint,
  type ChannelPlugin,
} from "openclaw/plugin-sdk";

/**
 * Strip "Reasoning:\n_..._" prefix that OpenClaw core prepends when
 * reasoning display is enabled.  Keychat has no collapsible UI for it,
 * so we silently drop it to keep messages clean.
 */
function stripReasoningPrefix(text: string): string {
  // Strip reasoning in multiple formats:
  // 1. "Reasoning:\n_line1_\n_line2_\n\nActual answer..."
  // 2. Leading italic blocks: "_thinking text_\n_more thinking_\n\nActual answer..."
  // 3. "**Heading**\n_thinking_\n\nActual answer..."
  let result = text;

  // Format 1: Explicit "Reasoning:" prefix
  result = result.replace(/^Reasoning:\n(?:_[^\n]*_\n?)+\n*/s, "");

  // Format 2: Leading italic lines (markdown _text_) at the start
  // Keep stripping italic lines until we hit a non-italic line
  result = result.replace(/^(?:_[^\n]*_\n*)+\n*/s, "");

  return result.trim();
}
import { KeychatConfigSchema } from "./config-schema.js";
import { getKeychatRuntime } from "./runtime.js";
import {
  listKeychatAccountIds,
  resolveDefaultKeychatAccountId,
  resolveKeychatAccount,
  type ResolvedKeychatAccount,
} from "./types.js";
import {
  KeychatBridgeClient,
  type AccountInfo,
  type InboundMessage,
  type SendMessageResult,
  type MlsGroupInfo,
  type MlsCommitResult,
} from "./bridge-client.js";
import { storeMnemonic, retrieveMnemonic } from "./keychain.js";
import { parseMediaUrl, downloadAndDecrypt, encryptAndUpload } from "./media.js";
import { transcribe, type SttConfig } from "./stt.js";
import { join } from "node:path";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { writeFile as writeFileAsync } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { signalDbPath, qrCodePath, WORKSPACE_KEYCHAT_DIR } from "./paths.js";

// ═══════════════════════════════════════════════════════════════════════════
// DM Policy enforcement — gate inbound messages before dispatch to agent
// Uses OpenClaw's resolveDmGroupAccessWithLists for consistent behavior
// with built-in channels (Signal, Telegram, Discord, etc.)
// ═══════════════════════════════════════════════════════════════════════════

/** Resolve the credentials file path for a channel, matching the framework naming convention.
 *  Without accountId: `keychat-<suffix>.json`
 *  With accountId:    `keychat-<accountId>-<suffix>.json`
 */
function resolveKeychatCredPath(suffix: string, accountId?: string): string {
  const base = "keychat";
  const safeAccount = accountId ? String(accountId).trim().toLowerCase().replace(/[\\/:*?"<>|]/g, "_").replace(/\.\./g, "_") : "";
  const filename = safeAccount ? `${base}-${safeAccount}-${suffix}.json` : `${base}-${suffix}.json`;
  return join(homedir(), ".openclaw", "credentials", filename);
}

/** Read the allow-from store for a channel (credentials/keychat[-<accountId>]-allowFrom.json). */
function readKeychatAllowFromStore(accountId?: string): string[] {
  try {
    const accountPath = accountId ? resolveKeychatCredPath("allowFrom", accountId) : null;
    const channelPath = resolveKeychatCredPath("allowFrom");

    if (accountPath && existsSync(accountPath)) {
      const store = JSON.parse(readFileSync(accountPath, "utf-8"));
      return (store.allowFrom ?? []).map((e: string) => String(e).trim()).filter(Boolean);
    }

    // Account-specific file doesn't exist — check channel-level fallback
    if (existsSync(channelPath)) {
      const raw = readFileSync(channelPath, "utf-8");
      const store = JSON.parse(raw);
      // Migrate: copy channel-level file to account-specific path so framework
      // and plugin stay in sync after the user upgrades to multi-account config
      if (accountPath) {
        try { writeFileSync(accountPath, raw, "utf-8"); } catch { /* best effort */ }
      }
      return (store.allowFrom ?? []).map((e: string) => String(e).trim()).filter(Boolean);
    }

    return [];
  } catch { return []; }
}

/** Append a pubkey to the allow-from store file. */
function appendKeychatAllowFromStore(pubkey: string, accountId?: string): void {
  const storePath = accountId
    ? resolveKeychatCredPath("allowFrom", accountId)
    : resolveKeychatCredPath("allowFrom");
  try {
    let store: { version: number; allowFrom: string[] } = { version: 1, allowFrom: [] };
    if (existsSync(storePath)) {
      store = JSON.parse(readFileSync(storePath, "utf-8"));
    }
    const normalized = normalizePubkey(pubkey);
    if (!store.allowFrom.includes(normalized)) {
      store.allowFrom.push(normalized);
      writeFileSync(storePath, JSON.stringify(store, null, 2) + "\n", "utf-8");
    }
  } catch { /* best effort */ }
}

/** Check if this account has any allowed peers (config + store). */
function hasAnyAllowedPeers(accountId: string, runtime: ReturnType<typeof getKeychatRuntime>): boolean {
  const cfg = runtime.config.loadConfig();
  const account = resolveKeychatAccount({ cfg, accountId });
  const configEntries = (account.config.allowFrom ?? []).filter((e) => String(e).trim() && String(e).trim() !== "*");
  const storeEntries = readKeychatAllowFromStore(accountId);
  return configEntries.length > 0 || storeEntries.length > 0;
}

/**
 * Resolve DM access decision for an inbound message.
 * Self-contained — does NOT depend on SDK functions (which fail in ESM plugin context).
 * Returns "allow" | "block" | "pairing".
 */
function resolveDmAccess(
  accountId: string,
  senderNostrPubkey: string,
  runtime: ReturnType<typeof getKeychatRuntime>,
): { decision: "allow" | "block" | "pairing" } {
  const cfg = runtime.config.loadConfig();
  const account = resolveKeychatAccount({ cfg, accountId });
  const dmPolicy = account.config.dmPolicy ?? "pairing";

  // "open" allows everyone
  if (dmPolicy === "open") return { decision: "allow" };

  // "disabled" blocks everyone
  if (dmPolicy === "disabled") return { decision: "block" };

  const senderNormalized = normalizePubkey(senderNostrPubkey);

  // Collect all allowed entries: config + store (pairing approvals)
  const configEntries = (account.config.allowFrom ?? []).map((e) => normalizePubkey(String(e)));
  const storeEntries = readKeychatAllowFromStore(accountId).map((e) => normalizePubkey(e));
  const allAllowed = [...configEntries, ...storeEntries];

  // Check wildcard
  if (allAllowed.includes("*")) return { decision: "allow" };

  // Check if sender is in any allowlist
  const isAllowed = allAllowed.includes(senderNormalized);

  if (dmPolicy === "allowlist") {
    return isAllowed ? { decision: "allow" } : { decision: "block" };
  }

  if (dmPolicy === "pairing") {
    return isAllowed ? { decision: "allow" } : { decision: "pairing" };
  }

  return { decision: "block" };
}

/** Generate a random 6-char alphanumeric pairing code. */
function generatePairingCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I/O/0/1 to avoid confusion
  let code = "";
  const { randomBytes } = require("node:crypto");
  const bytes = randomBytes(6);
  for (const b of bytes) code += chars[b % chars.length];
  return code;
}

/** Upsert a pairing request for a Keychat sender. Returns { code, created }. */
function upsertKeychatPairingRequest(senderId: string, meta?: Record<string, string>, accountId?: string): { code: string; created: boolean } {
  // Use channel-level pairing path (no accountId in filename) to match OpenClaw CLI's resolvePairingPath.
  // The accountId is stored inside each request object for multi-account disambiguation.
  const pairingPath = resolveKeychatCredPath("pairing");
  try {
    let data: { version: number; requests: Array<{ id: string; code: string; createdAt: string; lastSeenAt: string; accountId?: string; meta?: Record<string, string> }> } = { version: 1, requests: [] };
    if (existsSync(pairingPath)) {
      data = JSON.parse(readFileSync(pairingPath, "utf-8"));
    }

    const now = new Date().toISOString();
    const normalizedId = normalizePubkey(senderId);
    const existing = data.requests.find((r) => normalizePubkey(r.id) === normalizedId);

    if (existing) {
      existing.lastSeenAt = now;
      if (accountId) existing.accountId = accountId;
      if (meta) existing.meta = { ...existing.meta, ...meta };
      writeFileSync(pairingPath, JSON.stringify(data, null, 2) + "\n", "utf-8");
      return { code: existing.code, created: false };
    }

    // Generate unique code
    const existingCodes = new Set(data.requests.map((r) => r.code));
    let code = generatePairingCode();
    while (existingCodes.has(code)) code = generatePairingCode();

    data.requests.push({ id: normalizedId, code, createdAt: now, lastSeenAt: now, accountId, meta });

    // Cap at 50 pending requests
    if (data.requests.length > 50) {
      data.requests = data.requests.slice(-50);
    }

    writeFileSync(pairingPath, JSON.stringify(data, null, 2) + "\n", "utf-8");
    return { code, created: true };
  } catch {
    return { code: "", created: false };
  }
}

/** Look up the accountId for a pairing request by peer id. */
function getAccountIdForPairingPeer(peerId: string): string | undefined {
  const normalizedId = normalizePubkey(peerId);
  // Check all possible pairing files
  for (const [aid] of activeBridges) {
    const pairingPath = resolveKeychatCredPath("pairing", aid);
    try {
      if (!existsSync(pairingPath)) continue;
      const data = JSON.parse(readFileSync(pairingPath, "utf-8"));
      const req = data.requests?.find((r: { id: string; accountId?: string }) => normalizePubkey(r.id) === normalizedId);
      if (req?.accountId) return req.accountId;
    } catch { /* */ }
  }
  // Also check default (no accountId) pairing file
  const defaultPath = resolveKeychatCredPath("pairing");
  try {
    if (existsSync(defaultPath)) {
      const data = JSON.parse(readFileSync(defaultPath, "utf-8"));
      const req = data.requests?.find((r: { id: string; accountId?: string }) => normalizePubkey(r.id) === normalizedId);
      if (req?.accountId) return req.accountId;
    }
  } catch { /* */ }
  return undefined;
}

/** Build the pairing reply message text. */
function buildKeychatPairingReply(code: string, senderId: string): string {
  return [
    "OpenClaw: access not configured.",
    "",
    `keychatPubkey: ${senderId}`,
    "",
    `Pairing code: ${code}`,
    "",
    "Ask the bot owner to approve with:",
    `  openclaw pairing approve keychat ${code}`,
  ].join("\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// Task 7: Outbound message queue for offline/retry resilience
// ═══════════════════════════════════════════════════════════════════════════

interface PendingMessage {
  to: string;
  text: string;
  retries: number;
  accountId: string;
}

const pendingOutbound: PendingMessage[] = [];
const MAX_PENDING_QUEUE = 100;
const MAX_MESSAGE_RETRIES = 5;

// ═══════════════════════════════════════════════════════════════════════════
// Friend request / hello state machine
// ═══════════════════════════════════════════════════════════════════════════

enum FriendRequestState {
  IDLE = "IDLE",
  WAIT_ACCEPT = "WAIT_ACCEPT",
  SESSION_ESTABLISHED = "SESSION_ESTABLISHED",
  NORMAL_CHAT = "NORMAL_CHAT",
}

interface FriendRequestPeerFlow {
  state: FriendRequestState;
  /** true = A-role (we sent hello, waiting for accept-first).
   *  false = B-role (we received hello, sent accept-first back).
   *  This determines flush/dispatch behavior after session establishment. */
  initiatedByUs: boolean;
}

class FriendRequestManager {
  private readonly flowsByAccount = new Map<string, Map<string, FriendRequestPeerFlow>>();

  private getFlows(accountId: string): Map<string, FriendRequestPeerFlow> {
    let flows = this.flowsByAccount.get(accountId);
    if (!flows) {
      flows = new Map<string, FriendRequestPeerFlow>();
      this.flowsByAccount.set(accountId, flows);
    }
    return flows;
  }

  private getOrCreateFlow(accountId: string, peerPubkey: string): FriendRequestPeerFlow {
    const flows = this.getFlows(accountId);
    let flow = flows.get(peerPubkey);
    if (!flow) {
      flow = {
        state: FriendRequestState.IDLE,
        initiatedByUs: false,
      };
      flows.set(peerPubkey, flow);
    }
    return flow;
  }

  getState(accountId: string, peerPubkey: string): FriendRequestState {
    const flow = this.getFlows(accountId).get(peerPubkey);
    return flow?.state ?? FriendRequestState.IDLE;
  }

  isWaitingAccept(accountId: string, peerPubkey: string): boolean {
    return this.getState(accountId, peerPubkey) === FriendRequestState.WAIT_ACCEPT;
  }

  isInitiatorSidePending(accountId: string, peerPubkey: string): boolean {
    const flow = this.getFlows(accountId).get(peerPubkey);
    if (!flow) return false;
    return flow.initiatedByUs;
  }

  hasSession(accountId: string, peerPubkey: string): boolean {
    const state = this.getState(accountId, peerPubkey);
    return state === FriendRequestState.SESSION_ESTABLISHED || state === FriendRequestState.NORMAL_CHAT;
  }

  setSessionEstablished(accountId: string, peerPubkey: string): void {
    const flow = this.getOrCreateFlow(accountId, peerPubkey);
    // Protocol Step 4: accept-first decrypted and Signal session established.
    flow.state = FriendRequestState.SESSION_ESTABLISHED;
  }

  setNormalChat(accountId: string, peerPubkey: string): void {
    const flow = this.getOrCreateFlow(accountId, peerPubkey);
    flow.state = FriendRequestState.NORMAL_CHAT;
  }

  restoreWaitAccept(accountId: string, peerPubkey: string): void {
    const flow = this.getOrCreateFlow(accountId, peerPubkey);
    flow.state = FriendRequestState.WAIT_ACCEPT;
    flow.initiatedByUs = true;
  }

  resetPeer(accountId: string, peerPubkey: string): void {
    this.getFlows(accountId).delete(peerPubkey);
  }

  resetAccount(accountId: string): void {
    this.flowsByAccount.delete(accountId);
  }

  async ensureOutgoingHelloAndHandshakeSubscriptions(
    bridge: KeychatBridgeClient,
    accountId: string,
    peerPubkey: string,
    senderName: string,
  ): Promise<void> {
    const flow = this.getOrCreateFlow(accountId, peerPubkey);
    if (flow.state === FriendRequestState.WAIT_ACCEPT) return;
    if (flow.state === FriendRequestState.SESSION_ESTABLISHED || flow.state === FriendRequestState.NORMAL_CHAT) return;

    // Protocol Step 1: Send friend request (kind:1059 Gift Wrap).
    const helloResult = await bridge.sendHello(peerPubkey, senderName);
    flow.state = FriendRequestState.WAIT_ACCEPT;
    flow.initiatedByUs = true;

    // Protocol Step 3: accept-first is sent to A_onetimekey.
    // curve25519 identity pubkey is NOT a receiving address; subscribing to it
    // causes routing conflicts when multiple hellos are in flight.
    const handshakeAddresses = new Set<string>();
    if (helloResult.onetimekey) {
      handshakeAddresses.add(helloResult.onetimekey);
      getAddressToPeer(accountId).set(helloResult.onetimekey, peerPubkey);
      try { await bridge.saveAddressMapping(helloResult.onetimekey, peerPubkey); } catch { /* best effort */ }
    }
    if (handshakeAddresses.size > 0) {
      await bridge.addSubscription(Array.from(handshakeAddresses));
    }
  }

  async queueUntilSession(
    bridge: KeychatBridgeClient,
    accountId: string,
    peerPubkey: string,
    text: string,
  ): Promise<{ channel: "keychat"; to: string; messageId: string }> {
    const { id } = await bridge.savePendingHelloMessage(peerPubkey, text);
    this.getOrCreateFlow(accountId, peerPubkey).initiatedByUs = true;
    return {
      channel: "keychat" as const,
      to: peerPubkey,
      messageId: `pending-hello-${id}`,
    };
  }

  async flushQueuedAfterSession(
    bridge: KeychatBridgeClient,
    accountId: string,
    peerPubkey: string,
  ): Promise<void> {
    const flow = this.getOrCreateFlow(accountId, peerPubkey);
    const { messages } = await bridge.getPendingHelloMessages(peerPubkey);
    if (messages.length === 0) return;
    let promotedToNormalChat = false;
    for (const queued of messages) {
      try {
        const result = await bridge.sendMessage(peerPubkey, queued.text);
        await handleReceivingAddressRotation(bridge, accountId, result, peerPubkey);
        await bridge.deletePendingHelloMessageById(queued.id);
        if (!promotedToNormalChat) {
          // Protocol Step 5: first post-handshake send triggers ratchet switch.
          // Protocol Step 6: after that first message is sent, treat this peer as NORMAL_CHAT.
          flow.state = FriendRequestState.NORMAL_CHAT;
          promotedToNormalChat = true;
        }
      } catch (err) {
        throw err instanceof Error ? err : new Error(String(err));
      }
    }
    flow.initiatedByUs = false;
  }
}

const friendRequestManager = new FriendRequestManager();

/** Flush pending outbound messages — called after bridge restart and periodically. */
async function flushPendingOutbound(): Promise<void> {
  if (pendingOutbound.length === 0) return;

  // Check if any bridge is connected
  const bridges = [...activeBridges.entries()];
  if (bridges.length === 0) return;

  // Try to flush each message
  const toRetry: PendingMessage[] = [];
  while (pendingOutbound.length > 0) {
    const msg = pendingOutbound.shift()!;
    const bridge = activeBridges.get(msg.accountId);
    if (!bridge) {
      toRetry.push(msg);
      continue;
    }

    const connected = await bridge.isConnected();
    if (!connected) {
      toRetry.push(msg);
      continue;
    }

    try {
      const retryResult = await bridge.sendMessage(msg.to, msg.text);
      await handleReceivingAddressRotation(bridge, msg.accountId ?? DEFAULT_ACCOUNT_ID, retryResult, msg.to);
    } catch {
      msg.retries++;
      if (msg.retries >= MAX_MESSAGE_RETRIES) {
        console.warn(`[keychat] Dropping message to ${msg.to} after ${MAX_MESSAGE_RETRIES} retries`);
      } else {
        toRetry.push(msg);
      }
    }
  }

  // Put failed messages back
  for (const msg of toRetry) {
    if (pendingOutbound.length < MAX_PENDING_QUEUE) {
      pendingOutbound.push(msg);
    } else {
      console.warn(`[keychat] Pending outbound queue full, dropping message to ${msg.to}`);
    }
  }
}

// Periodic flush every 30s
setInterval(() => { flushPendingOutbound().catch(() => {}); }, 30_000);

/** Queue a message for later delivery when bridge is unavailable. */
function queueOutbound(to: string, text: string, accountId: string): void {
  if (pendingOutbound.length >= MAX_PENDING_QUEUE) {
    console.warn(`[keychat] Pending outbound queue full, dropping message to ${to}`);
    return;
  }
  pendingOutbound.push({ to, text, retries: 0, accountId });
}

// ═══════════════════════════════════════════════════════════════════════════
// Task 8: Session recovery tracking
// ═══════════════════════════════════════════════════════════════════════════

// Removed: sessionRecoveryAttempted — we no longer auto-send corruption notices

/** Retry a send operation with exponential backoff. */
async function retrySend<T>(fn: () => Promise<T>, maxRetries = 3, baseDelayMs = 500): Promise<T> {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (attempt === maxRetries) throw err;
      const delay = baseDelayMs * Math.pow(2, attempt);
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw new Error("unreachable");
}

// Active bridge clients per account
const activeBridges = new Map<string, KeychatBridgeClient>();
// Cached account info per account
const accountInfoCache = new Map<string, AccountInfo>();
// Bridge readiness promises — resolved when startAccount completes
const bridgeReadyResolvers = new Map<string, () => void>();
const bridgeReadyPromises = new Map<string, Promise<void>>();

/** Wait for a bridge to become ready, with timeout. */
async function waitForBridge(accountId: string, timeoutMs = 30000): Promise<KeychatBridgeClient> {
  const existing = activeBridges.get(accountId);
  if (existing) return existing;

  // Wait for the bridge to start
  let readyPromise = bridgeReadyPromises.get(accountId);
  if (!readyPromise) {
    readyPromise = new Promise<void>((resolve) => {
      bridgeReadyResolvers.set(accountId, resolve);
    });
    bridgeReadyPromises.set(accountId, readyPromise);
  }

  const timeout = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error(`Keychat bridge not ready after ${timeoutMs}ms`)), timeoutMs),
  );

  await Promise.race([readyPromise, timeout]);
  const bridge = activeBridges.get(accountId);
  if (!bridge) throw new Error(`Keychat bridge not running for account ${accountId}`);
  return bridge;
}

/** Peer session info learned from friend requests / hellos. */
interface PeerSession {
  signalPubkey: string;
  deviceId: number;
  name: string;
  nostrPubkey: string;
}

// Per-account maps (keyed by accountId)
const peerSessionsByAccount = new Map<string, Map<string, PeerSession>>();
const addressToPeerByAccount = new Map<string, Map<string, string>>();
const seenEventIdsByAccount = new Map<string, Set<string>>();

// Helpers to get per-account maps (auto-create on first access)
function getPeerSessions(accountId: string): Map<string, PeerSession> {
  let m = peerSessionsByAccount.get(accountId);
  if (!m) { m = new Map(); peerSessionsByAccount.set(accountId, m); }
  return m;
}
function getAddressToPeer(accountId: string): Map<string, string> {
  let m = addressToPeerByAccount.get(accountId);
  if (!m) { m = new Map(); addressToPeerByAccount.set(accountId, m); }
  return m;
}
function getSeenEventIds(accountId: string): Set<string> {
  let s = seenEventIdsByAccount.get(accountId);
  if (!s) { s = new Set(); seenEventIdsByAccount.set(accountId, s); }
  return s;
}
/**
 * Resolve display name for a keychat account.
 * Priority: channel config name > agent identity name > fallback.
 */
function resolveDisplayName(cfg: any, accountId: string, channelName?: string, fallback = "Keychat Agent"): string {
  if (channelName) return channelName;
  // Look up agent identity name via bindings
  const bindings = (cfg.bindings ?? []) as Array<{ agentId?: string; match?: { channel?: string; accountId?: string } }>;
  const binding = bindings.find(b => b.match?.channel === "keychat" && b.match?.accountId === accountId);
  const agentId = binding?.agentId ?? (accountId === DEFAULT_ACCOUNT_ID ? "main" : accountId);
  const agents = (cfg.agents?.list ?? []) as Array<{ id?: string; identity?: { name?: string }; name?: string }>;
  const agent = agents.find(a => a.id === agentId);
  return agent?.identity?.name || agent?.name || fallback;
}

// Mutex for friend request processing to prevent concurrent hello corruption
let helloProcessingLock: Promise<void> = Promise.resolve();
const SEEN_EVENT_MAX = 1000;

/** Mark an event as processed (in-memory + DB). Call BEFORE decrypt to prevent
 *  ratchet corruption on retry — Signal decrypt consumes message keys. */
function markProcessed(bridge: KeychatBridgeClient, accountId: string, eventId: string | undefined, createdAt?: number): void {
  if (!eventId) return;
  const seen = getSeenEventIds(accountId);
  seen.add(eventId);
  if (seen.size > SEEN_EVENT_MAX) {
    const first = seen.values().next().value;
    if (first) seen.delete(first);
  }
  bridge.markEventProcessed(eventId, createdAt).catch(() => {/* best effort */});
}
// per-account: peerNostrPubkey → subscribed receiving addresses (oldest..newest)
const peerSubscribedAddressesByAccount = new Map<string, Map<string, string[]>>();

// ── Summary notification (debounced, fires once after all accounts start) ──
let _summaryTimer: ReturnType<typeof setTimeout> | null = null;
const SUMMARY_DEBOUNCE_MS = 3000;

function scheduleSummaryNotification(ctx: { log?: { info: (...a: any[]) => void; warn?: (...a: any[]) => void } }): void {
  if (_summaryTimer) clearTimeout(_summaryTimer);
  _summaryTimer = setTimeout(async () => {
    _summaryTimer = null;
    try {
      const { KEYCHAT_DIR } = await import("./paths.js");
      const { writeFileSync } = await import("node:fs");

      // Check if ANY account still needs notification
      const contacts = getAllAgentContacts();
      const needsNotify: typeof contacts = [];
      for (const c of contacts) {
        const marker = join(KEYCHAT_DIR, `.notified-${c.accountId}`);
        if (!existsSync(marker)) needsNotify.push(c);
      }
      if (needsNotify.length === 0) return; // all already notified

      // Build summary with all agents (not just new ones — include all for context)
      const cfg = getKeychatRuntime().config.loadConfig();
      let lines: string[] = [];
      if (contacts.length === 1) {
        const c = contacts[0];
        const name = resolveDisplayName(cfg, c.accountId);
        lines.push(
          `[Keychat Plugin] Agent "${name}" is online and ready.`,
          `Keychat ID: ${c.npub}`,
          `Contact link: ${c.contactUrl}`,
          `Use the keychat_identity tool to get the QR code image.`,
          `Send the contact info to the user on their active channel so they can add this agent in Keychat app.`,
        );
      } else {
        lines.push(`[Keychat Plugin] ${contacts.length} agents are online and ready:`);
        lines.push(``);
        for (const c of contacts) {
          const name = resolveDisplayName(cfg, c.accountId);
          lines.push(`• ${name} (account: ${c.accountId})`);
          lines.push(`  Keychat ID: ${c.npub}`);
          lines.push(`  Link: ${c.contactUrl}`);
          lines.push(``);
        }
        lines.push(`Use the keychat_identity tool to get QR code images for each agent.`);
        lines.push(`Send all agent contact info to the user on their active channel so they can add them in Keychat app.`);
      }

      const { sendSystemEvent } = await import("./notify.js");
      await sendSystemEvent(lines.join("\n"));

      // Mark all as notified
      for (const c of needsNotify) {
        const marker = join(KEYCHAT_DIR, `.notified-${c.accountId}`);
        writeFileSync(marker, new Date().toISOString());
      }
    } catch (err) {
      ctx.log?.warn?.(`Failed to send summary notification: ${err}`);
    }
  }, SUMMARY_DEBOUNCE_MS);
}

function getPeerSubscribedAddresses(accountId: string): Map<string, string[]> {
  let m = peerSubscribedAddressesByAccount.get(accountId);
  if (!m) {
    m = new Map<string, string[]>();
    peerSubscribedAddressesByAccount.set(accountId, m);
  }
  return m;
}
// Minimum addresses to keep per peer after lazy cleanup (matches Keychat app: remainReceiveKeyPerRoom=2).
// Old addresses are only cleaned up when a message is received on a newer address,
// confirming the peer has moved on. Never delete proactively (e.g. at startup or after send).
const REMAIN_RECEIVE_KEYS_PER_PEER = 3;

// ═══════════════════════════════════════════════════════════════════════════
// MLS (Large Group) state
// ═══════════════════════════════════════════════════════════════════════════

/** Map listen_key → group_id for routing inbound MLS messages */
const mlsListenKeyToGroup = new Map<string, string>();
/** Set of MLS-initialized account IDs */
const mlsInitialized = new Set<string>();


/**
 * Normalize a pubkey: strip nostr: prefix, handle npub/hex.
 */
function normalizePubkey(input: string): string {
  const trimmed = input.replace(/^nostr:/i, "").replace(/^keychat:/i, "").trim();
  // If it's hex, lowercase it
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  // Decode npub (bech32) to hex so all keys use a consistent format
  if (trimmed.startsWith("npub1")) {
    try {
      const decoded = bech32Decode(trimmed);
      if (decoded) return decoded.toLowerCase();
    } catch { /* fall through */ }
  }
  return trimmed;
}

/** Decode bech32 npub to hex pubkey. */
function bech32Decode(npub: string): string | null {
  const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const pos = npub.lastIndexOf("1");
  if (pos < 1) return null;
  const data: number[] = [];
  for (let i = pos + 1; i < npub.length; i++) {
    const v = CHARSET.indexOf(npub.charAt(i));
    if (v === -1) return null;
    data.push(v);
  }
  // Remove 6-char checksum
  const values = data.slice(0, -6);
  // Convert from 5-bit groups to 8-bit bytes
  let acc = 0, bits = 0;
  const result: number[] = [];
  for (const v of values) {
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      result.push((acc >> bits) & 0xff);
    }
  }
  if (result.length !== 32) return null;
  return result.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const keychatPlugin: ChannelPlugin<ResolvedKeychatAccount> = {
  id: "keychat",
  meta: {
    id: "keychat",
    label: "Keychat",
    selectionLabel: "Keychat (E2E Encrypted)",
    docsPath: "/channels/keychat",
    docsLabel: "keychat",
    blurb:
      "Sovereign identity + E2E encrypted chat via Keychat protocol. Agent generates its own Public Key ID.",
    order: 50,
  },
  capabilities: {
    chatTypes: ["direct", "group"],
    media: true,
  },
  reload: { configPrefixes: ["channels.keychat"] },
  configSchema: buildChannelConfigSchema(KeychatConfigSchema),

  config: {
    listAccountIds: (cfg) => listKeychatAccountIds(cfg),
    resolveAccount: (cfg, accountId) => resolveKeychatAccount({ cfg, accountId }),
    defaultAccountId: (cfg) => resolveDefaultKeychatAccountId(cfg),
    isConfigured: (account) => account.configured,
    describeAccount: (account) => ({
      accountId: account.accountId,
      name: account.name,
      enabled: account.enabled,
      configured: account.configured,
      publicKey: account.publicKey,
      ...(account.lightningAddress ? { lightningAddress: account.lightningAddress } : {}),
    }),
    resolveAllowFrom: ({ cfg, accountId }) =>
      (resolveKeychatAccount({ cfg, accountId }).config.allowFrom ?? []).map((entry) =>
        String(entry),
      ),
    formatAllowFrom: ({ allowFrom }) =>
      allowFrom
        .map((entry) => String(entry).trim())
        .filter(Boolean)
        .map((entry) => {
          if (entry === "*") return "*";
          return normalizePubkey(entry);
        })
        .filter(Boolean),
  },

  pairing: {
    idLabel: "keychatPubkey",
    normalizeAllowEntry: (entry) => normalizePubkey(entry),
    notifyApproval: async ({ id }) => {
      // Look up which account this peer's pairing request came from
      const aid = getAccountIdForPairingPeer(id) ?? DEFAULT_ACCOUNT_ID;
      try {
        const bridge = await waitForBridge(aid, 10000);
        const approveResult = await bridge.sendMessage(id, "✅ Pairing approved! You can now chat with this agent.");
        await handleReceivingAddressRotation(bridge, aid, approveResult, id);
      } catch {
        // If specific account bridge fails, don't try others — wrong account = wrong identity
        console.error(`[keychat] notifyApproval: failed to send via account ${aid} to ${id}`);
      }
    },
  },

  security: {
    resolveDmPolicy: ({ cfg, account, accountId }) => {
      const channelCfg = (cfg.channels as Record<string, unknown> | undefined)?.keychat as
        | { accounts?: Record<string, unknown> } | undefined;
      const isMultiAccount = channelCfg?.accounts && Object.keys(channelCfg.accounts).length > 0;
      const prefix = isMultiAccount
        ? `channels.keychat.accounts.${accountId ?? DEFAULT_ACCOUNT_ID}`
        : "channels.keychat";
      return {
        policy: account.config.dmPolicy ?? "pairing",
        allowFrom: account.config.allowFrom ?? [],
        policyPath: `${prefix}.dmPolicy`,
        allowFromPath: `${prefix}.allowFrom`,
        approveHint: formatPairingApproveHint("keychat"),
        normalizeEntry: (raw) => normalizePubkey(raw),
      };
    },
  },

  messaging: {
    normalizeTarget: (target) => normalizePubkey(target),
    targetResolver: {
      looksLikeId: (input) => {
        const trimmed = input.trim();
        return trimmed.startsWith("npub1") || /^[0-9a-fA-F]{64}$/.test(trimmed);
      },
      hint: "<npub|hex pubkey>",
    },
  },

  outbound: {
    deliveryMode: "direct",
    textChunkLimit: 4000,
    sendText: async ({ to, text, accountId }) => {
      const aid = accountId ?? DEFAULT_ACCOUNT_ID;
      const bridge = await waitForBridge(aid);
      const core = getKeychatRuntime();
      const tableMode = core.channel.text.resolveMarkdownTableMode({
        cfg: core.config.loadConfig(),
        channel: "keychat",
        accountId: aid,
      });
      const message = stripReasoningPrefix(core.channel.text.convertMarkdownTables(text ?? "", tableMode));
      const normalizedTo = normalizePubkey(to);

      // Handle small group (Signal group) — route through sendGroupMessage (fan-out to each member)
      const smallGroupMatch = normalizedTo.match(/^group:(.+)$/);
      if (smallGroupMatch) {
        const groupId = smallGroupMatch[1];
        try {
          const result = await retrySend(() => bridge.sendGroupMessage(groupId, message));
          // Handle receiving address rotation for each group member
          if (result.member_rotations?.length) {
            for (const rot of result.member_rotations) {
              await handleReceivingAddressRotation(bridge, aid, { new_receiving_address: rot.new_receiving_address } as any, rot.member);
            }
          }
          return {
            channel: "keychat" as const,
            to: normalizedTo,
            messageId: result.event_ids?.[0] || `group-${Date.now()}`,
          };
        } catch (err) {
          console.warn(`[keychat] [${aid}] sendText to small group ${groupId} failed: ${err}`);
          return {
            channel: "keychat" as const,
            to: normalizedTo,
            messageId: `error-${Date.now()}`,
          };
        }
      }

      // Handle MLS group — route through mlsSendMessage
      const mlsGroupMatchText = normalizedTo.match(/^mls-group:(.+)$/);
      if (mlsGroupMatchText) {
        const groupId = mlsGroupMatchText[1];
        try {
          const result = await retrySend(() => bridge.mlsSendMessage(groupId, message));
          return {
            channel: "keychat" as const,
            to: normalizedTo,
            messageId: result.event_id,
          };
        } catch (err) {
          console.warn(`[keychat] [${aid}] sendText to MLS group ${groupId} failed: ${err}`);
          return {
            channel: "keychat" as const,
            to: normalizedTo,
            messageId: `error-${Date.now()}`,
          };
        }
      }

      // Handle /reset signal command — reset Signal session and re-send hello
      if (message.trim() === "/reset signal") {
        const result = await resetPeerSession(normalizedTo, aid, true);
        console.log(`[keychat] [${aid}] Reset session result for ${normalizedTo}:`, result);
        return {
          channel: "keychat" as const,
          to: normalizedTo,
          messageId: `reset-${Date.now()}`,
        };
      }

      // Check if we have a session with this peer (placeholder mappings with empty signalPubkey don't count).
      const existingPeer = getPeerSessions(aid).get(normalizedTo);
      const hasSession = !!(existingPeer && existingPeer.signalPubkey) || friendRequestManager.hasSession(aid, normalizedTo);
      if (!hasSession) {
        // Defensive: never send hello to non-pubkey targets (group IDs, prefixed targets, etc.)
        if (normalizedTo.includes(":")) {
          console.warn(`[keychat] [${aid}] sendText target "${normalizedTo}" is not a peer pubkey, skipping hello`);
          return {
            channel: "keychat" as const,
            to: normalizedTo,
            messageId: `skip-${Date.now()}`,
          };
        }

        // Protocol Step 1: No session yet, send friend request (kind:1059 Gift Wrap).
        console.log(`[keychat] No session with ${normalizedTo}, initiating hello...`);
        try {
          const name = "Keychat Agent";
          await friendRequestManager.ensureOutgoingHelloAndHandshakeSubscriptions(
            bridge,
            aid,
            normalizedTo,
            name,
          );
        } catch (err) {
          const reason = err instanceof Error ? err.message : String(err);
          throw new Error(`Failed to send friend request hello to ${normalizedTo}: ${reason}`);
        }

        // Protocol Step 3/4 window: queue outbound app messages until accept-first establishes session.
        return friendRequestManager.queueUntilSession(bridge, aid, normalizedTo, message);
      }

      // Existing session — send directly
      try {
        const result = await retrySend(() => bridge.sendMessage(normalizedTo, message));
        // Handle receiving address rotation
        await handleReceivingAddressRotation(bridge, aid, result, normalizedTo);
        return {
          channel: "keychat" as const,
          to: normalizedTo,
          messageId: result.event_id,
        };
      } catch (err) {
        // Queue for later delivery instead of throwing
        queueOutbound(normalizedTo, message, aid);
        console.warn(`[keychat] sendText failed, queued for retry: ${err}`);
        return {
          channel: "keychat" as const,
          to: normalizedTo,
          messageId: `queued-${Date.now()}`,
        };
      }
    },
    sendMedia: async ({ to, text, mediaUrl: incomingMediaUrl, filePath, buffer, accountId }: any) => {
      const aid = accountId ?? DEFAULT_ACCOUNT_ID;
      const bridge = await waitForBridge(aid);

      let mediaUrl = incomingMediaUrl ?? "";

      // If mediaUrl is a local file path (not http), treat it as filePath
      if (mediaUrl && !mediaUrl.startsWith("http://") && !mediaUrl.startsWith("https://")) {
        filePath = filePath || mediaUrl;
        mediaUrl = "";
      }

      // If a local file or buffer is provided (but no pre-resolved mediaUrl),
      // encrypt and upload via Blossom, then use the resulting media URL.
      if (!mediaUrl && (filePath || buffer)) {
        let uploadPath = filePath as string | undefined;
        if (!uploadPath && buffer) {
          // Save buffer to a temp file for encryptAndUpload
          uploadPath = join(tmpdir(), `keychat-upload-${Date.now()}`);
          await writeFileAsync(uploadPath, buffer as Buffer);
        }
        if (uploadPath) {
          const core = getKeychatRuntime();
          const cfg = core.config.loadConfig();
          const acct = resolveKeychatAccount({ cfg, accountId: aid });
          const signEvent = (content: string, tags: string[][]) =>
            bridge.signBlossomEvent(content, tags);
          const result = await encryptAndUpload(uploadPath, signEvent, acct.mediaServer);
          mediaUrl = result.mediaUrl;
        }
      }

      // Send the media URL as a message (same as Keychat app)
      const caption = text;
      const messageText = caption ? `${mediaUrl}\n${caption}` : mediaUrl;

      // Check if target is a small group (Signal group — fan-out to each member)
      const normalizedTo = normalizePubkey(to);
      const smallGroupMatch = normalizedTo.match(/^group:(.+)$/);
      if (smallGroupMatch) {
        const groupId = smallGroupMatch[1];
        try {
          const result = await retrySend(() => bridge.sendGroupMessage(groupId, messageText));
          if (result.member_rotations?.length) {
            for (const rot of result.member_rotations) {
              await handleReceivingAddressRotation(bridge, aid, { new_receiving_address: rot.new_receiving_address } as any, rot.member);
            }
          }
          return {
            channel: "keychat" as const,
            to: normalizedTo,
            messageId: result.event_ids?.[0] || `group-media-${Date.now()}`,
          };
        } catch (err) {
          console.warn(`[keychat] sendMedia to small group ${groupId} failed: ${err}`);
          return {
            channel: "keychat" as const,
            to: normalizedTo,
            messageId: `failed-${Date.now()}`,
          };
        }
      }

      // Check if target is an MLS group
      const mlsGroupMatch = normalizedTo.match(/^mls-group:(.+)$/);
      if (mlsGroupMatch) {
        const groupId = mlsGroupMatch[1];
        try {
          const result = await retrySend(() => bridge.mlsSendMessage(groupId, messageText));
          return {
            channel: "keychat" as const,
            to,
            messageId: result.event_id,
          };
        } catch (err) {
          console.warn(`[keychat] sendMedia to MLS group failed: ${err}`);
          return {
            channel: "keychat" as const,
            to,
            messageId: `failed-${Date.now()}`,
          };
        }
      }

      // 1:1 DM
      try {
        const result = await retrySend(() => bridge.sendMessage(normalizedTo, messageText));
        await handleReceivingAddressRotation(bridge, aid, result, normalizedTo);
        return {
          channel: "keychat" as const,
          to: normalizedTo,
          messageId: result.event_id,
        };
      } catch (err) {
        queueOutbound(normalizedTo, messageText, aid);
        console.warn(`[keychat] sendMedia failed, queued for retry: ${err}`);
        return {
          channel: "keychat" as const,
          to: normalizedTo,
          messageId: `queued-${Date.now()}`,
        };
      }
    },
  },

  status: {
    defaultRuntime: {
      accountId: DEFAULT_ACCOUNT_ID,
      running: false,
      lastStartAt: null,
      lastStopAt: null,
      lastError: null,
    },
    collectStatusIssues: (accounts) => {
      const issues: Array<{
        channel: string;
        accountId: string;
        kind: "runtime" | "config";
        message: string;
      }> = [];

      // Check bridge binary exists (shared across all accounts)
      const bridgePath = join(
        import.meta.dirname ?? __dirname,
        "..",
        "bridge",
        "target",
        "release",
        "keychat-openclaw",
      );
      if (!existsSync(bridgePath)) {
        issues.push({
          channel: "keychat",
          accountId: accounts[0]?.accountId ?? DEFAULT_ACCOUNT_ID,
          kind: "runtime",
          message: "Bridge binary not found (will auto-download on start)",
        });
      }

      // Check peer sessions — warn if ALL accounts have zero peers
      const anyPeers = [...peerSessionsByAccount.values()].some((m) => m.size > 0);
      if (!anyPeers) {
        issues.push({
          channel: "keychat",
          accountId: accounts[0]?.accountId ?? DEFAULT_ACCOUNT_ID,
          kind: "runtime",
          message: "No peers connected yet",
        });
      }

      // Check Signal DB exists for each account
      for (const account of accounts) {
        const dbPath = signalDbPath(account.accountId);
        if (!existsSync(dbPath)) {
          issues.push({
            channel: "keychat",
            accountId: account.accountId,
            kind: "runtime",
            message: "Signal DB file missing",
          });
        }

        // Per-account errors
        const lastError = typeof account.lastError === "string" ? account.lastError.trim() : "";
        if (lastError) {
          issues.push({
            channel: "keychat",
            accountId: account.accountId,
            kind: "runtime",
            message: `Channel error: ${lastError}`,
          });
        }
      }

      return issues;
    },
    buildChannelSummary: ({ snapshot }) => ({
      configured: snapshot.configured ?? false,
      publicKey: (snapshot as Record<string, unknown>).publicKey ?? null,
      npub: (snapshot as Record<string, unknown>).npub ?? null,
      running: snapshot.running ?? false,
      lastStartAt: snapshot.lastStartAt ?? null,
      lastStopAt: snapshot.lastStopAt ?? null,
      lastError: snapshot.lastError ?? null,
    }),
    buildAccountSnapshot: ({ account, runtime }) => ({
      accountId: account.accountId,
      name: account.name,
      enabled: account.enabled,
      configured: account.configured,
      publicKey: account.publicKey,
      running: runtime?.running ?? false,
      lastStartAt: runtime?.lastStartAt ?? null,
      lastStopAt: runtime?.lastStopAt ?? null,
      lastError: runtime?.lastError ?? null,
      lastInboundAt: runtime?.lastInboundAt ?? null,
      lastOutboundAt: runtime?.lastOutboundAt ?? null,
    }),
  },

  gateway: {
    startAccount: async (ctx) => {
     try {
      const runtime = getKeychatRuntime();
      const account = ctx.account;

      ctx.log?.info(`[${account.accountId}] Starting Keychat channel...`);

      // Clean up any existing bridge from a previous start
      const oldBridge = activeBridges.get(account.accountId);
      if (oldBridge) {
        ctx.log?.info(`[${account.accountId}] Cleaning up previous bridge instance`);
        try {
          oldBridge.disableAutoRestart();
          await oldBridge.stop();
        } catch {
          // Best effort — old bridge may already be dead
        }
        activeBridges.delete(account.accountId);
      }

      // 1. Start the Rust bridge sidecar (auto-download binary if missing)
      const { ensureBinary } = await import("./ensure-binary.js");
      await ensureBinary();
      const bridge = new KeychatBridgeClient();
      await bridge.start();
      ctx.log?.info(`[${account.accountId}] Bridge sidecar started`);

      // 2. Initialize Signal Protocol DB
      const dbPath = `~/.openclaw/keychat/signal-${account.accountId}.db`;
      await bridge.init(dbPath);
      ctx.log?.info(`[${account.accountId}] Signal DB initialized`);

      // 3. Generate or restore identity
      // Priority: config mnemonic > keychain mnemonic > generate new
      let info: AccountInfo;
      let mnemonic = account.mnemonic;
      if (!mnemonic) {
        // Try keychain
        const keychainMnemonic = await retrieveMnemonic(account.accountId);
        if (keychainMnemonic) {
          mnemonic = keychainMnemonic;
          ctx.log?.info(`[${account.accountId}] Mnemonic retrieved from system keychain`);
        }
      }

      if (mnemonic) {
        // Restore from mnemonic
        info = await bridge.importIdentity(mnemonic);
        ctx.log?.info(`[${account.accountId}] Identity restored from mnemonic`);

        // If mnemonic was in config, try migrating to keychain
        if (account.mnemonic) {
          const stored = await storeMnemonic(account.accountId, mnemonic);
          if (stored) {
            ctx.log?.info(`[${account.accountId}] Mnemonic migrated to system keychain`);
            // Remove mnemonic from config (keep only publicKey/npub)
            const cfg = runtime.config.loadConfig();
            const channels = (cfg.channels ?? {}) as Record<string, unknown>;
            const keychatCfg = (channels.keychat ?? {}) as Record<string, unknown>;
            const { mnemonic: _removed, ...keychatCfgClean } = keychatCfg;
            await runtime.config.writeConfigFile({
              ...cfg,
              channels: { ...channels, keychat: keychatCfgClean },
            });
            ctx.log?.info(`[${account.accountId}] Mnemonic removed from config file`);
          }
        }
      } else {
        // Generate new identity
        info = await bridge.generateIdentity();
        ctx.log?.info(
          `[${account.accountId}] New Keychat identity generated: ${info.pubkey_npub}`,
        );

        // Store mnemonic in keychain first, fall back to config
        const stored = await storeMnemonic(account.accountId, info.mnemonic!);

        // Persist keys to config (mnemonic only if keychain failed)
        const cfg = runtime.config.loadConfig();
        const channels = (cfg.channels ?? {}) as Record<string, unknown>;
        const keychatCfg = (channels.keychat ?? {}) as Record<string, unknown>;
        await runtime.config.writeConfigFile({
          ...cfg,
          channels: {
            ...channels,
            keychat: {
              ...keychatCfg,
              ...(stored ? {} : { mnemonic: info.mnemonic }),
              publicKey: info.pubkey_hex,
              npub: info.pubkey_npub,
            },
          },
        });
      }

      accountInfoCache.set(account.accountId, info);

      // 4. Generate pre-key bundle (for Signal handshake with peers)
      const bundle = await bridge.generatePrekeyBundle();
      ctx.log?.info(`[${account.accountId}] Pre-key bundle generated`);

      // 5. Connect to Nostr relays
      await bridge.connect(account.relays);
      ctx.log?.info(
        `[${account.accountId}] Connected to ${account.relays.length} relay(s)`,
      );

      // 6. Log the agent's Keychat ID for the owner
      const contactUrl = `https://www.keychat.io/u/?k=${info.pubkey_npub}`;
      const qrPath = qrCodePath(account.accountId);

      // Generate QR codes (best-effort)
      let qrTerminal = "";
      try {
        const { generateQRTerminal } = await import("./qrcode.js");
        qrTerminal = await generateQRTerminal(contactUrl);
      } catch { /* qrcode not installed, skip */ }

      // Also save PNG for sharing (best-effort)
      try {
        mkdirSync(WORKSPACE_KEYCHAT_DIR, { recursive: true });
        const QRCode = await import("qrcode");
        await QRCode.toFile(qrPath, contactUrl, { width: 256 });
      } catch { /* skip */ }

      const cfg = runtime.config.loadConfig();
      const displayName = resolveDisplayName(cfg, account.accountId, account.name);

      ctx.log?.info(`\n` +
        `═══════════════════════════════════════════════════\n` +
        `  🔑 ${displayName} — Keychat ID:\n` +
        `\n` +
        `  ${info.pubkey_npub}\n` +
        `\n` +
        `  📱 Add contact (tap or scan):\n` +
        `  ${contactUrl}\n` +
        (qrTerminal ? `\n${qrTerminal}\n` : ``) +
        `═══════════════════════════════════════════════════\n`,
      );

      // Schedule a debounced summary notification covering all agents.
      // Only fires on first install (per-account markers prevent repeats on restart).
      scheduleSummaryNotification(ctx);

      ctx.setStatus({
        accountId: account.accountId,
        publicKey: info.pubkey_hex,
        contactUrl,
        qrCodePath: qrPath,
        running: true,
        configured: true,
        lastStartAt: Date.now(),
      } as any);

      activeBridges.set(account.accountId, bridge);

      // 7. Restore peer sessions and receiving addresses from DB
      console.log(`[keychat] [${account.accountId}] Step 7: restoring peer sessions...`);
      try {
        const { mappings } = await bridge.getPeerMappings();
        console.log(`[keychat] [${account.accountId}] Step 7: getPeerMappings returned ${mappings.length} mapping(s)`);
        if (mappings.length > 0) {
          ctx.log?.info(`[${account.accountId}] Restored ${mappings.length} peer mapping(s) from DB`);
          for (const m of mappings) {
            // Skip placeholder rows created by outgoing hello before reply arrives
            if (!m.signal_pubkey) continue;
            getPeerSessions(account.accountId).set(m.nostr_pubkey, {
              signalPubkey: m.signal_pubkey,
              deviceId: m.device_id,
              name: m.name,
              nostrPubkey: m.nostr_pubkey,
            });
            friendRequestManager.setSessionEstablished(account.accountId, m.nostr_pubkey);
          }
        }

        // Restore address-to-peer mappings from DB and populate peerSubscribedAddresses
        console.log(`[keychat] [${account.accountId}] Step 7b: getting address mappings...`);
        const { mappings: addrMappings } = await bridge.getAddressMappings();
        console.log(`[keychat] [${account.accountId}] Step 7b: getAddressMappings returned ${addrMappings.length} mapping(s)`);
        if (addrMappings.length > 0) {
          for (const am of addrMappings) {
            getAddressToPeer(account.accountId).set(am.address, am.peer_nostr_pubkey);
            // Track in peerSubscribedAddresses so cleanup works after restart
            const peerList = getPeerSubscribedAddresses(account.accountId).get(am.peer_nostr_pubkey) ?? [];
            peerList.push(am.address);
            getPeerSubscribedAddresses(account.accountId).set(am.peer_nostr_pubkey, peerList);
          }
          ctx.log?.info(`[${account.accountId}] Restored ${addrMappings.length} address-to-peer mapping(s) from DB`);
        }

        // Restore Protocol Step 1 WAIT_ACCEPT flows from persisted pending hello messages.
        // This lets startup continue waiting for Protocol Step 3 accept-first on A_onetimekey.
        const mappedPeers = new Set(addrMappings.map((m) => m.peer_nostr_pubkey));
        let restoredWaitAcceptPeers = 0;
        for (const peerPubkey of mappedPeers) {
          try {
            const { messages } = await bridge.getPendingHelloMessages(peerPubkey);
            if (messages.length === 0) continue;
            friendRequestManager.restoreWaitAccept(account.accountId, peerPubkey);
            restoredWaitAcceptPeers++;
          } catch {
            // best effort per peer
          }
        }
        if (restoredWaitAcceptPeers > 0) {
          ctx.log?.info(`[${account.accountId}] Restored WAIT_ACCEPT for ${restoredWaitAcceptPeers} pending hello peer(s)`);
        }

        // Address sync from Signal sessions removed — DB is authoritative after
        // sendGroupMessage/sendMessage address rotation fix.

        // Subscribe to all receiving addresses
        const toSubscribe = Array.from(getAddressToPeer(account.accountId).keys());
        if (toSubscribe.length > 0) {
          await bridge.addSubscription(toSubscribe);
          ctx.log?.info(
            `[${account.accountId}] Subscribed to ${toSubscribe.length} receiving address(es)`,
          );
        }
      } catch (err) {
        ctx.log?.error(`[${account.accountId}] Failed to restore sessions from DB: ${err}`);
        console.error(`[keychat] [${account.accountId}] Failed to restore sessions from DB:`, err);
      }

      // 8. Restore groups from DB
      try {
        const { groups } = await bridge.getAllGroups();
        if (groups.length > 0) {
          ctx.log?.info(`[${account.accountId}] Restored ${groups.length} group(s) from DB`);
          for (const g of groups) {
            ctx.log?.info(`[${account.accountId}]   Group: "${g.name}" (${g.group_id})`);
          }
        }
      } catch (err) {
        ctx.log?.error(`[${account.accountId}] Failed to restore groups from DB: ${err}`);
      }

      // 9. Initialize MLS (large group support)
      try {
        const mlsDbPath = dbPath.replace(/\.db$/, "-mls.db");
        await bridge.mlsInit(mlsDbPath);
        mlsInitialized.add(account.accountId);
        ctx.log?.info(`[${account.accountId}] MLS initialized`);

        // Publish KeyPackage (kind:10443) so others can invite us to MLS groups
        try {
          const kpResult = await bridge.mlsPublishKeyPackage();
          ctx.log?.info(`[${account.accountId}] MLS KeyPackage published (event ${kpResult.event_id})`);
        } catch (err) {
          ctx.log?.error(`[${account.accountId}] Failed to publish MLS KeyPackage: ${err}`);
        }

        // Restore MLS groups — listen keys come from DB (address_peer_mapping),
        // same as Signal ratchet addresses. No need to re-derive from MLS state.
        const { groups: mlsGroups } = await bridge.mlsGetGroups();
        for (const groupId of mlsGroups) {
          try {
            const mlsPeerKey = `mls:${groupId}`;
            // Find listen key from DB (already loaded in Step 7b)
            let listenKey: string | undefined;
            for (const [addr, peer] of getAddressToPeer(account.accountId).entries()) {
              if (peer === mlsPeerKey) { listenKey = addr; break; }
            }
            if (!listenKey) {
              // First time or DB was cleared — derive from MLS state
              const { listen_key } = await bridge.mlsGetListenKey(groupId);
              listenKey = listen_key;
              getAddressToPeer(account.accountId).set(listenKey, mlsPeerKey);
              try { await bridge.saveAddressMapping(listenKey, mlsPeerKey); } catch { /* */ }
            }
            mlsListenKeyToGroup.set(listenKey, groupId);
            await bridge.addSubscription([listenKey]);
            const info = await bridge.mlsGetGroupInfo(groupId);
            ctx.log?.info(`[${account.accountId}] MLS group restored: "${info.name}" (${groupId}), listen key: ${listenKey}`);
          } catch (err) {
            ctx.log?.error(`[${account.accountId}] Failed to restore MLS group ${groupId}: ${err}`);
          }
        }
      } catch (err) {
        ctx.log?.error(`[${account.accountId}] MLS init failed (non-fatal): ${err}`);
      }

      // 10. Initialize NWC (Nostr Wallet Connect) if configured
      if (account.nwcUri) {
        try {
          const { initNwc } = await import("./nwc.js");
          const nwc = await initNwc(account.nwcUri);
          const desc = nwc.describe();
          ctx.log?.info(`[${account.accountId}] ⚡ NWC connected: relay=${desc.relay}, wallet=${desc.walletPubkey.slice(0, 16)}...`);
          try {
            const balSats = await nwc.getBalanceSats();
            ctx.log?.info(`[${account.accountId}] ⚡ Wallet balance: ${balSats} sats`);
          } catch (err) {
            ctx.log?.info(`[${account.accountId}] ⚡ NWC connected (balance check not supported or failed: ${err})`);
          }
        } catch (err) {
          ctx.log?.error(`[${account.accountId}] NWC init failed (non-fatal): ${err}`);
        }
      }

      // Cache init args for auto-restart
      bridge.setInitArgs({ dbPath, mnemonic: account.mnemonic, relays: account.relays });

      // Register post-restart hook to restore peer sessions and subscriptions
      bridge.setRestartHook(async () => {
        ctx.log?.info(`[${account.accountId}] Restoring sessions after bridge restart...`);
        try {
          // Re-generate pre-key bundle
          await bridge.generatePrekeyBundle();
          // Restore peer mappings
          const { mappings } = await bridge.getPeerMappings();
          for (const m of mappings) {
            if (!m.signal_pubkey) continue;
            getPeerSessions(account.accountId).set(m.nostr_pubkey, {
              signalPubkey: m.signal_pubkey,
              deviceId: m.device_id,
              name: m.name,
              nostrPubkey: m.nostr_pubkey,
            });
            friendRequestManager.setSessionEstablished(account.accountId, m.nostr_pubkey);
          }
          // Restore address→peer mappings and peerSubscribedAddresses
          const { mappings: addrMappings } = await bridge.getAddressMappings();
          getPeerSubscribedAddresses(account.accountId).clear();
          for (const am of addrMappings) {
            getAddressToPeer(account.accountId).set(am.address, am.peer_nostr_pubkey);
            const peerList = getPeerSubscribedAddresses(account.accountId).get(am.peer_nostr_pubkey) ?? [];
            peerList.push(am.address);
            getPeerSubscribedAddresses(account.accountId).set(am.peer_nostr_pubkey, peerList);
          }
          const restartMappedPeers = new Set(addrMappings.map((m) => m.peer_nostr_pubkey));
          for (const peerPubkey of restartMappedPeers) {
            try {
              const { messages } = await bridge.getPendingHelloMessages(peerPubkey);
              if (messages.length > 0) {
                friendRequestManager.restoreWaitAccept(account.accountId, peerPubkey);
              }
            } catch { /* best effort */ }
          }
          // Re-subscribe to receiving addresses from address_peer_mapping
          const toSubRestart = Array.from(getAddressToPeer(account.accountId).keys());
          if (toSubRestart.length > 0) {
            await bridge.addSubscription(toSubRestart);
          }
          ctx.log?.info(`[${account.accountId}] Sessions restored: ${mappings.length} peer(s), ${addrMappings.length} address mapping(s)`);
          // Flush any pending outbound messages after restart
          await flushPendingOutbound();
        } catch (err) {
          ctx.log?.error(`[${account.accountId}] Failed to restore sessions after restart: ${err}`);
        }
      });

      // Start periodic health check (ping every 60s, restart if unresponsive)
      bridge.startHealthCheck();

      // Set up inbound message handler
      bridge.setInboundHandler(async (msg: InboundMessage) => {
        try {
          ctx.log?.info(`[${account.accountId}] ▶ Inbound handler invoked: kind=${msg.event_kind} from=${msg.from_pubkey?.slice(0,16)} to=${msg.to_address?.slice(0,16)} prekey=${msg.is_prekey} event=${msg.event_id?.slice(0,16)}`);
          // Deduplicate events — check in-memory first, then DB
          if (msg.event_id) {
            if (getSeenEventIds(account.accountId).has(msg.event_id)) {
              return; // Already processed (in-memory)
            }
            // Check persistent DB
            try {
              const { processed } = await bridge.isEventProcessed(msg.event_id);
              if (processed) {
                getSeenEventIds(account.accountId).add(msg.event_id);
                return; // Already processed (persisted)
              }
            } catch {
              // DB check failed — continue with processing
            }
          }

          if (msg.event_kind === 1059) {
            markProcessed(bridge, account.accountId, msg.event_id, msg.created_at);

            // Check if this is an MLS group message (to_address matches a known listen key)
            const mlsGroupId = msg.to_address ? mlsListenKeyToGroup.get(msg.to_address) : undefined;
            ctx.log?.info(`[${account.accountId}] Kind:1059 routing: to_address=${msg.to_address ?? 'null'}, inner_kind=${msg.inner_kind ?? 'null'}, mlsGroupId=${mlsGroupId ?? 'null'}, mlsKeys=[${[...mlsListenKeyToGroup.keys()].map(k => k.slice(0, 12)).join(',')}]`);

            if (mlsGroupId && !msg.inner_kind) {
              // ── MLS group message (raw kind:1059, not Gift Wrap) ──
              await handleMlsGroupMessage(bridge, account.accountId, mlsGroupId, msg, ctx, runtime);
            } else if (msg.inner_kind === 444) {
              // ── MLS Welcome (Gift Wrap with inner kind:444) ──
              await handleMlsWelcome(bridge, account.accountId, msg, ctx, runtime);
            } else {
              // ── Gift Wrap (friend request / hello) ──
              await handleFriendRequest(bridge, account.accountId, msg, ctx, runtime);
            }
          } else if (msg.event_kind === 4) {
            // ── Kind:4 DM ──
            markProcessed(bridge, account.accountId, msg.event_id, msg.created_at);
            if (msg.nip04_decrypted) {
              // NIP-04 pre-decrypted message (e.g., group invite via Nip4ChatService)
              // Skip Signal decrypt — plaintext is already in msg.text / msg.encrypted_content
              await handleNip04Message(bridge, account.accountId, msg, ctx, runtime);
            } else {
              // Signal-encrypted message — decrypt consumes message keys, cannot retry
              await handleEncryptedDM(bridge, account.accountId, msg, ctx, runtime);
            }
          } else {
            ctx.log?.info(
              `[${account.accountId}] Ignoring inbound event_kind=${msg.event_kind}`,
            );
            markProcessed(bridge, account.accountId, msg.event_id, msg.created_at);
          }
        } catch (err) {
          ctx.log?.error(
            `[${account.accountId}] Error handling inbound message: ${err}`,
          );
        }
      });

      // Signal bridge readiness — unblock any queued outbound sends
      const readyResolver = bridgeReadyResolvers.get(account.accountId);
      if (readyResolver) {
        readyResolver();
        bridgeReadyResolvers.delete(account.accountId);
        bridgeReadyPromises.delete(account.accountId);
      }

      // Keep the channel alive until abortSignal fires (OpenClaw expects startAccount
      // to stay pending while the channel is running — resolving triggers auto-restart)
      const abortSignal = (ctx as any).abortSignal as AbortSignal | undefined;
      if (abortSignal) {
        await new Promise<void>((resolve) => {
          if (abortSignal.aborted) { resolve(); return; }
          abortSignal.addEventListener("abort", () => resolve(), { once: true });
        });
      } else {
        // Fallback: wait forever (shouldn't happen in practice)
        await new Promise<void>(() => {});
      }

      // Cleanup on abort
      bridge.disableAutoRestart();
      await bridge.disconnect();
      await bridge.stop();
      activeBridges.delete(account.accountId);
      accountInfoCache.delete(account.accountId);
      peerSessionsByAccount.delete(account.accountId);
      addressToPeerByAccount.delete(account.accountId);
      seenEventIdsByAccount.delete(account.accountId);
      peerSubscribedAddressesByAccount.delete(account.accountId);
      friendRequestManager.resetAccount(account.accountId);
      bridgeReadyPromises.delete(account.accountId);
      bridgeReadyResolvers.delete(account.accountId);
      ctx.log?.info(`[${account.accountId}] Keychat provider stopped`);
    },
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// Inbound message helpers
// ═══════════════════════════════════════════════════════════════════════════

/** Handle a Gift Wrap (kind:1059) friend request. */
async function handleFriendRequest(
  bridge: KeychatBridgeClient,
  accountId: string,
  msg: InboundMessage,
  ctx: { log?: { info: (m: string) => void; error: (m: string) => void; warn?: (m: string) => void }; setStatus: (s: Record<string, unknown> | any) => void },
  runtime: ReturnType<typeof getKeychatRuntime>,
): Promise<void> {
  // Serialize hello processing to prevent concurrent hellos from corrupting each other's sessions
  const previousLock = helloProcessingLock;
  let releaseLock: () => void;
  helloProcessingLock = new Promise<void>((resolve) => { releaseLock = resolve; });
  await previousLock;
  try {
    await handleFriendRequestInner(bridge, accountId, msg, ctx, runtime);
  } finally {
    releaseLock!();
  }
}

async function handleFriendRequestInner(
  bridge: KeychatBridgeClient,
  accountId: string,
  msg: InboundMessage,
  ctx: { log?: { info: (m: string) => void; error: (m: string) => void; warn?: (m: string) => void }; setStatus: (s: Record<string, unknown> | any) => void },
  runtime: ReturnType<typeof getKeychatRuntime>,
): Promise<void> {
  ctx.log?.info(`[${accountId}] Friend request (kind:1059) from ${msg.from_pubkey} (created_at=${msg.created_at})`);

  // No time-based filtering here — the Rust bridge already sets `since` in relay
  // subscriptions (last_seen - 3min buffer, same as Keychat app), and processed_events
  // table handles deduplication. Stale events are never delivered to us.

  // If we already have a session, re-process the hello to handle re-pairing
  // (e.g. peer deleted us and re-added, or our previous hello reply wasn't received)
  const existingPeer = getPeerSessions(accountId).get(msg.from_pubkey);
  if (existingPeer) {
    ctx.log?.info(`[${accountId}] Re-processing friend request from ${msg.from_pubkey} (existing session will be replaced)`);
  }

  // Check DM policy before processing — unified check via resolveDmAccess
  const core = runtime;
  const cfg = core.config.loadConfig();
  const account = resolveKeychatAccount({ cfg, accountId });
  const displayName = resolveDisplayName(cfg, accountId, account.name);

  const helloAccess = resolveDmAccess(accountId, msg.from_pubkey, runtime);
  if (helloAccess.decision === "block") {
    ctx.log?.info(`[${accountId}] Rejecting friend request from ${msg.from_pubkey} — dmPolicy block`);
    return;
  }
  let isPairingPending = helloAccess.decision === "pairing";

  // Auto-approve first peer: if no one is in the allowlist yet, this is likely the owner
  if (isPairingPending && !hasAnyAllowedPeers(accountId, runtime)) {
    ctx.log?.info(`[${accountId}] Auto-approving first friend request from ${msg.from_pubkey} (no existing allowed peers)`);
    appendKeychatAllowFromStore(msg.from_pubkey, accountId);
    isPairingPending = false;
  }

  // Protocol Step 2/3/4: Process inbound friend request and establish Signal session.
  const hello = await bridge.processHello(msg.encrypted_content);
  if (!hello.session_established) {
    ctx.log?.error(`[${accountId}] Failed to establish session from hello`);
    return;
  }

  ctx.log?.info(
    `[${accountId}] Session established with ${hello.peer_name} (nostr: ${hello.peer_nostr_pubkey}, signal: ${hello.peer_signal_pubkey})`,
  );

  // Store/update peer session info for this specific nostr pubkey only
  const peer: PeerSession = {
    signalPubkey: hello.peer_signal_pubkey,
    deviceId: hello.device_id,
    name: hello.peer_name,
    nostrPubkey: hello.peer_nostr_pubkey,
  };

  // Clean up only the legacy restore entry for THIS peer's signal pubkey (if it was keyed wrong)
  if (getPeerSessions(accountId).has(hello.peer_signal_pubkey) && hello.peer_signal_pubkey !== hello.peer_nostr_pubkey) {
    getPeerSessions(accountId).delete(hello.peer_signal_pubkey);
    ctx.log?.info(`[${accountId}] Cleaned up legacy signal-keyed entry: ${hello.peer_signal_pubkey}`);
  }

  // Update getAddressToPeer entries that pointed to the old signal key to use nostr key
  for (const [addr, oldPeerKey] of getAddressToPeer(accountId)) {
    if (oldPeerKey === hello.peer_signal_pubkey) {
      getAddressToPeer(accountId).set(addr, hello.peer_nostr_pubkey);
    }
  }

  getPeerSessions(accountId).set(hello.peer_nostr_pubkey, peer);
  // B-role: Protocol Step 2-3 — received hello, built X3DH session, sending accept-first.
  // initiatedByUs stays false (default) since we are the responder.
  friendRequestManager.setSessionEstablished(accountId, hello.peer_nostr_pubkey);

  // NOTE: peer mapping already persisted by Rust handle_process_hello (with local Signal keys).
  // Do NOT call savePeerMapping here — it would overwrite local_signal_pubkey/privkey with NULL.

  // Protocol Step 3: Receiver sends accept-first as kind:4 PreKey to initiator onetimekey.
  let pairingGreeting = "";
  if (isPairingPending) {
    const { code } = upsertKeychatPairingRequest(msg.from_pubkey, { name: hello.peer_name }, accountId);
    pairingGreeting = code
      ? `\n\nPairing code: ${code}\nAsk the bot owner to approve with:\n  openclaw pairing approve keychat ${code}`
      : "";
  }
  const greetingText = isPairingPending
    ? `👋 Hi! I received your request. It's pending approval — the owner will review it shortly.${pairingGreeting}`
    : `👋 Hi! I'm ${displayName}. We're connected now — feel free to chat!`;
  // Wrap as KeychatMessage so the receiver can identify this as a hello reply (type 102)
  const helloReplyMsg = JSON.stringify({
    type: 100,  // KeyChatEventKinds.dm — Keychat app displays type 100 as chat message (type 102 is silently dropped)
    c: "signal",
    msg: greetingText,
  });
  const sendResult = await retrySend(() => bridge.sendMessage(hello.peer_nostr_pubkey, helloReplyMsg, {
    isHelloReply: true,
    senderName: displayName,
  }));
  ctx.log?.info(`[${accountId}] Sent hello reply to ${hello.peer_nostr_pubkey}`);

  // Send profile so peer knows our display name
  try {
    await retrySend(() => bridge.sendProfile(hello.peer_nostr_pubkey, { name: displayName }));
    ctx.log?.info(`[${accountId}] Sent profile to ${hello.peer_nostr_pubkey}`);
  } catch (e) {
    ctx.log?.error(`[${accountId}] Failed to send profile to ${hello.peer_nostr_pubkey}: ${e}`);
  }

  // Handle receiving address rotation after send (per-peer, addresses persisted to DB)
  await handleReceivingAddressRotation(bridge, accountId, sendResult, hello.peer_nostr_pubkey);

  const initiatedByUs = friendRequestManager.isInitiatorSidePending(accountId, hello.peer_nostr_pubkey);

  // Flush any pending messages that were waiting for this session.
  if (initiatedByUs) {
    ctx.log?.info(`[${accountId}] Flushing pending hello messages for ${hello.peer_nostr_pubkey}`);
    await friendRequestManager.flushQueuedAfterSession(bridge, accountId, hello.peer_nostr_pubkey);
  }

  // Dispatch the peer's greeting through the agent pipeline so the AI can generate a proper welcome
  // But skip dispatch if we initiated the hello (we already know who they are)
  const weInitiated = initiatedByUs;
  if (!weInitiated) {
    const greetingText = `[New contact] ${hello.peer_name} connected via Keychat. Their greeting: ${hello.greeting || "(no message)"}`;
    await dispatchToAgent(bridge, accountId, hello.peer_nostr_pubkey, hello.peer_name, greetingText, msg.event_id + "_hello", runtime, ctx);
  } else {
    ctx.log?.info(`[${accountId}] Skipping dispatch for self-initiated hello to ${hello.peer_nostr_pubkey}`);
  }
}

/** Handle a NIP-04 pre-decrypted message (e.g., group invite). */
async function handleNip04Message(
  bridge: KeychatBridgeClient,
  accountId: string,
  msg: InboundMessage,
  ctx: { log?: { info: (m: string) => void; error: (m: string) => void; warn?: (m: string) => void }; setStatus: (s: Record<string, unknown> | any) => void },
  runtime: ReturnType<typeof getKeychatRuntime>,
): Promise<void> {
  const plaintext = msg.text || msg.encrypted_content;
  ctx.log?.info(`[${accountId}] NIP-04 decrypted message from ${msg.from_pubkey}: ${plaintext.slice(0, 80)}...`);

  // Try to parse as KeychatMessage
  let displayText = plaintext;
  try {
    const parsed = JSON.parse(plaintext);

    // Handle group invite (type=11, c="group")
    if (parsed && parsed.type === 11 && parsed.c === "group" && parsed.msg) {
      const roomProfile = JSON.parse(parsed.msg);
      let senderIdPubkey = msg.from_pubkey;
      let inviteMessage = "Group invite received";
      if (parsed.name) {
        try {
          const nameData = JSON.parse(parsed.name);
          if (Array.isArray(nameData) && nameData.length >= 2) {
            inviteMessage = nameData[0];
            senderIdPubkey = nameData[1];
          }
        } catch { /* ignore */ }
      }

      ctx.log?.info(`[${accountId}] Received group invite via NIP-04: ${roomProfile.name} from ${senderIdPubkey}`);
      const joinResult = await bridge.joinGroup(roomProfile, senderIdPubkey);
      ctx.log?.info(`[${accountId}] Joined group '${joinResult.name}' (${joinResult.group_id}), ${joinResult.member_count} members`);

      // Send hello to the group
      try {
        const helloText = `😃 Hi, I am Agent`;
        const ghResult = await bridge.sendGroupMessage(joinResult.group_id, helloText, { subtype: 14 });
        if (ghResult.member_rotations?.length) {
          for (const rot of ghResult.member_rotations) {
            await handleReceivingAddressRotation(bridge, accountId, { new_receiving_address: rot.new_receiving_address } as any, rot.member);
          }
        }
        ctx.log?.info(`[${accountId}] Sent group hello to ${joinResult.group_id}`);
      } catch (err) {
        ctx.log?.error(`[${accountId}] Failed to send group hello: ${err}`);
      }

      // Dispatch to agent
      displayText = `[Group Invite] ${inviteMessage}. Joined group "${joinResult.name}" with ${joinResult.member_count} members.`;
      const senderLabel = getPeerSessions(accountId).get(senderIdPubkey)?.name || senderIdPubkey.slice(0, 12);
      await dispatchGroupToAgent(bridge, accountId, joinResult.group_id, senderIdPubkey, senderLabel, displayText, msg.event_id, runtime, ctx, { message: displayText, pubkey: joinResult.group_id });
      return;
    }

    // Other NIP-04 messages — extract msg field if it's a KeychatMessage
    if (parsed && typeof parsed.msg === "string") {
      displayText = parsed.msg;
    }
  } catch {
    // Not JSON — use as-is
  }

  // Dispatch as regular DM from the sender
  const senderPubkey = msg.from_pubkey;
  const nip04Access = resolveDmAccess(accountId, senderPubkey, runtime);
  if (nip04Access.decision === "block") {
    ctx.log?.info(`[${accountId}] ⛔ Blocked NIP-04 message from ${senderPubkey} — dmPolicy`);
    return;
  }
  if (nip04Access.decision === "pairing") {
    ctx.log?.info(`[${accountId}] ⛔ NIP-04 message from ${senderPubkey} — pending pairing`);
    // Can't easily send pairing reply via NIP-04 without bridge session, just block
    return;
  }
  const peer = getPeerSessions(accountId).get(senderPubkey);
  const senderLabel = peer?.name || senderPubkey.slice(0, 12);
  await dispatchToAgent(bridge, accountId, senderPubkey, senderLabel, displayText, msg.event_id, runtime, ctx);
}

// ═══════════════════════════════════════════════════════════════════════════
// MLS Group Message Handlers
// ═══════════════════════════════════════════════════════════════════════════

/** Handle an incoming MLS group message (kind:1059 on listen key, not Gift Wrap). */
async function handleMlsGroupMessage(
  bridge: KeychatBridgeClient,
  accountId: string,
  groupId: string,
  msg: InboundMessage,
  ctx: { log?: { info: (m: string) => void; error: (m: string) => void; warn?: (m: string) => void }; setStatus: (s: Record<string, unknown> | any) => void },
  runtime: ReturnType<typeof getKeychatRuntime>,
): Promise<void> {
  try {
    // Parse the message type first
    const msgType = await bridge.mlsParseMessageType(groupId, msg.encrypted_content);
    ctx.log?.info(`[${accountId}] MLS message type: ${msgType} for group ${groupId}`);

    switch (msgType) {
      case "Application": {
        // Decrypt the application message
        let decrypted: { plaintext: string; sender: string };
        try {
          decrypted = await bridge.mlsDecryptMessage(groupId, msg.encrypted_content);
        } catch (decryptErr: any) {
          // OpenMLS throws "Cannot decrypt own messages" for our own messages
          // (sender key is deleted after sending for forward secrecy).
          // This is expected — just skip silently.
          if (decryptErr?.message?.includes("Cannot decrypt own")) {
            return;
          }
          throw decryptErr;
        }
        ctx.log?.info(`[${accountId}] MLS message from ${decrypted.sender.slice(0, 12)} in group ${groupId}`);

        // Skip messages from ourselves (fallback check)
        const myPubkey = accountInfoCache.get(accountId)?.pubkey_hex;
        if (decrypted.sender === myPubkey) {
          ctx.log?.info(`[${accountId}] Skipping own MLS message`);
          return;
        }

        // Get group info for context
        let groupName = groupId.slice(0, 12);
        try {
          const info = await bridge.mlsGetGroupInfo(groupId);
          groupName = info.name || groupName;
        } catch { /* best effort */ }

        // Check if message is an encrypted media URL
        let mlsDisplayText = decrypted.plaintext;
        let mlsMediaPath: string | undefined;
        const mlsMediaInfo = parseMediaUrl(decrypted.plaintext);
        if (mlsMediaInfo) {
          try {
            mlsMediaPath = await downloadAndDecrypt(mlsMediaInfo);
            ctx.log?.info(`[${accountId}] MLS group media downloaded: ${mlsMediaInfo.kctype} → ${mlsMediaPath}`);
            if (mlsMediaInfo.isVoiceNote) {
              try {
                const sttConfig: SttConfig = { provider: "whisper-cpp", language: "auto" };
                const transcription = await transcribe(mlsMediaPath!, sttConfig);
                ctx.log?.info(`[${accountId}] MLS voice note transcribed: ${transcription.slice(0, 80)}...`);
                mlsDisplayText = `[voice message, ${mlsMediaInfo.duration || '?'}s] ${transcription}`;
              } catch (sttErr) {
                ctx.log?.error(`[${accountId}] MLS voice note STT failed: ${sttErr}`);
                mlsDisplayText = `[voice message — transcription failed, audio saved to ${mlsMediaPath}]`;
              }
            } else {
              mlsDisplayText = `[${mlsMediaInfo.kctype}: ${mlsMediaInfo.sourceName || mlsMediaInfo.suffix}] (saved to ${mlsMediaPath})`;
            }
          } catch (err) {
            ctx.log?.error(`[${accountId}] MLS group media download failed: ${err}`);
            mlsDisplayText = `[${mlsMediaInfo.kctype} message — download failed]`;
          }
        }

        // Route to agent
        ctx.log?.info(`[${accountId}] MLS dispatching to agent: group="${groupName}", sender=${decrypted.sender.slice(0, 12)}, text=${mlsDisplayText.slice(0, 80)}`);
        await dispatchMlsGroupToAgent(
          bridge, accountId, groupId, groupName,
          decrypted.sender, decrypted.sender.slice(0, 12),
          mlsDisplayText, msg.event_id, runtime, ctx, mlsMediaPath,
        );
        ctx.log?.info(`[${accountId}] MLS dispatch complete for group="${groupName}"`);
        break;
      }
      case "Commit": {
        // Process the commit (add/remove/update/etc.)
        const commitResult = await bridge.mlsProcessCommit(groupId, msg.encrypted_content);
        ctx.log?.info(`[${accountId}] MLS commit: ${commitResult.commit_type} by ${commitResult.sender.slice(0, 12)} in group ${groupId}`);

        // Update listen key subscription
        const oldListenKey = msg.to_address;
        if (oldListenKey && oldListenKey !== commitResult.listen_key) {
          mlsListenKeyToGroup.delete(oldListenKey);
          getAddressToPeer(accountId).delete(oldListenKey);
          try { await bridge.deleteAddressMapping(oldListenKey); } catch { /* */ }
          try { await bridge.removeSubscription([oldListenKey]); } catch { /* best effort */ }
        }
        mlsListenKeyToGroup.set(commitResult.listen_key, groupId);
        await bridge.addSubscription([commitResult.listen_key]);
        const mlsPeerKeyCommit = `mls:${groupId}`;
        getAddressToPeer(accountId).set(commitResult.listen_key, mlsPeerKeyCommit);
        try { await bridge.saveAddressMapping(commitResult.listen_key, mlsPeerKeyCommit); } catch { /* */ }

        // Generate system message based on commit type
        let systemMsg = "";
        switch (commitResult.commit_type) {
          case "Add":
            systemMsg = `[System] ${commitResult.sender.slice(0, 12)} added [${commitResult.operated_members.map(m => m.slice(0, 12)).join(", ")}] to the group`;
            break;
          case "Remove": {
            const myPubkey = accountInfoCache.get(accountId)?.pubkey_hex;
            if (commitResult.operated_members.includes(myPubkey ?? "")) {
              systemMsg = "[System] You have been removed from the group";
            } else {
              systemMsg = `[System] ${commitResult.sender.slice(0, 12)} removed [${commitResult.operated_members.map(m => m.slice(0, 12)).join(", ")}]`;
            }
            break;
          }
          case "Update":
            systemMsg = `[System] ${commitResult.sender.slice(0, 12)} updated their key`;
            break;
          case "GroupContextExtensions": {
            // Refresh group info
            try {
              const info = await bridge.mlsGetGroupInfo(groupId);
              systemMsg = `[System] ${commitResult.sender.slice(0, 12)} updated group info: ${info.name}`;
              if (info.status === "dissolved") {
                systemMsg = "[System] The admin closed this group chat";
              }
            } catch {
              systemMsg = `[System] ${commitResult.sender.slice(0, 12)} updated group info`;
            }
            break;
          }
        }

        if (systemMsg) {
          ctx.log?.info(`[${accountId}] MLS system: ${systemMsg}`);
        }
        break;
      }
      case "Proposal":
        ctx.log?.info(`[${accountId}] MLS proposal received in group ${groupId} (not processed)`);
        break;
      default:
        ctx.log?.info(`[${accountId}] Unhandled MLS message type: ${msgType} in group ${groupId}`);
    }
  } catch (err) {
    ctx.log?.error(`[${accountId}] Failed to handle MLS group message: ${err}`);
  }
}

/** Handle an MLS Welcome message (inner kind:444 from Gift Wrap). */
async function handleMlsWelcome(
  bridge: KeychatBridgeClient,
  accountId: string,
  msg: InboundMessage,
  ctx: { log?: { info: (m: string) => void; error: (m: string) => void; warn?: (m: string) => void }; setStatus: (s: Record<string, unknown> | any) => void },
  runtime: ReturnType<typeof getKeychatRuntime>,
): Promise<void> {
  try {
    const welcomeContent = msg.text || msg.encrypted_content;
    if (!welcomeContent) {
      ctx.log?.error(`[${accountId}] MLS Welcome: no content`);
      return;
    }

    // Extract group_id from inner rumor's p-tags
    // The Keychat app sends Welcome (kind:444) with additionalTags: [[p, groupPubkey]]
    const innerPTags = (msg as any).inner_tags_p as string[] | undefined;
    const groupId = innerPTags?.[0];

    if (!groupId) {
      ctx.log?.error(`[${accountId}] MLS Welcome from ${msg.from_pubkey.slice(0, 12)}: no group_id in inner p-tags`);
      return;
    }

    ctx.log?.info(`[${accountId}] MLS Welcome from ${msg.from_pubkey.slice(0, 12)} for group ${groupId.slice(0, 12)}...`);

    // Join the group
    const joinResult = await bridge.mlsJoinGroup(groupId, welcomeContent);
    ctx.log?.info(`[${accountId}] Joined MLS group ${groupId.slice(0, 12)}, listen key: ${joinResult.listen_key.slice(0, 12)}...`);

    // Subscribe to the group's listen key
    mlsListenKeyToGroup.set(joinResult.listen_key, groupId);
    await bridge.addSubscription([joinResult.listen_key]);
    const mlsPeerKeyJoin = `mls:${groupId}`;
    getAddressToPeer(accountId).set(joinResult.listen_key, mlsPeerKeyJoin);
    try { await bridge.saveAddressMapping(joinResult.listen_key, mlsPeerKeyJoin); } catch { /* */ }

    // Get group info
    const info = await bridge.mlsGetGroupInfo(groupId);
    ctx.log?.info(`[${accountId}] MLS group "${info.name}": ${info.members.length} members`);

    // Send greeting: self_update produces a commit that must be published + committed
    try {
      const greetingResult = await bridge.mlsSelfUpdate(groupId, {
        name: "Agent",
        msg: "[System] Hello everyone! I am Agent",
        status: "confirmed",
      });

      // Publish the commit to the group's listen key
      await bridge.mlsPublishToGroup(joinResult.listen_key, greetingResult.encrypted_msg);
      ctx.log?.info(`[${accountId}] Published MLS greeting commit to group "${info.name}"`);

      // Merge pending commit
      await bridge.mlsSelfCommit(groupId);

      // Listen key changes after commit — re-subscribe
      const { listen_key: newKey } = await bridge.mlsGetListenKey(groupId);
      if (newKey !== joinResult.listen_key) {
        mlsListenKeyToGroup.delete(joinResult.listen_key);
        getAddressToPeer(accountId).delete(joinResult.listen_key);
        try { await bridge.deleteAddressMapping(joinResult.listen_key); } catch { /* */ }
        mlsListenKeyToGroup.set(newKey, groupId);
        await bridge.removeSubscription([joinResult.listen_key]);
        await bridge.addSubscription([newKey]);
        getAddressToPeer(accountId).set(newKey, `mls:${groupId}`);
        try { await bridge.saveAddressMapping(newKey, `mls:${groupId}`); } catch { /* */ }
        ctx.log?.info(`[${accountId}] MLS listen key rotated after greeting: ${newKey.slice(0, 12)}...`);
      }
    } catch (err) {
      ctx.log?.error(`[${accountId}] Failed to send MLS greeting: ${err}`);
    }

    // Re-publish KeyPackage since the old one was consumed
    try {
      const kpResult = await bridge.mlsPublishKeyPackage();
      ctx.log?.info(`[${accountId}] Re-published MLS KeyPackage after join (event ${kpResult.event_id})`);
    } catch (err) {
      ctx.log?.error(`[${accountId}] Failed to re-publish KeyPackage after join: ${err}`);
    }
  } catch (err) {
    ctx.log?.error(`[${accountId}] Failed to handle MLS Welcome: ${err}`);
  }
}

/** Dispatch an MLS group message to the agent. */
async function dispatchMlsGroupToAgent(
  bridge: KeychatBridgeClient,
  accountId: string,
  groupId: string,
  groupName: string,
  senderPubkey: string,
  senderName: string,
  displayText: string,
  eventId: string,
  runtime: ReturnType<typeof getKeychatRuntime>,
  ctx: { log?: { info: (m: string) => void; error: (m: string) => void; warn?: (m: string) => void }; setStatus: (s: Record<string, unknown> | any) => void },
  mediaPath?: string,
): Promise<void> {
  const core = runtime;
  const cfg = core.config.loadConfig();

  ctx.log?.info(`[${accountId}] dispatchMlsGroupToAgent: resolving route for group=${groupId.slice(0, 12)}`);
  const route = core.channel.routing.resolveAgentRoute({
    cfg,
    channel: "keychat",
    accountId,
    peer: {
      kind: "group",
      id: groupId,
    },
  });
  ctx.log?.info(`[${accountId}] dispatchMlsGroupToAgent: route resolved, sessionKey=${route.sessionKey}`);

  const body = core.channel.reply.formatAgentEnvelope({
    channel: "Keychat",
    from: senderName,
    timestamp: Date.now(),
    body: displayText,
  });

  const ctxPayload = core.channel.reply.finalizeInboundContext({
    Body: body,
    RawBody: displayText,
    CommandBody: displayText,
    From: `keychat:${senderPubkey}`,
    To: `keychat:mls-group:${groupId}`,
    SessionKey: route.sessionKey,
    AccountId: accountId,
    ChatType: "group" as const,
    SenderName: senderName,
    SenderId: senderPubkey,
    GroupId: groupId,
    GroupName: groupName,
    Provider: "keychat" as const,
    Surface: "keychat" as const,
    MessageSid: eventId,
    OriginatingChannel: "keychat" as const,
    OriginatingTo: `keychat:mls-group:${groupId}`,
    ...(mediaPath ? { MediaPath: mediaPath } : {}),
  });

  const tableMode = core.channel.text.resolveMarkdownTableMode({
    cfg,
    channel: "keychat",
    accountId,
  });
  const { onModelSelected, ...prefixOptions } = createReplyPrefixOptions({
    cfg,
    agentId: route.agentId,
    channel: "keychat",
    accountId,
  });

  // Buffer and merge deliver() calls
  let deliverBuffer: string[] = [];
  let deliverTimer: ReturnType<typeof setTimeout> | null = null;
  const DELIVER_DEBOUNCE_MS = 1500;

  const flushDeliverBuffer = async () => {
    deliverTimer = null;
    if (deliverBuffer.length === 0) return;
    const merged = deliverBuffer.join("\n\n").trim();
    deliverBuffer = [];
    if (!merged) return;
    try {
      await retrySend(() => bridge.mlsSendMessage(groupId, merged));
    } catch (err) {
      ctx.log?.error(`[${accountId}] MLS group reply delivery failed: ${err}`);
    }
  };

  await core.channel.reply.dispatchReplyWithBufferedBlockDispatcher({
    ctx: ctxPayload,
    cfg,
    dispatcherOptions: {
      ...prefixOptions,
      deliver: async (payload: { text?: string }) => {
        if (!payload.text) return;
        const message = stripReasoningPrefix(core.channel.text.convertMarkdownTables(payload.text, tableMode));
        deliverBuffer.push(message);
        if (deliverTimer) clearTimeout(deliverTimer);
        deliverTimer = setTimeout(() => { flushDeliverBuffer(); }, DELIVER_DEBOUNCE_MS);
      },
      onError: (err: unknown) => {
        ctx.log?.error(`[${accountId}] MLS group reply delivery failed: ${err}`);
      },
    },
    replyOptions: {
      onModelSelected,
    },
  });

  // Flush remaining
  if (deliverTimer) clearTimeout(deliverTimer);
  await flushDeliverBuffer();
}

/** Handle a kind:4 DM (Signal-encrypted message). */
async function handleEncryptedDM(
  bridge: KeychatBridgeClient,
  accountId: string,
  msg: InboundMessage,
  ctx: { log?: { info: (m: string) => void; error: (m: string) => void; warn?: (m: string) => void }; setStatus: (s: Record<string, unknown> | any) => void },
  runtime: ReturnType<typeof getKeychatRuntime>,
): Promise<void> {
  // kind:4 is published from an ephemeral event key, so from_pubkey is not a stable peer identifier.
  // to_address is authoritative because it is our subscribed receiving address used for routing.
  // Resolve by to_address first from in-memory map, then DB mapping cache.
  let peerNostrPubkey: string | null = null;
  if (msg.to_address) {
    peerNostrPubkey = getAddressToPeer(accountId).get(msg.to_address) ?? null;
    if (!peerNostrPubkey) {
      try {
        const { mappings: dbMappings } = await bridge.getAddressMappings();
        const found = dbMappings.find((m) => m.address === msg.to_address);
        if (found) {
          peerNostrPubkey = found.peer_nostr_pubkey;
          getAddressToPeer(accountId).set(msg.to_address, peerNostrPubkey);
          ctx.log?.info(`[${accountId}] Resolved peer from DB address mapping: ${peerNostrPubkey}`);
        }
      } catch { /* best effort */ }
    }
  }

  // Protocol Step 3: accept-first arrives on A_onetimekey as a kind:4 PreKey message.
  // Only this path can establish a new session before normal routing metadata exists.
  const hasPeerSession = peerNostrPubkey ? getPeerSessions(accountId).has(peerNostrPubkey) : false;
  ctx.log?.info(`[${accountId}] DEBUG: peerNostrPubkey=${peerNostrPubkey}, hasPeerSession=${hasPeerSession}, is_prekey=${msg.is_prekey}, to_address=${msg.to_address}`);
  if ((!peerNostrPubkey || !hasPeerSession) && msg.is_prekey) {
    try {
      const prekeyInfo = await bridge.parsePrekeySender(msg.encrypted_content);
      ctx.log?.info(`[${accountId}] parsePrekeySender result: is_prekey=${prekeyInfo.is_prekey}, signal_identity_key=${prekeyInfo.signal_identity_key}`);
      if (prekeyInfo.is_prekey && prekeyInfo.signal_identity_key) {
        const sigKey = prekeyInfo.signal_identity_key;
        // Identify the sender deterministically for accept-first:
        // 1) signed_pre_key_id mapping (preferred), 2) to_address/onetimekey mapping.
        if (!peerNostrPubkey || !getPeerSessions(accountId).has(peerNostrPubkey)) {
          let senderNostrId: string | null = null;
          let senderName = sigKey.slice(0, 12);
          if (prekeyInfo.signed_pre_key_id != null) {
            try {
              const lookup = await bridge.lookupPeerBySignedPrekeyId(prekeyInfo.signed_pre_key_id);
              if (lookup.nostr_pubkey) {
                senderNostrId = lookup.nostr_pubkey;
                ctx.log?.info(`[${accountId}] PreKey sender identified via signed_prekey_id=${prekeyInfo.signed_pre_key_id} → ${senderNostrId}`);
              }
            } catch (e) {
              ctx.log?.error(`[${accountId}] lookupPeerBySignedPrekeyId failed: ${e}`);
            }
          }

          // Fallback to onetimekey routing mapping from Protocol Step 1 hello.
          if (!senderNostrId && peerNostrPubkey) {
            senderNostrId = peerNostrPubkey;
            ctx.log?.info(`[${accountId}] PreKey sender identified via onetimekey addressToPeer mapping: ${senderNostrId}`);
          }

          if (!senderNostrId) {
            ctx.log?.error(
              `[${accountId}] ⚠️ PreKey from unknown signal key ${sigKey} — signed_prekey_id lookup and onetimekey mapping both failed. Dropping.`,
            );
            return;
          }

          // Protocol Step 4: Reproduce X3DH and decrypt accept-first PreKey payload.
          const decryptResult = await bridge.decryptMessage(sigKey, msg.encrypted_content, true);
          const { plaintext } = decryptResult;

          // Try to extract name from PrekeyMessageModel if available
          try {
            const parsed = JSON.parse(plaintext);
            if (parsed?.name) senderName = parsed.name;
          } catch { /* not JSON */ }

          // Register the peer session
          const newPeer: PeerSession = {
            signalPubkey: sigKey,
            deviceId: 1,
            name: senderName,
            nostrPubkey: senderNostrId,
          };
          getPeerSessions(accountId).set(senderNostrId, newPeer);
          await bridge.savePeerMapping(senderNostrId, sigKey, 1, senderName);
          // Clear sensitive PreKey material now that session is established
          try { await bridge.clearPrekeyMaterial(senderNostrId); } catch { /* best effort */ }
          ctx.log?.info(`[${accountId}] ✅ Session established with ${senderNostrId} (signal: ${sigKey})`);

          // A-role: Protocol Step 4 — received accept-first, reproduced X3DH, session established.
          // initiatedByUs was already set to true when we sent the hello (ensureOutgoingHelloAndHandshakeSubscriptions).
          friendRequestManager.setSessionEstablished(accountId, senderNostrId);

          // Step 4: after accept-first decrypt, subscribe to per-peer ratchet addresses from alice_addrs.
          try {
            const aliceAddrs: string[] = decryptResult?.alice_addrs ?? [];
            const added = await registerPeerReceivingAddresses(bridge, accountId, senderNostrId, aliceAddrs);
            if (added > 0) {
              const total = getPeerSubscribedAddresses(accountId).get(senderNostrId)?.length ?? 0;
              ctx.log?.info(`[${accountId}] Registered ${added} receiving address(es) for new peer ${senderNostrId.slice(0,16)} (total ${total})`);
            }
          } catch { /* best effort */ }

          const initiatedByUs = friendRequestManager.isInitiatorSidePending(accountId, senderNostrId);
          if (initiatedByUs) {
            await friendRequestManager.flushQueuedAfterSession(bridge, accountId, senderNostrId);
          }

          // Parse and dispatch the decrypted content
          let displayText = plaintext;
          try {
            const parsed = JSON.parse(plaintext);
            // PrekeyMessageModel uses 'message' field; KeychatMessage uses 'msg'
            if (parsed && typeof parsed.message === "string") {
              displayText = parsed.message;
              // The message field may contain a nested KeychatMessage JSON
              try {
                const inner = JSON.parse(parsed.message);
                if (inner && typeof inner.msg === "string") {
                  displayText = inner.msg;
                }
              } catch { /* not nested JSON */ }
            } else if (parsed && typeof parsed.msg === "string") {
              displayText = parsed.msg;
            }
            // If this is a PrekeyMessageModel (hello reply wrapper), don't dispatch to agent
            if (parsed?.nostrId && parsed?.signalId) {
              ctx.log?.info(`[${accountId}] Hello reply from ${senderNostrId}: ${displayText.slice(0, 80)}`);
              return; // Protocol handshake overhead — don't dispatch
            }
          } catch { /* not JSON — dispatch as regular message */ }

          // DM Policy gate
          const prekeyAccess = resolveDmAccess(accountId, senderNostrId, runtime);
          if (prekeyAccess.decision === "block") {
            ctx.log?.info(`[${accountId}] ⛔ Blocked PreKey message from ${senderNostrId} — dmPolicy`);
            return;
          }
          if (prekeyAccess.decision === "pairing") {
            ctx.log?.info(`[${accountId}] ⛔ PreKey message from ${senderNostrId} — pending pairing`);
            const { code, created } = upsertKeychatPairingRequest(senderNostrId, { name: senderName }, accountId);
            if (created && code) {
              try {
                const pairingResult = await retrySend(() => bridge.sendMessage(senderNostrId, buildKeychatPairingReply(code, senderNostrId)));
                await handleReceivingAddressRotation(bridge, accountId, pairingResult, senderNostrId);
              } catch { /* best effort */ }
            }
            return;
          }
          // Dispatch non-hello PreKey messages to agent
          await dispatchToAgent(bridge, accountId, senderNostrId, senderName, displayText, msg.event_id, runtime, ctx);
          return;
        }
      }
    } catch (err) {
      ctx.log?.error(`[${accountId}] PreKey parse/decrypt FAILED: ${err}`);
      console.error(`[keychat] PreKey error:`, err);
    }
  }

  // No brute-force fallback — if we can't identify the peer, drop the message.
  // Guessing would risk sending replies to the wrong person (privacy leak).

  if (!peerNostrPubkey) {
    ctx.log?.error(
      `[${accountId}] Cannot identify peer for inbound kind:4 (to_address=${msg.to_address}, from=${msg.from_pubkey})`,
    );
    return;
  }

  const peer = getPeerSessions(accountId).get(peerNostrPubkey);
  if (!peer) {
    ctx.log?.error(`[${accountId}] No session info for peer ${peerNostrPubkey}`);
    return;
  }

  // Decrypt using peer's Signal (curve25519) pubkey
  ctx.log?.info(`[${accountId}] Routing decrypt to peer ${peerNostrPubkey} (signal: ${peer.signalPubkey})`);
  let decryptResult;
  // peer is now guaranteed correct (no fallback to other peers)
  try {
    decryptResult = await bridge.decryptMessage(peer.signalPubkey, msg.encrypted_content, msg.is_prekey);
  } catch (err) {
    // Do NOT try other peers — Signal decrypt consumes message keys (irreversible).
    // Attempting decrypt with wrong peer would corrupt their ratchet state.
    ctx.log?.error(
      `[${accountId}] ⚠️ Decrypt failed for peer ${peerNostrPubkey} (signal: ${peer.signalPubkey}), event_id=${msg.event_id}: ${err}. Dropping message. Peer may need to reset Signal session.`,
    );
    return;
  }
  const { plaintext } = decryptResult;
  // State transitions are constrained to:
  // - Protocol Step 4: setSessionEstablished in accept-first handlers.
  // - Protocol Step 5/6: set NORMAL_CHAT only when flushing first queued post-handshake send.

  // Step 5+: after decrypt, use ONLY alice_addrs from this message (per-peer ratchet addresses).
  try {
    const aliceAddrs: string[] = (decryptResult as any)?.alice_addrs ?? [];
    const newAddrs = await registerPeerReceivingAddresses(bridge, accountId, peerNostrPubkey, aliceAddrs);
    if (newAddrs > 0) {
      const peerAddrs = getPeerSubscribedAddresses(accountId).get(peerNostrPubkey) ?? [];
      ctx.log?.info(
        `[${accountId}] Updated ${newAddrs} receiving address(es) after decrypt (peer: ${peerNostrPubkey.slice(0,16)}, total ${peerAddrs.length})`,
      );
    }
  } catch (err) {
    ctx.log?.error(`[${accountId}] Failed to update receiving addresses after decrypt: ${err}`);
  }

  // Lazy cleanup: now that we received a message on msg.to_address, remove older
  // addresses for this peer (keep REMAIN_RECEIVE_KEYS_PER_PEER most recent).
  // This matches Keychat app's deleteReceiveKey behavior — only clean up when we
  // have proof the peer is using a newer address.
  if (peerNostrPubkey && msg.to_address) {
    try {
      const peerAddrs = getPeerSubscribedAddresses(accountId).get(peerNostrPubkey) ?? [];
      const idx = peerAddrs.indexOf(msg.to_address);
      if (idx >= 0 && peerAddrs.length > REMAIN_RECEIVE_KEYS_PER_PEER) {
        // Keep addresses from (idx - REMAIN_RECEIVE_KEYS_PER_PEER + 1) onward
        const keepFrom = Math.max(0, idx - REMAIN_RECEIVE_KEYS_PER_PEER + 1);
        if (keepFrom > 0) {
          const staleAddrs = peerAddrs.slice(0, keepFrom);
          const remaining = peerAddrs.slice(keepFrom);
          getPeerSubscribedAddresses(accountId).set(peerNostrPubkey, remaining);
          for (const old of staleAddrs) {
            getAddressToPeer(accountId).delete(old);
            try { await bridge.removeSubscription([old]); } catch { /* */ }
            try { await bridge.deleteAddressMapping(old); } catch { /* */ }
          }
          if (staleAddrs.length > 0) {
            ctx.log?.info(
              `[${accountId}] Lazy cleanup: removed ${staleAddrs.length} old address(es) for peer ${peerNostrPubkey.slice(0,16)}, kept ${remaining.length}`,
            );
          }
        }
      }
    } catch (err) {
      ctx.log?.error(`[${accountId}] Lazy address cleanup failed: ${err}`);
    }
  }

  // The decrypted content may be a KeychatMessage JSON — extract the `msg` field
  // and optionally the `name` field (MsgReply for quoted messages)
  let displayText = plaintext;
  let groupContext: { groupId: string; groupMessage: { message: string; pubkey: string; subtype?: number; ext?: string } } | null = null;
  ctx.log?.info(`[${accountId}] Raw plaintext (first 300 chars): ${plaintext.slice(0, 300)}`);
  try {
    const parsed = JSON.parse(plaintext);
    if (parsed && typeof parsed.msg === "string") {
      // Check if this is a group message (type=30, c="group")
      if (parsed.type === 30 && parsed.c === "group") {
        try {
          const gm = JSON.parse(parsed.msg);
          if (gm && typeof gm.message === "string" && typeof gm.pubkey === "string") {
            groupContext = { groupId: gm.pubkey, groupMessage: gm };
            displayText = gm.message;

            // Handle group system messages
            const isSystemMsg = [14, 15, 16, 17, 20, 32].includes(gm.subtype);
            if (isSystemMsg) {
              displayText = `[System] ${gm.message}`;

              // Update DB state for destructive group events
              if (gm.subtype === 17) {
                // groupDissolve — mark group as disabled
                try {
                  await bridge.updateGroupStatus(gm.pubkey, "disabled");
                  ctx.log?.info(`[${accountId}] Group ${gm.pubkey} dissolved, marked disabled`);
                } catch (err) {
                  ctx.log?.error(`[${accountId}] Failed to disable dissolved group: ${err}`);
                }
              } else if (gm.subtype === 16) {
                // groupSelfLeave — remove the member who left
                try {
                  await bridge.removeGroupMember(gm.pubkey, peerNostrPubkey);
                  ctx.log?.info(`[${accountId}] Removed ${peerNostrPubkey} from group ${gm.pubkey} (self-leave)`);
                } catch (err) {
                  ctx.log?.error(`[${accountId}] Failed to remove left member: ${err}`);
                }
              } else if (gm.subtype === 32 && gm.ext) {
                // groupRemoveSingleMember — ext contains the removed member's id_pubkey
                try {
                  await bridge.removeGroupMember(gm.pubkey, gm.ext);
                  ctx.log?.info(`[${accountId}] Removed ${gm.ext} from group ${gm.pubkey} (kicked)`);
                } catch (err) {
                  ctx.log?.error(`[${accountId}] Failed to remove kicked member: ${err}`);
                }
              } else if (gm.subtype === 20 && gm.ext) {
                // groupChangeRoomName — ext contains the new name
                try {
                  await bridge.updateGroupName(gm.pubkey, gm.ext);
                  ctx.log?.info(`[${accountId}] Group ${gm.pubkey} renamed to "${gm.ext}"`);
                } catch (err) {
                  ctx.log?.error(`[${accountId}] Failed to update group name: ${err}`);
                }
              }
            }
          }
        } catch {
          displayText = parsed.msg;
        }
      } else {
        displayText = parsed.msg;

        // Check for quoted/reply message in `name` field (MsgReply JSON)
        // Format: { id?: string, user: string, content: string }
        if (parsed.name && parsed.type === 100) {
          try {
            const reply = JSON.parse(parsed.name);
            if (reply && typeof reply.content === "string") {
              const quotedUser = reply.user || "unknown";
              displayText = `[Replying to ${quotedUser}: "${reply.content}"]\n${parsed.msg}`;
            }
          } catch {
            // name is not MsgReply JSON (could be other data), ignore
          }
        }
      }
    }
  } catch {
    // Not JSON — use plaintext as-is
  }

  // Handle group invite messages (type=11, c="group")
  if (!groupContext) {
    try {
      const parsed = JSON.parse(plaintext);
      if (parsed && parsed.type === 11 && parsed.c === "group" && parsed.msg) {
        const roomProfile = JSON.parse(parsed.msg);
        // Extract sender info from parsed.name: JSON array [realMessage, senderIdPubkey]
        let senderIdPubkey = peerNostrPubkey;
        let inviteMessage = "Group invite received";
        if (parsed.name) {
          try {
            const nameData = JSON.parse(parsed.name);
            if (Array.isArray(nameData) && nameData.length >= 2) {
              inviteMessage = nameData[0];
              senderIdPubkey = nameData[1];
            }
          } catch { /* ignore */ }
        }

        // Join the group via bridge
        ctx.log?.info(`[${accountId}] Received group invite: ${roomProfile.name} from ${senderIdPubkey}`);
        const joinResult = await bridge.joinGroup(roomProfile, senderIdPubkey);
        ctx.log?.info(`[${accountId}] Joined group '${joinResult.name}' (${joinResult.group_id}), ${joinResult.member_count} members`);

        // Send hello to the group
        const helloText = `😃 Hi, I am Agent`;
        try {
          const ghResult2 = await bridge.sendGroupMessage(joinResult.group_id, helloText, { subtype: 14 });
          if (ghResult2.member_rotations?.length) {
            for (const rot of ghResult2.member_rotations) {
              await handleReceivingAddressRotation(bridge, accountId, { new_receiving_address: rot.new_receiving_address } as any, rot.member);
            }
          }
        } catch (err) {
          ctx.log?.error(`[${accountId}] Failed to send group hello: ${err}`);
        }

        // Dispatch invite notification to agent
        displayText = `[Group Invite] ${inviteMessage}. Joined group "${joinResult.name}" with ${joinResult.member_count} members.`;
        // Route as group message
        groupContext = { groupId: joinResult.group_id, groupMessage: { message: displayText, pubkey: joinResult.group_id } };
      }
    } catch {
      // Not a group invite, continue normal processing
    }
  }

  // Check if message is an encrypted media URL
  let mediaPath: string | undefined;
  const mediaInfo = parseMediaUrl(displayText);
  if (mediaInfo) {
    try {
      const localPath = await downloadAndDecrypt(mediaInfo);
      mediaPath = localPath;
      ctx.log?.info(`[${accountId}] Downloaded ${mediaInfo.kctype}: ${localPath}`);
      
      // Voice note: transcribe to text via STT
      if (mediaInfo.isVoiceNote) {
        try {
          const sttConfig: SttConfig = { 
            provider: "whisper-cpp",
            language: "auto",
          };
          const transcription = await transcribe(localPath, sttConfig);
          ctx.log?.info(`[${accountId}] Voice note transcribed (${mediaInfo.duration || '?'}s): ${transcription.slice(0, 80)}...`);
          displayText = `[voice message, ${mediaInfo.duration || '?'}s] ${transcription}`;
        } catch (sttErr) {
          ctx.log?.error(`[${accountId}] Voice note STT failed: ${sttErr}`);
          displayText = `[voice message, ${mediaInfo.duration || '?'}s — transcription failed, audio saved to ${localPath}]`;
        }
      } else {
        displayText = `[${mediaInfo.kctype}: ${mediaInfo.sourceName || mediaInfo.suffix}] (saved to ${localPath})`;
      }
    } catch (err) {
      ctx.log?.error(`[${accountId}] Failed to download media: ${err}`);
      displayText = `[${mediaInfo.kctype} message — download failed]`;
    }
  }

  ctx.log?.info(
    `[${accountId}] Decrypted from ${peer.name} (${peerNostrPubkey}): ${displayText.slice(0, 50)}...`,
  );

  // Forward to OpenClaw's message pipeline via shared dispatch helper
  const senderLabel = peer.name || peerNostrPubkey.slice(0, 12);

  if (groupContext) {
    // Route group messages to a group-specific dispatch
    ctx.log?.info(`[${accountId}] Detected group message: groupId=${groupContext.groupId}, subtype=${groupContext.groupMessage.subtype}, sender=${peerNostrPubkey}`);
    await dispatchGroupToAgent(bridge, accountId, groupContext.groupId, peerNostrPubkey, senderLabel, displayText, msg.event_id, runtime, ctx, groupContext.groupMessage, mediaPath);
  } else {
    // DM Policy gate
    const dmAccess = resolveDmAccess(accountId, peerNostrPubkey, runtime);
    if (dmAccess.decision === "block") {
      ctx.log?.info(`[${accountId}] ⛔ Blocked DM from ${peerNostrPubkey} — dmPolicy`);
      return;
    }
    if (dmAccess.decision === "pairing") {
      ctx.log?.info(`[${accountId}] ⛔ DM from ${peerNostrPubkey} — pending pairing`);
      const { code, created } = upsertKeychatPairingRequest(peerNostrPubkey, { name: peer.name }, accountId);
      if (created && code) {
        try {
          const pairingResult = await retrySend(() => bridge.sendMessage(peerNostrPubkey, buildKeychatPairingReply(code, peerNostrPubkey)));
          await handleReceivingAddressRotation(bridge, accountId, pairingResult, peerNostrPubkey);
        } catch { /* best effort */ }
      }
      return;
    }
    ctx.log?.info(`[${accountId}] Routing as 1:1 DM (no group context detected)`);
    await dispatchToAgent(bridge, accountId, peerNostrPubkey, senderLabel, displayText, msg.event_id, runtime, ctx, mediaPath);
  }
}

/** Shared helper: dispatch a message through the agent pipeline. */
async function dispatchToAgent(
  bridge: KeychatBridgeClient,
  accountId: string,
  peerNostrPubkey: string,
  peerName: string,
  displayText: string,
  eventId: string,
  runtime: ReturnType<typeof getKeychatRuntime>,
  ctx: { log?: { info: (m: string) => void; error: (m: string) => void; warn?: (m: string) => void }; setStatus: (s: Record<string, unknown> | any) => void },
  mediaPath?: string,
): Promise<void> {
  const core = runtime;
  const cfg = core.config.loadConfig();

  const route = core.channel.routing.resolveAgentRoute({
    cfg,
    channel: "keychat",
    accountId,
    peer: {
      kind: "direct",
      id: peerNostrPubkey,
    },
  });

  const senderLabel = peerName || peerNostrPubkey.slice(0, 12);
  const body = core.channel.reply.formatAgentEnvelope({
    channel: "Keychat",
    from: senderLabel,
    timestamp: Date.now(),
    body: displayText,
  });

  const ctxPayload = core.channel.reply.finalizeInboundContext({
    Body: body,
    RawBody: displayText,
    CommandBody: displayText,
    From: `keychat:${peerNostrPubkey}`,
    To: `keychat:${accountId}`,
    SessionKey: route.sessionKey,
    AccountId: accountId,
    ChatType: "direct" as const,
    SenderName: senderLabel,
    SenderId: peerNostrPubkey,
    Provider: "keychat" as const,
    Surface: "keychat" as const,
    MessageSid: eventId,
    OriginatingChannel: "keychat" as const,
    OriginatingTo: `keychat:${peerNostrPubkey}`,
    ...(mediaPath ? { MediaPath: mediaPath } : {}),
  });

  const tableMode = core.channel.text.resolveMarkdownTableMode({
    cfg,
    channel: "keychat",
    accountId,
  });
  const { onModelSelected, ...prefixOptions } = createReplyPrefixOptions({
    cfg,
    agentId: route.agentId,
    channel: "keychat",
    accountId,
  });

  const peerPubkey = peerNostrPubkey;

  // Buffer multiple deliver() calls and merge them into a single Keychat message.
  // The dispatcher may call deliver() multiple times for tool-call narration, thinking
  // leakage, or chunked streaming — we batch them to avoid message spam.
  let deliverBuffer: string[] = [];
  let deliverTimer: ReturnType<typeof setTimeout> | null = null;
  const DELIVER_DEBOUNCE_MS = 1500;

  const flushDeliverBuffer = async () => {
    deliverTimer = null;
    if (deliverBuffer.length === 0) return;
    const merged = deliverBuffer.join("\n\n").trim();
    deliverBuffer = [];
    if (!merged) return;
    try {
      const result = await retrySend(() => bridge.sendMessage(peerPubkey, merged));
      await handleReceivingAddressRotation(bridge, accountId, result, peerPubkey);
    } catch (err) {
      ctx.log?.error(`[${accountId}] Reply delivery failed: ${err}`);
    }
  };

  await core.channel.reply.dispatchReplyWithBufferedBlockDispatcher({
    ctx: ctxPayload,
    cfg,
    dispatcherOptions: {
      ...prefixOptions,
      deliver: async (payload: { text?: string }) => {
        if (!payload.text) return;
        const message = stripReasoningPrefix(core.channel.text.convertMarkdownTables(payload.text, tableMode));
        deliverBuffer.push(message);
        // Reset debounce timer — wait for more chunks before sending
        if (deliverTimer) clearTimeout(deliverTimer);
        deliverTimer = setTimeout(() => { flushDeliverBuffer(); }, DELIVER_DEBOUNCE_MS);
      },
      onError: (err: unknown) => {
        ctx.log?.error(`[${accountId}] Reply delivery failed: ${err}`);
      },
    },
    replyOptions: {
      onModelSelected,
    },
  });

  // Flush any remaining buffered text after dispatcher completes
  if (deliverTimer) clearTimeout(deliverTimer);
  await flushDeliverBuffer();
}

/** Shared helper: dispatch a GROUP message through the agent pipeline. */
async function dispatchGroupToAgent(
  bridge: KeychatBridgeClient,
  accountId: string,
  groupId: string,
  peerNostrPubkey: string,
  peerName: string,
  displayText: string,
  eventId: string,
  runtime: ReturnType<typeof getKeychatRuntime>,
  ctx: { log?: { info: (m: string) => void; error: (m: string) => void; warn?: (m: string) => void }; setStatus: (s: Record<string, unknown> | any) => void },
  groupMessage: { message: string; pubkey: string; subtype?: number; ext?: string },
  mediaPath?: string,
): Promise<void> {
  const core = runtime;
  const cfg = core.config.loadConfig();

  // Use group-specific session key
  const route = core.channel.routing.resolveAgentRoute({
    cfg,
    channel: "keychat",
    accountId,
    peer: {
      kind: "group",
      id: groupId,
    },
  });

  const senderLabel = peerName || peerNostrPubkey.slice(0, 12);

  // Get group info for context
  let groupName = groupId.slice(0, 12);
  try {
    const groupInfo = await bridge.getGroup(groupId);
    if (groupInfo.name) groupName = groupInfo.name;
  } catch { /* best effort */ }

  const body = core.channel.reply.formatAgentEnvelope({
    channel: "Keychat",
    from: senderLabel,
    timestamp: Date.now(),
    body: displayText,
  });

  const ctxPayload = core.channel.reply.finalizeInboundContext({
    Body: body,
    RawBody: displayText,
    CommandBody: displayText,
    From: `keychat:${peerNostrPubkey}`,
    To: `keychat:group:${groupId}`,
    SessionKey: route.sessionKey,
    AccountId: accountId,
    ChatType: "group" as const,
    SenderName: senderLabel,
    SenderId: peerNostrPubkey,
    GroupId: groupId,
    GroupName: groupName,
    Provider: "keychat" as const,
    Surface: "keychat" as const,
    MessageSid: eventId,
    OriginatingChannel: "keychat" as const,
    OriginatingTo: `keychat:group:${groupId}`,
    ...(mediaPath ? { MediaPath: mediaPath } : {}),
  });

  const tableMode = core.channel.text.resolveMarkdownTableMode({
    cfg,
    channel: "keychat",
    accountId,
  });
  const { onModelSelected, ...prefixOptions } = createReplyPrefixOptions({
    cfg,
    agentId: route.agentId,
    channel: "keychat",
    accountId,
  });

  // Buffer and merge deliver() calls
  let deliverBuffer: string[] = [];
  let deliverTimer: ReturnType<typeof setTimeout> | null = null;
  const DELIVER_DEBOUNCE_MS = 1500;

  const flushDeliverBuffer = async () => {
    deliverTimer = null;
    if (deliverBuffer.length === 0) return;
    const merged = deliverBuffer.join("\n\n").trim();
    deliverBuffer = [];
    if (!merged) return;
    try {
      // Send reply to the GROUP, not individual peer
      const groupResult = await retrySend(() => bridge.sendGroupMessage(groupId, merged));
      // Handle receiving address rotation for each group member
      if (groupResult.member_rotations?.length) {
        for (const rot of groupResult.member_rotations) {
          await handleReceivingAddressRotation(bridge, accountId, { new_receiving_address: rot.new_receiving_address } as any, rot.member);
        }
      }
    } catch (err) {
      ctx.log?.error(`[${accountId}] Group reply delivery failed: ${err}`);
    }
  };

  await core.channel.reply.dispatchReplyWithBufferedBlockDispatcher({
    ctx: ctxPayload,
    cfg,
    dispatcherOptions: {
      ...prefixOptions,
      deliver: async (payload: { text?: string }) => {
        if (!payload.text) return;
        const message = stripReasoningPrefix(core.channel.text.convertMarkdownTables(payload.text, tableMode));
        deliverBuffer.push(message);
        if (deliverTimer) clearTimeout(deliverTimer);
        deliverTimer = setTimeout(() => { flushDeliverBuffer(); }, DELIVER_DEBOUNCE_MS);
      },
      onError: (err: unknown) => {
        ctx.log?.error(`[${accountId}] Group reply delivery failed: ${err}`);
      },
    },
    replyOptions: {
      onModelSelected,
    },
  });

  // Flush remaining
  if (deliverTimer) clearTimeout(deliverTimer);
  await flushDeliverBuffer();
}

/** Subscribe + persist per-peer receiving addresses derived from ratchet updates. */
async function registerPeerReceivingAddresses(
  bridge: KeychatBridgeClient,
  accountId: string,
  peerNostrPubkey: string,
  addresses: string[],
): Promise<number> {
  const unique = Array.from(new Set(addresses.filter(Boolean)));
  const newAddrs = unique.filter((a) => !getAddressToPeer(accountId).has(a));
  if (newAddrs.length === 0) return 0;

  await bridge.addSubscription(newAddrs);
  const peerAddrs = getPeerSubscribedAddresses(accountId).get(peerNostrPubkey) ?? [];
  for (const addr of newAddrs) {
    getAddressToPeer(accountId).set(addr, peerNostrPubkey);
    peerAddrs.push(addr);
    try { await bridge.saveAddressMapping(addr, peerNostrPubkey); } catch { /* best effort */ }
  }
  getPeerSubscribedAddresses(accountId).set(peerNostrPubkey, peerAddrs);
  return newAddrs.length;
}

/** After each send or decrypt, rotate receiving addresses if a new one was generated. */
async function handleReceivingAddressRotation(
  bridge: KeychatBridgeClient,
  accountId: string,
  sendResult: SendMessageResult,
  peerKey?: string,
): Promise<void> {
  if (!sendResult.new_receiving_address) return;

  const { address } = await bridge.computeAddress(sendResult.new_receiving_address);

  if (!peerKey) {
    console.warn(`[keychat] handleReceivingAddressRotation: peerKey is falsy, skipping DB save for ${address.slice(0,16)}`);
    return;
  }
  await registerPeerReceivingAddresses(bridge, accountId, peerKey, [address]);
}

/**
 * Perform an MLS self-update (key rotation) for the given group.
 * This generates a new epoch, rotates the listen key, and re-publishes the KeyPackage.
 */
export async function updateGroupKey(
  groupId: string,
  accountId: string = DEFAULT_ACCOUNT_ID,
): Promise<void> {
  const bridge = activeBridges.get(accountId);
  if (!bridge) throw new Error(`No bridge for account ${accountId}`);

  const log = (...args: unknown[]) => console.log(`[keychat:${accountId}] MLS key rotation:`, ...args);

  // 1. Get current listen key
  const { listen_key: oldKey } = await bridge.mlsGetListenKey(groupId);

  // 2. Generate self-update commit
  const result = await bridge.mlsSelfUpdate(groupId, { name: "Agent" });

  // 3. Publish commit to the OLD listen key
  await bridge.mlsPublishToGroup(oldKey, result.encrypted_msg);

  // 4. Merge pending commit locally
  await bridge.mlsSelfCommit(groupId);

  // 5. Get new listen key
  const { listen_key: newKey } = await bridge.mlsGetListenKey(groupId);

  // 6. Update subscriptions if key changed
  if (newKey !== oldKey) {
    mlsListenKeyToGroup.delete(oldKey);
    mlsListenKeyToGroup.set(newKey, groupId);
    await bridge.removeSubscription([oldKey]);
    await bridge.addSubscription([newKey]);
    log(`listen key rotated: ${oldKey.slice(0, 12)}... → ${newKey.slice(0, 12)}...`);
  } else {
    log(`completed (key unchanged)`);
  }

  // 7. Re-publish KeyPackage
  try {
    await bridge.mlsPublishKeyPackage();
  } catch (err) {
    log(`warning: failed to re-publish KeyPackage: ${err}`);
  }

}

/**
 * Get the agent's Keychat ID info for display/pairing.
 */
export function getAgentKeychatId(
  accountId: string = DEFAULT_ACCOUNT_ID,
): AccountInfo | undefined {
  return accountInfoCache.get(accountId);
}

/**
 * Generate a Keychat add-contact URL for the agent.
 * Users can open this URL or scan the QR code with Keychat app.
 */
export function getAgentKeychatUrl(accountId: string = DEFAULT_ACCOUNT_ID): string | null {
  const info = accountInfoCache.get(accountId);
  if (!info) return null;
  return `https://www.keychat.io/u/?k=${info.pubkey_npub}`;
}

/**
 * Get the agent's contact info for pairing/sharing.
 * Returns npub, contact URL, and QR code path if available.
 */
export function getContactInfo(accountId: string = DEFAULT_ACCOUNT_ID): {
  npub: string;
  contactUrl: string;
  qrCodePath: string;
} | null {
  const info = accountInfoCache.get(accountId);
  if (!info) return null;
  return {
    npub: info.pubkey_npub,
    contactUrl: `https://www.keychat.io/u/?k=${info.pubkey_npub}`,
    qrCodePath: qrCodePath(accountId),
  };
}

/**
 * Get contact info for ALL active Keychat accounts/agents.
 * Returns an array of { accountId, npub, contactUrl, qrCodePath, name }.
 */
export function getAllAgentContacts(): Array<{
  accountId: string;
  npub: string;
  contactUrl: string;
  qrCodePath: string;
}> {
  const results: Array<{
    accountId: string;
    npub: string;
    contactUrl: string;
    qrCodePath: string;
  }> = [];
  for (const [accountId, info] of accountInfoCache.entries()) {
    results.push({
      accountId,
      npub: info.pubkey_npub,
      contactUrl: `https://www.keychat.io/u/?k=${info.pubkey_npub}`,
      qrCodePath: qrCodePath(accountId),
    });
  }
  return results;
}

/**
 * Reset the Signal session with a peer and optionally re-send hello.
 * Equivalent to "Reset Signal Session" in the Keychat app.
 *
 * @param peerPubkey - Nostr pubkey (hex or npub) of the peer
 * @param accountId - Account to reset session for
 * @param resendHello - Whether to send a new hello after reset (default: true)
 */
export async function resetPeerSession(
  peerPubkey: string,
  accountId: string = DEFAULT_ACCOUNT_ID,
  resendHello: boolean = true,
): Promise<{ reset: boolean; helloSent?: boolean; error?: string }> {
  const normalizedPeer = normalizePubkey(peerPubkey);
  const bridge = activeBridges.get(accountId);
  if (!bridge) {
    return { reset: false, error: `No active bridge for account ${accountId}` };
  }

  // 1. Find the peer's signal pubkey
  const peerInfo = getPeerSessions(accountId).get(normalizedPeer);
  const signalPubkey = peerInfo?.signalPubkey;

  // 2. Delete Signal session via bridge RPC
  if (signalPubkey) {
    try {
      await bridge.deleteSession(signalPubkey);
      console.log(`[keychat] [${accountId}] Deleted Signal session for ${normalizedPeer} (signal: ${signalPubkey})`);
    } catch (err) {
      console.error(`[keychat] [${accountId}] Failed to delete Signal session: ${err}`);
    }
  }

  // 3. Clear in-memory maps
  getPeerSessions(accountId).delete(normalizedPeer);

  // Clear address mappings pointing to this peer
  const addrMap = getAddressToPeer(accountId);
  for (const [addr, peer] of addrMap) {
    if (peer === normalizedPeer) {
      addrMap.delete(addr);
      try { await bridge.deleteAddressMapping(addr); } catch { /* best effort */ }
    }
  }

  // Reset friend-request state machine for this peer.
  friendRequestManager.resetPeer(accountId, normalizedPeer);
  try { await bridge.deletePendingHelloMessages(normalizedPeer); } catch { /* best effort */ }
  getPeerSubscribedAddresses(accountId).delete(normalizedPeer);

  console.log(`[keychat] [${accountId}] Session reset for peer ${normalizedPeer}`);

  // 4. Optionally re-send hello
  if (resendHello) {
    try {
      const name = "Keychat Agent";
      await friendRequestManager.ensureOutgoingHelloAndHandshakeSubscriptions(
        bridge,
        accountId,
        normalizedPeer,
        name,
      );
      console.log(`[keychat] [${accountId}] Hello re-sent to ${normalizedPeer}`);
      return { reset: true, helloSent: true };
    } catch (err) {
      console.error(`[keychat] [${accountId}] Failed to re-send hello: ${err}`);
      return { reset: true, helloSent: false, error: `Reset OK but hello failed: ${err}` };
    }
  }

  return { reset: true };
}

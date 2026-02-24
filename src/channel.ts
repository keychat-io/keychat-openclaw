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
  // Matches the exact format from formatReasoningMessage():
  //   "Reasoning:\n_line1_\n_line2_\n\nActual answer..."
  const re = /^Reasoning:\n(?:_[^\n]*_\n?)+\n*/;
  return text.replace(re, "").trim();
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
import { join } from "node:path";
import { existsSync, mkdirSync } from "node:fs";
import { signalDbPath, qrCodePath, WORKSPACE_KEYCHAT_DIR } from "./paths.js";

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
// Pending hello messages — queued while waiting for session establishment
// ═══════════════════════════════════════════════════════════════════════════

interface PendingHelloMessage {
  text: string;
  resolve: (result: { channel: "keychat"; to: string; messageId: string }) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

/** Messages waiting for a hello reply to establish session. Keyed by peer nostr pubkey hex. */
const pendingHelloMessages = new Map<string, PendingHelloMessage[]>();
/** Peers we've already sent a hello to (avoid duplicate hellos). */
const helloSentTo = new Set<string>();
const HELLO_TIMEOUT_MS = 120_000; // 2 minutes to wait for hello reply

/** Flush pending hello messages for a peer after session is established. */
async function flushPendingHelloMessages(bridge: KeychatBridgeClient, accountId: string, peerPubkey: string): Promise<void> {
  const pending = pendingHelloMessages.get(peerPubkey);
  if (!pending || pending.length === 0) return;
  pendingHelloMessages.delete(peerPubkey);
  helloSentTo.delete(peerPubkey);

  console.log(`[keychat] Flushing ${pending.length} pending message(s) to ${peerPubkey}`);
  for (const msg of pending) {
    clearTimeout(msg.timer);
    try {
      const result = await bridge.sendMessage(peerPubkey, msg.text);
      await handleReceivingAddressRotation(bridge, accountId, result, peerPubkey);
      msg.resolve({
        channel: "keychat" as const,
        to: peerPubkey,
        messageId: result.event_id,
      });
    } catch (err) {
      msg.reject(err instanceof Error ? err : new Error(String(err)));
    }
  }
}

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
      await bridge.sendMessage(msg.to, msg.text);
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
// peerNostrPubkey → list of subscribed receiving addresses (most recent last, max MAX_RECEIVING_ADDRESSES per peer)
const peerSubscribedAddresses = new Map<string, string[]>();
const MAX_RECEIVING_ADDRESSES = 3;

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
  const trimmed = input.replace(/^nostr:/i, "").trim();
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
      // Try each active bridge — notifyApproval doesn't receive accountId,
      // so send from whichever bridge has a session with this peer.
      for (const [, bridge] of activeBridges) {
        try {
          await bridge.sendMessage(id, "✅ Pairing approved! You can now chat with this agent.");
          return; // sent successfully
        } catch { /* try next bridge */ }
      }
      // Fallback: wait for default bridge
      try {
        const bridge = await waitForBridge(DEFAULT_ACCOUNT_ID, 10000);
        await bridge.sendMessage(id, "✅ Pairing approved! You can now chat with this agent.");
      } catch { /* bridge not ready, skip notification */ }
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

      // Check if we have a session with this peer (placeholder mappings with empty signalPubkey don't count)
      const existingPeer = getPeerSessions(aid).get(normalizedTo);
      const hasSession = !!(existingPeer && existingPeer.signalPubkey);
      if (!hasSession) {
        // No session — need to send hello first and queue the message
        console.log(`[keychat] No session with ${normalizedTo}, initiating hello...`);

        // Send hello if we haven't already
        if (!helloSentTo.has(normalizedTo)) {
          helloSentTo.add(normalizedTo);
          try {
            const accountInfo = accountInfoCache.get(aid);
            const name = accountInfo?.pubkey_npub ? "Keychat Agent" : "Keychat Agent";
            const helloResult = await bridge.sendHello(normalizedTo, name);
            console.log(`[keychat] Hello sent to ${normalizedTo} (event: ${helloResult.event_id})`);

            // Register the onetimekey as an address mapping so the hello reply
            // (sent to our onetimekey) can be routed to this peer.
            if (helloResult.onetimekey) {
              getAddressToPeer(aid).set(helloResult.onetimekey, normalizedTo);
              console.log(`[keychat] Registered onetimekey ${helloResult.onetimekey.slice(0, 16)}... → ${normalizedTo.slice(0, 16)}`);
              try {
                await bridge.saveAddressMapping(helloResult.onetimekey, normalizedTo);
              } catch { /* best effort */ }
            }
          } catch (err) {
            helloSentTo.delete(normalizedTo);
            console.error(`[keychat] Failed to send hello to ${normalizedTo}: ${err}`);
            // Queue for later delivery
            queueOutbound(normalizedTo, message, aid);
            return {
              channel: "keychat" as const,
              to: normalizedTo,
              messageId: `queued-${Date.now()}`,
            };
          }
        }

        // Queue the message and wait for session establishment
        return new Promise<{ channel: "keychat"; to: string; messageId: string }>((resolve, reject) => {
          const timer = setTimeout(() => {
            // Timeout — remove from queue and reject
            const pending = pendingHelloMessages.get(normalizedTo);
            if (pending) {
              const idx = pending.findIndex((m) => m.timer === timer);
              if (idx >= 0) pending.splice(idx, 1);
              if (pending.length === 0) {
                pendingHelloMessages.delete(normalizedTo);
                helloSentTo.delete(normalizedTo);
              }
            }
            // Fall back to queuing for retry
            queueOutbound(normalizedTo, message, aid);
            resolve({
              channel: "keychat" as const,
              to: normalizedTo,
              messageId: `queued-hello-timeout-${Date.now()}`,
            });
          }, HELLO_TIMEOUT_MS);

          const entry: PendingHelloMessage = { text: message, resolve, reject, timer };
          const existing = pendingHelloMessages.get(normalizedTo) ?? [];
          existing.push(entry);
          pendingHelloMessages.set(normalizedTo, existing);
        });
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
    sendMedia: async ({ to, text, mediaUrl: incomingMediaUrl, accountId }) => {
      const aid = accountId ?? DEFAULT_ACCOUNT_ID;
      const bridge = await waitForBridge(aid);

      // Media URL is resolved by the SDK before reaching the plugin
      const mediaUrl = incomingMediaUrl ?? "";

      // Send the media URL as a message (same as Keychat app)
      const caption = text;
      const messageText = caption ? `${mediaUrl}\n${caption}` : mediaUrl;

      // Check if target is an MLS group
      const mlsGroupMatch = to.match(/^mls-group:(.+)$/);
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
      const normalizedTo = normalizePubkey(to);
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

      // Notify agent on first install only (not on every restart)
      const { KEYCHAT_DIR } = await import("./paths.js");
      const notifiedMarker = join(KEYCHAT_DIR, `.notified-${account.accountId}`);
      if (!existsSync(notifiedMarker)) {
        try {
          const { sendSystemEvent } = await import("./notify.js");
          await sendSystemEvent(
            `[Keychat Plugin] Agent "${displayName}" (account: ${account.accountId}) is online and ready.\n` +
            `Use the keychat_identity tool to get the agent's Keychat ID, contact link, and QR code.\n` +
            `Then send the contact info to the user on their active channel using the message tool.\n` +
            `The user can open the link or scan the QR code in Keychat app to add this agent as a contact.`,
          );
          // Mark as notified so we don't repeat on restart
          const { writeFileSync } = await import("node:fs");
          writeFileSync(notifiedMarker, new Date().toISOString());
        } catch {
          ctx.log?.warn?.(`[${account.accountId}] Failed to send system event notification`);
        }
      }

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
          }
        } else {
          // Fallback to raw sessions if no mappings exist yet (backward compat)
          const { sessions } = await bridge.getAllSessions();
          if (sessions.length > 0) {
            ctx.log?.info(`[${account.accountId}] Restored ${sessions.length} peer session(s) from DB (no mappings yet)`);
            for (const s of sessions) {
              getPeerSessions(account.accountId).set(s.signal_pubkey, {
                signalPubkey: s.signal_pubkey,
                deviceId: parseInt(s.device_id, 10),
                name: "",
                nostrPubkey: s.signal_pubkey,
              });
            }
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
            const peerList = peerSubscribedAddresses.get(am.peer_nostr_pubkey) ?? [];
            peerList.push(am.address);
            peerSubscribedAddresses.set(am.peer_nostr_pubkey, peerList);
          }
          ctx.log?.info(`[${account.accountId}] Restored ${addrMappings.length} address-to-peer mapping(s) from DB`);
        }

        // Sync: ensure each peer has up to MAX_RECEIVING_ADDRESSES from session alice_addrs
        // This fills in missing addresses for peers that had sessions but incomplete mappings
        const { addresses: allAliceAddrs } = await bridge.getReceivingAddresses();
        if (allAliceAddrs.length > 0) {
          // Build signal_pubkey → nostr_pubkey mapping from getPeerSessions
          const signalToNostr = new Map<string, string>();
          for (const [nostrPk, info] of getPeerSessions(account.accountId).entries()) {
            signalToNostr.set(info.signalPubkey, nostrPk);
          }

          // Group alice_addrs by peer (via session_address → signal_pubkey → nostr_pubkey)
          const aliceByPeer = new Map<string, string[]>();
          for (const a of allAliceAddrs) {
            const peerNostr = signalToNostr.get(a.session_address);
            if (!peerNostr) continue;
            let list = aliceByPeer.get(peerNostr);
            if (!list) { list = []; aliceByPeer.set(peerNostr, list); }
            list.push(a.nostr_pubkey);
          }

          // For each peer, take latest MAX_RECEIVING_ADDRESSES and save any missing ones
          for (const [peerNostr, aliceAddrs] of aliceByPeer) {
            const latest = aliceAddrs.slice(-MAX_RECEIVING_ADDRESSES);
            const existing = peerSubscribedAddresses.get(peerNostr) ?? [];
            const existingSet = new Set(existing);
            for (const addr of latest) {
              if (!existingSet.has(addr)) {
                getAddressToPeer(account.accountId).set(addr, peerNostr);
                existing.push(addr);
                try { await bridge.saveAddressMapping(addr, peerNostr); } catch { /* */ }
              }
            }
            // Trim to MAX if over
            while (existing.length > MAX_RECEIVING_ADDRESSES) {
              const old = existing.shift()!;
              getAddressToPeer(account.accountId).delete(old);
              try { await bridge.deleteAddressMapping(old); } catch { /* */ }
            }
            peerSubscribedAddresses.set(peerNostr, existing);
          }
        }

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

        // Restore MLS groups and subscribe to their listen keys
        const { groups: mlsGroups } = await bridge.mlsGetGroups();
        for (const groupId of mlsGroups) {
          try {
            const { listen_key } = await bridge.mlsGetListenKey(groupId);
            mlsListenKeyToGroup.set(listen_key, groupId);
            await bridge.addSubscription([listen_key]);
            const info = await bridge.mlsGetGroupInfo(groupId);
            ctx.log?.info(`[${account.accountId}] MLS group restored: "${info.name}" (${groupId}), listen key: ${listen_key.slice(0, 12)}...`);
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
          }
          // Restore address→peer mappings and peerSubscribedAddresses
          const { mappings: addrMappings } = await bridge.getAddressMappings();
          peerSubscribedAddresses.clear();
          for (const am of addrMappings) {
            getAddressToPeer(account.accountId).set(am.address, am.peer_nostr_pubkey);
            const peerList = peerSubscribedAddresses.get(am.peer_nostr_pubkey) ?? [];
            peerList.push(am.address);
            peerSubscribedAddresses.set(am.peer_nostr_pubkey, peerList);
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

  // Skip stale friend requests (relay replays old events on reconnect)
  const MAX_FRIEND_REQUEST_AGE_SECS = 60; // 1 minute
  if (msg.created_at) {
    const ageSecs = Math.floor(Date.now() / 1000) - msg.created_at;
    if (ageSecs > MAX_FRIEND_REQUEST_AGE_SECS) {
      ctx.log?.info(`[${accountId}] Ignoring stale friend request from ${msg.from_pubkey} (age=${ageSecs}s > ${MAX_FRIEND_REQUEST_AGE_SECS}s)`);
      return;
    }
  }

  // If we already have a session, re-process the hello to handle re-pairing
  // (e.g. peer deleted us and re-added, or our previous hello reply wasn't received)
  const existingPeer = getPeerSessions(accountId).get(msg.from_pubkey);
  if (existingPeer) {
    ctx.log?.info(`[${accountId}] Re-processing friend request from ${msg.from_pubkey} (existing session will be replaced)`);
  }

  // Check DM policy before processing — reject unauthorized friend requests
  const core = runtime;
  const cfg = core.config.loadConfig();
  const account = resolveKeychatAccount({ cfg, accountId });
  const displayName = resolveDisplayName(cfg, accountId, account.name);
  const policy = account.config.dmPolicy ?? "pairing";
  const allowFrom = (account.config.allowFrom ?? []).map((e) => normalizePubkey(String(e)));

  if (policy === "disabled") {
    ctx.log?.info(`[${accountId}] Rejecting friend request — dmPolicy is disabled`);
    return;
  }

  const senderNormalized = normalizePubkey(msg.from_pubkey);

  if (policy === "allowlist" && !allowFrom.includes(senderNormalized)) {
    ctx.log?.info(`[${accountId}] Rejecting friend request from ${msg.from_pubkey} — not in allowlist`);
    return;
  }

  if (policy === "pairing" && !allowFrom.includes(senderNormalized)) {
    // Not yet approved — we still establish the session (so we can send the pending message)
    // but flag it for approval via OpenClaw's pairing system
    ctx.log?.info(`[${accountId}] Friend request from ${msg.from_pubkey} — pending pairing approval`);
    // Continue processing but will send a "pending approval" message instead of full access
  }

  // Process hello via bridge — establishes Signal session
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

  // NOTE: peer mapping already persisted by Rust handle_process_hello (with local Signal keys).
  // Do NOT call savePeerMapping here — it would overwrite local_signal_pubkey/privkey with NULL.

  // Auto-reply with hello (type 102 = DM_ADD_CONTACT_FROM_BOB)
  const isPendingApproval = policy === "pairing" && !allowFrom.includes(senderNormalized);
  const greetingText = isPendingApproval
    ? "👋 Hi! I received your request. It's pending approval — the owner will review it shortly."
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

  // Handle receiving address rotation after send (per-peer, limited to MAX_RECEIVING_ADDRESSES)
  await handleReceivingAddressRotation(bridge, accountId, sendResult, hello.peer_nostr_pubkey);

  // Flush any pending messages that were waiting for this session
  if (pendingHelloMessages.has(hello.peer_nostr_pubkey)) {
    ctx.log?.info(`[${accountId}] Flushing pending hello messages for ${hello.peer_nostr_pubkey}`);
    await flushPendingHelloMessages(bridge, accountId, hello.peer_nostr_pubkey);
  }

  // Dispatch the peer's greeting through the agent pipeline so the AI can generate a proper welcome
  // But skip dispatch if we initiated the hello (we already know who they are)
  const weInitiated = helloSentTo.has(hello.peer_nostr_pubkey) || pendingHelloMessages.has(hello.peer_nostr_pubkey);
  if (!weInitiated) {
    const greetingText = `[New contact] ${hello.peer_name} connected via Keychat. Their greeting: ${hello.greeting || "(no message)"}`;
    await dispatchToAgent(bridge, accountId, hello.peer_nostr_pubkey, hello.peer_name, greetingText, msg.event_id + "_hello", runtime, ctx);
  } else {
    ctx.log?.info(`[${accountId}] Skipping dispatch for self-initiated hello to ${hello.peer_nostr_pubkey}`);
    helloSentTo.delete(hello.peer_nostr_pubkey);
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
        await bridge.sendGroupMessage(joinResult.group_id, helloText, { subtype: 14 });
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
        const decrypted = await bridge.mlsDecryptMessage(groupId, msg.encrypted_content);
        ctx.log?.info(`[${accountId}] MLS message from ${decrypted.sender.slice(0, 12)} in group ${groupId}`);

        // Skip messages from ourselves
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
            mlsDisplayText = `[${mlsMediaInfo.kctype}: ${mlsMediaInfo.sourceName || mlsMediaInfo.suffix}] (saved to ${mlsMediaPath})`;
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
          try { await bridge.removeSubscription([oldListenKey]); } catch { /* best effort */ }
        }
        mlsListenKeyToGroup.set(commitResult.listen_key, groupId);
        await bridge.addSubscription([commitResult.listen_key]);

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
        mlsListenKeyToGroup.set(newKey, groupId);
        await bridge.removeSubscription([joinResult.listen_key]);
        await bridge.addSubscription([newKey]);
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
  // from_pubkey is EPHEMERAL — use to_address to find the actual peer
  let peerNostrPubkey: string | null = null;
  if (msg.to_address) {
    peerNostrPubkey = getAddressToPeer(accountId).get(msg.to_address) ?? null;
  }

  // Fallback: try from_pubkey directly (may work for initial messages)
  if (!peerNostrPubkey) {
    peerNostrPubkey = getPeerSessions(accountId).has(msg.from_pubkey) ? msg.from_pubkey : null;
  }

  // Fallback: query DB for address mapping before brute-force
  if (!peerNostrPubkey && msg.to_address) {
    try {
      const { mappings: dbMappings } = await bridge.getAddressMappings();
      const found = dbMappings.find((m) => m.address === msg.to_address);
      if (found) {
        peerNostrPubkey = found.peer_nostr_pubkey;
        getAddressToPeer(accountId).set(msg.to_address, peerNostrPubkey);
        ctx.log?.info(`[${accountId}] Resolved peer from DB address mapping: ${peerNostrPubkey}`);
      }
    } catch { /* DB lookup failed */ }
  }

  // ---- PreKey-based peer identification (replaces brute-force) ----
  // If we still can't identify the peer, try the PreKey path: extract the
  // Signal identity key from the ciphertext and look up the peer directly.
  // This is deterministic and avoids the old brute-force fallback.
  const hasPeerSession = peerNostrPubkey ? getPeerSessions(accountId).has(peerNostrPubkey) : false;
  ctx.log?.info(`[${accountId}] DEBUG: peerNostrPubkey=${peerNostrPubkey}, hasPeerSession=${hasPeerSession}, is_prekey=${msg.is_prekey}, to_address=${msg.to_address}`);
  if ((!peerNostrPubkey || !hasPeerSession) && msg.is_prekey) {
    ctx.log?.info(`[${accountId}] Entering PreKey path, encrypted_content length=${msg.encrypted_content?.length}, first40=${msg.encrypted_content?.slice(0, 40)}`);
    try {
      const prekeyInfo = await bridge.parsePrekeySender(msg.encrypted_content);
      ctx.log?.info(`[${accountId}] parsePrekeySender result: is_prekey=${prekeyInfo.is_prekey}, signal_identity_key=${prekeyInfo.signal_identity_key}`);
      if (prekeyInfo.is_prekey && prekeyInfo.signal_identity_key) {
        const sigKey = prekeyInfo.signal_identity_key;
        ctx.log?.info(`[${accountId}] PreKey message detected — signal identity: ${sigKey}`);

        // Strategy 1: Look up Signal key in existing getPeerSessions
        for (const [nostrPk, ps] of getPeerSessions(accountId)) {
          if (ps.signalPubkey === sigKey) {
            peerNostrPubkey = nostrPk;
            ctx.log?.info(`[${accountId}] PreKey routed to existing peer ${nostrPk} via signal key match`);
            break;
          }
        }

        // Strategy 2: Look up in DB peer_mapping
        if (!peerNostrPubkey) {
          try {
            const { mappings } = await bridge.getPeerMappings();
            const found = mappings.find((m) => m.signal_pubkey === sigKey);
            if (found) {
              peerNostrPubkey = found.nostr_pubkey;
              ctx.log?.info(`[${accountId}] PreKey routed to peer ${peerNostrPubkey} via DB peer_mapping`);
            }
          } catch { /* DB lookup failed */ }
        }

        // Strategy 3: This is a new peer replying to our hello — decrypt first,
        // then identify via PrekeyMessageModel.nostr_id or helloSentTo set
        if (!peerNostrPubkey || !getPeerSessions(accountId).has(peerNostrPubkey)) {
          ctx.log?.info(`[${accountId}] PreKey from unknown signal key ${sigKey} — attempting decrypt to identify sender`);

          const decryptResult = await bridge.decryptMessage(sigKey, msg.encrypted_content, true);
          const { plaintext } = decryptResult;

          // Try to extract nostr_id from PrekeyMessageModel
          let senderNostrId: string | null = null;
          let senderName = sigKey.slice(0, 12);
          try {
            const parsed = JSON.parse(plaintext);
            if (parsed?.nostrId) {
              senderNostrId = parsed.nostrId;
              senderName = parsed.name || senderName;
              ctx.log?.info(`[${accountId}] PreKey sender identified via PrekeyMessageModel: nostr_id=${senderNostrId}`);
            }
          } catch { /* not a PrekeyMessageModel */ }

          // Fallback: use peerNostrPubkey from addressToPeer (onetimekey mapping)
          if (!senderNostrId && peerNostrPubkey) {
            senderNostrId = peerNostrPubkey;
            ctx.log?.info(`[${accountId}] PreKey sender identified via onetimekey addressToPeer mapping: ${senderNostrId}`);
          }

          // Fallback: if only one pending hello, assume it's the responder
          if (!senderNostrId && helloSentTo.size === 1) {
            senderNostrId = helloSentTo.values().next().value ?? null;
            ctx.log?.info(`[${accountId}] PreKey sender inferred from single pending hello: ${senderNostrId}`);
          }

          // Fallback: if there are pending hellos, try to match
          if (!senderNostrId && helloSentTo.size > 1) {
            // Multiple pending hellos — can't determine which one. Log warning.
            ctx.log?.error(
              `[${accountId}] ⚠️ PreKey from unknown signal key ${sigKey} with ${helloSentTo.size} pending hellos — cannot determine sender. Dropping message.`,
            );
            return;
          }

          if (!senderNostrId) {
            ctx.log?.error(
              `[${accountId}] ⚠️ PreKey from unknown signal key ${sigKey} — no pending hellos and no PrekeyMessageModel. Dropping.`,
            );
            return;
          }

          // Register the peer session
          const newPeer: PeerSession = {
            signalPubkey: sigKey,
            deviceId: 1,
            name: senderName,
            nostrPubkey: senderNostrId,
          };
          getPeerSessions(accountId).set(senderNostrId, newPeer);
          await bridge.savePeerMapping(senderNostrId, sigKey, 1, senderName);
          ctx.log?.info(`[${accountId}] ✅ Session established with ${senderNostrId} (signal: ${sigKey})`);

          // After PreKey decrypt, subscribe to receiving addresses for this new peer.
          // alice_addrs from decrypt contains ratchet-derived addresses; take only latest MAX_RECEIVING_ADDRESSES.
          try {
            const aliceAddrs: string[] = decryptResult?.alice_addrs ?? [];
            if (aliceAddrs.length > 0) {
              const latest = aliceAddrs.slice(-MAX_RECEIVING_ADDRESSES);
              const newAddrs = latest.filter((a) => !getAddressToPeer(accountId).has(a));
              if (newAddrs.length > 0) {
                await bridge.addSubscription(newAddrs);
                const peerAddrs = peerSubscribedAddresses.get(senderNostrId!) ?? [];
                for (const a of newAddrs) {
                  getAddressToPeer(accountId).set(a, senderNostrId!);
                  peerAddrs.push(a);
                  try { await bridge.saveAddressMapping(a, senderNostrId!); } catch { /* */ }
                }
                // Trim to MAX_RECEIVING_ADDRESSES
                while (peerAddrs.length > MAX_RECEIVING_ADDRESSES) {
                  const old = peerAddrs.shift()!;
                  getAddressToPeer(accountId).delete(old);
                  try { await bridge.removeSubscription([old]); } catch { /* */ }
                  try { await bridge.deleteAddressMapping(old); } catch { /* */ }
                }
                peerSubscribedAddresses.set(senderNostrId!, peerAddrs);
                ctx.log?.info(`[${accountId}] Registered ${newAddrs.length} receiving address(es) for new peer ${senderNostrId!.slice(0,16)} (kept ${peerAddrs.length})`);
              }
            }
          } catch { /* best effort */ }

          // Flush pending hello messages now that session is established
          if (pendingHelloMessages.has(senderNostrId)) {
            ctx.log?.info(`[${accountId}] Flushing ${pendingHelloMessages.get(senderNostrId)?.length} pending message(s) to ${senderNostrId}`);
            await flushPendingHelloMessages(bridge, accountId, senderNostrId);
          }
          helloSentTo.delete(senderNostrId);

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
              return; // Protocol overhead — don't dispatch
            }
          } catch { /* not JSON — dispatch as regular message */ }

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

  // Last resort: brute-force peer lookup (only for non-PreKey messages)
  if (!peerNostrPubkey) {
    ctx.log?.error(
      `[${accountId}] ⚠️ Address mapping miss for to_address=${msg.to_address} — falling back to brute-force peer lookup.`,
    );
    if (getPeerSessions(accountId).size === 1) {
      peerNostrPubkey = getPeerSessions(accountId).keys().next().value ?? null;
    } else {
      for (const [key] of getPeerSessions(accountId)) {
        peerNostrPubkey = key;
        break;
      }
    }
    if (peerNostrPubkey && msg.to_address) {
      getAddressToPeer(accountId).set(msg.to_address, peerNostrPubkey);
      try {
        await bridge.saveAddressMapping(msg.to_address, peerNostrPubkey);
      } catch { /* best effort */ }
    }
  }

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
  let actualPeer = peer;
  try {
    decryptResult = await bridge.decryptMessage(peer.signalPubkey, msg.encrypted_content, msg.is_prekey);
  } catch (err) {
    ctx.log?.error(
      `[${accountId}] ⚠️ Decrypt failed for mapped peer ${peerNostrPubkey} (signal: ${peer.signalPubkey}): ${err}. Trying other peers...`,
    );
    // Fallback: try other peers — this means address→peer mapping was wrong
    for (const [key, otherPeer] of getPeerSessions(accountId)) {
      if (key === peerNostrPubkey) continue;
      try {
        decryptResult = await bridge.decryptMessage(otherPeer.signalPubkey, msg.encrypted_content, msg.is_prekey);
        actualPeer = otherPeer;
        peerNostrPubkey = key;
        // Fix address mapping
        if (msg.to_address) getAddressToPeer(accountId).set(msg.to_address, key);
        ctx.log?.info(`[${accountId}] Decrypt succeeded with peer ${key} — address mapping corrected`);
        break;
      } catch { continue; }
    }
    if (!decryptResult) {
      ctx.log?.error(
        `[${accountId}] ⚠️ All decrypt attempts failed for peer ${peerNostrPubkey} (event_id=${msg.event_id}, created_at=${msg.created_at}). Skipping message.`,
      );
      return;
    }
  }
  const peer_ = actualPeer;
  const { plaintext } = decryptResult;

  // After decrypt, use alice_addrs from decrypt result (per-peer ratchet addresses).
  // handleReceivingAddressRotation handles the per-message new_receiving_address from send;
  // for decrypt, we use alice_addrs which contains the current peer's ratchet addresses.
  try {
    const aliceAddrs: string[] = (decryptResult as any)?.alice_addrs ?? [];
    if (aliceAddrs.length > 0) {
      const latest = aliceAddrs.slice(-MAX_RECEIVING_ADDRESSES);
      const newAddrs = latest.filter((a) => !getAddressToPeer(accountId).has(a));
      if (newAddrs.length > 0) {
        await bridge.addSubscription(newAddrs);
        const peerAddrs = peerSubscribedAddresses.get(peerNostrPubkey) ?? [];
        for (const a of newAddrs) {
          getAddressToPeer(accountId).set(a, peerNostrPubkey);
          peerAddrs.push(a);
          try { await bridge.saveAddressMapping(a, peerNostrPubkey); } catch { /* */ }
        }
        while (peerAddrs.length > MAX_RECEIVING_ADDRESSES) {
          const old = peerAddrs.shift()!;
          getAddressToPeer(accountId).delete(old);
          try { await bridge.removeSubscription([old]); } catch { /* */ }
          try { await bridge.deleteAddressMapping(old); } catch { /* */ }
        }
        peerSubscribedAddresses.set(peerNostrPubkey, peerAddrs);
        ctx.log?.info(
          `[${accountId}] Updated ${newAddrs.length} receiving address(es) after decrypt (peer: ${peerNostrPubkey.slice(0,16)}, kept ${peerAddrs.length})`,
        );
      }
    }
  } catch (err) {
    ctx.log?.error(`[${accountId}] Failed to update receiving addresses after decrypt: ${err}`);
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
          await bridge.sendGroupMessage(joinResult.group_id, helloText, { subtype: 14 });
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
      displayText = `[${mediaInfo.kctype}: ${mediaInfo.sourceName || mediaInfo.suffix}] (saved to ${localPath})`;
    } catch (err) {
      ctx.log?.error(`[${accountId}] Failed to download media: ${err}`);
      displayText = `[${mediaInfo.kctype} message — download failed]`;
    }
  }

  ctx.log?.info(
    `[${accountId}] Decrypted from ${peer_.name} (${peerNostrPubkey}): ${displayText.slice(0, 50)}...`,
  );

  // Forward to OpenClaw's message pipeline via shared dispatch helper
  const senderLabel = peer_.name || peerNostrPubkey.slice(0, 12);

  if (groupContext) {
    // Route group messages to a group-specific dispatch
    ctx.log?.info(`[${accountId}] Detected group message: groupId=${groupContext.groupId}, subtype=${groupContext.groupMessage.subtype}, sender=${peerNostrPubkey}`);
    await dispatchGroupToAgent(bridge, accountId, groupContext.groupId, peerNostrPubkey, senderLabel, displayText, msg.event_id, runtime, ctx, groupContext.groupMessage, mediaPath);
  } else {
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
    OriginatingTo: `keychat:${accountId}`,
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
      await retrySend(() => bridge.sendGroupMessage(groupId, merged));
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

/** After each send or decrypt, rotate receiving addresses if a new one was generated. */
async function handleReceivingAddressRotation(
  bridge: KeychatBridgeClient,
  accountId: string,
  sendResult: SendMessageResult,
  peerKey?: string,
): Promise<void> {
  if (!sendResult.new_receiving_address) return;

  const { address } = await bridge.computeAddress(sendResult.new_receiving_address);

  // Map the new address to the peer (in-memory + DB)
  if (peerKey) {
    getAddressToPeer(accountId).set(address, peerKey);
    try {
      await bridge.saveAddressMapping(address, peerKey);
    } catch {
      // Best effort persistence
    }
  }

  const peerAddrKey = peerKey || accountId;
  const addrs = peerSubscribedAddresses.get(peerAddrKey) ?? [];
  addrs.push(address);

  // Keep only the latest MAX_RECEIVING_ADDRESSES addresses per peer
  const staleAddrs: string[] = [];
  while (addrs.length > MAX_RECEIVING_ADDRESSES) {
    const old = addrs.shift()!;
    getAddressToPeer(accountId).delete(old);
    staleAddrs.push(old);
  }
  peerSubscribedAddresses.set(peerAddrKey, addrs);

  // Remove stale addresses from relay subscription and DB
  if (staleAddrs.length > 0) {
    try { await bridge.removeSubscription(staleAddrs); } catch { /* best effort */ }
    for (const old of staleAddrs) {
      try { await bridge.deleteAddressMapping(old); } catch { /* best effort */ }
    }
  }

  // Add new address to relay subscription
  await bridge.addSubscription([address]);
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

  // Clear from helloSentTo to allow re-sending
  helloSentTo.delete(normalizedPeer);
  pendingHelloMessages.delete(normalizedPeer);

  console.log(`[keychat] [${accountId}] Session reset for peer ${normalizedPeer}`);

  // 4. Optionally re-send hello
  if (resendHello) {
    try {
      const accountInfo = accountInfoCache.get(accountId);
      const name = accountInfo?.pubkey_npub ?? "Keychat Agent";
      helloSentTo.add(normalizedPeer);
      const helloResult = await bridge.sendHello(normalizedPeer, name);
      console.log(`[keychat] [${accountId}] Hello re-sent to ${normalizedPeer} (event: ${helloResult.event_id})`);

      if (helloResult.onetimekey) {
        getAddressToPeer(accountId).set(helloResult.onetimekey, normalizedPeer);
        try { await bridge.saveAddressMapping(helloResult.onetimekey, normalizedPeer); } catch { /* */ }
      }
      return { reset: true, helloSent: true };
    } catch (err) {
      helloSentTo.delete(normalizedPeer);
      console.error(`[keychat] [${accountId}] Failed to re-send hello: ${err}`);
      return { reset: true, helloSent: false, error: `Reset OK but hello failed: ${err}` };
    }
  }

  return { reset: true };
}

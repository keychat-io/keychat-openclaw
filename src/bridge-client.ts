/**
 * TypeScript client for the Keychat sidecar (keychat-openclaw).
 * Communicates via JSON-RPC over stdin/stdout of a child process.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { createInterface, type Interface } from "node:readline";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { createRequire } from "node:module";
import { bridgeEnv } from "./paths.js";

export interface AccountInfo {
  pubkey_hex: string;
  pubkey_npub: string;
  prikey_nsec: string;
  curve25519_pk_hex: string;
  mnemonic: string | null;
}

export interface PrekeyBundleInfo {
  registration_id: number;
  identity_key_hex: string;
  signed_prekey_id: number;
  signed_prekey_public_hex: string;
  signed_prekey_signature_hex: string;
  prekey_id: number;
  prekey_public_hex: string;
}

interface RpcResponse {
  id: number;
  result?: unknown;
  error?: { code: number; message: string };
}

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
};

type BetterSqlite3Database = {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...params: any[]): { lastInsertRowid?: number | bigint };
    all(...params: any[]): any[];
  };
  close(): void;
};

const require = createRequire(import.meta.url);

/** Inbound message pushed from the bridge when a relay delivers a DM. */
export interface InboundMessage {
  from_pubkey: string;
  text: string;
  event_id: string;
  created_at: number;
  is_prekey: boolean;
  encrypted_content: string;
  event_kind: number;
  to_address: string | null;
  nip04_decrypted: boolean;
  /** For Gift Wrap events: the inner rumor's kind (14=DM, 444=MLS Welcome) */
  inner_kind?: number;
  inner_tags_p?: string[];
}

export interface SendMessageResult {
  sent: boolean;
  event_id: string;
  new_receiving_address?: string;
  derived_receiving_address?: string;
  is_prekey?: boolean;
  sending_to_onetimekey?: boolean;
}

export interface ProcessHelloResult {
  session_established: boolean;
  peer_nostr_pubkey: string;
  peer_signal_pubkey: string;
  peer_name: string;
  device_id: number;
  msg_type: number;
  greeting: string;
}

export type InboundMessageHandler = (msg: InboundMessage) => void;

export class KeychatBridgeClient {
  private process: ChildProcess | null = null;
  private readline: Interface | null = null;
  private nextId = 1;
  private pending = new Map<number, PendingRequest>();
  private bridgePath: string;
  private onInboundMessage: InboundMessageHandler | null = null;
  private pendingInbound: InboundMessage[] = [];

  // Auto-restart on crash
  private autoRestart = true;
  private restartAttempts = 0;
  private maxRestartAttempts = 5;
  private restartDelayMs = 1000;
  private initArgs: { dbPath?: string; mnemonic?: string; relays?: string[] } | null = null;
  private signalDbPath: string | null = null;

  constructor(bridgePath?: string) {
    // Default: look for the binary relative to the extension directory
    this.bridgePath =
      bridgePath ??
      join(
        import.meta.dirname ?? __dirname,
        "..",
        "bridge",
        "target",
        "release",
        "keychat-openclaw",
      );
  }

  /** Start the bridge sidecar process. */
  async start(): Promise<void> {
    if (this.process) {
      throw new Error("Bridge already started");
    }

    if (!existsSync(this.bridgePath)) {
      throw new Error(
        `keychat-openclaw binary not found at ${this.bridgePath}. Run 'cargo build --release' in the bridge directory.`,
      );
    }

    this.process = spawn(this.bridgePath, [], {
      stdio: ["pipe", "pipe", "pipe"],
      env: bridgeEnv(),
    });

    this.readline = createInterface({
      input: this.process.stdout!,
      crlfDelay: Infinity,
    });

    this.readline.on("line", (line: string) => {
      try {
        const parsed = JSON.parse(line);

        // Check if this is an unsolicited push event (id=0, has "event" field)
        if (parsed.id === 0 && parsed.event === "inbound_message" && parsed.data) {
          console.log(`[keychat-bridge] Inbound push received: event_kind=${(parsed.data as any).event_kind} from=${(parsed.data as any).from_pubkey?.slice(0,16)} to=${(parsed.data as any).to_address?.slice(0,16)} prekey=${(parsed.data as any).is_prekey}`);
          if (this.onInboundMessage) {
            this.onInboundMessage(parsed.data as InboundMessage);
          } else {
            // Buffer messages until handler is ready
            this.pendingInbound.push(parsed.data as InboundMessage);
          }
          return;
        }

        // Otherwise it's a response to a request
        const response = parsed as RpcResponse;
        const pending = this.pending.get(response.id);
        if (pending) {
          this.pending.delete(response.id);
          if (response.error) {
            pending.reject(new Error(response.error.message));
          } else {
            pending.resolve(response.result);
          }
        }
      } catch {
        // Ignore non-JSON lines
      }
    });

    this.process.stderr?.on("data", (data: Buffer) => {
      // Bridge logs go to stderr — route to appropriate log level
      const msg = data.toString().trim();
      if (!msg) return;
      if (msg.includes(" INFO ")) {
        console.log(`[keychat] ${msg}`);
      } else if (msg.includes(" WARN ")) {
        console.warn(`[keychat] ${msg}`);
      } else {
        console.error(`[keychat] ${msg}`);
      }
    });

    this.process.on("exit", (code) => {
      // Reject all pending requests
      for (const [id, pending] of this.pending) {
        pending.reject(new Error(`Bridge process exited with code ${code}`));
      }
      this.pending.clear();
      this.process = null;
      this.readline = null;

      // Auto-restart on unexpected exit
      if (this.autoRestart && code !== 0) {
        const delay = Math.min(this.restartDelayMs * Math.pow(2, this.restartAttempts), 30000);
        console.error(`[keychat] Unexpected exit (code=${code}), restarting in ${delay}ms (attempt ${this.restartAttempts + 1}/${this.maxRestartAttempts})`);
        setTimeout(() => this.restart(), delay);
      }
    });

    // Verify the bridge is alive
    await this.call("ping");
  }

  /** Cache init params so the bridge can replay them on restart. */
  setInitArgs(args: { dbPath?: string; mnemonic?: string; relays?: string[] }): void {
    this.initArgs = args;
  }

  /** Disable auto-restart (call before intentional stop). */
  disableAutoRestart(): void {
    this.autoRestart = false;
  }

  /** Callback invoked after a successful restart — lets channel.ts restore sessions/subscriptions. */
  private onRestartComplete: (() => Promise<void>) | null = null;

  /** Register a post-restart hook to restore peer sessions and subscriptions. */
  setRestartHook(hook: () => Promise<void>): void {
    this.onRestartComplete = hook;
  }

  /** Restart the bridge after an unexpected crash. */
  private async restart(): Promise<void> {
    if (this.restartAttempts >= this.maxRestartAttempts) {
      console.error(`[keychat] Max restart attempts (${this.maxRestartAttempts}) reached, giving up`);
      return;
    }
    this.restartAttempts++;
    try {
      await this.start();
      // Replay init sequence
      if (this.initArgs) {
        if (this.initArgs.dbPath) await this.init(this.initArgs.dbPath);
        if (this.initArgs.mnemonic) await this.importIdentity(this.initArgs.mnemonic);
        if (this.initArgs.relays) await this.connect(this.initArgs.relays);
      }
      // Restore peer sessions and subscriptions via hook
      if (this.onRestartComplete) {
        try {
          await this.onRestartComplete();
        } catch (err) {
          console.error(`[keychat] Post-restart hook failed: ${err}`);
        }
      }
      this.restartAttempts = 0;
      console.error(`[keychat] Restart successful (sessions restored)`);
    } catch (err) {
      console.error(`[keychat] Restart failed: ${err}`);
    }
  }

  /** Periodic health check — ping the bridge and restart if unresponsive. */
  private healthCheckInterval: ReturnType<typeof setInterval> | null = null;
  private readonly HEALTH_CHECK_INTERVAL_MS = 60_000; // 1 minute
  private readonly HEALTH_CHECK_TIMEOUT_MS = 10_000;

  /** Start periodic health checks. */
  startHealthCheck(): void {
    this.stopHealthCheck();
    this.healthCheckInterval = setInterval(async () => {
      if (!this.process) return;
      try {
        const pingPromise = this.call("ping");
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error("health check timeout")), this.HEALTH_CHECK_TIMEOUT_MS),
        );
        await Promise.race([pingPromise, timeoutPromise]);
        // Also check relay connectivity and auto-reconnect if needed
        try {
          const result = await this.call("relay_health_check") as { reconnected?: boolean };
          if (result?.reconnected) {
            console.log(`[keychat] Relay health check: reconnected and resubscribed`);
          }
        } catch (relayErr) {
          console.warn(`[keychat] Relay health check failed: ${relayErr}`);
        }
      } catch {
        console.error(`[keychat] Health check failed — killing stale process`);
        try { this.process?.kill(); } catch { /* ignore */ }
        // Auto-restart will trigger from the exit handler
      }
    }, this.HEALTH_CHECK_INTERVAL_MS);
  }

  /** Stop periodic health checks. */
  stopHealthCheck(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
  }

  /** Stop the bridge sidecar. */
  async stop(): Promise<void> {
    this.autoRestart = false;
    this.stopHealthCheck();
    if (this.process) {
      this.process.stdin?.end();
      this.process.kill();
      this.process = null;
      this.readline = null;
    }
  }

  /** Send a JSON-RPC call and wait for the response. */
  private call(method: string, params?: Record<string, unknown>): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!this.process?.stdin?.writable) {
        reject(new Error("Bridge not started or stdin not writable"));
        return;
      }

      const id = this.nextId++;
      this.pending.set(id, { resolve, reject });

      const request = JSON.stringify({ id, method, params: params ?? {} });
     try {
        this.process.stdin.write(request + '\n');
      } catch (error) {
        this.pending.delete(id);
        reject(new Error(`Bridge write failed: ${error}`));
        return;
      }
      // Timeout after 30 seconds
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`Bridge call '${method}' timed out`));
        }
      }, 30000);
    });
  }

  /** Register a handler for inbound messages pushed from the bridge. */
  setInboundHandler(handler: InboundMessageHandler): void {
    this.onInboundMessage = handler;
    // Flush any messages that arrived before the handler was ready
    if (this.pendingInbound.length > 0) {
      const pending = this.pendingInbound.splice(0);
      for (const msg of pending) {
        handler(msg);
      }
    }
  }

  // =========================================================================
  // Public API methods
  // =========================================================================

  /** Initialize Signal Protocol DB. */
  async init(dbPath: string): Promise<{ initialized: boolean; db_path: string }> {
    this.signalDbPath = this.resolveDbPath(dbPath);
    return (await this.call("init", { db_path: dbPath })) as {
      initialized: boolean;
      db_path: string;
    };
  }

  /** Generate a new Keychat identity (mnemonic + keypairs). */
  async generateIdentity(): Promise<AccountInfo> {
    return (await this.call("generate_identity")) as AccountInfo;
  }

  /** Import identity from mnemonic. */
  async importIdentity(mnemonic: string, password?: string): Promise<AccountInfo> {
    return (await this.call("import_identity", { mnemonic, password })) as AccountInfo;
  }

  /** Get current account public info. */
  async getAccountInfo(): Promise<AccountInfo> {
    return (await this.call("get_account_info")) as AccountInfo;
  }

  /** Generate a Signal pre-key bundle for key exchange. */
  async generatePrekeyBundle(): Promise<PrekeyBundleInfo> {
    return (await this.call("generate_prekey_bundle")) as PrekeyBundleInfo;
  }

  /** Process a peer's pre-key bundle to establish Signal session. */
  async processPrekeyBundle(params: {
    remote_address: string;
    device_id?: number;
    registration_id?: number;
    identity_key: string;
    signed_prekey_id: number;
    signed_prekey_public: string;
    signed_prekey_signature: string;
    prekey_id: number;
    prekey_public: string;
  }): Promise<{ session_established: boolean }> {
    return (await this.call("process_prekey_bundle", params)) as {
      session_established: boolean;
    };
  }

  /** Send an encrypted message. */
  async sendMessage(
    to: string,
    text: string,
    opts?: { isHelloReply?: boolean; senderName?: string },
  ): Promise<SendMessageResult> {
    return (await this.call("send_message", {
      to,
      text,
      is_hello_reply: opts?.isHelloReply ?? false,
      sender_name: opts?.senderName,
    })) as SendMessageResult;
  }

  /** Process an incoming hello/friend-request to establish a Signal session. */
  async processHello(message: string): Promise<ProcessHelloResult> {
    return (await this.call("process_hello", { message })) as ProcessHelloResult;
  }

  /** Compute a Nostr address (pubkey) from a receiving-address seed. */
  async computeAddress(seed: string): Promise<{ address: string }> {
    return (await this.call("compute_address", { seed })) as { address: string };
  }

  /** Subscribe to additional Nostr pubkeys for inbound messages. */
  async addSubscription(pubkeys: string[]): Promise<{ subscribed: boolean }> {
    return (await this.call("add_subscription", { pubkeys })) as { subscribed: boolean };
  }

  async removeSubscription(pubkeys: string[]): Promise<{ removed: boolean }> {
    return (await this.call("remove_subscription", { pubkeys })) as { removed: boolean };
  }

  /** Decrypt a received message. */
  async decryptMessage(
    from: string,
    ciphertext: string,
    isPrekey?: boolean,
  ): Promise<{ plaintext: string; my_next_addrs?: string[] }> {
    return (await this.call("decrypt_message", {
      from,
      ciphertext,
      is_prekey: isPrekey ?? false,
    })) as { plaintext: string; my_next_addrs?: string[] };
  }

  /** Connect to Nostr relays. */
  async connect(relays?: string[]): Promise<{ connected: boolean; relays: string[] }> {
    return (await this.call("connect", { relays })) as {
      connected: boolean;
      relays: string[];
    };
  }

  /** Disconnect from relays. */
  async disconnect(): Promise<{ disconnected: boolean }> {
    return (await this.call("disconnect")) as { disconnected: boolean };
  }

  /** Check if a Signal session exists with a peer. */
  async hasSession(pubkey: string): Promise<{ exists: boolean }> {
    return (await this.call("has_session", { pubkey })) as { exists: boolean };
  }

  /** Get all receiving addresses from Signal sessions in DB (for resubscription on restart). */

  /** Get all peer sessions from DB. */
  async getAllSessions(): Promise<{ sessions: Array<{ signal_pubkey: string; device_id: string }> }> {
    return (await this.call("get_all_sessions", {})) as any;
  }

  /** Get all peer mappings (nostr↔signal pubkey). */
  async getPeerMappings(): Promise<{ mappings: Array<{ nostr_pubkey: string; signal_pubkey: string; device_id: number; name: string }> }> {
    return (await this.call("get_peer_mappings", {})) as any;
  }

  /** Save a peer mapping. */
  async savePeerMapping(nostrPubkey: string, signalPubkey: string, deviceId: number, name: string): Promise<{ saved: boolean }> {
    return (await this.call("save_peer_mapping", { nostr_pubkey: nostrPubkey, signal_pubkey: signalPubkey, device_id: deviceId, name })) as any;
  }

  /** Mark an event as processed (persisted to DB). */
  async markEventProcessed(eventId: string, createdAt?: number): Promise<{ marked: boolean }> {
    return (await this.call("mark_event_processed", { event_id: eventId, created_at: createdAt })) as any;
  }

  /** Check if an event was already processed. */
  async isEventProcessed(eventId: string): Promise<{ processed: boolean }> {
    return (await this.call("is_event_processed", { event_id: eventId })) as any;
  }

  /** Send a hello/friend request to a Nostr pubkey via Gift Wrap. */
  async sendHello(toPubkey: string, name?: string): Promise<{ sent: boolean; event_id: string; to_pubkey: string; onetimekey?: string }> {
    return (await this.call("send_hello", { to_pubkey: toPubkey, name })) as any;
  }

  /** Parse sender identity key from a PreKey Signal message (before decryption). */
  async parsePrekeySender(ciphertext: string): Promise<{ is_prekey: boolean; signal_identity_key?: string; signed_pre_key_id?: number }> {
    return (await this.call("parse_prekey_sender", { ciphertext })) as any;
  }

  async lookupPeerBySignedPrekeyId(signedPrekeyId: number): Promise<{ nostr_pubkey: string | null }> {
    return (await this.call("lookup_peer_by_signed_prekey_id", { signed_prekey_id: signedPrekeyId })) as any;
  }

  async clearPrekeyMaterial(nostrPubkey: string): Promise<void> {
    await this.call("clear_prekey_material", { nostr_pubkey: nostrPubkey });
  }

  /** Send a profile update (type 48) to an existing peer. */
  async sendProfile(peerNostrPubkey: string, opts?: { name?: string; avatar?: string; lightning?: string; bio?: string }): Promise<{ sent: boolean; event_id?: string }> {
    return (await this.call("send_profile", {
      peer_nostr_pubkey: peerNostrPubkey,
      name: opts?.name,
      avatar: opts?.avatar,
      lightning: opts?.lightning,
      bio: opts?.bio,
    })) as any;
  }

  /** Save an address-to-peer mapping. */
  async saveAddressMapping(address: string, peerNostrPubkey: string): Promise<{ saved: boolean }> {
    return (await this.call("save_address_mapping", { address, peer_nostr_pubkey: peerNostrPubkey })) as any;
  }

  /** Get all address-to-peer mappings. */
  async getAddressMappings(): Promise<{ mappings: Array<{ address: string; peer_nostr_pubkey: string }> }> {
    return (await this.call("get_address_mappings", {})) as any;
  }

  /** Delete an address-to-peer mapping. */
  async deleteAddressMapping(address: string): Promise<{ deleted: boolean }> {
    return (await this.call("delete_address_mapping", { address })) as any;
  }

  /** Persist a message queued while waiting for Protocol Step 3 accept-first. */
  async savePendingHelloMessage(peerPubkey: string, text: string): Promise<{ id: number }> {
    return this.withSignalDb((db) => {
      this.ensurePendingHelloTable(db);
      const createdAt = Math.floor(Date.now() / 1000);
      const result = db
        .prepare(
          "INSERT INTO pending_hello_messages (peer_pubkey, message_text, created_at) VALUES (?, ?, ?)",
        )
        .run(peerPubkey, text, createdAt);
      const rawId = result.lastInsertRowid ?? 0;
      return { id: Number(rawId) };
    });
  }

  /** Load persisted hello-queue messages for a peer. */
  async getPendingHelloMessages(peerPubkey: string): Promise<{ messages: { id: number; text: string }[] }> {
    return this.withSignalDb((db) => {
      this.ensurePendingHelloTable(db);
      const rows = db
        .prepare(
          "SELECT id, message_text FROM pending_hello_messages WHERE peer_pubkey = ? ORDER BY id ASC",
        )
        .all(peerPubkey) as Array<{ id: number; message_text: string }>;
      return {
        messages: rows.map((row) => ({ id: Number(row.id), text: row.message_text })),
      };
    });
  }

  /** Delete persisted hello-queue messages for a peer after successful flush. */
  async deletePendingHelloMessages(peerPubkey: string): Promise<void> {
    this.withSignalDb((db) => {
      this.ensurePendingHelloTable(db);
      db.prepare("DELETE FROM pending_hello_messages WHERE peer_pubkey = ?").run(peerPubkey);
    });
  }

  /** Delete one persisted hello-queue message by row id. */
  async deletePendingHelloMessageById(id: number): Promise<void> {
    this.withSignalDb((db) => {
      this.ensurePendingHelloTable(db);
      db.prepare("DELETE FROM pending_hello_messages WHERE id = ?").run(id);
    });
  }

  /** Check if bridge is connected and responsive (ping with 5s timeout). */
  async isConnected(): Promise<boolean> {
    if (!this.process?.stdin?.writable) return false;
    try {
      const pingPromise = this.call("ping");
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error("ping timeout")), 5000),
      );
      await Promise.race([pingPromise, timeoutPromise]);
      return true;
    } catch {
      return false;
    }
  }

  private resolveDbPath(input: string): string {
    if (input.startsWith("~/")) {
      return join(homedir(), input.slice(2));
    }
    return input;
  }

  private getSignalDbPathOrThrow(): string {
    if (!this.signalDbPath) {
      throw new Error("Signal DB path unavailable. Call init(dbPath) before pending hello operations.");
    }
    return this.signalDbPath;
  }

  private withSignalDb<T>(run: (db: BetterSqlite3Database) => T): T {
    const dbPath = this.getSignalDbPathOrThrow();
    let DbCtor: (new (filename: string) => BetterSqlite3Database) | null = null;
    try {
      DbCtor = require("better-sqlite3") as new (filename: string) => BetterSqlite3Database;
    } catch {
      const sqliteBuiltin = require("node:sqlite") as { DatabaseSync: new (filename: string) => BetterSqlite3Database };
      DbCtor = sqliteBuiltin.DatabaseSync;
    }
    const db = new DbCtor(dbPath);
    try {
      return run(db);
    } finally {
      db.close();
    }
  }

  private ensurePendingHelloTable(db: BetterSqlite3Database): void {
    db.exec(
      "CREATE TABLE IF NOT EXISTS pending_hello_messages (" +
        "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
        "peer_pubkey TEXT NOT NULL, " +
        "message_text TEXT NOT NULL, " +
        "created_at INTEGER NOT NULL" +
      ")",
    );
  }

  /** Delete a Signal session for a peer. */
  async deleteSession(signalPubkey: string, deviceId?: number): Promise<{ deleted: boolean }> {
    return (await this.call("delete_session", { signal_pubkey: signalPubkey, device_id: deviceId })) as any;
  }

  /** Sign a Blossom (kind:24242) Nostr event for media upload auth. */
  async signBlossomEvent(content: string, tags: string[][]): Promise<string> {
    const result = (await this.call("sign_blossom_event", { content, tags })) as { event_json: string };
    return result.event_json;
  }

  // =========================================================================
  // Group (small group / sendAll)
  // =========================================================================

  /** Create a new small group. */
  async createGroup(name: string): Promise<{ group_id: string; name: string }> {
    return (await this.call("create_group", { name })) as any;
  }

  /** Get group info. */
  async getGroup(groupId: string): Promise<{
    group_id: string | null;
    name?: string;
    my_id_pubkey?: string;
    status?: string;
    version?: number;
    members?: Array<{ idPubkey: string; name: string; isAdmin: boolean }>;
  }> {
    return (await this.call("get_group", { group_id: groupId })) as any;
  }

  /** Get all groups. */
  async getAllGroups(): Promise<{
    groups: Array<{ group_id: string; name: string; my_id_pubkey: string; status: string; version: number }>;
  }> {
    return (await this.call("get_all_groups")) as any;
  }

  /** Join a group from an invite (RoomProfile). */
  async joinGroup(roomProfile: Record<string, unknown>, senderIdPubkey?: string): Promise<{
    joined: boolean;
    group_id: string;
    name: string;
    member_count: number;
  }> {
    return (await this.call("join_group", {
      room_profile: roomProfile,
      sender_id_pubkey: senderIdPubkey,
    })) as any;
  }

  /** Add a member to a group. */
  async addGroupMember(groupId: string, idPubkey: string, name?: string, isAdmin?: boolean): Promise<{ added: boolean }> {
    return (await this.call("add_group_member", {
      group_id: groupId,
      id_pubkey: idPubkey,
      name: name ?? "",
      is_admin: isAdmin ?? false,
    })) as any;
  }

  /** Remove a member from a group. */
  async removeGroupMember(groupId: string, idPubkey: string): Promise<{ removed: boolean }> {
    return (await this.call("remove_group_member", { group_id: groupId, id_pubkey: idPubkey })) as any;
  }

  /** Get group members. */
  async getGroupMembers(groupId: string): Promise<{
    members: Array<{ idPubkey: string; name: string; isAdmin: boolean }>;
  }> {
    return (await this.call("get_group_members", { group_id: groupId })) as any;
  }

  /** Send a message to all members of a group (sendAll). */
  async sendGroupMessage(groupId: string, text: string, opts?: { subtype?: number; ext?: string }): Promise<{
    sent: boolean;
    group_id: string;
    sent_count: number;
    total_members: number;
    event_ids: string[];
    errors: string[];
    member_rotations?: Array<{ member: string; new_receiving_address: string }>;
  }> {
    return (await this.call("send_group_message", {
      group_id: groupId,
      text,
      subtype: opts?.subtype,
      ext: opts?.ext,
    })) as any;
  }

  /** Update group name. */
  async updateGroupName(groupId: string, name: string): Promise<{ updated: boolean }> {
    return (await this.call("update_group_name", { group_id: groupId, name })) as any;
  }

  /** Update group status (enabled/disabled). */
  async updateGroupStatus(groupId: string, status: string): Promise<{ updated: boolean }> {
    return (await this.call("update_group_status", { group_id: groupId, status })) as any;
  }

  /** Delete a group. */
  async deleteGroup(groupId: string): Promise<{ deleted: boolean }> {
    return (await this.call("delete_group", { group_id: groupId })) as any;
  }

  // ---------------------------------------------------------------------------
  // MLS (Large Group) methods
  // ---------------------------------------------------------------------------

  /** Initialize MLS for the current identity. */
  async mlsInit(dbPath?: string): Promise<{ initialized: boolean; nostr_id: string }> {
    return (await this.call("mls_init", { db_path: dbPath })) as any;
  }

  /** Create a key package for MLS (to be published as kind:10443). */
  async mlsCreateKeyPackage(): Promise<{
    key_package: string;
    mls_protocol_version: string;
    ciphersuite: string;
    extensions: string;
  }> {
    return (await this.call("mls_create_key_package", {})) as any;
  }

  /** Create a new MLS group. */
  async mlsCreateGroup(params: {
    group_id: string;
    name: string;
    description?: string;
    admin_pubkeys?: string[];
    relays?: string[];
    status?: string;
  }): Promise<{ created: boolean; group_id: string }> {
    return (await this.call("mls_create_group", params)) as any;
  }

  /** Add members to an MLS group using their key packages. */
  async mlsAddMembers(groupId: string, keyPackages: string[]): Promise<{
    commit_msg: string;
    welcome: string; // base64
    listen_key: string;
  }> {
    return (await this.call("mls_add_members", {
      group_id: groupId,
      key_packages: keyPackages,
    })) as any;
  }

  /** Merge pending commit (call after add_members, self_update, etc.). */
  async mlsSelfCommit(groupId: string): Promise<{ committed: boolean }> {
    return (await this.call("mls_self_commit", { group_id: groupId })) as any;
  }

  /** Join an MLS group from a Welcome message (base64). */
  async mlsJoinGroup(groupId: string, welcomeBase64: string): Promise<MlsGroupInfo> {
    return (await this.call("mls_join_group", {
      group_id: groupId,
      welcome: welcomeBase64,
    })) as any;
  }

  /** Encrypt a message for an MLS group. */
  async mlsCreateMessage(groupId: string, text: string): Promise<{
    encrypted_msg: string;
    listen_key: string;
  }> {
    return (await this.call("mls_create_message", {
      group_id: groupId,
      text,
    })) as any;
  }

  /** Decrypt a received MLS group message. */
  async mlsDecryptMessage(groupId: string, message: string): Promise<{
    plaintext: string;
    sender: string;
    listen_key: string;
  }> {
    return (await this.call("mls_decrypt_message", {
      group_id: groupId,
      message,
    })) as any;
  }

  /** Parse the type of an MLS message without consuming it. */
  async mlsParseMessageType(groupId: string, data: string): Promise<MlsMessageInType> {
    return (await this.call("mls_parse_message_type", {
      group_id: groupId,
      data,
    })) as any;
  }

  /** Process a commit from another member (add/remove/update/etc.). */
  async mlsProcessCommit(groupId: string, message: string): Promise<MlsCommitResult> {
    return (await this.call("mls_process_commit", {
      group_id: groupId,
      message,
    })) as any;
  }

  /** Get the current listen key (onetimekey) for an MLS group. */
  async mlsGetListenKey(groupId: string): Promise<{ listen_key: string }> {
    return (await this.call("mls_get_listen_key", { group_id: groupId })) as any;
  }

  /** Get MLS group info. */
  async mlsGetGroupInfo(groupId: string): Promise<MlsGroupInfo> {
    return (await this.call("mls_get_group_info", { group_id: groupId })) as any;
  }

  /** List all MLS groups. */
  async mlsGetGroups(): Promise<{ groups: string[] }> {
    return (await this.call("mls_get_groups", {})) as any;
  }

  /** Self-update key material in a group. */
  async mlsSelfUpdate(groupId: string, extension?: Record<string, unknown>): Promise<{
    encrypted_msg: string;
    listen_key: string;
  }> {
    return (await this.call("mls_self_update", {
      group_id: groupId,
      extension,
    })) as any;
  }

  /** Update group context extensions (name, description, etc.). */
  async mlsUpdateGroupExtensions(groupId: string, opts: {
    name?: string;
    description?: string;
    admin_pubkeys?: string[];
    relays?: string[];
    status?: string;
  }): Promise<{ encrypted_msg: string; listen_key: string }> {
    return (await this.call("mls_update_group_extensions", {
      group_id: groupId,
      ...opts,
    })) as any;
  }

  /** Remove members from an MLS group. */
  async mlsRemoveMembers(groupId: string, members: string[]): Promise<{
    encrypted_msg: string;
    listen_key: string;
  }> {
    return (await this.call("mls_remove_members", {
      group_id: groupId,
      members,
    })) as any;
  }

  /** Delete an MLS group. */
  async mlsDeleteGroup(groupId: string): Promise<{ deleted: boolean }> {
    return (await this.call("mls_delete_group", { group_id: groupId })) as any;
  }

  /** Get sender of an MLS message without consuming it. */
  async mlsGetSender(groupId: string, message: string): Promise<{ sender: string | null }> {
    return (await this.call("mls_get_sender", {
      group_id: groupId,
      message,
    })) as any;
  }

  /** Send a message to an MLS group (encrypt + publish to relay). */
  async mlsSendMessage(groupId: string, text: string): Promise<{
    sent: boolean;
    event_id: string;
    listen_key: string;
  }> {
    return (await this.call("mls_send_message", {
      group_id: groupId,
      text,
    })) as any;
  }

  /** Publish pre-encrypted content (e.g., MLS commit) to a group's listen key. */
  async mlsPublishToGroup(listenKey: string, content: string): Promise<{ event_id: string }> {
    return (await this.call("mls_publish_to_group", {
      listen_key: listenKey,
      content,
    })) as any;
  }

  /** Create a new KeyPackage, publish it as kind:10443, and return result. */
  async mlsPublishKeyPackage(): Promise<{ event_id: string; key_package: string }> {
    return (await this.call("mls_publish_key_package", {})) as any;
  }

  /** Fetch the latest KeyPackage (kind:10443) for a pubkey from relays. */
  async mlsFetchKeyPackage(pubkey: string): Promise<{ key_package: string | null }> {
    return (await this.call("mls_fetch_key_package", { pubkey })) as any;
  }
}

// ---------------------------------------------------------------------------
// MLS Types
// ---------------------------------------------------------------------------

export interface MlsGroupInfo {
  group_id: string;
  name: string;
  description: string;
  admin_pubkeys: string[];
  relays: string[];
  status: string;
  members: string[];
  listen_key: string;
}

export type MlsMessageInType =
  | "Application"
  | "Proposal"
  | "Commit"
  | "Welcome"
  | "GroupInfo"
  | "KeyPackage"
  | "Custom";

export type MlsCommitType = "Add" | "Update" | "Remove" | "GroupContextExtensions";

export interface MlsCommitResult {
  sender: string;
  commit_type: MlsCommitType;
  operated_members: string[];
  listen_key: string;
}

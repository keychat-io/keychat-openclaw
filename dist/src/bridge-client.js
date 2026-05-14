/**
 * TypeScript client for the Keychat sidecar (keychat-openclaw).
 * Communicates via JSON-RPC over stdin/stdout of a child process.
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { createRequire } from "node:module";
import { bridgeEnv } from "./paths.js";
const require = createRequire(import.meta.url);
export class KeychatBridgeClient {
    process = null;
    readline = null;
    nextId = 1;
    pending = new Map();
    bridgePath;
    onInboundMessage = null;
    pendingInbound = [];
    // Auto-restart on crash
    autoRestart = true;
    restartAttempts = 0;
    maxRestartAttempts = 5;
    restartDelayMs = 1000;
    initArgs = null;
    signalDbPath = null;
    constructor(bridgePath) {
        const baseDir = import.meta.dirname ?? __dirname;
        const platformBinary = join(baseDir, "..", `keychat-bridge-${process.platform === "darwin" ? "darwin" : "linux"}-${process.arch}`);
        const devBinary = join(baseDir, "..", "bridge", "target", "release", "keychat-openclaw");
        this.bridgePath = bridgePath ?? (existsSync(platformBinary) ? platformBinary : devBinary);
    }
    /** Start the bridge sidecar process. */
    async start() {
        if (this.process) {
            throw new Error("Bridge already started");
        }
        if (!existsSync(this.bridgePath)) {
            throw new Error(`keychat-openclaw binary not found at ${this.bridgePath}. Run 'cargo build --release' in the bridge directory.`);
        }
        this.process = spawn(this.bridgePath, [], {
            stdio: ["pipe", "pipe", "pipe"],
            env: bridgeEnv(),
        });
        this.readline = createInterface({
            input: this.process.stdout,
            crlfDelay: Infinity,
        });
        this.readline.on("line", (line) => {
            try {
                const parsed = JSON.parse(line);
                // Check if this is an unsolicited push event (id=0, has "event" field)
                if (parsed.id === 0 && parsed.event === "inbound_message" && parsed.data) {
                    console.log(`[keychat-bridge] Inbound push received: event_kind=${parsed.data.event_kind} from=${parsed.data.from_pubkey?.slice(0, 16)} to=${parsed.data.arrived_at?.slice(0, 16)} prekey=${parsed.data.is_prekey}`);
                    if (this.onInboundMessage) {
                        this.onInboundMessage(parsed.data);
                    }
                    else {
                        // Buffer messages until handler is ready
                        this.pendingInbound.push(parsed.data);
                    }
                    return;
                }
                // Otherwise it's a response to a request
                const response = parsed;
                const pending = this.pending.get(response.id);
                if (pending) {
                    this.pending.delete(response.id);
                    if (response.error) {
                        pending.reject(new Error(response.error.message));
                    }
                    else {
                        pending.resolve(response.result);
                    }
                }
                else {
                    console.warn(`[keychat-bridge] ⚠ RPC response id=${response.id} has no pending request (already timed out?)`);
                }
            }
            catch (parseErr) {
                // Log unparseable lines for debugging (may reveal merged/corrupt stdout)
                console.error(`[keychat-bridge] ⚠ Failed to parse bridge stdout line (${line.length} chars): ${line.slice(0, 200)}${line.length > 200 ? "..." : ""}`);
            }
        });
        this.process.stderr?.on("data", (data) => {
            // Bridge logs go to stderr — route to appropriate log level
            const msg = data.toString().trim();
            if (!msg)
                return;
            if (msg.includes(" INFO ")) {
                console.log(`[keychat] ${msg}`);
            }
            else if (msg.includes(" WARN ")) {
                console.warn(`[keychat] ${msg}`);
            }
            else {
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
    /** Cache init params so the bridge can replay them on restart.
     *  NOTE: mnemonic is NOT cached here — it must be read from keychain on restart. */
    setInitArgs(args) {
        this.initArgs = args;
    }
    /** Disable auto-restart (call before intentional stop). */
    disableAutoRestart() {
        this.autoRestart = false;
    }
    /** Callback invoked after a successful restart — lets channel.ts restore sessions/subscriptions. */
    onRestartComplete = null;
    /** Register a post-restart hook to restore peer sessions and subscriptions. */
    setRestartHook(hook) {
        this.onRestartComplete = hook;
    }
    /** Restart the bridge after an unexpected crash. */
    /** Optional callback to resolve mnemonic from keychain (defense-in-depth for restart). */
    mnemonicResolver = null;
    /** Register a fallback mnemonic resolver (e.g. keychain lookup). */
    setMnemonicResolver(resolver) {
        this.mnemonicResolver = resolver;
    }
    async restart() {
        if (this.restartAttempts >= this.maxRestartAttempts) {
            console.error(`[keychat] Max restart attempts (${this.maxRestartAttempts}) reached, giving up`);
            return;
        }
        this.restartAttempts++;
        try {
            await this.start();
            // Replay init sequence
            if (this.initArgs) {
                if (this.initArgs.dbPath)
                    await this.init(this.initArgs.dbPath);
                // Always read mnemonic from keychain — never cache secrets in memory
                if (!this.mnemonicResolver) {
                    throw new Error("No mnemonic resolver registered — cannot restore identity");
                }
                const mnemonic = await this.mnemonicResolver();
                if (mnemonic) {
                    await this.importIdentity(mnemonic);
                }
                else {
                    throw new Error("Keychain returned no mnemonic — cannot restore identity");
                }
                if (this.initArgs.relays)
                    await this.connect(this.initArgs.relays);
            }
            // Restore peer sessions and subscriptions via hook
            if (this.onRestartComplete) {
                try {
                    await this.onRestartComplete();
                }
                catch (err) {
                    console.error(`[keychat] Post-restart hook failed: ${err}`);
                }
            }
            this.restartAttempts = 0;
            console.error(`[keychat] Restart successful (sessions restored)`);
        }
        catch (err) {
            console.error(`[keychat] Restart failed: ${err}`);
            // Schedule retry with exponential backoff (exit handler won't fire since start() succeeded)
            if (this.restartAttempts < this.maxRestartAttempts) {
                const delay = Math.min(this.restartDelayMs * Math.pow(2, this.restartAttempts), 30000);
                console.error(`[keychat] Will retry restart in ${delay}ms (attempt ${this.restartAttempts + 1}/${this.maxRestartAttempts})`);
                setTimeout(() => this.restart(), delay);
            }
        }
    }
    /** Periodic health check — ping the bridge and restart if unresponsive. */
    healthCheckInterval = null;
    HEALTH_CHECK_INTERVAL_MS = 60_000; // 1 minute
    HEALTH_CHECK_TIMEOUT_MS = 60_000; // 60s — generous to avoid false kills during message bursts
    consecutiveHealthFailures = 0;
    HEALTH_KILL_THRESHOLD = 2; // require 2 consecutive failures before killing
    /** Start periodic health checks. */
    startHealthCheck() {
        this.stopHealthCheck();
        this.consecutiveHealthFailures = 0;
        this.healthCheckInterval = setInterval(async () => {
            if (!this.process)
                return;
            // Skip health check if the bridge is actively processing RPC calls —
            // a busy bridge is not a stuck bridge.
            if (this.pending.size > 0) {
                this.consecutiveHealthFailures = 0;
                return;
            }
            try {
                const pingPromise = this.call("ping");
                const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error("health check timeout")), this.HEALTH_CHECK_TIMEOUT_MS));
                await Promise.race([pingPromise, timeoutPromise]);
                this.consecutiveHealthFailures = 0;
                // Also check relay connectivity and auto-reconnect if needed
                try {
                    const result = await this.call("relay_health_check");
                    if (result?.reconnected) {
                        console.log(`[keychat] Relay health check: reconnected and resubscribed`);
                    }
                }
                catch (relayErr) {
                    console.warn(`[keychat] Relay health check failed: ${relayErr}`);
                }
            }
            catch (parseErr) {
                this.consecutiveHealthFailures++;
                if (this.consecutiveHealthFailures >= this.HEALTH_KILL_THRESHOLD) {
                    console.error(`[keychat] Health check failed ${this.consecutiveHealthFailures} consecutive times — killing stale process`);
                    this.consecutiveHealthFailures = 0;
                    try {
                        this.process?.kill();
                    }
                    catch { /* ignore */ }
                    // Auto-restart will trigger from the exit handler
                }
                else {
                    console.warn(`[keychat] Health check failed (${this.consecutiveHealthFailures}/${this.HEALTH_KILL_THRESHOLD}) — will retry next cycle`);
                }
            }
        }, this.HEALTH_CHECK_INTERVAL_MS);
    }
    /** Stop periodic health checks. */
    stopHealthCheck() {
        if (this.healthCheckInterval) {
            clearInterval(this.healthCheckInterval);
            this.healthCheckInterval = null;
        }
    }
    /** Stop the bridge sidecar. */
    async stop() {
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
    call(method, params) {
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
            }
            catch (error) {
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
    setInboundHandler(handler) {
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
    async init(dbPath) {
        this.signalDbPath = this.resolveDbPath(dbPath);
        return (await this.call("init", { db_path: dbPath }));
    }
    /** Generate a new Keychat identity (mnemonic + keypairs). */
    async generateIdentity() {
        return (await this.call("generate_identity"));
    }
    /** Import identity from mnemonic. */
    async importIdentity(mnemonic, password) {
        return (await this.call("import_identity", { mnemonic, password }));
    }
    /** Get current account public info. */
    async getAccountInfo() {
        return (await this.call("get_account_info"));
    }
    /** Generate a Signal pre-key bundle for key exchange. */
    async generatePrekeyBundle() {
        return (await this.call("generate_prekey_bundle"));
    }
    /** Process a peer's pre-key bundle to establish Signal session. */
    async processPrekeyBundle(params) {
        return (await this.call("process_prekey_bundle", params));
    }
    /** Send an encrypted message. */
    async sendMessage(to, text, opts) {
        return (await this.call("send_message", {
            to,
            text,
            is_hello_reply: opts?.isHelloReply ?? false,
            sender_name: opts?.senderName,
        }));
    }
    /** Process an incoming hello/friend-request to establish a Signal session. */
    async processHello(message) {
        return (await this.call("process_hello", { message }));
    }
    /** Compute a Nostr address (pubkey) from a receiving-address seed. */
    async computeAddress(seed) {
        return (await this.call("compute_address", { seed }));
    }
    /** Subscribe to additional Nostr pubkeys for inbound messages. */
    async addSubscription(pubkeys) {
        return (await this.call("add_subscription", { pubkeys }));
    }
    async removeSubscription(pubkeys) {
        return (await this.call("remove_subscription", { pubkeys }));
    }
    /** Decrypt a received message. */
    async decryptMessage(from, ciphertext, isPrekey, localSignalPubkey, nostrPubkey) {
        return (await this.call("decrypt_message", {
            from,
            ciphertext,
            is_prekey: isPrekey ?? false,
            ...(localSignalPubkey ? { my_signal_key: localSignalPubkey } : {}),
            ...(nostrPubkey ? { nostr_pubkey: nostrPubkey } : {}),
        }));
    }
    /** Connect to Nostr relays. */
    async connect(relays) {
        return (await this.call("connect", { relays }));
    }
    /** Disconnect from relays. */
    async disconnect() {
        return (await this.call("disconnect"));
    }
    /** Check if a Signal session exists with a peer. */
    async hasSession(pubkey) {
        return (await this.call("has_session", { pubkey }));
    }
    /** Get all receiving addresses from Signal sessions in DB (for resubscription on restart). */
    /** Get all peer sessions from DB. */
    async getAllSessions() {
        return (await this.call("get_all_sessions", {}));
    }
    /** Get all peer mappings (nostr↔signal pubkey). */
    async getPeerMappings() {
        return (await this.call("get_peer_mappings", {}));
    }
    /** Save a peer mapping. */
    async savePeerMapping(nostrPubkey, signalPubkey, deviceId, name) {
        return (await this.call("save_peer_mapping", { nostr_pubkey: nostrPubkey, peer_signal_key: signalPubkey, device_id: deviceId, name }));
    }
    /** Delete a peer mapping by nostr pubkey. */
    async deletePeerMapping(nostrPubkey) {
        return (await this.call("delete_peer_mapping", { nostr_pubkey: nostrPubkey }));
    }
    /** Mark an event as processed (persisted to DB). */
    async markEventProcessed(eventId, createdAt) {
        return (await this.call("mark_event_processed", { event_id: eventId, created_at: createdAt }));
    }
    /** Check if an event was already processed. */
    async isEventProcessed(eventId) {
        return (await this.call("is_event_processed", { event_id: eventId }));
    }
    /** Send a hello/friend request to a Nostr pubkey via Gift Wrap. */
    async sendHello(toPubkey, name) {
        return (await this.call("send_hello", { to_pubkey: toPubkey, name }));
    }
    /** Parse sender identity key from a PreKey Signal message (before decryption). */
    async parsePrekeySender(ciphertext) {
        return (await this.call("parse_prekey_sender", { ciphertext }));
    }
    async lookupPeerBySignedPrekeyId(signedPrekeyId) {
        return (await this.call("lookup_peer_by_signed_prekey_id", { signed_prekey_id: signedPrekeyId }));
    }
    async clearPrekeyMaterial(nostrPubkey) {
        await this.call("clear_prekey_material", { nostr_pubkey: nostrPubkey });
    }
    /** Verify a Schnorr signature (used for PrekeyMessageModel globalSign verification). */
    async verifySchnorr(pubkey, message, signature) {
        const result = await this.call("verify_schnorr", { pubkey, message, signature });
        return result.valid;
    }
    /** Send a profile update (type 48) to an existing peer. */
    async sendProfile(peerNostrPubkey, opts) {
        return (await this.call("send_profile", {
            peer_nostr_pubkey: peerNostrPubkey,
            name: opts?.name,
            avatar: opts?.avatar,
            lightning: opts?.lightning,
            bio: opts?.bio,
        }));
    }
    /** Save an address-to-peer mapping. */
    async saveReceivingAddress(address, peerNostrPubkey) {
        return (await this.call("save_address_mapping", { address, peer_nostr_pubkey: peerNostrPubkey }));
    }
    /** Get all address-to-peer mappings. */
    async getReceivingAddresses() {
        return (await this.call("get_address_mappings", {}));
    }
    /** Delete an address-to-peer mapping. */
    async deleteReceivingAddress(address) {
        return (await this.call("delete_address_mapping", { address }));
    }
    /** Save peer_inbox for a peer. */
    async saveMySendingAddress(nostrPubkey, address) {
        return (await this.call("save_peer_inbox", { nostr_pubkey: nostrPubkey, address }));
    }
    /** Persist a message queued while waiting for Protocol Step 3 accept-first. */
    async savePendingHelloMessage(peerPubkey, text) {
        return this.withSignalDb((db) => {
            this.ensurePendingHelloTable(db);
            const createdAt = Math.floor(Date.now() / 1000);
            const result = db
                .prepare("INSERT INTO pending_hello_messages (peer_pubkey, message_text, created_at) VALUES (?, ?, ?)")
                .run(peerPubkey, text, createdAt);
            const rawId = result.lastInsertRowid ?? 0;
            return { id: Number(rawId) };
        });
    }
    /** Load persisted hello-queue messages for a peer. */
    async getPendingHelloMessages(peerPubkey) {
        return this.withSignalDb((db) => {
            this.ensurePendingHelloTable(db);
            const rows = db
                .prepare("SELECT id, message_text FROM pending_hello_messages WHERE peer_pubkey = ? ORDER BY id ASC")
                .all(peerPubkey);
            return {
                messages: rows.map((row) => ({ id: Number(row.id), text: row.message_text })),
            };
        });
    }
    /** Delete persisted hello-queue messages for a peer after successful flush. */
    async deletePendingHelloMessages(peerPubkey) {
        this.withSignalDb((db) => {
            this.ensurePendingHelloTable(db);
            db.prepare("DELETE FROM pending_hello_messages WHERE peer_pubkey = ?").run(peerPubkey);
        });
    }
    /** Delete one persisted hello-queue message by row id. */
    async deletePendingHelloMessageById(id) {
        this.withSignalDb((db) => {
            this.ensurePendingHelloTable(db);
            db.prepare("DELETE FROM pending_hello_messages WHERE id = ?").run(id);
        });
    }
    /** Check if bridge is connected and responsive (ping with 5s timeout). */
    async isConnected() {
        if (!this.process?.stdin?.writable)
            return false;
        try {
            const pingPromise = this.call("ping");
            const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error("ping timeout")), 5000));
            await Promise.race([pingPromise, timeoutPromise]);
            return true;
        }
        catch {
            return false;
        }
    }
    resolveDbPath(input) {
        if (input.startsWith("~/")) {
            return join(homedir(), input.slice(2));
        }
        return input;
    }
    getSignalDbPathOrThrow() {
        if (!this.signalDbPath) {
            throw new Error("Signal DB path unavailable. Call init(dbPath) before pending hello operations.");
        }
        return this.signalDbPath;
    }
    withSignalDb(run) {
        const dbPath = this.getSignalDbPathOrThrow();
        let DbCtor = null;
        try {
            DbCtor = require("better-sqlite3");
        }
        catch {
            const sqliteBuiltin = require("node:sqlite");
            DbCtor = sqliteBuiltin.DatabaseSync;
        }
        const db = new DbCtor(dbPath);
        try {
            return run(db);
        }
        finally {
            db.close();
        }
    }
    ensurePendingHelloTable(db) {
        db.exec("CREATE TABLE IF NOT EXISTS pending_hello_messages (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "peer_pubkey TEXT NOT NULL, " +
            "message_text TEXT NOT NULL, " +
            "created_at INTEGER NOT NULL" +
            ")");
    }
    /** Delete a Signal session for a peer. */
    async deleteSession(signalPubkey, deviceId) {
        return (await this.call("delete_session", { peer_signal_key: signalPubkey, device_id: deviceId }));
    }
    /** Clean up orphaned session rows with no matching peer_mapping entry. */
    async cleanupOrphanedSessions() {
        return (await this.call("cleanup_orphaned_sessions", {}));
    }
    /** Sign a Blossom (kind:24242) Nostr event for media upload auth. */
    async signBlossomEvent(content, tags) {
        const result = (await this.call("sign_blossom_event", { content, tags }));
        return result.event_json;
    }
    // =========================================================================
    // Group (small group / sendAll)
    // =========================================================================
    /** Create a new small group. */
    async createGroup(name) {
        return (await this.call("create_group", { name }));
    }
    /** Get group info. */
    async getGroup(groupId) {
        return (await this.call("get_group", { group_id: groupId }));
    }
    /** Get all groups. */
    async getAllGroups() {
        return (await this.call("get_all_groups"));
    }
    /** Join a group from an invite (RoomProfile). */
    async joinGroup(roomProfile, senderIdPubkey) {
        return (await this.call("join_group", {
            room_profile: roomProfile,
            sender_id_pubkey: senderIdPubkey,
        }));
    }
    /** Add a member to a group. */
    async addGroupMember(groupId, idPubkey, name, isAdmin) {
        return (await this.call("add_group_member", {
            group_id: groupId,
            id_pubkey: idPubkey,
            name: name ?? "",
            is_admin: isAdmin ?? false,
        }));
    }
    /** Remove a member from a group. */
    async removeGroupMember(groupId, idPubkey) {
        return (await this.call("remove_group_member", { group_id: groupId, id_pubkey: idPubkey }));
    }
    /** Get group members. */
    async getGroupMembers(groupId) {
        return (await this.call("get_group_members", { group_id: groupId }));
    }
    /** Send a message to all members of a group (sendAll). */
    async sendGroupMessage(groupId, text, opts) {
        return (await this.call("send_group_message", {
            group_id: groupId,
            text,
            subtype: opts?.subtype,
            ext: opts?.ext,
        }));
    }
    /** Update group name. */
    async updateGroupName(groupId, name) {
        return (await this.call("update_group_name", { group_id: groupId, name }));
    }
    /** Update group status (enabled/disabled). */
    async updateGroupStatus(groupId, status) {
        return (await this.call("update_group_status", { group_id: groupId, status }));
    }
    /** Delete a group. */
    async deleteGroup(groupId) {
        return (await this.call("delete_group", { group_id: groupId }));
    }
    // ---------------------------------------------------------------------------
    // MLS (Large Group) methods
    // ---------------------------------------------------------------------------
    /** Initialize MLS for the current identity. */
    async mlsInit(dbPath) {
        return (await this.call("mls_init", { db_path: dbPath }));
    }
    /** Create a key package for MLS (to be published as kind:10443). */
    async mlsCreateKeyPackage() {
        return (await this.call("mls_create_key_package", {}));
    }
    /** Create a new MLS group. */
    async mlsCreateGroup(params) {
        return (await this.call("mls_create_group", params));
    }
    /** Add members to an MLS group using their key packages. */
    async mlsAddMembers(groupId, keyPackages) {
        return (await this.call("mls_add_members", {
            group_id: groupId,
            key_packages: keyPackages,
        }));
    }
    /** Merge pending commit (call after add_members, self_update, etc.). */
    async mlsSelfCommit(groupId) {
        return (await this.call("mls_self_commit", { group_id: groupId }));
    }
    /** Join an MLS group from a Welcome message (base64). */
    async mlsJoinGroup(groupId, welcomeBase64) {
        return (await this.call("mls_join_group", {
            group_id: groupId,
            welcome: welcomeBase64,
        }));
    }
    /** Encrypt a message for an MLS group. */
    async mlsCreateMessage(groupId, text) {
        return (await this.call("mls_create_message", {
            group_id: groupId,
            text,
        }));
    }
    /** Decrypt a received MLS group message. */
    async mlsDecryptMessage(groupId, message) {
        return (await this.call("mls_decrypt_message", {
            group_id: groupId,
            message,
        }));
    }
    /** Parse the type of an MLS message without consuming it. */
    async mlsParseMessageType(groupId, data) {
        return (await this.call("mls_parse_message_type", {
            group_id: groupId,
            data,
        }));
    }
    /** Process a commit from another member (add/remove/update/etc.). */
    async mlsProcessCommit(groupId, message) {
        return (await this.call("mls_process_commit", {
            group_id: groupId,
            message,
        }));
    }
    /** Get the current listen key (onetimekey) for an MLS group. */
    async mlsGetListenKey(groupId) {
        return (await this.call("mls_get_listen_key", { group_id: groupId }));
    }
    /** Get MLS group info. */
    async mlsGetGroupInfo(groupId) {
        return (await this.call("mls_get_group_info", { group_id: groupId }));
    }
    /** List all MLS groups. */
    async mlsGetGroups() {
        return (await this.call("mls_get_groups", {}));
    }
    /** Self-update key material in a group. */
    async mlsSelfUpdate(groupId, extension) {
        return (await this.call("mls_self_update", {
            group_id: groupId,
            extension,
        }));
    }
    /** Update group context extensions (name, description, etc.). */
    async mlsUpdateGroupExtensions(groupId, opts) {
        return (await this.call("mls_update_group_extensions", {
            group_id: groupId,
            ...opts,
        }));
    }
    /** Remove members from an MLS group. */
    async mlsRemoveMembers(groupId, members) {
        return (await this.call("mls_remove_members", {
            group_id: groupId,
            members,
        }));
    }
    /** Delete an MLS group. */
    async mlsDeleteGroup(groupId) {
        return (await this.call("mls_delete_group", { group_id: groupId }));
    }
    /** Get sender of an MLS message without consuming it. */
    async mlsGetSender(groupId, message) {
        return (await this.call("mls_get_sender", {
            group_id: groupId,
            message,
        }));
    }
    /** Send a message to an MLS group (encrypt + publish to relay). */
    async mlsSendMessage(groupId, text) {
        return (await this.call("mls_send_message", {
            group_id: groupId,
            text,
        }));
    }
    /** Publish pre-encrypted content (e.g., MLS commit) to a group's listen key. */
    async mlsPublishToGroup(listenKey, content) {
        return (await this.call("mls_publish_to_group", {
            listen_key: listenKey,
            content,
        }));
    }
    /** Create a new KeyPackage, publish it as kind:10443, and return result. */
    async mlsPublishKeyPackage() {
        return (await this.call("mls_publish_key_package", {}));
    }
    /** Fetch the latest KeyPackage (kind:10443) for a pubkey from relays. */
    async mlsFetchKeyPackage(pubkey) {
        return (await this.call("mls_fetch_key_package", { pubkey }));
    }
}

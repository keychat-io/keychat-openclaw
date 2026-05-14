/**
 * Nostr Wallet Connect (NWC) — NIP-47 client implementation.
 *
 * Connects to a remote Lightning wallet via Nostr relay.
 * The agent can: make_invoice, lookup_invoice, get_balance, list_transactions.
 * Pay operations require owner approval (forwarded as invoice to owner).
 *
 * Connection URI format:
 *   nostr+walletconnect://<wallet_pubkey>?relay=<relay_url>&secret=<hex_secret>
 */
import NDK, { NDKEvent, NDKPrivateKeySigner, } from "@nostr-dev-kit/ndk";
// ─── Parse connection URI ───────────────────────────────────────────────
export function parseNwcUri(uri) {
    try {
        // nostr+walletconnect://<pubkey>?relay=...&secret=...
        const cleaned = uri.trim();
        if (!cleaned.startsWith("nostr+walletconnect://"))
            return null;
        const url = new URL(cleaned.replace("nostr+walletconnect://", "https://"));
        const walletPubkey = url.hostname;
        const relay = url.searchParams.get("relay");
        const secret = url.searchParams.get("secret");
        const lud16 = url.searchParams.get("lud16") || undefined;
        if (!walletPubkey || !relay || !secret)
            return null;
        if (!/^[0-9a-f]{64}$/i.test(walletPubkey))
            return null;
        if (!/^[0-9a-f]{64}$/i.test(secret))
            return null;
        return { walletPubkey, relay: decodeURIComponent(relay), secret, lud16 };
    }
    catch {
        return null;
    }
}
// ─── NWC Client ─────────────────────────────────────────────────────────
export class NwcClient {
    ndk;
    signer;
    walletPubkey;
    connected = false;
    sub = null;
    pendingRequests = new Map();
    connInfo;
    constructor(connInfo) {
        this.connInfo = connInfo;
        this.signer = new NDKPrivateKeySigner(connInfo.secret);
        this.walletPubkey = connInfo.walletPubkey;
        this.ndk = new NDK({
            explicitRelayUrls: [connInfo.relay],
            signer: this.signer,
        });
    }
    /** Connect to the NWC relay and subscribe for responses. */
    async connect() {
        if (this.connected)
            return;
        await this.ndk.connect();
        this.connected = true;
        // Subscribe for responses (kind:23195) and notifications (kind:23197)
        const clientPubkey = (await this.signer.user()).pubkey;
        const filter = {
            kinds: [23195, 23196, 23197],
            "#p": [clientPubkey],
            since: Math.floor(Date.now() / 1000) - 60, // 60s buffer for clock skew
        };
        this.sub = this.ndk.subscribe(filter, { closeOnEose: false });
        this.sub.on("event", async (event) => {
            console.log(`[nwc] Received event kind:${event.kind} id:${event.id?.slice(0, 12)} from:${event.pubkey?.slice(0, 12)}`);
            try {
                await this.handleResponse(event);
            }
            catch (err) {
                console.error("[nwc] Error handling response:", err);
            }
        });
        console.log(`[nwc] Connected to ${this.connInfo.relay}, wallet: ${this.walletPubkey.slice(0, 16)}...`);
    }
    /** Disconnect and clean up. */
    async disconnect() {
        if (this.sub) {
            this.sub.stop();
            this.sub = null;
        }
        // Reject all pending requests
        for (const [, pending] of this.pendingRequests) {
            clearTimeout(pending.timer);
            pending.reject(new Error("NWC client disconnected"));
        }
        this.pendingRequests.clear();
        this.connected = false;
        console.log("[nwc] Disconnected");
    }
    /** Send a NIP-47 request and wait for response (poll-based for reliability). */
    async request(method, params = {}, timeoutMs = 30_000) {
        if (!this.connected) {
            await this.connect();
        }
        const payload = JSON.stringify({ method, params });
        const event = new NDKEvent(this.ndk);
        event.kind = 23194;
        event.tags = [["p", this.walletPubkey]];
        // Use NIP-04 encryption (default per NIP-47 when no encryption tag in info event)
        event.content = await this.signer.encrypt(await this.ndk.getUser({ pubkey: this.walletPubkey }), payload, "nip04");
        await event.sign(this.signer);
        await event.publish();
        const requestId = event.id;
        console.log(`[nwc] Request sent: ${method} (${requestId?.slice(0, 12)})`);
        // Poll for response tagged with #e matching our request
        const clientPubkey = (await this.signer.user()).pubkey;
        const walletUser = await this.ndk.getUser({ pubkey: this.walletPubkey });
        const startTime = Date.now();
        const pollInterval = 1500; // ms
        while (Date.now() - startTime < timeoutMs) {
            await new Promise((r) => setTimeout(r, pollInterval));
            try {
                const responses = await this.ndk.fetchEvents({
                    kinds: [23195],
                    "#p": [clientPubkey],
                    "#e": [requestId],
                });
                for (const resp of responses) {
                    let decrypted;
                    try {
                        decrypted = await this.signer.decrypt(walletUser, resp.content, "nip04");
                    }
                    catch {
                        decrypted = await this.signer.decrypt(walletUser, resp.content, "nip44");
                    }
                    const parsed = JSON.parse(decrypted);
                    console.log(`[nwc] Response received: ${parsed.result_type} (${resp.id?.slice(0, 12)})`);
                    return parsed;
                }
            }
            catch {
                // fetch failed, retry
            }
        }
        throw new Error(`NWC request timed out: ${method}`);
    }
    /** Handle an incoming response event. */
    async handleResponse(event) {
        // Find which request this responds to
        const eTag = event.tags.find((t) => t[0] === "e");
        const requestId = eTag?.[1];
        // Decrypt content — try NIP-04 first (default per NIP-47), fallback to NIP-44
        const walletUser = await this.ndk.getUser({ pubkey: this.walletPubkey });
        let decrypted;
        try {
            decrypted = await this.signer.decrypt(walletUser, event.content, "nip04");
        }
        catch {
            decrypted = await this.signer.decrypt(walletUser, event.content, "nip44");
        }
        const response = JSON.parse(decrypted);
        if (event.kind === 23197) {
            // Notification — emit event (could be payment_received etc.)
            console.log(`[nwc] Notification: ${JSON.stringify(response)}`);
            // TODO: emit to channel for payment_received notifications
            return;
        }
        if (!requestId)
            return;
        const pending = this.pendingRequests.get(requestId);
        if (!pending)
            return;
        this.pendingRequests.delete(requestId);
        clearTimeout(pending.timer);
        pending.resolve(response);
    }
    // ─── Public API ─────────────────────────────────────────────────────
    /** Get wallet balance in msats. */
    async getBalance() {
        const resp = await this.request("get_balance");
        if (resp.error)
            throw new Error(`NWC get_balance: ${resp.error.message}`);
        return resp.result;
    }
    /** Get balance in sats (convenience). */
    async getBalanceSats() {
        const b = await this.getBalance();
        return Math.floor(b.balance / 1000);
    }
    /** Create an invoice (receive payment). */
    async makeInvoice(amountSats, description, expirySecs) {
        const params = {
            amount: amountSats * 1000, // convert to msats
        };
        if (description)
            params.description = description;
        if (expirySecs)
            params.expiry = expirySecs;
        const resp = await this.request("make_invoice", params);
        if (resp.error)
            throw new Error(`NWC make_invoice: ${resp.error.message}`);
        return resp.result;
    }
    /** Look up an invoice by payment hash or bolt11 string. */
    async lookupInvoice(opts) {
        const resp = await this.request("lookup_invoice", opts);
        if (resp.error)
            throw new Error(`NWC lookup_invoice: ${resp.error.message}`);
        return resp.result;
    }
    /** List transactions. */
    async listTransactions(opts) {
        const resp = await this.request("list_transactions", opts ?? {});
        if (resp.error)
            throw new Error(`NWC list_transactions: ${resp.error.message}`);
        return resp.result.transactions ?? [];
    }
    /** Get wallet info (supported methods). */
    async getInfo() {
        const resp = await this.request("get_info");
        if (resp.error)
            throw new Error(`NWC get_info: ${resp.error.message}`);
        return resp.result ?? {};
    }
    /**
     * Request payment of an invoice.
     * NOTE: This is gated — the agent should NOT call this directly.
     * Instead, forward the invoice to the owner for approval.
     */
    async payInvoice(invoice, amountMsats) {
        const params = { invoice };
        if (amountMsats)
            params.amount = amountMsats;
        const resp = await this.request("pay_invoice", params, 60_000);
        if (resp.error)
            throw new Error(`NWC pay_invoice: ${resp.error.message}`);
        return resp.result;
    }
    /** Check if connected. */
    isConnected() {
        return this.connected;
    }
    /** Get connection info summary (no secrets). */
    describe() {
        return {
            relay: this.connInfo.relay,
            walletPubkey: this.connInfo.walletPubkey,
            lud16: this.connInfo.lud16,
        };
    }
}
// ─── Singleton management ───────────────────────────────────────────────
let activeClient = null;
/** Initialize NWC from a connection URI string. */
export async function initNwc(uri) {
    const info = parseNwcUri(uri);
    if (!info)
        throw new Error("Invalid NWC connection URI");
    if (activeClient) {
        await activeClient.disconnect();
    }
    activeClient = new NwcClient(info);
    await activeClient.connect();
    return activeClient;
}
/** Get the active NWC client (null if not configured). */
export function getNwcClient() {
    return activeClient;
}
/** Disconnect and clear the active client. */
export async function disconnectNwc() {
    if (activeClient) {
        await activeClient.disconnect();
        activeClient = null;
    }
}

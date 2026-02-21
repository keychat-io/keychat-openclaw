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

import NDK, {
  NDKEvent,
  NDKPrivateKeySigner,
  type NDKFilter,
  type NDKSubscription,
} from "@nostr-dev-kit/ndk";

// ─── Types ──────────────────────────────────────────────────────────────

export interface NwcConnectionInfo {
  walletPubkey: string; // hex pubkey of wallet service
  relay: string; // relay URL
  secret: string; // hex secret (client private key)
  lud16?: string; // optional lightning address
}

export interface NwcInvoice {
  type: "incoming" | "outgoing";
  state?: "pending" | "settled" | "accepted" | "expired" | "failed";
  invoice?: string;
  description?: string;
  preimage?: string;
  payment_hash: string;
  amount: number; // msats
  fees_paid?: number;
  created_at?: number;
  expires_at?: number;
}

export interface NwcBalance {
  balance: number; // msats
}

interface NwcResponse {
  result_type: string;
  result?: Record<string, unknown> | null;
  error?: { code: string; message: string } | null;
}

// ─── Parse connection URI ───────────────────────────────────────────────

export function parseNwcUri(uri: string): NwcConnectionInfo | null {
  try {
    // nostr+walletconnect://<pubkey>?relay=...&secret=...
    const cleaned = uri.trim();
    if (!cleaned.startsWith("nostr+walletconnect://")) return null;

    const url = new URL(cleaned.replace("nostr+walletconnect://", "https://"));
    const walletPubkey = url.hostname;
    const relay = url.searchParams.get("relay");
    const secret = url.searchParams.get("secret");
    const lud16 = url.searchParams.get("lud16") || undefined;

    if (!walletPubkey || !relay || !secret) return null;
    if (!/^[0-9a-f]{64}$/i.test(walletPubkey)) return null;
    if (!/^[0-9a-f]{64}$/i.test(secret)) return null;

    return { walletPubkey, relay: decodeURIComponent(relay), secret, lud16 };
  } catch {
    return null;
  }
}

// ─── NWC Client ─────────────────────────────────────────────────────────

export class NwcClient {
  private ndk: NDK;
  private signer: NDKPrivateKeySigner;
  private walletPubkey: string;
  private connected = false;
  private sub: NDKSubscription | null = null;
  private pendingRequests = new Map<
    string,
    {
      resolve: (value: NwcResponse) => void;
      reject: (error: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();

  private connInfo: NwcConnectionInfo;

  constructor(connInfo: NwcConnectionInfo) {
    this.connInfo = connInfo;
    this.signer = new NDKPrivateKeySigner(connInfo.secret);
    this.walletPubkey = connInfo.walletPubkey;
    this.ndk = new NDK({
      explicitRelayUrls: [connInfo.relay],
      signer: this.signer,
    });
  }

  /** Connect to the NWC relay and subscribe for responses. */
  async connect(): Promise<void> {
    if (this.connected) return;
    await this.ndk.connect();
    this.connected = true;

    // Subscribe for responses (kind:23195) and notifications (kind:23197)
    const clientPubkey = (await this.signer.user()).pubkey;
    const filter: NDKFilter = {
      kinds: [23195 as number, 23196 as number, 23197 as number],
      "#p": [clientPubkey],
      since: Math.floor(Date.now() / 1000) - 60, // 60s buffer for clock skew
    };

    this.sub = this.ndk.subscribe(filter, { closeOnEose: false });
    this.sub.on("event", async (event: NDKEvent) => {
      console.log(`[nwc] Received event kind:${event.kind} id:${event.id?.slice(0, 12)} from:${event.pubkey?.slice(0, 12)}`);
      try {
        await this.handleResponse(event);
      } catch (err) {
        console.error("[nwc] Error handling response:", err);
      }
    });

    console.log(`[nwc] Connected to ${this.connInfo.relay}, wallet: ${this.walletPubkey.slice(0, 16)}...`);
  }

  /** Disconnect and clean up. */
  async disconnect(): Promise<void> {
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
  private async request(
    method: string,
    params: Record<string, unknown> = {},
    timeoutMs = 30_000,
  ): Promise<NwcResponse> {
    if (!this.connected) {
      await this.connect();
    }

    const payload = JSON.stringify({ method, params });
    const event = new NDKEvent(this.ndk);
    event.kind = 23194;
    event.tags = [["p", this.walletPubkey]];
    // Use NIP-04 encryption (default per NIP-47 when no encryption tag in info event)
    event.content = await this.signer.encrypt(
      await this.ndk.getUser({ pubkey: this.walletPubkey }),
      payload,
      "nip04",
    );

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
          kinds: [23195 as number],
          "#p": [clientPubkey],
          "#e": [requestId],
        });

        for (const resp of responses) {
          let decrypted: string;
          try {
            decrypted = await this.signer.decrypt(walletUser, resp.content, "nip04");
          } catch {
            decrypted = await this.signer.decrypt(walletUser, resp.content, "nip44");
          }
          const parsed = JSON.parse(decrypted) as NwcResponse;
          console.log(`[nwc] Response received: ${parsed.result_type} (${resp.id?.slice(0, 12)})`);
          return parsed;
        }
      } catch {
        // fetch failed, retry
      }
    }

    throw new Error(`NWC request timed out: ${method}`);
  }

  /** Handle an incoming response event. */
  private async handleResponse(event: NDKEvent): Promise<void> {
    // Find which request this responds to
    const eTag = event.tags.find((t) => t[0] === "e");
    const requestId = eTag?.[1];

    // Decrypt content — try NIP-04 first (default per NIP-47), fallback to NIP-44
    const walletUser = await this.ndk.getUser({ pubkey: this.walletPubkey });
    let decrypted: string;
    try {
      decrypted = await this.signer.decrypt(walletUser, event.content, "nip04");
    } catch {
      decrypted = await this.signer.decrypt(walletUser, event.content, "nip44");
    }
    const response = JSON.parse(decrypted) as NwcResponse;

    if (event.kind === 23197) {
      // Notification — emit event (could be payment_received etc.)
      console.log(`[nwc] Notification: ${JSON.stringify(response)}`);
      // TODO: emit to channel for payment_received notifications
      return;
    }

    if (!requestId) return;
    const pending = this.pendingRequests.get(requestId);
    if (!pending) return;

    this.pendingRequests.delete(requestId);
    clearTimeout(pending.timer);
    pending.resolve(response);
  }

  // ─── Public API ─────────────────────────────────────────────────────

  /** Get wallet balance in msats. */
  async getBalance(): Promise<NwcBalance> {
    const resp = await this.request("get_balance");
    if (resp.error) throw new Error(`NWC get_balance: ${resp.error.message}`);
    return resp.result as unknown as NwcBalance;
  }

  /** Get balance in sats (convenience). */
  async getBalanceSats(): Promise<number> {
    const b = await this.getBalance();
    return Math.floor(b.balance / 1000);
  }

  /** Create an invoice (receive payment). */
  async makeInvoice(
    amountSats: number,
    description?: string,
    expirySecs?: number,
  ): Promise<NwcInvoice> {
    const params: Record<string, unknown> = {
      amount: amountSats * 1000, // convert to msats
    };
    if (description) params.description = description;
    if (expirySecs) params.expiry = expirySecs;

    const resp = await this.request("make_invoice", params);
    if (resp.error) throw new Error(`NWC make_invoice: ${resp.error.message}`);
    return resp.result as unknown as NwcInvoice;
  }

  /** Look up an invoice by payment hash or bolt11 string. */
  async lookupInvoice(opts: {
    paymentHash?: string;
    invoice?: string;
  }): Promise<NwcInvoice> {
    const resp = await this.request("lookup_invoice", opts);
    if (resp.error) throw new Error(`NWC lookup_invoice: ${resp.error.message}`);
    return resp.result as unknown as NwcInvoice;
  }

  /** List transactions. */
  async listTransactions(opts?: {
    from?: number;
    until?: number;
    limit?: number;
    offset?: number;
    type?: "incoming" | "outgoing";
  }): Promise<NwcInvoice[]> {
    const resp = await this.request("list_transactions", opts ?? {});
    if (resp.error) throw new Error(`NWC list_transactions: ${resp.error.message}`);
    return (resp.result as unknown as { transactions: NwcInvoice[] }).transactions ?? [];
  }

  /** Get wallet info (supported methods). */
  async getInfo(): Promise<Record<string, unknown>> {
    const resp = await this.request("get_info");
    if (resp.error) throw new Error(`NWC get_info: ${resp.error.message}`);
    return resp.result ?? {};
  }

  /**
   * Request payment of an invoice.
   * NOTE: This is gated — the agent should NOT call this directly.
   * Instead, forward the invoice to the owner for approval.
   */
  async payInvoice(invoice: string, amountMsats?: number): Promise<{ preimage: string; fees_paid?: number }> {
    const params: Record<string, unknown> = { invoice };
    if (amountMsats) params.amount = amountMsats;

    const resp = await this.request("pay_invoice", params, 60_000);
    if (resp.error) throw new Error(`NWC pay_invoice: ${resp.error.message}`);
    return resp.result as unknown as { preimage: string; fees_paid?: number };
  }

  /** Check if connected. */
  isConnected(): boolean {
    return this.connected;
  }

  /** Get connection info summary (no secrets). */
  describe(): { relay: string; walletPubkey: string; lud16?: string } {
    return {
      relay: this.connInfo.relay,
      walletPubkey: this.connInfo.walletPubkey,
      lud16: this.connInfo.lud16,
    };
  }
}

// ─── Singleton management ───────────────────────────────────────────────

let activeClient: NwcClient | null = null;

/** Initialize NWC from a connection URI string. */
export async function initNwc(uri: string): Promise<NwcClient> {
  const info = parseNwcUri(uri);
  if (!info) throw new Error("Invalid NWC connection URI");

  if (activeClient) {
    await activeClient.disconnect();
  }

  activeClient = new NwcClient(info);
  await activeClient.connect();
  return activeClient;
}

/** Get the active NWC client (null if not configured). */
export function getNwcClient(): NwcClient | null {
  return activeClient;
}

/** Disconnect and clear the active client. */
export async function disconnectNwc(): Promise<void> {
  if (activeClient) {
    await activeClient.disconnect();
    activeClient = null;
  }
}

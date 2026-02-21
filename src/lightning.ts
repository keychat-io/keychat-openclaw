/**
 * Lightning wallet — receive-only via Lightning Address (LNURL-pay).
 *
 * The agent can:
 * - Generate invoices from its configured Lightning address
 * - Tell users its Lightning address for payments
 * - Forward outbound payment requests (invoices) to the owner
 *
 * The agent CANNOT send payments directly.
 */

export interface LnurlPayMetadata {
  callback: string;
  minSendable: number; // millisatoshis
  maxSendable: number; // millisatoshis
  metadata: string;
  tag: string;
}

export interface LnurlInvoice {
  pr: string; // BOLT11 payment request
  routes: unknown[];
  verify?: string; // verification URL
}

/**
 * Parse a Lightning address into a LNURL-pay endpoint URL.
 * e.g. "user@domain.com" → "https://domain.com/.well-known/lnurlp/user"
 */
export function lightningAddressToLnurlp(address: string): string | null {
  const parts = address.trim().split("@");
  if (parts.length !== 2) return null;
  const [user, domain] = parts;
  if (!user || !domain) return null;
  return `https://${domain}/.well-known/lnurlp/${user}`;
}

/**
 * Fetch LNURL-pay metadata for a Lightning address.
 */
export async function fetchLnurlPayMetadata(
  lightningAddress: string,
): Promise<LnurlPayMetadata | null> {
  const url = lightningAddressToLnurlp(lightningAddress);
  if (!url) return null;

  try {
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as LnurlPayMetadata;
    if (data.tag !== "payRequest") return null;
    return data;
  } catch (err) {
    console.error(`[keychat/lightning] Failed to fetch LNURL-pay metadata: ${err}`);
    return null;
  }
}

/**
 * Request an invoice from the LNURL-pay callback.
 * @param amountSats Amount in satoshis
 * @param comment Optional comment/memo
 */
export async function requestInvoice(
  lightningAddress: string,
  amountSats: number,
  comment?: string,
): Promise<LnurlInvoice | null> {
  const meta = await fetchLnurlPayMetadata(lightningAddress);
  if (!meta) return null;

  const amountMsats = amountSats * 1000;
  if (amountMsats < meta.minSendable || amountMsats > meta.maxSendable) {
    console.error(
      `[keychat/lightning] Amount ${amountSats} sats outside range: ${meta.minSendable / 1000}-${meta.maxSendable / 1000} sats`,
    );
    return null;
  }

  let callbackUrl = `${meta.callback}${meta.callback.includes("?") ? "&" : "?"}amount=${amountMsats}`;
  if (comment) {
    callbackUrl += `&comment=${encodeURIComponent(comment)}`;
  }

  try {
    const res = await fetch(callbackUrl, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as LnurlInvoice;
    if (!data.pr) return null;
    return data;
  } catch (err) {
    console.error(`[keychat/lightning] Failed to request invoice: ${err}`);
    return null;
  }
}

/**
 * Verify if an invoice has been paid (if verify URL is available).
 */
export async function verifyPayment(verifyUrl: string): Promise<boolean> {
  try {
    const res = await fetch(verifyUrl, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return false;
    const data = (await res.json()) as { settled: boolean };
    return data.settled === true;
  } catch {
    return false;
  }
}

/**
 * Format satoshi amounts for display.
 */
export function formatSats(sats: number): string {
  if (sats >= 100_000_000) return `${(sats / 100_000_000).toFixed(8)} BTC`;
  if (sats >= 1_000_000) return `${(sats / 1_000_000).toFixed(2)}M sats`;
  if (sats >= 1_000) return `${(sats / 1_000).toFixed(1)}k sats`;
  return `${sats} sats`;
}

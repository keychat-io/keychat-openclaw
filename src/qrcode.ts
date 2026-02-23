export async function generateQRDataUrl(npub: string): Promise<string> {
  try {
    const QRCode = await import("qrcode");
    const url = `https://www.keychat.io/u/?k=${npub}`;
    return await QRCode.toDataURL(url, { width: 256, margin: 2 });
  } catch {
    return ""; // QR code generation not available
  }
}

/**
 * Generate a QR code as Unicode block characters for terminal display.
 * Uses half-block characters (▀▄█ ) so each text row encodes 2 pixel rows.
 * Can be scanned by phone camera directly from the screen.
 */
export async function generateQRTerminal(url: string): Promise<string> {
  try {
    const QRCode = await import("qrcode");
    return await QRCode.toString(url, { type: "terminal", small: true });
  } catch {
    return ""; // qrcode not installed
  }
}

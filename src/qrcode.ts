export async function generateQRDataUrl(npub: string): Promise<string> {
  try {
    const QRCode = await import("qrcode");
    const url = `https://www.keychat.io/u/?k=${npub}`;
    return await QRCode.toDataURL(url, { width: 256, margin: 2 });
  } catch {
    return ""; // QR code generation not available
  }
}

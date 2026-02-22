import { createDecipheriv, createCipheriv, randomBytes, createHash } from "node:crypto";
import { writeFile, mkdir, readFile } from "node:fs/promises";
import { join, extname, basename } from "node:path";

export interface KeychatMediaInfo {
  url: string;
  kctype: string;
  suffix: string;
  key: string;
  iv: string;
  size: number;
  hash?: string;
  sourceName?: string;
}

export interface MediaUploadResult {
  /** The full Keychat media URL with encryption params */
  mediaUrl: string;
  /** The kctype (image, video, file) */
  kctype: string;
}

/** Default Blossom media server (same as Keychat app default) */
const DEFAULT_MEDIA_SERVER = "https://relay.keychat.io";

/** Determine kctype from file extension or mime type */
function resolveKctype(filePath: string, mimeType?: string): string {
  const ext = extname(filePath).toLowerCase();
  const imageExts = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".svg"];
  const videoExts = [".mp4", ".avi", ".mov", ".mkv", ".webm", ".flv", ".wmv", ".m4v"];

  if (mimeType?.startsWith("image/") || imageExts.includes(ext)) return "image";
  if (mimeType?.startsWith("video/") || videoExts.includes(ext)) return "video";
  return "file";
}

/**
 * Encrypt a file with AES-256-CTR (matches Keychat app's encryptFile).
 * Returns the encrypted bytes + key/iv/hash/suffix/sourceName.
 */
async function encryptFile(filePath: string): Promise<{
  encrypted: Buffer;
  key: string;
  iv: string;
  hash: string;
  suffix: string;
  sourceName: string;
}> {
  const fileBytes = await readFile(filePath);
  const key = randomBytes(32);
  const iv = randomBytes(16);

  const cipher = createCipheriv("aes-256-ctr", key, iv);
  const encrypted = Buffer.concat([cipher.update(fileBytes), cipher.final()]);

  const sha256 = createHash("sha256").update(encrypted).digest("base64");

  const fileName = basename(filePath);
  const suffix = extname(filePath).replace(".", "");

  return {
    encrypted,
    key: key.toString("base64"),
    iv: iv.toString("base64"),
    hash: sha256,
    suffix,
    sourceName: fileName,
  };
}

/**
 * Upload encrypted bytes to a Blossom server.
 * Uses Nostr auth (kind:24242 event signed by agent's key).
 */
async function uploadToBlossom(
  encrypted: Buffer,
  hash: string,
  signEvent: (content: string, tags: string[][]) => Promise<string>,
  server?: string,
): Promise<string> {
  const baseUrl = server || DEFAULT_MEDIA_SERVER;

  // Sign authorization event (kind:24242)
  const expiration = Math.floor(Date.now() / 1000) + 86400 * 30; // 30 days
  const eventJson = await signEvent(hash, [
    ["t", "upload"],
    ["x", hash],
    ["expiration", expiration.toString()],
  ]);

  const authHeader = `Nostr ${Buffer.from(eventJson).toString("base64")}`;

  const response = await fetch(`${baseUrl}/upload`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/octet-stream",
      Authorization: authHeader,
    },
    body: new Uint8Array(encrypted),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`Blossom upload failed (${response.status}): ${body}`);
  }

  const data = (await response.json()) as { url?: string; size?: number };
  if (!data.url) throw new Error("Blossom upload response missing url");
  return data.url;
}

/**
 * Encrypt and upload a local file, returning a Keychat media URL.
 *
 * @param filePath - Local file path to upload
 * @param signEvent - Function to sign a Nostr kind:24242 event for Blossom auth
 * @param server - Optional Blossom server URL (defaults to relay.keychat.io)
 * @param mimeType - Optional MIME type hint
 */
export async function encryptAndUpload(
  filePath: string,
  signEvent: (content: string, tags: string[][]) => Promise<string>,
  server?: string,
  mimeType?: string,
): Promise<MediaUploadResult> {
  const { encrypted, key, iv, hash, suffix, sourceName } = await encryptFile(filePath);
  const url = await uploadToBlossom(encrypted, hash, signEvent, server);
  const kctype = resolveKctype(filePath, mimeType);

  // Construct the Keychat media URL (same format as app)
  const parsedUrl = new URL(url);
  const mediaUrl = new URL(parsedUrl.origin + parsedUrl.pathname);
  mediaUrl.searchParams.set("kctype", kctype);
  mediaUrl.searchParams.set("suffix", suffix);
  mediaUrl.searchParams.set("key", key);
  mediaUrl.searchParams.set("iv", iv);
  mediaUrl.searchParams.set("size", encrypted.length.toString());
  mediaUrl.searchParams.set("hash", hash);
  mediaUrl.searchParams.set("sourceName", sourceName);

  return { mediaUrl: mediaUrl.toString(), kctype };
}

/** Parse a Keychat encrypted media URL. Returns null if not a media message. */
export function parseMediaUrl(content: string): KeychatMediaInfo | null {
  const trimmed = content.trim();
  if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) return null;

  let uri: URL;
  try { uri = new URL(trimmed); } catch { return null; }

  const kctype = uri.searchParams.get("kctype");
  if (!kctype) return null;

  const key = uri.searchParams.get("key");
  const iv = uri.searchParams.get("iv");
  if (!key || !iv) return null;

  return {
    url: uri.origin + uri.pathname,
    kctype,
    suffix: uri.searchParams.get("suffix") || kctype,
    key,
    iv,
    size: parseInt(uri.searchParams.get("size") || "0", 10),
    hash: uri.searchParams.get("hash") || undefined,
    sourceName: uri.searchParams.get("sourceName") || undefined,
  };
}

/** Download and decrypt a Keychat media file. Returns local file path. */
export async function downloadAndDecrypt(media: KeychatMediaInfo): Promise<string> {
  const response = await fetch(media.url);
  if (!response.ok) throw new Error(`Download failed: ${response.status}`);
  const encrypted = Buffer.from(await response.arrayBuffer());

  const keyBuf = Buffer.from(media.key, "base64");
  const ivBuf = Buffer.from(media.iv, "base64");
  const decipher = createDecipheriv("aes-256-ctr", keyBuf, ivBuf);
  const decrypted = Buffer.concat([decipher.update(encrypted)]);

  const mediaDir = join(process.env.HOME || "~", ".openclaw", "keychat", "media");
  await mkdir(mediaDir, { recursive: true });
  const filename = media.sourceName || `${Date.now()}.${media.suffix}`;
  const filepath = join(mediaDir, filename);
  await writeFile(filepath, decrypted);

  return filepath;
}

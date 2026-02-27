import { MarkdownConfigSchema, buildChannelConfigSchema } from "openclaw/plugin-sdk";
import { z } from "zod";

const allowFromEntry = z.union([z.string(), z.number()]);

/** Per-account config fields (used both at top-level and inside accounts.*) */
const KeychatAccountSchema = z.object({
  /** Account name */
  name: z.string().optional(),

  /** Whether this channel is enabled */
  enabled: z.boolean().optional(),

  /** Markdown formatting overrides */
  markdown: MarkdownConfigSchema.optional(),

  /** Mnemonic phrase for identity (auto-generated on first start) */
  mnemonic: z.string().optional(),

  /** Public key hex (derived, read-only) */
  publicKey: z.string().optional(),

  /** npub bech32 (derived, read-only) */
  npub: z.string().optional(),

  /** WebSocket relay URLs */
  relays: z.array(z.string()).optional(),

  /** DM access policy */
  dmPolicy: z.enum(["pairing", "allowlist", "open", "disabled"]).optional(),

  /** Allowed sender pubkeys (npub or hex format) */
  allowFrom: z.array(allowFromEntry).optional(),

  /** Lightning address for receiving payments (e.g. "user@walletofsatoshi.com") */
  lightningAddress: z.string().optional(),

  /** Nostr Wallet Connect URI (nostr+walletconnect://...) for Lightning wallet access */
  nwcUri: z.string().optional(),

  /** Blossom media server URL for encrypted file upload/download */
  mediaServer: z.string().optional(),
});

/** Top-level keychat config: single-account fields + optional multi-account map. */
export const KeychatConfigSchema = KeychatAccountSchema.extend({
  /** Multiple named accounts, each with its own identity/config. */
  accounts: z.record(z.string(), KeychatAccountSchema).optional(),
});

export type KeychatConfig = z.infer<typeof KeychatConfigSchema>;

export const keychatChannelConfigSchema = buildChannelConfigSchema(KeychatConfigSchema);

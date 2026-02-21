import type { OpenClawConfig } from "openclaw/plugin-sdk";

export interface KeychatAccountConfig {
  enabled?: boolean;
  name?: string;
  /** Mnemonic phrase for identity (auto-generated on first start) */
  mnemonic?: string;
  /** Public key hex (derived from mnemonic) */
  publicKey?: string;
  /** npub bech32 public key */
  npub?: string;
  /** Nostr relay URLs */
  relays?: string[];
  /** DM access policy */
  dmPolicy?: "pairing" | "allowlist" | "open" | "disabled";
  /** Allowed sender pubkeys */
  allowFrom?: Array<string | number>;
  /** Lightning address for receiving payments */
  lightningAddress?: string;
  /** Nostr Wallet Connect URI */
  nwcUri?: string;
}

export interface ResolvedKeychatAccount {
  accountId: string;
  name?: string;
  enabled: boolean;
  configured: boolean;
  /** Mnemonic for identity restoration */
  mnemonic?: string;
  /** Nostr public key hex */
  publicKey: string;
  /** npub bech32 */
  npub?: string;
  /** Relay URLs */
  relays: string[];
  /** Lightning address for receiving payments */
  lightningAddress?: string;
  /** Nostr Wallet Connect URI */
  nwcUri?: string;
  config: KeychatAccountConfig;
}

const DEFAULT_ACCOUNT_ID = "default";

const DEFAULT_RELAYS = [
  "wss://relay.keychat.io",
  "wss://relay.damus.io",
];

export function listKeychatAccountIds(cfg: OpenClawConfig): string[] {
  const keychatCfg = (cfg.channels as Record<string, unknown> | undefined)?.keychat as
    | KeychatAccountConfig
    | undefined;

  // Even without mnemonic, we return default — identity will be auto-generated
  if (keychatCfg && keychatCfg.enabled !== false) {
    return [DEFAULT_ACCOUNT_ID];
  }

  // If keychat config exists at all (even empty), consider it a configured account
  if (keychatCfg !== undefined) {
    return [DEFAULT_ACCOUNT_ID];
  }

  return [];
}

export function resolveDefaultKeychatAccountId(cfg: OpenClawConfig): string {
  return DEFAULT_ACCOUNT_ID;
}

export function resolveKeychatAccount(opts: {
  cfg: OpenClawConfig;
  accountId?: string | null;
}): ResolvedKeychatAccount {
  const accountId = opts.accountId ?? DEFAULT_ACCOUNT_ID;
  const keychatCfg = (opts.cfg.channels as Record<string, unknown> | undefined)?.keychat as
    | KeychatAccountConfig
    | undefined;

  const enabled = keychatCfg?.enabled !== false;
  const mnemonic = keychatCfg?.mnemonic?.trim();
  // Configured = has mnemonic (identity exists) or will be auto-generated
  const configured = true; // Always configured — identity auto-generates

  return {
    accountId,
    name: keychatCfg?.name?.trim() || undefined,
    enabled,
    configured,
    mnemonic: mnemonic || undefined,
    publicKey: keychatCfg?.publicKey ?? "",
    npub: keychatCfg?.npub,
    relays: keychatCfg?.relays ?? DEFAULT_RELAYS,
    lightningAddress: keychatCfg?.lightningAddress?.trim() || undefined,
    nwcUri: keychatCfg?.nwcUri?.trim() || undefined,
    config: {
      enabled: keychatCfg?.enabled,
      name: keychatCfg?.name,
      mnemonic: keychatCfg?.mnemonic,
      publicKey: keychatCfg?.publicKey,
      npub: keychatCfg?.npub,
      relays: keychatCfg?.relays,
      dmPolicy: keychatCfg?.dmPolicy,
      allowFrom: keychatCfg?.allowFrom,
      lightningAddress: keychatCfg?.lightningAddress,
      nwcUri: keychatCfg?.nwcUri,
    },
  };
}

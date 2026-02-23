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

/** Top-level keychat channel config — supports single-account or multi-account. */
export interface KeychatChannelConfig extends KeychatAccountConfig {
  /** Multi-account: each key is an accountId with its own config. */
  accounts?: Record<string, KeychatAccountConfig>;
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
  "wss://relay.primal.net",
  "wss://relay.nostr.band",
  "wss://relay.0xchat.com",
];

export function listKeychatAccountIds(cfg: OpenClawConfig): string[] {
  const keychatCfg = (cfg.channels as Record<string, unknown> | undefined)?.keychat as
    | KeychatChannelConfig
    | undefined;

  if (!keychatCfg) return [];

  // Multi-account: return all account keys that aren't explicitly disabled
  if (keychatCfg.accounts && Object.keys(keychatCfg.accounts).length > 0) {
    return Object.entries(keychatCfg.accounts)
      .filter(([_, acct]) => acct.enabled !== false)
      .map(([id]) => id);
  }

  // Single-account (backward compat): config exists → "default" account
  return [DEFAULT_ACCOUNT_ID];
}

export function resolveDefaultKeychatAccountId(cfg: OpenClawConfig): string {
  return DEFAULT_ACCOUNT_ID;
}

export function resolveKeychatAccount(opts: {
  cfg: OpenClawConfig;
  accountId?: string | null;
}): ResolvedKeychatAccount {
  const accountId = opts.accountId ?? DEFAULT_ACCOUNT_ID;
  const channelCfg = (opts.cfg.channels as Record<string, unknown> | undefined)?.keychat as
    | KeychatChannelConfig
    | undefined;

  // Multi-account: look up specific account; single-account: use top-level config
  const acctCfg: KeychatAccountConfig | undefined =
    channelCfg?.accounts && Object.keys(channelCfg.accounts).length > 0
      ? channelCfg.accounts[accountId]
      : channelCfg;

  const enabled = acctCfg?.enabled !== false;
  const mnemonic = acctCfg?.mnemonic?.trim();
  const configured = true; // Always configured — identity auto-generates

  return {
    accountId,
    name: acctCfg?.name?.trim() || undefined,
    enabled,
    configured,
    mnemonic: mnemonic || undefined,
    publicKey: acctCfg?.publicKey ?? "",
    npub: acctCfg?.npub,
    relays: acctCfg?.relays ?? DEFAULT_RELAYS,
    lightningAddress: acctCfg?.lightningAddress?.trim() || undefined,
    nwcUri: acctCfg?.nwcUri?.trim() || undefined,
    config: {
      enabled: acctCfg?.enabled,
      name: acctCfg?.name,
      mnemonic: acctCfg?.mnemonic,
      publicKey: acctCfg?.publicKey,
      npub: acctCfg?.npub,
      relays: acctCfg?.relays,
      dmPolicy: acctCfg?.dmPolicy,
      allowFrom: acctCfg?.allowFrom,
      lightningAddress: acctCfg?.lightningAddress,
      nwcUri: acctCfg?.nwcUri,
    },
  };
}

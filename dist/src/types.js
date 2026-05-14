const DEFAULT_ACCOUNT_ID = "default";
const DEFAULT_RELAYS = [
    "wss://relay.keychat.io",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
    "wss://nostr.mom",
];
export function listKeychatAccountIds(cfg) {
    const keychatCfg = cfg.channels?.keychat;
    if (!keychatCfg)
        return [];
    // Multi-account: return all account keys that aren't explicitly disabled
    if (keychatCfg.accounts && Object.keys(keychatCfg.accounts).length > 0) {
        return Object.entries(keychatCfg.accounts)
            .filter(([_, acct]) => acct.enabled !== false)
            .map(([id]) => id);
    }
    // Single-account (backward compat): config exists → "default" account
    return [DEFAULT_ACCOUNT_ID];
}
export function resolveDefaultKeychatAccountId(cfg) {
    return DEFAULT_ACCOUNT_ID;
}
export function resolveKeychatAccount(opts) {
    const accountId = opts.accountId ?? DEFAULT_ACCOUNT_ID;
    const channelCfg = opts.cfg.channels?.keychat;
    // Multi-account: look up specific account; single-account: use top-level config
    const acctCfg = channelCfg?.accounts && Object.keys(channelCfg.accounts).length > 0
        ? channelCfg.accounts[accountId]
        : channelCfg;
    const enabled = acctCfg?.enabled !== false;
    // Legacy: mnemonic may still be in config for old installations → will be migrated to keychain on init
    const mnemonic = acctCfg?.mnemonic?.trim() || (acctCfg !== channelCfg ? channelCfg?.mnemonic?.trim() : undefined);
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
        mediaServer: acctCfg?.mediaServer?.trim() || undefined,
        config: {
            enabled: acctCfg?.enabled,
            name: acctCfg?.name,
            mnemonic: acctCfg?.mnemonic,
            publicKey: acctCfg?.publicKey,
            npub: acctCfg?.npub,
            relays: acctCfg?.relays,
            dmPolicy: acctCfg?.dmPolicy,
            allowFrom: acctCfg?.allowFrom,
            owner: acctCfg?.owner,
            lightningAddress: acctCfg?.lightningAddress,
            nwcUri: acctCfg?.nwcUri,
            mediaServer: acctCfg?.mediaServer,
        },
    };
}

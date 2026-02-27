# Keychat — OpenClaw Channel Plugin

E2E encrypted AI agent communication via Keychat protocol.

## What is this?

This plugin gives your OpenClaw agent a **sovereign identity** — a self-generated Public Key ID (Nostr keypair) — and enables **end-to-end encrypted communication** using the Signal Protocol over Nostr relays.

## Install

```bash
openclaw plugins install @keychat-io/keychat
openclaw gateway restart
```

That's it. The plugin automatically downloads the bridge binary and initializes the config on first load.

Alternatively, install via shell script:

```bash
curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-openclaw/main/scripts/install.sh | bash
```

Supported platforms: macOS (ARM/x64), Linux (x64/ARM64).

### Security Warnings

During installation, OpenClaw's security scanner may show two warnings. Both are expected:

| Warning                                    | Reason                                                                           |
| ------------------------------------------ | -------------------------------------------------------------------------------- |
| Shell command execution (bridge-client.ts) | Spawns a Rust sidecar for Signal Protocol and MLS encryption.                    |
| Shell command execution (keychain.ts)      | Stores identity mnemonics in the OS keychain (macOS Keychain / Linux libsecret). |

Source code is fully open: [github.com/keychat-io/keychat-openclaw](https://github.com/keychat-io/keychat-openclaw)

### Upgrade

Tell your agent "upgrade keychat" in any chat, or manually:

```bash
openclaw plugins update keychat
openclaw gateway restart
```

## Add Your Agent as a Keychat Contact

After `openclaw gateway restart`, the agent will send you its **Keychat ID**, **contact link**, and **QR code** in your active chat (Telegram, webchat, etc.):

```
🔑 Keychat ID: npub1...
📱 Add contact: https://www.keychat.io/u/?k=npub1...
🖼️ QR code image
```

Open the [Keychat app](https://keychat.io) → tap the link, paste the npub, or scan the QR code to add as contact. If `dmPolicy` is `open`, the agent accepts immediately. The default policy is `pairing`, which requires owner approval.

**Can't find the public key?** Just ask your agent in chat: "What's your Keychat ID?"

## Configuration

All options go under `channels.keychat` in your OpenClaw config (`~/.openclaw/openclaw.json`):

| Option             | Type     | Default                      | Description                                               |
| ------------------ | -------- | ---------------------------- | --------------------------------------------------------- |
| `enabled`          | boolean  | `true`                       | Enable/disable the Keychat channel                        |
| `name`             | string   | —                            | Display name for this account                             |
| `relays`           | string[] | `["wss://relay.keychat.io"]` | Nostr relay WebSocket URLs                                |
| `dmPolicy`         | enum     | `"pairing"`                     | Access policy: `pairing`, `allowlist`, `open`, `disabled` |
| `allowFrom`        | string[] | `[]`                         | Allowed sender pubkeys (npub or hex)                      |
| `lightningAddress` | string   | —                            | Lightning address for receiving payments                  |
| `nwcUri`           | string   | —                            | Nostr Wallet Connect URI for wallet access                |

### DM Policies

- **`open`**: Anyone can message the agent
- **`pairing`**: New contacts require owner approval via OpenClaw (default)
- **`allowlist`**: Only pubkeys in `allowFrom` can communicate
- **`disabled`**: No inbound messages accepted

## Lightning Wallet

### Lightning Address (receive-only)

```json
{ "lightningAddress": "user@walletofsatoshi.com" }
```

### Nostr Wallet Connect (NWC)

For full wallet access (create invoices, check balance, verify payments):

```json
{ "nwcUri": "nostr+walletconnect://pubkey?relay=wss://...&secret=..." }
```

Generate an NWC connection string from your wallet app (Keychat, Alby Hub, Mutiny, Coinos, etc.).

**Security note**: The agent can receive payments freely. Outbound payments require owner approval.

## Architecture

```
┌──────────────┐    JSON-RPC     ┌─────────────────────┐    Nostr     ┌─────────┐
│  OpenClaw    │◄──────────────►│  keychat  │◄───────────►│  Relays  │
│  (TypeScript │    stdin/stdout │  (Rust sidecar)     │  WebSocket  │         │
│   plugin)    │                │                     │             │         │
└──────────────┘                └─────────────────────┘             └─────────┘
                                  │ Signal Protocol DB │
                                  │ (SQLite)           │
                                  └────────────────────┘
```

- **TypeScript plugin**: OpenClaw channel integration, routing, pairing, message dispatch
- **Rust sidecar**: Signal Protocol sessions, Nostr transport, encryption/decryption
- **Communication**: JSON-RPC over stdin/stdout
- **Encryption**: Signal Protocol (Double Ratchet) with forward and backward secrecy
- **Transport**: Nostr relays (kind:4 DMs + kind:1059 Gift Wrap for friend requests)

## Security

- **E2E Encryption**: All messages encrypted with Signal Protocol — relay operators cannot read content
- **Forward & Backward Secrecy**: Double Ratchet ensures compromising current keys reveals neither past nor future messages
- **Sovereign Identity**: Agent generates its own keypair — no third-party identity provider
- **Key Storage**: Mnemonic stored in system keychain (macOS Keychain, Linux secret service)
- **Sending Address Rotation**: Each outbound message uses a fresh Nostr keypair, preventing metadata correlation
- **Receiving Address Rotation**: Ratchet-derived addresses rotate almost per message, preventing traffic analysis

## Troubleshooting

- **Bridge not starting**: Check `ls ~/.openclaw/extensions/keychat/bridge/target/release/keychat`. If missing, restart gateway (auto-downloads) or build from source: `cd bridge && cargo build --release`
- **Relay issues**: Verify relay URLs (`wss://...`), try alternative relays
- **Decryption errors**: Peer should delete old contact and re-add the agent
- **Messages not delivered**: Plugin queues failed messages (up to 100) and retries every 30s

## Development

```bash
cd bridge && cargo build --release
cargo test
```

### Project Structure

```
├── src/
│   ├── channel.ts        # Main channel plugin
│   ├── bridge-client.ts  # RPC client for Rust sidecar
│   ├── config-schema.ts  # Zod config schema
│   ├── keychain.ts       # System keychain integration
│   ├── lightning.ts      # LNURL-pay support
│   ├── nwc.ts            # Nostr Wallet Connect (NIP-47)
│   ├── media.ts          # Blossom media encryption/upload
│   ├── qrcode.ts         # QR code generation
│   ├── runtime.ts        # Plugin runtime accessor
│   └── types.ts          # Account types and resolvers
├── bridge/src/
│   ├── main.rs           # Sidecar entry point
│   ├── rpc.rs            # JSON-RPC dispatch
│   ├── signal.rs         # Signal Protocol manager
│   ├── protocol.rs       # Keychat protocol types
│   ├── mls.rs            # MLS large group support
│   └── transport.rs      # Nostr relay transport
├── scripts/
│   └── install.sh        # One-line installer
├── index.ts              # Plugin entry point
├── openclaw.plugin.json  # Plugin manifest
└── LICENSE               # AGPL-3.0
```

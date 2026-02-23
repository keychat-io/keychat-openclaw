# Keychat — OpenClaw Channel Plugin

E2E encrypted AI agent communication via Keychat protocol.

## What is this?

This plugin gives your OpenClaw agent a **sovereign identity** — a self-generated Public Key ID (Nostr keypair) — and enables **end-to-end encrypted communication** using the Signal Protocol over Nostr relays.

Your agent becomes a full Keychat citizen: it can receive friend requests, establish Signal Protocol sessions, and exchange messages with Keychat app users. All messages are encrypted with forward and backward secrecy — not even relay operators can read them.

## Install

### Option A: OpenClaw plugin (recommended)

```bash
openclaw plugins install @keychat-io/keychat-openclaw
openclaw gateway restart
```

Supported platforms: macOS (ARM/x64), Linux (x64/ARM64).

### Option B: Shell script (full install)

```bash
curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-openclaw/main/scripts/install.sh | bash
```

This clones the repo, downloads the binary, registers the plugin, and restarts the gateway in one step.

### Post-install setup

If you installed via Option A and the bridge binary or config wasn't initialized automatically, run:

```bash
bash ~/.openclaw/extensions/keychat-openclaw/scripts/setup.sh
```

This downloads the binary and adds `channels.keychat` to your config.

### Security Warnings

During installation, OpenClaw's security scanner may show three warnings. All are expected:

| Warning | Reason |
|---------|--------|
| Shell command execution (bridge-client.ts) | Keychat's Signal Protocol and MLS Protocol encryption are implemented in Rust. The plugin spawns a Rust sidecar process to bridge between Node.js and the native crypto layer. |
| Shell command execution (keychain.ts) | Agent identity mnemonics are stored in the OS keychain (macOS Keychain / Linux libsecret) rather than plain files, which is the more secure option. |
| Shell command execution (notify.ts) | After startup, the plugin notifies the agent so it can proactively send the Keychat ID and QR code to the user on their active channel (Telegram, webchat, etc). |

Source code is fully open: [github.com/keychat-io/keychat-openclaw](https://github.com/keychat-io/keychat-openclaw)

### Upgrade

**Easiest way:** Just tell your agent "upgrade keychat" in any chat. The agent will handle it and reconnect automatically.

Or manually:

If you installed via **Option A**:

```bash
openclaw plugins install @keychat-io/keychat-openclaw@latest
openclaw gateway restart
```

If you installed via **Option B**:

```bash
curl -fsSL https://raw.githubusercontent.com/keychat-io/keychat-openclaw/main/scripts/install.sh | bash
```

### Add Your Agent as a Keychat Contact

1. After `openclaw gateway restart`, the agent will send you its **Keychat ID**, **contact link**, and **QR code** in your active chat (Telegram, webchat, etc.):
   ```
   🔑 Keychat ID: npub1...
   📱 Add contact: https://www.keychat.io/u/?k=npub1...
   🖼️ QR code image
   ```
2. Open the [Keychat app](https://keychat.io) → tap the link, paste the npub, or scan the QR code to add as contact
3. If `dmPolicy` is `open`, the agent accepts immediately; if `pairing` (default), the owner must approve via OpenClaw

## Configuration

All options go under `channels.keychat` in your OpenClaw config:

| Option             | Type     | Default                      | Description                                               |
| ------------------ | -------- | ---------------------------- | --------------------------------------------------------- |
| `enabled`          | boolean  | `false`                      | Enable/disable the Keychat channel                        |
| `name`             | string   | —                            | Display name for this account                             |
| `relays`           | string[] | `["wss://relay.keychat.io"]` | Nostr relay WebSocket URLs                                |
| `dmPolicy`         | enum     | `"pairing"`                  | Access policy: `pairing`, `allowlist`, `open`, `disabled` |
| `allowFrom`        | string[] | `[]`                         | Allowed sender pubkeys (npub or hex)                      |
| `mnemonic`         | string   | —                            | Identity mnemonic (auto-generated, stored in keychain)    |
| `publicKey`        | string   | —                            | Derived hex public key (read-only)                        |
| `npub`             | string   | —                            | Derived bech32 npub (read-only)                           |
| `lightningAddress` | string   | —                            | Lightning address for receiving payments                  |
| `nwcUri`           | string   | —                            | Nostr Wallet Connect URI for wallet access                |
| `markdown`         | object   | —                            | Markdown formatting overrides                             |

### DM Policies

- **`pairing`** (default): New contacts require owner approval via OpenClaw's pairing system
- **`allowlist`**: Only pubkeys in `allowFrom` can communicate
- **`open`**: Anyone can message the agent
- **`disabled`**: No inbound messages accepted

## Lightning Wallet

Keychat supports Lightning payments:

### Lightning Address (receive-only)

Configure a Lightning address so your agent can generate invoices:

```json
{
  "lightningAddress": "user@walletofsatoshi.com"
}
```

The agent can create invoices via LNURL-pay protocol. Note: payment verification depends on the provider (some don't support verify URLs).

### Nostr Wallet Connect (NWC)

For full wallet access (create invoices, check balance, verify payments), configure NWC:

```json
{
  "nwcUri": "nostr+walletconnect://pubkey?relay=wss://...&secret=..."
}
```

Generate an NWC connection string from your wallet app (Keychat, Alby Hub, Mutiny, Coinos, etc.).

**Security note**: The agent can receive payments freely. Outbound payments require owner approval — the agent will forward the invoice to the owner instead of paying directly.

## Architecture

```
┌──────────────┐    JSON-RPC     ┌─────────────────────┐    Nostr     ┌─────────┐
│  OpenClaw    │◄──────────────►│  keychat-openclaw  │◄───────────►│  Relays  │
│  (TypeScript │    stdin/stdout │  (Rust sidecar)     │  WebSocket  │         │
│   plugin)    │                │                     │             │         │
└──────────────┘                └─────────────────────┘             └─────────┘
                                  │ Signal Protocol DB │
                                  │ (SQLite)           │
                                  └────────────────────┘
```

- **TypeScript plugin** (`src/channel.ts`): Integrates with OpenClaw's channel system, handles routing, pairing, and message dispatch
- **Rust sidecar** (`bridge/`): Manages Signal Protocol sessions, Nostr transport, encryption/decryption
- **Communication**: JSON-RPC over stdin/stdout of spawned child process
- **Encryption**: Signal Protocol (Double Ratchet) for E2E encryption
- **Transport**: Nostr relays (kind:4 DMs + kind:1059 Gift Wrap for friend requests)

## Pairing

1. After gateway restart, the agent sends its **npub**, **contact link**, and **QR code** to the owner's active chat
2. Owner shares the link with the contact, or the contact adds the npub directly in the Keychat app
3. Keychat app sends a **friend request** (Gift Wrap, kind:1059)
4. Agent immediately establishes a Signal Protocol session and replies
5. If `dmPolicy` is `pairing`, the owner must approve via `openclaw pair approve keychat <pubkey>`; if `open`, the agent accepts immediately
6. Full bidirectional E2E encrypted chat is established

## Security

- **E2E Encryption**: All messages encrypted with Signal Protocol — relay operators cannot read content
- **Forward Secrecy**: Compromising current keys doesn't reveal past messages (Double Ratchet)
- **Backward Secrecy**: New messages use fresh keys after each exchange
- **Sovereign Identity**: Agent generates its own keypair — no third-party identity provider
- **Key Storage**: Mnemonic stored in system keychain (macOS Keychain, Linux secret service); falls back to config file
- **Ephemeral Senders**: Each outbound message uses a fresh Nostr keypair, preventing metadata correlation
- **Receiving Address Rotation**: Ratchet-derived addresses rotate per message, preventing traffic analysis

## Troubleshooting

### Bridge not starting

- Ensure the binary exists: `ls bridge/target/release/keychat-openclaw`
- Rebuild: `cd bridge && cargo build --release`
- Check logs for startup errors

### Relay connection issues

- Verify relay URLs are correct WebSocket endpoints (`wss://...`)
- Test relay connectivity: `websocat wss://relay.keychat.io`
- Try alternative relays

### Session corruption

- If messages fail to decrypt, the plugin will automatically warn the peer
- The peer should re-add the agent as a contact to establish a new session
- As a last resort, delete the Signal DB: `rm ~/.openclaw/keychat/signal-default.db` and restart

### Messages not delivered

- Check if the bridge is responsive: look for health check logs
- The plugin queues failed messages (up to 100) and retries every 30s
- Pending messages are also flushed after bridge restart

### No QR code generated

- Install the `qrcode` npm package: `npm install qrcode`
- The contact URL in logs works without QR code

## Development

### Building

```bash
# Build the Rust sidecar
cd bridge && cargo build --release

# Run tests
cargo test
```

### Project Structure

```
├── src/
│   ├── channel.ts        # Main channel plugin (OpenClaw integration)
│   ├── bridge-client.ts  # TypeScript RPC client for the Rust sidecar
│   ├── config-schema.ts  # Zod config schema
│   ├── keychain.ts       # System keychain integration
│   ├── lightning.ts      # Lightning address (LNURL-pay) support
│   ├── nwc.ts            # Nostr Wallet Connect (NIP-47) client
│   ├── media.ts          # Blossom media encryption/upload
│   ├── qrcode.ts         # QR code generation
│   ├── runtime.ts        # Plugin runtime accessor
│   └── types.ts          # Account types and resolvers
├── bridge/
│   └── src/
│       ├── main.rs       # Sidecar entry point (stdin/stdout loop)
│       ├── rpc.rs        # JSON-RPC dispatch
│       ├── signal.rs     # Signal Protocol manager
│       ├── protocol.rs   # Keychat protocol types
│       ├── mls.rs        # MLS large group support
│       └── transport.rs  # Nostr relay transport
├── scripts/
│   └── install.sh        # One-line installer
├── index.ts              # Plugin entry point
├── openclaw.plugin.json  # Plugin manifest
└── LICENSE               # AGPL-3.0
```

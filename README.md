# Keychat — OpenClaw Channel Plugin

[![npm version](https://img.shields.io/npm/v/@keychat-io/keychat)](https://www.npmjs.com/package/@keychat-io/keychat)
[![GitHub release](https://img.shields.io/github/v/release/keychat-io/keychat-openclaw)](https://github.com/keychat-io/keychat-openclaw/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/keychat-io/keychat-openclaw/total)](https://github.com/keychat-io/keychat-openclaw/releases)
[![License: AGPL-3.0](https://img.shields.io/github/license/keychat-io/keychat-openclaw)](LICENSE)

E2E encrypted AI agent communication via Keychat protocol.

## What is this?

This plugin gives your OpenClaw agent four things no other channel can:

- **Sovereign identity** — The agent generates its own cryptographic keypair. No platform account, no API token from a third party. The agent *is* its public key.
- **Sovereign network** — Messages travel through Nostr relays that anyone can run and the agent can switch at will. No single company controls the transport layer.
- **End-to-end encryption** — Every message is encrypted with the Signal Protocol (Double Ratchet). Relay operators, network intermediaries, and even the plugin author cannot read the content.
- **Metadata protection** — Both sending and receiving addresses rotate with almost every message via ratchet-derived Nostr keypairs, making it extremely difficult to correlate traffic to a specific agent or conversation.

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

Ask your agent in any existing channel (Telegram, Discord, webchat, etc.):

> "What's your Keychat ID?"

The agent will reply with its **Keychat ID** (npub) and **contact link**:

```
🔑 Keychat ID: npub1...
📱 Add contact: https://www.keychat.io/u/?k=npub1...
```

Open the [Keychat app](https://keychat.io) → tap the link or paste the npub to add as contact. The first person to add the agent as a contact becomes its owner. Any subsequent contact requests require owner approval.

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

## Documentation

- [Setup Guide](docs/setup-guide.md) — Step-by-step installation and configuration
- [Troubleshooting](docs/troubleshooting.md) — Common issues and fixes
- [Development](docs/development.md) — Building, testing, release process, and project structure

# Keychat — Setup Guide

Step-by-step instructions to get your OpenClaw agent communicating via Keychat.

## Prerequisites

- **macOS or Linux** (arm64 or x86_64)
- **Node.js 20+**
- **OpenClaw**: Installed and configured (`openclaw gateway status` should work)

## Step 1: Install the Plugin

```bash
openclaw plugins install @keychat-io/keychat
```

This auto-downloads the pre-compiled Rust sidecar binary for your platform. No Rust toolchain needed.

> **Building from source** (optional): If no pre-compiled binary is available for your platform, install [Rust](https://rustup.rs/) and run `cd bridge && cargo build --release`.

## Step 2: Configure OpenClaw

Edit `~/.openclaw/openclaw.json` and add the Keychat channel config:

```json
{
  "channels": {
    "keychat": {
      "enabled": true,
      "relays": [
        "wss://relay.keychat.io",
        "wss://relay.damus.io"
      ],
      "dmPolicy": "pairing"
    }
  }
}
```

### DM Policies

| Policy | Description |
|--------|-------------|
| `pairing` | New contacts require owner approval (default) |
| `allowlist` | Only pubkeys in `allowFrom` can communicate |
| `open` | Anyone can message the agent |
| `disabled` | No inbound messages accepted |

## Step 3: Restart the Gateway

```bash
openclaw gateway restart
```

Watch the logs for your agent's Keychat ID:

```
═══════════════════════════════════════════════════
  🔑 Agent Keychat ID (scan with Keychat app):

  npub1...

  Add contact link:
  https://www.keychat.io/u/?k=npub1...
═══════════════════════════════════════════════════
```

A QR code is also saved to `~/.openclaw/keychat/qr-default.png`.

## Step 4: Connect with Keychat App

1. Open the [Keychat app](https://www.keychat.io/) on your phone
2. Tap **Add Contact**
3. Scan the QR code at `~/.openclaw/keychat/qr-default.png`, or paste the npub / contact URL
4. Send a friend request
5. If `dmPolicy` is `pairing`, approve the request:
   ```bash
   openclaw pair approve keychat <sender-pubkey>
   ```

## Step 5: Start Chatting

Send a message from the Keychat app — your agent will respond with E2E encrypted messages.

## Identity Management

- **First run**: Agent auto-generates a mnemonic and stores it in your system keychain (macOS Keychain / Linux libsecret)
- **Backup**: Export the mnemonic from your keychain if needed
- **Restore**: Set `mnemonic` in the channel config to restore an existing identity on a new machine
- **Signal DB**: Stored at `~/.openclaw/keychat/signal-default.db` — **do not delete** (destroys all encrypted sessions)

## Verifying the Setup

```bash
openclaw gateway status
```

The Keychat channel should show as running with the agent's npub.

## Lightning Wallet (Optional)

Add a Lightning address for receiving payments:

```json
{
  "channels": {
    "keychat": {
      "lightningAddress": "user@walletofsatoshi.com"
    }
  }
}
```

For full wallet access (balance, payments), configure [Nostr Wallet Connect](https://github.com/nostr-protocol/nips/blob/master/47.md):

```json
{
  "channels": {
    "keychat": {
      "nwcUri": "nostr+walletconnect://pubkey?relay=wss://...&secret=..."
    }
  }
}
```

# Keychat — Setup Guide

Step-by-step instructions to get your OpenClaw agent communicating via Keychat.

## Prerequisites

- **macOS or Linux** (arm64 or x86_64)
- **Rust toolchain**: Install via [rustup](https://rustup.rs/):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **Node.js 20+**: Required for OpenClaw
- **OpenClaw**: Installed and configured (`openclaw gateway status` should work)

## Step 1: Build the Bridge Binary

```bash
cd ~/.openclaw/workspace/openclaw/extensions/keychat/bridge
cargo build --release
```

This produces `target/release/keychat-for-agent`. Build time: ~2-5 minutes on first run.

## Step 2: Configure OpenClaw

Edit `~/.openclaw/config.yaml`:

```yaml
channels:
  keychat:
    enabled: true
    relays:
      - wss://relay.keychat.io
      - wss://relay.damus.io
    dmPolicy: pairing  # or: allowlist, open, disabled
    # allowFrom:       # optional: restrict to specific pubkeys
    #   - npub1abc...
```

## Step 3: Restart the Gateway

```bash
openclaw gateway restart
```

Watch the logs for:
```
═══════════════════════════════════════════════════
  🔑 Agent Keychat ID (scan with Keychat app):

  npub1...

  Add contact link:
  https://www.keychat.io/u/?k=npub1...
═══════════════════════════════════════════════════
```

## Step 4: Connect with Keychat App

1. Open the [Keychat app](https://www.keychat.io/) on your phone
2. Tap "Add Contact"
3. Scan the QR code at `~/.openclaw/keychat-qr.png`, or paste the npub
4. Send a friend request
5. If `dmPolicy` is `pairing`, approve the request:
   ```bash
   openclaw pair approve keychat <sender-pubkey>
   ```

## Step 5: Start Chatting

Send a message from the Keychat app — your agent will respond with E2E encrypted messages.

## Identity Management

- **First run**: Agent auto-generates a mnemonic and stores it in your system keychain
- **Backup**: The mnemonic is your agent's identity. Export it from keychain if needed
- **Restore**: Set `mnemonic` in config to restore an existing identity on a new machine
- **Key files**: Signal DB at `~/.openclaw/keychat-signal-default.db`

## Verifying the Setup

Check the agent's status:
```bash
openclaw gateway status
```

The Keychat channel should show as running with the agent's npub.

# Development

## Building

```bash
cd bridge && cargo build --release
cargo test
```

## Release Rules

**Never publish directly.** Every release must pass integration testing on a separate Linux test server first.

1. **Make changes** on the dev machine
2. **Deploy to the test server** — install the branch/build and restart the gateway
3. **Run the integration test checklist** (see below)
4. **Only after all tests pass** — bump version, tag, push, and `npm publish`

This exists because shipping broken builds to npm has happened too many times. The test server catches cross-platform issues (macOS → Linux), field name mismatches, and binary packaging bugs before they reach users.

## Integration Test Checklist

Run these tests on the Linux test server before every release. All must pass.

| # | Test | How to verify |
|---|------|---------------|
| 1 | **Binary loads correctly** | Gateway starts without crash; `keychat-bridge-linux-x64` spawns; check logs for `[keychat] Bridge started` |
| 2 | **Friend request (inbound)** | Send hello from dev agent → test server accepts → session established; no `.slice` or field errors in logs |
| 3 | **Friend request (outbound)** | Test server sends hello to dev agent → dev agent receives → session established |
| 4 | **1:1 messaging (both directions)** | Dev agent sends text → test server receives and decrypts → agent replies → dev agent receives reply |
| 5 | **Media send** | Dev agent sends image via `sendMedia` → test server receives encrypted media URL → downloads and decrypts |
| 6 | **Media receive** | Test server sends image → dev agent receives and decrypts |
| 7 | **Gateway restart survival** | Restart test server gateway → verify existing sessions still work (send/receive without re-pairing) |
| 8 | **Multiple peers** | Both dev agent and a Keychat app user connected simultaneously; messages route to correct peers |
| 9 | **npm package clean** | `npm pack --dry-run` contains no binary files; package size < 200KB |

**Quick test command** (from dev machine):
```bash
# Deploy latest code to test server
ssh testserver "cd ~/.openclaw/extensions/keychat && git pull && npm install --omit=dev"
ssh testserver "openclaw gateway restart"

# Then run through tests 1-8 manually or via agent-to-agent messaging
```

Failures block the release. Fix, redeploy, retest.

## Project Structure

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

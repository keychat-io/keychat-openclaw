# Keychat OpenClaw Plugin — Bug Tracker

Record of significant bugs encountered, root causes, and fixes applied.

---

## BUG-001: Health Check False Kill During Message Burst

**Date**: 2026-03-06  
**Severity**: Critical (caused permanent Keychat outage)  
**Commit**: `3bc825c` (branch `fix/health-check-and-restart`)

### Symptom
Bridge stopped responding to all Keychat messages. Logs showed `Relay health check failed: Error: Not connected` every minute indefinitely.

### Trigger
A new friend request arrived at 08:26:24. The bridge processed the X3DH handshake + multiple Signal encrypt/decrypt cycles + 4 relay subscription updates within ~46 seconds. During this burst, the health check ping timed out (10s limit), and the health check killed the bridge process.

### Root Cause
- Health check timeout was 10s — too short for legitimate message processing bursts
- A single timeout was enough to kill the bridge (no consecutive failure requirement)
- No awareness of whether the bridge was actively processing (busy vs stuck)

### Fix
- Increased ping timeout from 10s to 60s
- Require 2 consecutive health check failures before killing (`HEALTH_KILL_THRESHOLD = 2`)
- Skip health check when bridge has pending RPC calls (`this.pending.size > 0`) — a busy bridge is not a stuck bridge
- Single failure logs a warning instead of killing

### Files Changed
- `src/bridge-client.ts`: `HEALTH_CHECK_TIMEOUT_MS`, `consecutiveHealthFailures`, `HEALTH_KILL_THRESHOLD`, pending-check skip logic

---

## BUG-002: Restart Always Fails — "No account initialized"

**Date**: 2026-03-06 (latent since keychain migration was implemented)  
**Severity**: Critical (any bridge restart permanently breaks Keychat)  
**Commit**: `3bc825c` (branch `fix/health-check-and-restart`)

### Symptom
After bridge process was killed (by BUG-001), restart attempt logged:
```
[keychat] Restart failed: Error: No account initialized
```
Bridge never recovered. All Keychat communication permanently down until manual gateway restart.

### Root Cause
`setInitArgs()` cached `account.mnemonic` (a config object property) for use during restart. But the mnemonic lives in the system keychain, not in config. `account.mnemonic` was always `undefined` — the mnemonic was never successfully cached in `initArgs`.

On restart, `importIdentity()` was skipped (because `initArgs.mnemonic` was falsy), so the Rust bridge's `self.account` stayed `None`. Any subsequent operation that needed the account (connect, generatePrekeyBundle, etc.) failed with "No account initialized".

**This bug was latent from day one** — it never manifested because the bridge had never needed to restart before BUG-001 triggered the first kill.

### Why It Was Wrong
The mnemonic should **never** be cached in JS process memory. It belongs exclusively in the system keychain (secure chip). Caching it in a plain JS object (`initArgs.mnemonic`) is both:
1. A security violation — secrets sitting in process memory
2. Redundant — keychain is the source of truth

### Fix
- Removed `mnemonic` field from `initArgs` type and usage entirely
- Added `mnemonicResolver` callback: `restart()` always reads mnemonic from keychain via `retrieveMnemonic(accountId)`
- Simplified init flow in `channel.ts`: legacy config→keychain migration runs first (if needed), then **always** reads from keychain as the single source of truth
- Marked `mnemonic` fields in `KeychatAccountConfig` and `ResolvedKeychatAccount` as `@deprecated` (kept only for legacy migration)
- Added retry with exponential backoff on restart failure

### Files Changed
- `src/bridge-client.ts`: removed `mnemonic` from `initArgs`, added `mnemonicResolver`, retry logic in `restart()`
- `src/channel.ts`: simplified identity init flow, registered keychain resolver
- `src/types.ts`: `@deprecated` annotations on mnemonic fields

---

## BUG-003: send_hello PreKey Detection Used Wrong Byte Check

**Date**: 2026-02-21  
**Severity**: High (agent could not initiate friend requests)

### Symptom
Agent sent hello to a peer, peer accepted, but the PreKey response message was not recognized as a PreKey message. Signal session was never established from the agent's side.

### Root Cause
`parse_prekey_sender()` in `rpc.rs` checked `ciphertext_bytes[0] == 3` to detect PreKey messages. Signal's `PreKeySignalMessage` is protobuf-encoded; the first byte is a field tag (observed value: `0x34` = 52), not a fixed type indicator.

The Keychat app uses `PreKeySignalMessage::try_from().is_ok()` for detection — should have checked the reference implementation first.

### Fix
Changed `parse_prekey_sender()` to use `PreKeySignalMessage::try_from()` (try-parse, not byte inspection).

### Lesson
**Never guess protocol formats — read the reference implementation.**

---

## BUG-004: Receiving Address Explosion (510 Addresses)

**Date**: 2026-02-21  
**Severity**: Medium (wasted relay resources, potential performance issues)

### Symptom
After PreKey decryption, `getReceivingAddresses()` returned all peers' ratchet addresses (510 total). All were subscribed as new peer addresses.

### Root Cause
Used `getReceivingAddresses()` (global, all peers) instead of `decryptResult.alice_addrs` (current peer only).

### Fix
Use `alice_addrs` from decrypt result. Limit each peer to `MAX_RECEIVING_ADDRESSES` (3).

---

## BUG-005: onetimekey Not Subscribed After Sending Hello

**Date**: 2026-02-21  
**Severity**: High (could not receive peer's accept reply)

### Symptom
Agent sent hello, peer accepted and replied, but agent never received the reply.

### Root Cause
After sending hello, the agent must subscribe to:
1. `onetimekey` — the ephemeral Nostr pubkey included in the hello, where the peer sends their first reply
2. `curve25519PkHex` — the agent's Signal identity pubkey
3. Ratchet-derived addresses

The onetimekey subscription was missing.

### Fix
Subscribe to onetimekey + curve25519PkHex immediately after sending hello.

### Lesson
**If you don't listen on the right addresses, you won't hear the reply. This bug has been documented — never repeat it.**

---

## BUG-006: clearPrekeyMaterial Deleted local_signal_keypair

**Date**: 2026-03-01  
**Severity**: Critical (permanent message loss for affected peer)

### Symptom
After friend request, subsequent messages from that peer could not be decrypted. After gateway restart, all messages from the peer were permanently unrecoverable.

### Root Cause
`clearPrekeyMaterial()` set `local_signal_pubkey` and `local_signal_privkey` to NULL. But these are the ephemeral Signal store index — needed for the entire lifetime of the peer session. Without them, the Rust bridge cannot locate the correct per-peer Signal store.

### Fix
Only clear `signed_prekey_id` and `onetimekey` (truly one-time material). Preserve `local_signal_keypair`.

---

## BUG-007: my_sending_address Never Written to DB

**Date**: 2026-03-01  
**Severity**: Critical (messages sent to wrong address)

### Symptom
Messages sent by agent were delivered to the peer's nostr pubkey instead of their current ratchet address. Peer could not decrypt them.

### Root Cause
`my_sending_address` (the cached address where we should send messages to a peer) was supposed to be updated from `next_send_addrs` returned by `decrypt_signal()`. But the Signal store's `store_session()` always returned `None` for `to_receiver_address`, so `next_send_addrs` was always empty.

An older version had a fallback that read `bobAddress` from the Signal session and derived the correct address. Commit `1db9627` removed this fallback, assuming `my_sending_address` cache worked. It never did.

### Fix
After every `decrypt_signal()`, unconditionally read `bobAddress` from the Signal session and derive the sending address. Don't rely on `next_send_addrs` return value.

### Lesson
**Don't remove fallback code unless you've verified the "primary" path actually works.** A simple `SELECT my_sending_address FROM DB` would have revealed it was always empty.

---

## BUG-008: handle_send_message Double-Wrapped KeychatMessage

**Date**: 2026-03-01  
**Severity**: Medium (group messages displayed as 1:1 DMs in app)

### Symptom
Group messages appeared as 1:1 DM in the Keychat app with garbled content.

### Root Cause
Commit `e540266` made `handle_send_message` unconditionally wrap text in `KeychatMessage{type:100, c:"signal"}`. But `sendGroupMessage` already wraps in `{type:30, c:"group"}`. Double wrapping: outer type:100 overrode inner type:30.

### Fix
Check if text is already valid KeychatMessage JSON before wrapping. If it is, pass through.

---

## BUG-009: Binary Deployed to Wrong Path (Recurring)

**Date**: 2026-03-01 (and earlier occasions)  
**Severity**: Medium (deployed code has no effect)

### Symptom
Code changes deployed but behavior unchanged. Gateway continues using the old binary.

### Root Cause
Gateway loads binary from `extensions/keychat/keychat-bridge`, but deployments were copying to `bridge/target/release/keychat-openclaw`.

### Fix
**Before every deployment**: `ps aux | grep keychat | grep -v grep` to confirm the actual binary path the gateway is using.

---

## BUG-010: Rust Bridge Peer Cache Not Updated on savePeerMapping

**Date**: 2026-02-22  
**Severity**: High (subsequent messages after friend request fail)

### Symptom
After friend request established Signal session, the next message from peer failed to decrypt because peer lookup returned stale data.

### Root Cause
`handle_save_peer_mapping` wrote to DB but did not update `self.peers` in-memory cache. Subsequent lookups used the stale in-memory cache.

### Fix
Update `self.peers` HashMap simultaneously when writing to DB in `handle_save_peer_mapping`.

---

## BUG-011: npm Package Included macOS Binary

**Date**: 2026-02 (v0.1.49)  
**Severity**: Critical (Linux users crash on startup)

### Symptom
Linux users installing via npm got the macOS binary. Bridge crashed immediately on startup.

### Root Cause
`npm pack` included the local `keychat-bridge` binary (macOS arm64). The `.npmignore` didn't exclude it.

### Fix
Ensure `.npmignore` excludes all binaries. Binaries are downloaded from GitHub Releases per-platform at install time via `postinstall`.

### Lesson
**Always test on the Linux test server before publishing to npm.**

---

## BUG-012: peer_signal_key vs peer_signal_pubkey Field Name Mismatch

**Date**: 2026-02 (v0.1.50)  
**Severity**: High (friend requests fail)

### Symptom
Adding friends via the published npm package failed silently.

### Root Cause
TypeScript code referenced `peer_signal_pubkey` but the Rust bridge returned `peer_signal_key`. Field name mismatch caused the value to be `undefined`.

### Fix
Aligned field names across TS and Rust.

### Lesson
**Always test on the Linux test server before publishing to npm.**

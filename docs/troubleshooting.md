# Troubleshooting

- **Bridge not starting**: Check `ls ~/.openclaw/extensions/keychat/bridge/target/release/keychat`. If missing, restart gateway (auto-downloads) or build from source: `cd bridge && cargo build --release`
- **Relay issues**: Verify relay URLs (`wss://...`), try alternative relays
- **Decryption errors**: Peer should delete old contact and re-add the agent
- **Messages not delivered**: Plugin queues failed messages (up to 100) and retries every 30s

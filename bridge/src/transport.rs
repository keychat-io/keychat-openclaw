//! Nostr relay transport — real WebSocket connections, Gift Wrap send/receive.
//! Uses nostr-relay-pool for relay management.

use anyhow::Result;
use nostr::nips::nip04;
use nostr::nips::nip44;
use nostr::types::Timestamp;
use nostr::{Event, EventBuilder, Filter, JsonUtil, Keys, Kind, PublicKey, SecretKey, Tag};
use nostr_relay_pool::prelude::*;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use crate::protocol::KeychatAccount;

/// An inbound message received from a relay.
#[derive(Debug, Serialize, Clone)]
pub struct InboundMessage {
    pub from_pubkey: String,
    pub text: String,
    pub event_id: String,
    pub created_at: u64,
    /// Whether this is a Signal pre-key message
    pub is_prekey: bool,
    /// The raw encrypted content (for Signal decryption)
    pub encrypted_content: String,
    /// Which kind of event (4 = NIP-04, 1059 = Gift Wrap)
    pub event_kind: u16,
    /// The `p` tag recipient address (for kind:4, identifies which receiving address was targeted)
    pub to_address: Option<String>,
    /// Whether the content was already decrypted (e.g., NIP-04 group invite)
    #[serde(default)]
    pub nip04_decrypted: bool,
    /// For Gift Wrap events: the inner rumor's kind (e.g., 14=DM, 444=MLS Welcome)
    #[serde(default)]
    pub inner_kind: Option<u16>,
    /// For Gift Wrap events: p-tags from the inner rumor (e.g., group_id for MLS Welcome)
    #[serde(default)]
    pub inner_tags_p: Vec<String>,
}

pub struct NostrTransport {
    pool: RelayPool,
    relays: Vec<String>,
    our_pubkey: PublicKey,
    our_secret: SecretKey,
    /// Channel for sending inbound messages to the RPC layer
    inbound_tx: mpsc::UnboundedSender<InboundMessage>,
    /// Tracked receiving addresses for the ratchet subscription
    ratchet_addrs: Mutex<HashSet<String>>,
    /// Counter for generating unique subscription IDs
    sub_counter: std::sync::atomic::AtomicU64,
}

impl NostrTransport {
    /// Connect to Nostr relays and start listening for DMs.
    /// Connect to Nostr relays. `last_seen` is the timestamp of the last
    /// processed event (from DB); subscription will start from that point
    /// to catch any missed messages. Falls back to 1 hour if None.
    pub async fn connect(
        account: &KeychatAccount,
        relays: &[String],
        inbound_tx: mpsc::UnboundedSender<InboundMessage>,
        last_seen: Option<u64>,
        initial_addrs: &[String],
    ) -> Result<Self> {
        let pool = RelayPool::default();

        // Add relays
        for relay_url in relays {
            match pool.add_relay(relay_url, RelayOptions::default()).await {
                Ok(_) => log::info!("Added relay: {}", relay_url),
                Err(e) => log::warn!("Failed to add relay {}: {}", relay_url, e),
            }
        }

        // Connect to all relays
        pool.connect().await;
        log::info!("Connected to {} relay(s)", relays.len());

        let our_pubkey = account.keys.public_key();
        let our_secret = account.keys.secret_key().clone();

        let transport = Self {
            pool,
            relays: relays.to_vec(),
            our_pubkey,
            our_secret: our_secret.clone(),
            inbound_tx,
            ratchet_addrs: Mutex::new(HashSet::new()),
            sub_counter: std::sync::atomic::AtomicU64::new(0),
        };

        // Pre-populate known receiving addresses so the initial subscription
        // includes them alongside the main pubkey.
        if !initial_addrs.is_empty() {
            let mut addrs = transport.ratchet_addrs.lock().await;
            for addr in initial_addrs {
                addrs.insert(addr.clone());
            }
            log::info!("Pre-populated {} receiving address(es)", initial_addrs.len());
        }

        // Subscribe to events addressed to us
        transport.subscribe(account, last_seen).await?;

        Ok(transport)
    }

    /// Subscribe to NIP-04 DMs and NIP-59 Gift Wrap events tagged to us.
    async fn subscribe(&self, account: &KeychatAccount, last_seen: Option<u64>) -> Result<()> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        // Start from last processed event minus a 10-minute buffer to catch events
        // with created_at slightly before last_seen (e.g. network delays, clock skew).
        // Duplicates are filtered by processed_events table.
        let since_secs = match last_seen {
            Some(ts) => ts.saturating_sub(600), // 10 min buffer
            None => now_secs.saturating_sub(3600),
        };
        let since = Timestamp::from(since_secs);
        log::info!("Subscribing since {} (last_seen: {:?}, now: {})", since_secs, last_seen, now_secs);

        // Add our main pubkey to the address set so everything
        // goes through a single subscription (hides which is the real npub)
        {
            let mut addrs = self.ratchet_addrs.lock().await;
            addrs.insert(self.our_pubkey.to_string());
        }
        self.resubscribe_ratchet_addrs_since(Some(since_secs)).await?;
        log::info!("Subscribed to DMs (main + ratchet addresses in single subscription)");

        // Spawn a task to handle incoming events
        let pool = self.pool.clone();
        let our_secret = self.our_secret.clone();
        let our_pubkey = self.our_pubkey;
        let inbound_tx = self.inbound_tx.clone();

        tokio::spawn(async move {
            Self::event_loop(pool, our_secret, our_pubkey, inbound_tx).await;
        });

        Ok(())
    }

    /// Event loop: receive events from relays and process them.
    async fn event_loop(
        pool: RelayPool,
        our_secret: SecretKey,
        our_pubkey: PublicKey,
        inbound_tx: mpsc::UnboundedSender<InboundMessage>,
    ) {
        log::info!("Event loop started");

        loop {
            match pool.notifications().recv().await {
                Ok(notification) => {
                    match notification {
                        RelayPoolNotification::Event { event, .. } => {
                            let p_tags: Vec<String> = event.tags.iter()
                                .filter_map(|t| {
                                    let s = t.as_slice();
                                    if s.len() >= 2 && s[0] == "p" { Some(s[1][..16].to_string()) } else { None }
                                })
                                .collect();
                            log::info!("Event received: kind={} id={} pubkey={} p_tags={:?}",
                                event.kind.as_u16(), &event.id.to_string()[..16], &event.pubkey.to_string()[..16], p_tags);

                            // Skip our own events
                            if event.pubkey == our_pubkey {
                                log::info!("Skipping own event {}", &event.id.to_string()[..16]);
                                continue;
                            }

                            match event.kind {
                                Kind::EncryptedDirectMessage => {
                                    // NIP-04 encrypted DM
                                    Self::handle_nip04_dm(
                                        &event,
                                        &our_secret,
                                        &inbound_tx,
                                    );
                                }
                                Kind::GiftWrap => {
                                    // NIP-59 Gift Wrap
                                    Self::handle_gift_wrap(
                                        &event,
                                        &our_secret,
                                        &inbound_tx,
                                    );
                                }
                                _ => {}
                            }
                        }
                        RelayPoolNotification::Shutdown => {
                            log::info!("Relay pool shutdown");
                            break;
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    log::error!("Notification recv error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Handle a kind:4 DM from Keychat.
    /// Keychat uses `getUnencryptEvent` — the event content is raw base64-encoded
    /// Signal ciphertext, NOT NIP-04 encrypted. Do NOT attempt NIP-04 decryption.
    /// The event is signed by an ephemeral key; the `p` tag(s) indicate the recipient address.
    fn handle_nip04_dm(
        event: &Event,
        _our_secret: &SecretKey,
        inbound_tx: &mpsc::UnboundedSender<InboundMessage>,
    ) {
        let ephemeral_sender = event.pubkey.to_string();

        // Extract the `p` tag to identify which receiving address this was sent to
        let to_address = event.tags.iter().find_map(|tag| {
            let values: Vec<&str> = tag.as_slice().iter().map(|s| s.as_str()).collect();
            if values.len() >= 2 && values[0] == "p" {
                Some(values[1].to_string())
            } else {
                None
            }
        });

        // Content may be either:
        // 1. Raw base64 Signal ciphertext (normal Keychat DMs) — pure base64, no '?' character
        // 2. NIP-04 encrypted content (group invites via Nip4ChatService) — format: base64?iv=base64
        // Signal base64 ciphertext never contains '?', so any '?' means NIP-04
        let looks_like_nip04 = event.content.contains('?');
        let (content, nip04_decrypted) = if looks_like_nip04 {
            // NIP-04 encrypted — decrypt first to get the inner content
            match nip04::decrypt(_our_secret, &event.pubkey, &event.content) {
                Ok(decrypted) => {
                    log::info!("NIP-04 decrypted kind:4 message (was group invite or nip04 message)");
                    (decrypted, true)
                }
                Err(e) => {
                    log::error!("NIP-04 decrypt failed: {}, passing through raw content", e);
                    (event.content.clone(), false)
                }
            }
        } else {
            // Raw base64 Signal ciphertext — pass through directly
            (event.content.clone(), false)
        };
        // Always check if the (possibly NIP-04 decrypted) content is a PreKey message.
        // NIP-04 decryption just unwraps the transport layer; the inner content
        // is still base64 Signal ciphertext that may be a PreKeyWhisperMessage.
        let is_prekey = Self::looks_like_prekey_message(&content);

        log::info!(
            "Keychat DM from ephemeral {} → to {} (prekey: {}, {} bytes)",
            &ephemeral_sender[..16],
            to_address.as_deref().unwrap_or("unknown"),
            is_prekey,
            content.len(),
        );

        let msg = InboundMessage {
            from_pubkey: if nip04_decrypted { event.pubkey.to_string() } else { ephemeral_sender },
            text: if nip04_decrypted { content.clone() } else { String::new() },
            event_id: event.id.to_string(),
            created_at: event.created_at.as_u64(),
            is_prekey,
            encrypted_content: content, // raw base64 Signal ciphertext, or NIP-04 decrypted plaintext
            event_kind: 4,
            to_address,
            nip04_decrypted,
            inner_kind: None, inner_tags_p: vec![],
        };

        if let Err(e) = inbound_tx.send(msg) {
            log::error!("Failed to send inbound message: {}", e);
        }
    }

    /// Handle a NIP-59 Gift Wrap event (kind:1059).
    /// This can be either:
    /// 1. A real NIP-59 Gift Wrap (hello/friend request) → decrypt layers
    /// 2. An MLS group message (raw NIP-44 content on listen key) → pass through
    fn handle_gift_wrap(
        event: &Event,
        our_secret: &SecretKey,
        inbound_tx: &mpsc::UnboundedSender<InboundMessage>,
    ) {
        // Extract p-tag (to_address) from the outer event
        let to_address = event.tags.iter().find_map(|tag| {
            let values: Vec<&str> = tag.as_slice().iter().map(|s| s.as_str()).collect();
            if values.len() >= 2 && values[0] == "p" {
                Some(values[1].to_string())
            } else {
                None
            }
        });

        // Try to unwrap as NIP-59 Gift Wrap first
        let seal_json = match nip44::decrypt(our_secret, &event.pubkey, &event.content) {
            Ok(json) => json,
            Err(_) => {
                // Failed to decrypt as Gift Wrap — likely an MLS group message
                // (content is NIP-44 encrypted with export_secret, not our identity key)
                log::info!(
                    "Kind:1059 event {} not a Gift Wrap (to: {}), passing as MLS candidate",
                    event.id,
                    to_address.as_deref().unwrap_or("unknown"),
                );
                let msg = InboundMessage {
                    from_pubkey: event.pubkey.to_string(),
                    text: String::new(),
                    event_id: event.id.to_string(),
                    created_at: event.created_at.as_u64(),
                    is_prekey: false,
                    encrypted_content: event.content.clone(),
                    event_kind: 1059,
                    to_address,
                    nip04_decrypted: false,
                    inner_kind: None, // Not a Gift Wrap — raw MLS content
                    inner_tags_p: vec![],
                };
                if let Err(e) = inbound_tx.send(msg) {
                    log::error!("Failed to send inbound MLS message: {}", e);
                }
                return;
            }
        };

        // Parse seal event
        let seal = match Event::from_json(&seal_json) {
            Ok(e) => e,
            Err(e) => {
                log::warn!("Failed to parse seal: {}", e);
                return;
            }
        };

        // Verify seal
        if seal.verify().is_err() {
            log::warn!("Seal verification failed");
            return;
        }

        let sender_pubkey = seal.pubkey;

        // Unwrap seal → rumor (NIP-44 decrypt with sender's key)
        let rumor_json = match nip44::decrypt(our_secret, &sender_pubkey, &seal.content) {
            Ok(json) => json,
            Err(e) => {
                log::warn!("Failed to unwrap seal from {}: {}", sender_pubkey, e);
                return;
            }
        };

        // Parse rumor
        let rumor: serde_json::Value = match serde_json::from_str(&rumor_json) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Failed to parse rumor: {}", e);
                return;
            }
        };

        let content = rumor
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let kind = rumor
            .get("kind")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;

        // Extract p-tags from inner rumor (e.g., group_id for MLS Welcome kind:444)
        let inner_tags_p: Vec<String> = rumor
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|tags| {
                tags.iter()
                    .filter_map(|tag| {
                        let arr = tag.as_array()?;
                        if arr.len() >= 2 && arr[0].as_str()? == "p" {
                            arr[1].as_str().map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        log::info!(
            "Gift Wrap DM from {} (kind:{}, inner_p_tags: {:?}): {} bytes",
            sender_pubkey,
            kind,
            inner_tags_p,
            content.len(),
        );

        let msg = InboundMessage {
            from_pubkey: sender_pubkey.to_string(),
            text: content.to_string(),
            event_id: event.id.to_string(),
            created_at: event.created_at.as_u64(),
            is_prekey: false,
            encrypted_content: content.to_string(),
            event_kind: 1059,
            to_address,
            nip04_decrypted: false,
            inner_kind: Some(kind),
            inner_tags_p,
        };

        if let Err(e) = inbound_tx.send(msg) {
            log::error!("Failed to send inbound gift wrap message: {}", e);
        }
    }

    /// Send a NIP-04 encrypted DM (what Keychat actually uses for Signal messages).
    /// Keychat sends Signal-encrypted content inside NIP-04 events with ephemeral sender keys.
    pub async fn send_nip04_dm(
        &self,
        sender_keys: &Keys,
        to_pubkey: &str,
        encrypted_content: &str,
    ) -> Result<String> {
        let receiver = to_pubkey.parse::<PublicKey>()?;

        // NIP-04 encrypt the Signal ciphertext
        let nip04_encrypted = nip04::encrypt(sender_keys.secret_key(), &receiver, encrypted_content)?;

        let tags = vec![Tag::public_key(receiver)];

        let event = EventBuilder::new(Kind::EncryptedDirectMessage, nip04_encrypted)
            .tags(tags)
            .sign(sender_keys)
            .await?;

        let event_id = event.id.to_string();

        // Publish to all relays
        let output = self.pool.send_event(event).await?;
        log::info!(
            "Published NIP-04 DM {} (success: {}, failed: {})",
            event_id,
            output.success.len(),
            output.failed.len(),
        );

        Ok(event_id)
    }

    /// Send an "unencrypted" kind:4 DM — content is already Signal-encrypted,
    /// so we just put the base64 ciphertext directly as the event content
    /// (no NIP-04 encryption). This matches Keychat's `getUnencryptEvent`.
    /// Multiple receiver pubkeys can be tagged (for Signal receiving address rotation).
    pub async fn send_keychat_dm(
        &self,
        sender_keys: &Keys,
        receiver_pubkeys: &[&str],
        content: &str,
    ) -> Result<String> {
        let mut tags = Vec::new();
        for pk_hex in receiver_pubkeys {
            let pubkey = pk_hex.parse::<PublicKey>()?;
            tags.push(Tag::public_key(pubkey));
        }

        let event = EventBuilder::new(Kind::EncryptedDirectMessage, content.to_string())
            .tags(tags)
            .sign(sender_keys)
            .await?;

        let event_id = event.id.to_string();

        let output = self.pool.send_event(event).await?;
        log::info!(
            "Published Keychat DM {} (success: {}, failed: {})",
            event_id,
            output.success.len(),
            output.failed.len(),
        );

        Ok(event_id)
    }

    /// Send an MLS group message as kind:1059 event (NOT a real NIP-59 Gift Wrap).
    /// Content is already MLS+NIP-44 encrypted. Uses ephemeral sender key.
    /// p-tag = group's onetimekey (listen key).
    pub async fn send_mls_event(
        &self,
        listen_key: &str,
        encrypted_content: &str,
        additional_tags: Option<Vec<(&str, &str)>>,
    ) -> Result<String> {
        let pubkey = listen_key.parse::<PublicKey>()?;
        let ephemeral_keys = Keys::generate();

        let mut tags = vec![Tag::public_key(pubkey)];
        if let Some(extra) = additional_tags {
            for (k, v) in extra {
                tags.push(Tag::custom(
                    nostr::TagKind::Custom(std::borrow::Cow::Owned(k.to_string())),
                    vec![v.to_string()],
                ));
            }
        }

        let event = EventBuilder::new(Kind::GiftWrap, encrypted_content.to_string())
            .tags(tags)
            .sign(&ephemeral_keys)
            .await?;

        let event_id = event.id.to_string();

        let output = self.pool.send_event(event).await?;
        log::info!(
            "Published MLS event {} to {} (success: {}, failed: {})",
            event_id,
            &listen_key[..12],
            output.success.len(),
            output.failed.len(),
        );

        Ok(event_id)
    }

    /// Send a NIP-59 Gift Wrap DM.
    pub async fn send_gift_wrap(
        &self,
        account: &KeychatAccount,
        recipient_pubkey_hex: &str,
        content: &str,
    ) -> Result<String> {
        self.send_gift_wrap_inner(account, recipient_pubkey_hex, content, false).await
    }

    /// Send a Gift Wrap event. If `timestamp_tweaked` is true, randomize
    /// the created_at within ±2 days (NIP-59 privacy).  Keychat app does
    /// NOT tweak hello messages, so we default to false for compatibility.
    pub async fn send_gift_wrap_inner(
        &self,
        account: &KeychatAccount,
        recipient_pubkey_hex: &str,
        content: &str,
        timestamp_tweaked: bool,
    ) -> Result<String> {
        let sender_keys = &account.keys;
        let receiver = recipient_pubkey_hex.parse::<PublicKey>()?;

        // Create rumor (kind:1059 to match Keychat app convention — NOT standard NIP-59 kind:14)
        let rumor = EventBuilder::new(Kind::GiftWrap, content.to_string())
            .tags(vec![Tag::public_key(receiver)])
            .build(sender_keys.public_key());

        // Seal (kind:13)
        let seal: Event = EventBuilder::seal(sender_keys, &receiver, rumor)
            .await?
            .sign(sender_keys)
            .await?;

        // Gift wrap (kind:1059) with ephemeral key
        let ephemeral_keys = Keys::generate();
        let wrapped_content = nip44::encrypt(
            ephemeral_keys.secret_key(),
            &receiver,
            seal.as_json(),
            Default::default(),
        )?;

        let ts = if timestamp_tweaked {
            Timestamp::tweaked(nostr::nips::nip59::RANGE_RANDOM_TIMESTAMP_TWEAK)
        } else {
            Timestamp::now()
        };

        let gift_wrap = EventBuilder::new(Kind::GiftWrap, wrapped_content)
            .tags(vec![Tag::public_key(receiver)])
            .custom_created_at(ts)
            .sign(&ephemeral_keys)
            .await?;

        let event_id = gift_wrap.id.to_string();

        let output = self.pool.send_event(gift_wrap).await?;
        log::info!(
            "Published Gift Wrap {} (success: {}, failed: {})",
            event_id,
            output.success.len(),
            output.failed.len(),
        );

        Ok(event_id)
    }

    /// Publish an MLS KeyPackage as a kind:10443 replaceable event.
    /// The event content is the hex-encoded KeyPackage.
    /// The event is signed with the identity key, so `author = identity pubkey`.
    pub async fn publish_key_package(
        &self,
        identity_keys: &Keys,
        key_package_hex: &str,
    ) -> Result<String> {
        let event = EventBuilder::new(Kind::from_u16(10443), key_package_hex.to_string())
            .sign(identity_keys)
            .await?;

        let event_id = event.id.to_string();

        let output = self.pool.send_event(event).await?;
        log::info!(
            "Published MLS KeyPackage {} (success: {}, failed: {})",
            event_id,
            output.success.len(),
            output.failed.len(),
        );

        Ok(event_id)
    }

    /// Fetch the latest KeyPackage (kind:10443) for a given pubkey from relays.
    /// Returns the event content (hex KeyPackage) if found, None otherwise.
    pub async fn fetch_key_package(&self, pubkey_hex: &str) -> Result<Option<String>> {
        let pubkey = pubkey_hex.parse::<PublicKey>()?;
        let filter = Filter::new()
            .author(pubkey)
            .kind(Kind::from_u16(10443))
            .limit(1);

        let events = self.pool.fetch_events(
            filter,
            std::time::Duration::from_secs(5),
            ReqExitPolicy::ExitOnEOSE,
        ).await?;

        Ok(events.into_iter().next().map(|e| e.content.to_string()))
    }

    /// Subscribe to additional pubkeys (ratchet-derived receiving addresses).
    /// Add receiving addresses and resubscribe with full list.
    pub async fn subscribe_additional_pubkeys(&self, pubkeys: &[&str]) -> Result<()> {
        if pubkeys.is_empty() {
            return Ok(());
        }
        {
            let mut addrs = self.ratchet_addrs.lock().await;
            for pk in pubkeys {
                addrs.insert(pk.to_string());
            }
        }
        self.resubscribe_ratchet_addrs().await
    }

    /// Remove receiving addresses and resubscribe with updated list.
    pub async fn unsubscribe_pubkeys(&self, pubkeys: &[&str]) -> Result<()> {
        if pubkeys.is_empty() {
            return Ok(());
        }
        {
            let mut addrs = self.ratchet_addrs.lock().await;
            for pk in pubkeys {
                addrs.remove(*pk);
            }
        }
        self.resubscribe_ratchet_addrs().await
    }

    /// Resubscribe to all tracked addresses in one subscription.
    /// `since_override` is used for initial subscribe (from last_seen); otherwise defaults to 1h ago.
    async fn resubscribe_ratchet_addrs_since(&self, since_override: Option<u64>) -> Result<()> {
        let addrs = self.ratchet_addrs.lock().await;
        if addrs.is_empty() {
            return Ok(());
        }

        let since_secs = since_override.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(3600)
        });
        let since = Timestamp::from(since_secs);

        let mut parsed = Vec::new();
        for pk_hex in addrs.iter() {
            match pk_hex.parse::<PublicKey>() {
                Ok(pk) => parsed.push(pk),
                Err(e) => log::warn!("Failed to parse pubkey {}: {}", pk_hex, e),
            }
        }
        if parsed.is_empty() {
            return Ok(());
        }

        let filter = Filter::new()
            .kinds(vec![Kind::EncryptedDirectMessage, Kind::GiftWrap])
            .pubkeys(parsed)
            .since(since);

        // Use a unique subscription ID each time to force relays to re-scan
        // historical events. Some relays skip historical re-delivery when the
        // subscription ID is reused with a different filter.
        let sub_counter = self.sub_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let sub_id = SubscriptionId::new(format!("keychat-{}", sub_counter));
        let opts = SubscribeOptions::default();
        // Unsubscribe old subscription first (if any)
        if sub_counter > 0 {
            let old_id = SubscriptionId::new(format!("keychat-{}", sub_counter - 1));
            let _ = self.pool.unsubscribe(old_id).await;
        }
        self.pool.subscribe_with_id(sub_id, filter, opts).await?;
        log::info!("Subscription updated: {} address(es) (sub #{})", addrs.len(), sub_counter);
        Ok(())
    }

    /// Convenience: resubscribe with default since (1h ago).
    async fn resubscribe_ratchet_addrs(&self) -> Result<()> {
        self.resubscribe_ratchet_addrs_since(None).await
    }

    /// Check relay connectivity and resubscribe if needed.
    pub async fn check_relay_health(&self) -> Result<bool> {
        let relays = self.pool.relays().await;
        let mut disconnected = Vec::new();
        for (url, relay) in &relays {
            let status = relay.status();
            if status != RelayStatus::Connected {
                disconnected.push(url.clone());
                log::warn!("Relay {} is {:?}, will reconnect", url, status);
            }
        }
        if !disconnected.is_empty() {
            log::info!("Reconnecting {} disconnected relay(s)...", disconnected.len());
            self.pool.connect().await;
            // Give relays a moment to establish connections
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            // Resubscribe to ensure we receive events
            self.resubscribe_ratchet_addrs().await?;
            log::info!("Relay health check: reconnected and resubscribed");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Disconnect from all relays.
    pub async fn disconnect(self) -> Result<()> {
        self.pool.disconnect().await;
        log::info!("Disconnected from all relays");
        Ok(())
    }

    /// Check if content is a base64-encoded Signal PreKey message.
    /// Uses the same approach as Keychat app: try to parse as PreKeySignalMessage.
    fn looks_like_prekey_message(content: &str) -> bool {
        use signal_store::libsignal_protocol::PreKeySignalMessage;
        if let Ok(bytes) = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            content.trim(),
        ) {
            let is_prekey = PreKeySignalMessage::try_from(bytes.as_slice()).is_ok();
            log::info!("looks_like_prekey_message: len={}, is_prekey={}", bytes.len(), is_prekey);
            is_prekey
        } else {
            log::info!("looks_like_prekey_message: base64 decode failed");
            false
        }
    }
}

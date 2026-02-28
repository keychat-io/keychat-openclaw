//! JSON-RPC request/response handling.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use tokio::sync::mpsc;

use nostr;
use nostr::JsonUtil;

use crate::mls::MlsManager;
use crate::protocol::{
    event_kinds, message_type, GroupMessage, KeychatAccount, KeychatMessage, PrekeyMessageModel,
    QRUserModel, RoomProfile,
};
use crate::signal::{self, SignalManager};
use crate::transport::{InboundMessage, NostrTransport};

/// JSON-RPC request from the TypeScript plugin.
#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// JSON-RPC response back to TypeScript.
#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

/// Per-peer session info tracked by the bridge.
#[derive(Debug, Clone)]
pub struct PeerSession {
    /// Remote Signal identity (curve25519 public key hex)
    pub curve25519_pk_hex: String,
    /// Device ID used for Signal session addressing
    pub device_id: u32,
    /// The peer's one-time receiving key (from hello)
    pub onetimekey: Option<String>,
    /// The peer's Nostr pubkey hex
    pub nostr_pubkey: String,
}

/// Bridge state holding all managers.
pub struct BridgeState {
    pub signal: Option<SignalManager>,
    pub transport: Option<NostrTransport>,
    pub account: Option<KeychatAccount>,
    pub inbound_tx: mpsc::UnboundedSender<InboundMessage>,
    /// Tracked peer sessions keyed by peer's nostr pubkey hex
    pub peers: std::collections::HashMap<String, PeerSession>,
    /// Default device_id for our sessions (increments)
    pub next_device_id: u32,
    /// MLS manager (initialized on mls_init)
    pub mls: Option<MlsManager>,
}

impl BridgeState {
    pub async fn new(inbound_tx: mpsc::UnboundedSender<InboundMessage>) -> Result<Self> {
        Ok(Self {
            signal: None,
            transport: None,
            account: None,
            inbound_tx,
            peers: std::collections::HashMap::new(),
            next_device_id: 1,
            mls: None,
        })
    }

    pub async fn handle_request(&mut self, line: &str) -> RpcResponse {
        let req: RpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                return RpcResponse {
                    id: 0,
                    result: None,
                    error: Some(RpcError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                    }),
                };
            }
        };

        let id = req.id;
        match self.dispatch(req).await {
            Ok(result) => RpcResponse {
                id,
                result: Some(result),
                error: None,
            },
            Err(e) => RpcResponse {
                id,
                result: None,
                error: Some(RpcError {
                    code: -32000,
                    message: format!("{}", e),
                }),
            },
        }
    }

    async fn dispatch(&mut self, req: RpcRequest) -> Result<serde_json::Value> {
        match req.method.as_str() {
            "init" => self.handle_init(req.params).await,
            "generate_identity" => self.handle_generate_identity(req.params).await,
            "import_identity" => self.handle_import_identity(req.params).await,
            "get_account_info" => self.handle_get_account_info().await,

            // --- Signal key management ---
            "generate_prekey_bundle" => self.handle_generate_prekey_bundle().await,
            "process_prekey_bundle" => self.handle_process_prekey_bundle(req.params).await,

            // --- Keychat hello/handshake protocol ---
            "generate_hello" => self.handle_generate_hello(req.params).await,
            "process_hello" => self.handle_process_hello(req.params).await,
            "send_hello" => self.handle_send_hello(req.params).await,
            "send_profile" => self.handle_send_profile(req.params).await,

            // --- Messaging ---
            "send_message" => self.handle_send_message(req.params).await,
            "decrypt_message" => self.handle_decrypt_message(req.params).await,
            "parse_prekey_sender" => self.handle_parse_prekey_sender(req.params).await,
            "lookup_peer_by_signed_prekey_id" => self.handle_lookup_peer_by_spk(req.params).await,
            "clear_prekey_material" => self.handle_clear_prekey_material(req.params).await,

            // --- Transport ---
            "connect" => self.handle_connect(req.params).await,
            "disconnect" => self.handle_disconnect().await,

            // --- Subscriptions ---
            "add_subscription" => self.handle_add_subscription(req.params).await,
            "remove_subscription" => self.handle_remove_subscription(req.params).await,

            // --- Queries ---
            "has_session" => self.handle_has_session(req.params).await,
            "compute_address" => self.handle_compute_address(req.params).await,
            "get_all_sessions" => self.handle_get_all_sessions().await,
            "get_peer_mappings" => self.handle_get_peer_mappings().await,
            "save_peer_mapping" => self.handle_save_peer_mapping(req.params).await,
            "save_address_mapping" => self.handle_save_address_mapping(req.params).await,
            "get_address_mappings" => self.handle_get_address_mappings().await,
            "delete_address_mapping" => self.handle_delete_address_mapping(req.params).await,

            // --- Group (small group / sendAll) ---
            "create_group" => self.handle_create_group(req.params).await,
            "get_group" => self.handle_get_group(req.params).await,
            "get_all_groups" => self.handle_get_all_groups().await,
            "join_group" => self.handle_join_group(req.params).await,
            "add_group_member" => self.handle_add_group_member(req.params).await,
            "remove_group_member" => self.handle_remove_group_member(req.params).await,
            "get_group_members" => self.handle_get_group_members(req.params).await,
            "send_group_message" => self.handle_send_group_message(req.params).await,
            "update_group_name" => self.handle_update_group_name(req.params).await,
            "update_group_status" => self.handle_update_group_status(req.params).await,
            "delete_group" => self.handle_delete_group(req.params).await,

            // --- Blossom auth ---
            "sign_blossom_event" => self.handle_sign_blossom_event(req.params).await,
            "mark_event_processed" => self.handle_mark_event_processed(req.params).await,
            "is_event_processed" => self.handle_is_event_processed(req.params).await,
            "delete_session" => self.handle_delete_session(req.params).await,
            // --- MLS (large group) ---
            "mls_init" => self.handle_mls_init(req.params).await,
            "mls_create_key_package" => self.handle_mls_create_key_package(req.params).await,
            "mls_create_group" => self.handle_mls_create_group(req.params).await,
            "mls_add_members" => self.handle_mls_add_members(req.params).await,
            "mls_self_commit" => self.handle_mls_self_commit(req.params).await,
            "mls_join_group" => self.handle_mls_join_group(req.params).await,
            "mls_create_message" => self.handle_mls_create_message(req.params).await,
            "mls_decrypt_message" => self.handle_mls_decrypt_message(req.params).await,
            "mls_parse_message_type" => self.handle_mls_parse_message_type(req.params).await,
            "mls_process_commit" => self.handle_mls_process_commit(req.params).await,
            "mls_get_listen_key" => self.handle_mls_get_listen_key(req.params).await,
            "mls_get_group_info" => self.handle_mls_get_group_info(req.params).await,
            "mls_get_groups" => self.handle_mls_get_groups(req.params).await,
            "mls_self_update" => self.handle_mls_self_update(req.params).await,
            "mls_update_group_extensions" => self.handle_mls_update_group_extensions(req.params).await,
            "mls_remove_members" => self.handle_mls_remove_members(req.params).await,
            "mls_delete_group" => self.handle_mls_delete_group(req.params).await,
            "mls_get_sender" => self.handle_mls_get_sender(req.params).await,
            "mls_get_export_secret_keys" => self.handle_mls_get_export_secret_keys(req.params).await,
            "mls_send_message" => self.handle_mls_send_message(req.params).await,
            "mls_publish_to_group" => self.handle_mls_publish_to_group(req.params).await,
            "mls_publish_key_package" => self.handle_mls_publish_key_package(req.params).await,
            "mls_fetch_key_package" => self.handle_mls_fetch_key_package(req.params).await,

            "ping" => Ok(serde_json::json!({"pong": true})),
            "relay_health_check" => self.handle_relay_health_check().await,

            _ => anyhow::bail!("Unknown method: {}", req.method),
        }
    }

    // -----------------------------------------------------------------------
    // Init / Identity
    // -----------------------------------------------------------------------

    async fn handle_init(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let db_path: String = params
            .get("db_path")
            .and_then(|v| v.as_str())
            .unwrap_or("~/.openclaw/keychat-signal.db")
            .to_string();
        let db_path = shellexpand::tilde(&db_path).to_string();

        log::info!("Initializing Signal DB at: {}", db_path);
        let signal = SignalManager::new(&db_path).await?;
        self.signal = Some(signal);

        // If we already have an account, initialize the store for it
        if let Some(account) = &self.account {
            let signal = self.signal.as_mut().unwrap();
            signal.get_or_create_store_for(account)?;
        }

        // Restore ephemeral Signal stores from peer_mapping (per-peer keys)
        {
            let signal = self.signal.as_mut().unwrap();
            if let Ok(mappings) = signal.get_all_peer_mappings_full().await {
                let mut restored = 0u32;
                for (_nostr_pk, _signal_pk, _device_id, _name, local_pk, local_sk, _otk) in &mappings {
                    if let (Some(lpk), Some(lsk)) = (local_pk, local_sk) {
                        if lpk.is_empty() || lsk.is_empty() { continue; }
                        if let Err(e) = signal.restore_ephemeral_store(lpk, lsk) {
                            log::warn!("Failed to restore ephemeral store {}: {}", &lpk[..16.min(lpk.len())], e);
                        } else {
                            restored += 1;
                        }
                    }
                }
                if restored > 0 {
                    log::info!("Restored {} ephemeral Signal store(s) from peer_mapping", restored);
                }
            }
        }

        Ok(serde_json::json!({"initialized": true, "db_path": db_path}))
    }

    async fn handle_generate_identity(
        &mut self,
        _params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let account = KeychatAccount::generate()?;
        let info = account.public_info();
        self.account = Some(account);
        Ok(serde_json::to_value(info)?)
    }

    async fn handle_import_identity(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let mnemonic: String = params
            .get("mnemonic")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("mnemonic required"))?
            .to_string();
        let password = params
            .get("password")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let account = KeychatAccount::from_mnemonic(&mnemonic, password)?;
        let info = account.public_info();
        self.account = Some(account);
        Ok(serde_json::to_value(info)?)
    }

    async fn handle_get_account_info(&self) -> Result<serde_json::Value> {
        let account = self
            .account
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;
        Ok(serde_json::to_value(account.public_info())?)
    }

    // -----------------------------------------------------------------------
    // Signal key management (low-level)
    // -----------------------------------------------------------------------

    async fn handle_generate_prekey_bundle(&mut self) -> Result<serde_json::Value> {
        let signal = self
            .signal
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let account = self
            .account
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;
        let bundle = signal.generate_prekey_bundle(account).await?;
        Ok(serde_json::to_value(bundle)?)
    }

    async fn handle_process_prekey_bundle(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let signal = self
            .signal
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let account = self
            .account
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;
        signal.process_prekey_bundle(account, &params).await?;
        Ok(serde_json::json!({"session_established": true}))
    }

    // -----------------------------------------------------------------------
    // Keychat Hello / Handshake
    // -----------------------------------------------------------------------

    /// Generate a complete Keychat hello message ready to send.
    /// Params: { name: string, to_pubkey?: string }
    /// Returns: { hello: KeychatMessage, qr_user_model: QRUserModel, send_to?: string }
    async fn handle_generate_hello(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let signal = self
            .signal
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized. Call 'init' first."))?;
        let account = self
            .account
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized. Call 'generate_identity' first."))?;

        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Keychat User");

        let to_pubkey = params
            .get("to_pubkey")
            .and_then(|v| v.as_str());

        // Generate the QRUserModel with EPHEMERAL Signal identity
        let (qr_model, eph_pk_hex, eph_sk_hex, _onetimekey) = signal
            .generate_hello_bundle_ephemeral(account, name)
            .await?;
        let qr_model_json = serde_json::to_string(&qr_model)?;

        // Create the KeychatMessage wrapper
        let greeting = format!("😄Hi, I'm {}.\nLet's start an encrypted chat.", name);
        let keychat_msg = KeychatMessage {
            msg_type: event_kinds::DM_ADD_CONTACT_FROM_ALICE,
            c: "signal".to_string(),
            msg: Some(greeting),
            name: Some(qr_model_json.clone()),
            data: None,
        };

        let keychat_msg_json = serde_json::to_string(&keychat_msg)?;

        let mut result = serde_json::json!({
            "hello_message": keychat_msg_json,
            "keychat_message": keychat_msg,
            "qr_user_model": qr_model,
            "nostr_pubkey": account.nostr_pubkey_hex(),
            "signal_pubkey": eph_pk_hex,
            "local_signal_privkey": eph_sk_hex,
        });

        if let Some(to) = to_pubkey {
            result["send_to"] = serde_json::json!(to);
        }

        Ok(result)
    }

    /// Process a received hello message and establish a Signal session.
    /// Params: { message: string (KeychatMessage JSON), device_id?: number }
    /// Returns: { session_established: bool, peer_nostr_pubkey, peer_signal_pubkey }
    async fn handle_process_hello(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let signal = self
            .signal
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let account = self
            .account
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;

        // Parse the KeychatMessage
        let msg_str = params
            .get("message")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'message' (KeychatMessage JSON) required"))?;

        let keychat_msg: KeychatMessage = serde_json::from_str(msg_str)?;

        // Extract the QRUserModel from the name field
        let qr_model_str = keychat_msg
            .name
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("KeychatMessage.name (QRUserModel) is missing"))?;
        let qr_model: QRUserModel = serde_json::from_str(qr_model_str)?;

        let device_id = params
            .get("device_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(self.next_device_id as u64) as u32;

        // Generate per-peer ephemeral Signal keypair for B (receiver) — matches Keychat app behavior
        // where each room gets its own Signal identity via createSignalId()
        let (eph_pk, eph_sk) = KeychatAccount::generate_ephemeral_signal_keypair();
        let eph_pk_hex = hex::encode(&eph_pk);
        let eph_sk_hex = hex::encode(&eph_sk);

        // Process the pre-key bundle using the ephemeral keypair (not account's global key)
        signal
            .process_prekey_bundle_from_model_with_keypair(&eph_pk, &eph_sk, &qr_model, device_id)
            .await?;

        log::info!(
            "process_hello: established session with ephemeral Signal key {} for peer {}",
            &eph_pk_hex[..16], &qr_model.pubkey[..16]
        );

        // Track the peer
        let peer = PeerSession {
            curve25519_pk_hex: qr_model.curve25519_pk_hex.clone(),
            device_id,
            onetimekey: if qr_model.onetimekey.is_empty() {
                None
            } else {
                Some(qr_model.onetimekey.clone())
            },
            nostr_pubkey: qr_model.pubkey.clone(),
        };
        self.peers.insert(qr_model.pubkey.clone(), peer);

        // Persist peer mapping with ephemeral Signal keys (per-peer, not account global)
        // Include onetimekey so it survives bridge restart (needed to send accept-first to correct address)
        let local_sig_pk = eph_pk_hex;
        let local_sig_sk = eph_sk_hex;
        let otk = if qr_model.onetimekey.is_empty() { None } else { Some(qr_model.onetimekey.as_str()) };
        signal
            .save_peer_mapping_full_with_spk_otk(
                &qr_model.pubkey,
                &qr_model.curve25519_pk_hex,
                device_id,
                &qr_model.name,
                Some(&local_sig_pk),
                Some(&local_sig_sk),
                None,
                otk,
            )
            .await?;

        Ok(serde_json::json!({
            "session_established": true,
            "peer_nostr_pubkey": qr_model.pubkey,
            "peer_signal_pubkey": qr_model.curve25519_pk_hex,
            "peer_name": qr_model.name,
            "peer_onetimekey": if qr_model.onetimekey.is_empty() { None } else { Some(&qr_model.onetimekey) },
            "device_id": device_id,
            "msg_type": keychat_msg.msg_type,
            "greeting": keychat_msg.msg,
        }))
    }

    /// Send a hello/friend request to a specified Nostr pubkey via Gift Wrap.
    /// Params: { to_pubkey: string, name?: string }
    async fn handle_send_hello(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let raw_pubkey = params
            .get("to_pubkey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'to_pubkey' required"))?;
        // Support both npub1... (bech32) and hex formats
        let to_pubkey = if raw_pubkey.starts_with("npub1") {
            use nostr::nips::nip19::FromBech32;
            let pk = nostr::PublicKey::from_bech32(raw_pubkey)?;
            pk.to_hex()
        } else {
            raw_pubkey.to_string()
        };
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Keychat Agent");

        // Generate hello with EPHEMERAL Signal identity (each peer gets a unique key)
        let signal = self.signal.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;

        let (qr_model, eph_pk_hex, eph_sk_hex, onetimekey) = signal
            .generate_hello_bundle_ephemeral(account, name)
            .await?;

        // Build the KeychatMessage
        let qr_model_json = serde_json::to_string(&qr_model)?;
        let greeting = format!("😄Hi, I'm {}.\nLet's start an encrypted chat.", name);
        let keychat_msg = crate::protocol::KeychatMessage {
            msg_type: crate::protocol::event_kinds::DM_ADD_CONTACT_FROM_ALICE,
            c: "signal".to_string(),
            msg: Some(greeting),
            name: Some(qr_model_json),
            data: None,
        };
        let hello_message = serde_json::to_string(&keychat_msg)?;

        // Save peer mapping with ephemeral Signal keys + signed_prekey_id
        // peer's signal key is unknown until they reply — leave empty
        signal.save_peer_mapping_full_with_spk(
            &to_pubkey,
            "",  // peer's signal key unknown until they reply with hello
            1,
            name,
            Some(&eph_pk_hex),   // OUR local ephemeral Signal pubkey
            Some(&eph_sk_hex),   // OUR local ephemeral Signal privkey
            Some(qr_model.signed_id),  // Our signed prekey ID — used to identify PreKey replies
        ).await?;

        log::info!(
            "Generated hello with ephemeral Signal key {} for peer {}",
            &eph_pk_hex[..16], to_pubkey
        );

        // Send as Gift Wrap
        let account = self.account.as_ref().unwrap();
        let transport = self.transport.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected to relays"))?;
        let event_id = transport.send_gift_wrap(account, &to_pubkey, &hello_message).await?;

        // Subscribe to onetimekey so we receive the hello reply
        if !onetimekey.is_empty() {
            if let Err(e) = transport.subscribe_additional_pubkeys(&[&onetimekey]).await {
                log::warn!("Failed to subscribe to onetimekey {}: {}", onetimekey, e);
            } else {
                log::info!("Subscribed to onetimekey {} for hello reply", &onetimekey[..16]);
            }
        }

        log::info!("Sent hello Gift Wrap to {} — event {}", to_pubkey, event_id);

        Ok(serde_json::json!({
            "sent": true,
            "event_id": event_id,
            "to_pubkey": to_pubkey,
            "local_signal_pubkey": eph_pk_hex,
            "onetimekey": onetimekey,
        }))
    }

    // -----------------------------------------------------------------------
    // Messaging
    // -----------------------------------------------------------------------

    /// Send a message to a peer.
    /// Params: { to: string (nostr pubkey), text: string, is_hello_reply?: bool }
    ///
    /// Flow (mirrors Keychat app's SignalChatService.sendMessage):
    ///   1. Determine destination address:
    ///      - Query Signal session for bobAddress
    ///      - If bobAddress starts with "05" (raw curve25519), use peer's nostr pubkey
    ///      - If peer has onetimekey and we'd send to nostr pubkey, use onetimekey instead
    ///      - Otherwise, bobAddress is a ratchet-derived seed → hash to get receiving address
    ///   2. If sending to onetimekey, wrap message in PrekeyMessageModel (contains our Signal ID + Schnorr sig)
    /// Send a profile update (type 48) to an existing peer.
    /// Params: { peer_nostr_pubkey, name?, avatar?, lightning?, bio? }
    async fn handle_send_profile(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let peer_nostr_pubkey = params
            .get("peer_nostr_pubkey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'peer_nostr_pubkey' required"))?
            .to_string();

        let account = self.account.as_ref().ok_or_else(|| anyhow::anyhow!("No account"))?;
        let my_pubkey = account.nostr_pubkey_hex();

        let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("Keychat Guide");
        let avatar = params.get("avatar").and_then(|v| v.as_str());
        let lightning = params.get("lightning").and_then(|v| v.as_str());
        let bio = params.get("bio").and_then(|v| v.as_str());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Build ProfileRequestModel JSON
        let mut profile = serde_json::json!({
            "pubkey": my_pubkey,
            "name": name,
            "version": now,
        });
        if let Some(a) = avatar { profile["avatar"] = serde_json::json!(a); }
        if let Some(l) = lightning { profile["lightning"] = serde_json::json!(l); }
        if let Some(b) = bio { profile["bio"] = serde_json::json!(b); }

        let profile_json = serde_json::to_string(&profile)?;

        // Build KeychatMessage with type 48
        let keychat_msg = KeychatMessage {
            msg_type: event_kinds::SIGNAL_SEND_PROFILE,
            c: "signal".to_string(),
            msg: Some(format!("[{}'s Profile]", name)),
            name: Some(profile_json),
            data: None,
        };
        let keychat_msg_json = serde_json::to_string(&keychat_msg)?;

        // Send via existing send_message infrastructure
        let send_params = serde_json::json!({
            "to": peer_nostr_pubkey,
            "text": keychat_msg_json,
        });
        let result = self.handle_send_message(send_params).await?;

        log::info!("Sent profile '{}' to peer {}", name, peer_nostr_pubkey);
        Ok(serde_json::json!({
            "sent": true,
            "event_id": result.get("event_id"),
        }))
    }

    ///   3. Signal encrypt the content
    ///   4. Base64 encode ciphertext
    ///   5. NIP-04 encrypt with ephemeral sender key
    ///   6. Publish kind:4 to relay
    async fn handle_send_message(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let to_str: String = params
            .get("to")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'to' pubkey required"))?
            .to_string();
        let text: String = params
            .get("text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'text' required"))?
            .to_string();

        let account = self
            .account
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;

        // Look up peer session info
        let mut peer = self.peers.get(&to_str).cloned();
        let mut local_signal_pubkey: Option<String> = None;

        // Fallback: if peer not in memory, try to load from DB peer_mapping
        if let Some(signal) = self.signal.as_ref() {
            if let Ok(Some(m)) = signal.get_peer_mapping_by_nostr_pubkey(&to_str).await {
                local_signal_pubkey = m.4.filter(|s| !s.is_empty());
                if peer.is_none() {
                    if m.1.is_empty() {
                        // Placeholder mapping (hello sent, no reply yet)
                        log::info!("Peer {} has placeholder mapping (no signal pubkey yet), waiting for hello reply", to_str);
                    } else {
                        log::info!("Loaded peer {} from DB peer_mapping (signal: {}, local_signal: {:?})", to_str, &m.1[..16.min(m.1.len())], &local_signal_pubkey);
                        let restored_peer = PeerSession {
                            nostr_pubkey: m.0.clone(),
                            curve25519_pk_hex: m.1.clone(),
                            device_id: m.2 as u32,
                            onetimekey: m.6.clone().filter(|s| !s.is_empty()),
                        };
                        self.peers.insert(to_str.clone(), restored_peer.clone());
                        peer = Some(restored_peer);
                    }
                }
            }
        }

        let (signal_pubkey, device_id, nostr_pubkey) = if let Some(p) = &peer {
            (p.curve25519_pk_hex.clone(), p.device_id, p.nostr_pubkey.clone())
        } else {
            let device_id = params
                .get("device_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(1) as u32;
            (to_str.clone(), device_id, to_str.clone())
        };

        if signal_pubkey.is_empty() {
            anyhow::bail!("No Signal session with peer {} yet (missing peer signal pubkey)", to_str);
        }

        let signal = self
            .signal
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;

        // Determine destination address (mirrors Keychat's _getSignalToAddress)
        // 1. Query Signal session for bobAddress
        // 2. If bobAddress starts with "05" (raw curve25519) → use nostr pubkey
        // 3. If bobAddress is ratchet-derived → hash via generateSeedFromRatchetkeyPair
        // 4. If dest == nostr pubkey and onetimekey exists → use onetimekey
        let mut dest_pubkey = nostr_pubkey.clone();
        let mut sending_to_onetimekey = false;

        let bob_address = if let Some(ref lsk) = local_signal_pubkey {
            signal.get_bob_address_by_local_key(lsk, &signal_pubkey, device_id).await?
        } else {
            signal.get_bob_address(account, &signal_pubkey, device_id).await?
        };

        if let Some(ref bob_addr) = bob_address {
            if bob_addr.starts_with("05") {
                // Raw curve25519 key — use nostr pubkey
                log::info!("bobAddress is raw curve25519, using nostr pubkey");
                dest_pubkey = nostr_pubkey.clone();
            } else {
                // Ratchet-derived — hash to get receiving address
                let derived = crate::signal::generate_seed_from_ratchetkey_pair(bob_addr)?;
                log::info!("Derived peer receiving address from bobAddress: {}", derived);
                dest_pubkey = derived;
            }
        }

        // If destination is still the nostr pubkey and peer has onetimekey, use onetimekey
        if dest_pubkey == nostr_pubkey {
            if let Some(ref p) = peer {
                if let Some(ref otk) = p.onetimekey {
                    if !otk.is_empty() {
                        dest_pubkey = otk.clone();
                        sending_to_onetimekey = true;
                        log::info!("Sending to peer's onetimekey: {}", otk);
                    }
                }
            }
        }

        // Step 2: If sending to onetimekey, wrap in PrekeyMessageModel
        let plaintext_to_encrypt = if sending_to_onetimekey {
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as i64;
            // Use ephemeral signal key if available, otherwise account's default
            let signal_id_for_sign = local_signal_pubkey.as_deref()
                .unwrap_or(&account.signal_pubkey_hex()).to_string();
            let sign_content = KeychatAccount::get_sign_message(
                &account.nostr_pubkey_hex(),
                &signal_id_for_sign,
                time,
            );
            let sig = account.schnorr_sign(&sign_content)?;

            let nostr_id_for_pmm = account.nostr_pubkey_hex();
            let signal_id_for_pmm = signal_id_for_sign;
            let pmm = PrekeyMessageModel {
                nostr_id: nostr_id_for_pmm,
                signal_id: signal_id_for_pmm,
                time,
                sig,
                name: params.get("sender_name").and_then(|v| v.as_str()).unwrap_or("Keychat Agent").to_string(),
                message: text.clone(),
                lightning: None,
                avatar: None,
            };
            log::info!("Wrapping message in PrekeyMessageModel for onetimekey delivery");
            serde_json::to_string(&pmm)?
        } else {
            text.clone()
        };

        // Step 3: Signal encrypt (use ephemeral store if available for this peer)
        let encrypt_result = signal
            .encrypt_with_store(
                &account,
                local_signal_pubkey.as_deref(),
                &signal_pubkey,
                &plaintext_to_encrypt,
                device_id,
            )
            .await?;

        // Step 4: Base64 encode
        let b64_ciphertext = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &encrypt_result.ciphertext,
        );

        // Update receiving address if ratchet advanced
        if let Some(ref new_addr) = encrypt_result.new_receiving_address {
            log::info!("New receiving address from ratchet: {}", new_addr);
        }

        // Step 5-6: Generate ephemeral Nostr keypair and send as Keychat DM
        // Keychat uses "unencrypted" kind:4 events — content is already Signal-encrypted
        // (base64 ciphertext goes directly as event content, no NIP-04 encryption)
        let sender_keys = nostr::Keys::generate();

        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected to relays"))?;

        // Tag both the destination pubkey and signal receiving address if available
        let mut receiver_pubkeys = vec![dest_pubkey.as_str()];
        if let Some(ref new_addr) = encrypt_result.new_receiving_address {
            // The new_receiving_address contains ratchet info, but we need to
            // also tag it so Keychat knows about the address rotation
            // Format is "seed-signedPublic", we might need to hash it
            log::info!("Ratchet new_receiving_address: {}", new_addr);
        }

        let event_id = transport
            .send_keychat_dm(&sender_keys, &receiver_pubkeys, &b64_ciphertext)
            .await?;

        // If we sent to onetimekey, clear it from memory and DB (one-time use)
        if sending_to_onetimekey {
            if let Some(p) = self.peers.get_mut(&to_str) {
                p.onetimekey = None;
            }
            // Clear from DB too so it's not restored on restart
            if let Some(sig) = self.signal.as_ref() {
                let _ = sig.clear_onetimekey(&to_str).await;
            }
        }

        // Auto-subscribe to ratchet-derived receiving address
        let mut derived_receiving_address: Option<String> = None;
        if let Some(ref new_addr) = encrypt_result.new_receiving_address {
            match signal::generate_seed_from_ratchetkey_pair(new_addr) {
                Ok(derived_pubkey) => {
                    log::info!("Derived receiving address from ratchet: {}", derived_pubkey);
                    if let Some(ref t) = self.transport {
                        if let Err(e) = t.subscribe_additional_pubkeys(&[&derived_pubkey]).await {
                            log::warn!("Failed to subscribe to derived address: {}", e);
                        }
                    }
                    derived_receiving_address = Some(derived_pubkey);
                }
                Err(e) => {
                    log::warn!("Failed to derive receiving address from ratchet key: {}", e);
                }
            }
        }

        Ok(serde_json::json!({
            "sent": true,
            "event_id": event_id,
            "is_prekey": encrypt_result.is_prekey,
            "dest_pubkey": dest_pubkey,
            "sending_to_onetimekey": sending_to_onetimekey,
            "new_receiving_address": encrypt_result.new_receiving_address,
            "derived_receiving_address": derived_receiving_address,
            "ephemeral_sender": sender_keys.public_key().to_string(),
        }))
    }

    /// Decrypt a received message.
    /// Params: { from: string (signal pubkey), ciphertext: string (base64), is_prekey?: bool, device_id?: u32, room_id?: u32 }
    /// Parse the sender's Signal identity key from a PreKey message.
    /// This allows identifying who sent a PreKey message before decrypting.
    async fn handle_parse_prekey_sender(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let ciphertext_b64 = params
            .get("ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'ciphertext' required"))?;

        let ciphertext_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            ciphertext_b64.trim(),
        )?;

        if ciphertext_bytes.is_empty() {
            return Err(anyhow::anyhow!("Empty ciphertext"));
        }

        // Try to parse as PreKeySignalMessage (same approach as Keychat app: try_from)
        let prekey_msg = match signal_store::libsignal_protocol::PreKeySignalMessage::try_from(ciphertext_bytes.as_slice()) {
            Ok(msg) => msg,
            Err(_) => {
                log::info!("parse_prekey_sender: not a PreKeySignalMessage (len={})", ciphertext_bytes.len());
                return Ok(serde_json::json!({
                    "is_prekey": false,
                }));
            }
        };

        let identity_key = prekey_msg.identity_key();
        let identity_key_bytes = identity_key.serialize();
        let identity_key_hex = hex::encode(&identity_key_bytes);
        let signed_pre_key_id = prekey_msg.signed_pre_key_id();

        let spk_id: u32 = signed_pre_key_id.into();
        log::info!("parse_prekey_sender: PreKey detected, identity_key={}, signed_pre_key_id={}", &identity_key_hex[..16], spk_id);
        Ok(serde_json::json!({
            "is_prekey": true,
            "signal_identity_key": identity_key_hex,
            "signed_pre_key_id": spk_id,
        }))
    }

    async fn handle_lookup_peer_by_spk(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let spk_id = params
            .get("signed_prekey_id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("'signed_prekey_id' required"))? as u32;

        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;

        let peer = signal.lookup_peer_by_signed_prekey_id(spk_id).await?;
        log::info!("lookup_peer_by_signed_prekey_id({}): {:?}", spk_id, peer);
        Ok(serde_json::json!({
            "nostr_pubkey": peer,
        }))
    }

    async fn handle_clear_prekey_material(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let nostr_pubkey = params
            .get("nostr_pubkey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'nostr_pubkey' required"))?;
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        signal.clear_prekey_material(nostr_pubkey).await?;
        Ok(serde_json::json!({ "ok": true }))
    }

    async fn handle_decrypt_message(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let from_pubkey: String = params
            .get("from")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'from' pubkey required"))?
            .to_string();
        let ciphertext_b64: String = params
            .get("ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'ciphertext' required"))?
            .to_string();
        let is_prekey: bool = params
            .get("is_prekey")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let device_id: u32 = params
            .get("device_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;
        let room_id: u32 = params
            .get("room_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let account = self
            .account
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;
        let signal = self
            .signal
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;

        let ciphertext_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &ciphertext_b64,
        )?;

        // Look up local signal key for this peer (to use the correct ephemeral store).
        // For hello-reply PreKey messages from unknown peers, there may be no remote signal mapping yet;
        // in that case we later try all known local ephemeral stores as a fallback.
        let mappings = signal.get_all_peer_mappings_full().await.unwrap_or_default();
        let local_signal_pubkey: Option<String> = mappings
            .iter()
            .find(|m| m.1 == from_pubkey)
            .and_then(|m| m.4.clone())
            .filter(|s| !s.is_empty());

        log::info!("decrypt_message: from={}, is_prekey={}, device_id={}, ciphertext_len={}, local_store={:?}",
            from_pubkey, is_prekey, device_id, ciphertext_bytes.len(),
            local_signal_pubkey.as_ref().map(|s| &s[..16.min(s.len())]));

        let result = if let Some(ref local_store_key) = local_signal_pubkey {
            match signal
                .decrypt_with_store(account, Some(local_store_key), &from_pubkey, &ciphertext_bytes, device_id, room_id, is_prekey)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("Ephemeral store decrypt failed, trying account default store: {}", e);
                    signal.decrypt(account, &from_pubkey, &ciphertext_bytes, device_id, room_id, is_prekey).await?
                }
            }
        } else if is_prekey {
            // Unknown prekey sender (common for hello reply): try each saved local ephemeral store.
            let mut tried = 0usize;
            let mut local_candidates: Vec<String> = mappings
                .iter()
                .filter_map(|m| m.4.clone())
                .filter(|s| !s.is_empty())
                .collect();
            local_candidates.sort();
            local_candidates.dedup();

            let mut decrypted: Option<crate::signal::DecryptResult> = None;
            for candidate in &local_candidates {
                tried += 1;
                match signal
                    .decrypt_with_store(account, Some(candidate), &from_pubkey, &ciphertext_bytes, device_id, room_id, true)
                    .await
                {
                    Ok(r) => {
                        log::info!("PreKey decrypt succeeded with fallback local store {}", &candidate[..16.min(candidate.len())]);
                        decrypted = Some(r);
                        break;
                    }
                    Err(_) => continue,
                }
            }

            if let Some(r) = decrypted {
                r
            } else {
                log::warn!("PreKey decrypt failed with {} fallback local store(s); trying default store", tried);
                signal.decrypt(account, &from_pubkey, &ciphertext_bytes, device_id, room_id, is_prekey).await?
            }
        } else {
            signal.decrypt(account, &from_pubkey, &ciphertext_bytes, device_id, room_id, is_prekey).await?
        };

        let plaintext = String::from_utf8(result.plaintext)?;

        // Try to parse as KeychatMessage
        let parsed = serde_json::from_str::<KeychatMessage>(&plaintext).ok();

        let mut response = serde_json::json!({
            "plaintext": plaintext,
            "msg_key_hash": result.msg_key_hash,
        });

        if let Some(km) = &parsed {
            response["keychat_message"] = serde_json::to_value(km)?;
            // If it's a hello message, extract QRUserModel
            if km.msg_type == event_kinds::DM_ADD_CONTACT_FROM_ALICE
                || km.msg_type == event_kinds::DM_ADD_CONTACT_FROM_BOB
            {
                if let Some(ref name_str) = km.name {
                    if let Ok(qr) = serde_json::from_str::<QRUserModel>(name_str) {
                        response["qr_user_model"] = serde_json::to_value(&qr)?;
                    }
                }
            }
        }

        if let Some(addrs) = result.my_next_addrs {
            response["my_next_addrs"] = serde_json::to_value(addrs)?;
        }

        Ok(response)
    }

    // -----------------------------------------------------------------------
    // Transport
    // -----------------------------------------------------------------------

    async fn handle_connect(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let relays: Vec<String> = params
            .get("relays")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_else(|| {
                vec![
                    "wss://relay.keychat.io".to_string(),
                    "wss://relay.damus.io".to_string(),
                    "wss://nos.lol".to_string(),
                    "wss://relay.ditto.pub".to_string(),
                ]
            });

        let account = self
            .account
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;

        // Query last processed event time for smarter subscription lookback
        let last_seen = match &self.signal {
            Some(sig) => sig.last_processed_event_time().await.unwrap_or(None),
            None => None,
        };
        log::info!("Last processed event time: {:?}", last_seen);

        // Pre-load known receiving addresses from DB so the initial subscription
        // includes them (avoids missing historical kind:4 events).
        let initial_addrs: Vec<String> = match &self.signal {
            Some(sig) => sig.get_all_address_mappings().await
                .unwrap_or_default()
                .into_iter()
                .map(|(addr, _peer)| addr)
                .collect(),
            None => vec![],
        };
        log::info!("Pre-loading {} address(es) for initial subscription", initial_addrs.len());

        let transport = NostrTransport::connect(account, &relays, self.inbound_tx.clone(), last_seen, &initial_addrs).await?;
        self.transport = Some(transport);

        Ok(serde_json::json!({
            "connected": true,
            "relays": relays,
        }))
    }

    async fn handle_disconnect(&mut self) -> Result<serde_json::Value> {
        if let Some(transport) = self.transport.take() {
            transport.disconnect().await?;
        }
        Ok(serde_json::json!({"disconnected": true}))
    }

    /// Subscribe to additional pubkeys for receiving ratchet-derived messages.
    /// Params: { pubkeys: [string] }
    async fn handle_add_subscription(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let pubkeys: Vec<String> = params
            .get("pubkeys")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow::anyhow!("'pubkeys' array required"))?;

        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected to relays"))?;

        let pk_refs: Vec<&str> = pubkeys.iter().map(|s| s.as_str()).collect();
        transport.subscribe_additional_pubkeys(&pk_refs).await?;

        Ok(serde_json::json!({
            "subscribed": true,
            "pubkeys": pubkeys,
        }))
    }

    async fn handle_remove_subscription(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let pubkeys: Vec<String> = params
            .get("pubkeys")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow::anyhow!("'pubkeys' array required"))?;

        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected to relays"))?;

        let pk_refs: Vec<&str> = pubkeys.iter().map(|s| s.as_str()).collect();
        transport.unsubscribe_pubkeys(&pk_refs).await?;

        Ok(serde_json::json!({
            "removed": true,
            "pubkeys": pubkeys,
        }))
    }

    async fn handle_has_session(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let pubkey: String = params
            .get("pubkey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'pubkey' required"))?
            .to_string();
        let device_id: u32 = params
            .get("device_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;

        let signal = self
            .signal
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let account = self
            .account
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;

        let exists = signal.has_session(account, &pubkey, device_id).await?;
        Ok(serde_json::json!({"exists": exists}))
    }

    async fn handle_compute_address(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let seed = params
            .get("seed")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'seed' (private_hex-public_hex) required"))?;
        let address = crate::signal::generate_seed_from_ratchetkey_pair(seed)?;
        Ok(serde_json::json!({"address": address}))
    }


    /// Get all peer sessions from DB.
    async fn handle_get_all_sessions(&self) -> Result<serde_json::Value> {
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;
        let sessions = signal.get_all_sessions_info(account).await?;
        let result: Vec<serde_json::Value> = sessions.into_iter().map(|(addr, device)| {
            serde_json::json!({"signal_pubkey": addr, "device_id": device})
        }).collect();
        Ok(serde_json::json!({"sessions": result}))
    }

    /// Get all peer mappings (nostr↔signal), including local signal keys.
    async fn handle_get_peer_mappings(&self) -> Result<serde_json::Value> {
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let mappings = signal.get_all_peer_mappings_full().await?;
        let result: Vec<serde_json::Value> = mappings.into_iter().map(|(nostr_pk, signal_pk, device_id, name, local_pk, _local_sk, _otk)| {
            let mut v = serde_json::json!({"nostr_pubkey": nostr_pk, "signal_pubkey": signal_pk, "device_id": device_id, "name": name});
            if let Some(lpk) = local_pk {
                v["local_signal_pubkey"] = serde_json::json!(lpk);
            }
            v
        }).collect();
        Ok(serde_json::json!({"mappings": result}))
    }

    /// Save a peer mapping from TS side.
    async fn handle_save_peer_mapping(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let nostr_pubkey = params.get("nostr_pubkey").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("nostr_pubkey required"))?;
        let signal_pubkey = params.get("signal_pubkey").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("signal_pubkey required"))?;
        let device_id = params.get("device_id").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
        let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
        signal.save_peer_mapping(nostr_pubkey, signal_pubkey, device_id, name).await?;

        // Also update in-memory peer cache so sendMessage uses the new signal key
        if !signal_pubkey.is_empty() {
            let peer = PeerSession {
                nostr_pubkey: nostr_pubkey.to_string(),
                curve25519_pk_hex: signal_pubkey.to_string(),
                device_id,
                onetimekey: None,
            };
            self.peers.insert(nostr_pubkey.to_string(), peer);
            log::info!("Updated in-memory peer cache for {} (signal: {})", nostr_pubkey, signal_pubkey);
        }

        Ok(serde_json::json!({"saved": true}))
    }

    /// Save an address-to-peer mapping.
    async fn handle_save_address_mapping(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let address = params.get("address").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("address required"))?;
        let peer_nostr_pubkey = params.get("peer_nostr_pubkey").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("peer_nostr_pubkey required"))?;
        signal.save_address_mapping(address, peer_nostr_pubkey).await?;
        Ok(serde_json::json!({"saved": true}))
    }

    /// Get all address-to-peer mappings.
    async fn handle_get_address_mappings(&self) -> Result<serde_json::Value> {
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let mappings = signal.get_all_address_mappings().await?;
        let result: Vec<serde_json::Value> = mappings.into_iter().map(|(addr, peer)| {
            serde_json::json!({"address": addr, "peer_nostr_pubkey": peer})
        }).collect();
        Ok(serde_json::json!({"mappings": result}))
    }

    /// Delete an address-to-peer mapping.
    async fn handle_delete_address_mapping(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let address = params.get("address").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("address required"))?;
        signal.delete_address_mapping(address).await?;
        Ok(serde_json::json!({"deleted": true}))
    }

    /// Mark an event as processed.
    async fn handle_mark_event_processed(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let event_id = params.get("event_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("event_id required"))?;
        let created_at = params.get("created_at").and_then(|v| v.as_u64());
        signal.mark_event_processed(event_id, created_at).await?;
        Ok(serde_json::json!({"marked": true}))
    }

    /// Check if an event was already processed.
    async fn handle_is_event_processed(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let event_id = params.get("event_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("event_id required"))?;
        let processed = signal.is_event_processed(event_id).await?;
        Ok(serde_json::json!({"processed": processed}))
    }

    // -----------------------------------------------------------------------
    // Session management
    // -----------------------------------------------------------------------

    /// Delete a Signal session for a peer.
    /// Params: { signal_pubkey: string, device_id?: number }
    async fn handle_delete_session(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let signal = self.signal.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;
        let signal_pubkey = params.get("signal_pubkey").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("signal_pubkey required"))?;
        let device_id = params.get("device_id").and_then(|v| v.as_u64())
            .map(|v| v as u32);
        signal.delete_session(account, signal_pubkey, device_id).await?;
        Ok(serde_json::json!({"deleted": true}))
    }

    // -----------------------------------------------------------------------
    // Group (small group / sendAll)
    // -----------------------------------------------------------------------

    /// Create a new small group.
    /// Params: { name: string }
    async fn handle_create_group(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let name = params.get("name").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'name' required"))?;
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;

        // Generate a random keypair for the group ID (same as Keychat app)
        let group_keys = nostr::Keys::generate();
        let group_id = group_keys.public_key().to_string();
        let my_id_pubkey = account.nostr_pubkey_hex();

        signal.create_group(&group_id, name, &my_id_pubkey).await?;
        // Add self as admin member
        signal.add_group_member(&group_id, &my_id_pubkey, "Agent", true).await?;

        log::info!("Created group '{}' with id {}", name, group_id);
        Ok(serde_json::json!({
            "group_id": group_id,
            "name": name,
        }))
    }

    /// Get group info.
    async fn handle_get_group(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'group_id' required"))?;
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;

        let group = signal.get_group(group_id).await?;
        match group {
            Some((id, name, my_id, status, version)) => {
                let members = signal.get_group_members(group_id).await?;
                let members_json: Vec<serde_json::Value> = members.into_iter().map(|(pk, n, admin)| {
                    serde_json::json!({"idPubkey": pk, "name": n, "isAdmin": admin})
                }).collect();
                Ok(serde_json::json!({
                    "group_id": id,
                    "name": name,
                    "my_id_pubkey": my_id,
                    "status": status,
                    "version": version,
                    "members": members_json,
                }))
            }
            None => Ok(serde_json::json!({"group_id": null})),
        }
    }

    /// Get all groups.
    async fn handle_get_all_groups(&self) -> Result<serde_json::Value> {
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let groups = signal.get_all_groups().await?;
        let result: Vec<serde_json::Value> = groups.into_iter().map(|(id, name, my_id, status, version)| {
            serde_json::json!({"group_id": id, "name": name, "my_id_pubkey": my_id, "status": status, "version": version})
        }).collect();
        Ok(serde_json::json!({"groups": result}))
    }

    /// Join a group from an invite (RoomProfile).
    /// Params: { room_profile: RoomProfile JSON, sender_id_pubkey: string }
    async fn handle_join_group(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let profile_val = params.get("room_profile")
            .ok_or_else(|| anyhow::anyhow!("'room_profile' required"))?;
        let profile: RoomProfile = serde_json::from_value(profile_val.clone())?;
        let sender_id_pubkey = params.get("sender_id_pubkey").and_then(|v| v.as_str())
            .unwrap_or("");

        let account = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;

        let group_id = profile.old_to_room_pub_key.as_deref().unwrap_or(&profile.pubkey);
        let my_id_pubkey = account.nostr_pubkey_hex();

        // Create or update the group
        signal.create_group(group_id, &profile.name, &my_id_pubkey).await?;

        // Add all members from the profile
        for user in &profile.users {
            let id_pubkey = user.get("idPubkey").and_then(|v| v.as_str()).unwrap_or("");
            let name = user.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let is_admin = user.get("isAdmin").and_then(|v| v.as_bool()).unwrap_or(false);
            if !id_pubkey.is_empty() {
                signal.add_group_member(group_id, id_pubkey, name, is_admin).await?;
            }
        }

        log::info!("Joined group '{}' (id: {}) via invite from {}", profile.name, group_id, sender_id_pubkey);
        Ok(serde_json::json!({
            "joined": true,
            "group_id": group_id,
            "name": profile.name,
            "member_count": profile.users.len(),
        }))
    }

    /// Add a member to a group.
    async fn handle_add_group_member(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'group_id' required"))?;
        let id_pubkey = params.get("id_pubkey").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'id_pubkey' required"))?;
        let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let is_admin = params.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false);

        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        signal.add_group_member(group_id, id_pubkey, name, is_admin).await?;
        Ok(serde_json::json!({"added": true}))
    }

    /// Remove a member from a group.
    async fn handle_remove_group_member(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'group_id' required"))?;
        let id_pubkey = params.get("id_pubkey").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'id_pubkey' required"))?;

        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        signal.remove_group_member(group_id, id_pubkey).await?;
        Ok(serde_json::json!({"removed": true}))
    }

    /// Get group members.
    async fn handle_get_group_members(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'group_id' required"))?;
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        let members = signal.get_group_members(group_id).await?;
        let result: Vec<serde_json::Value> = members.into_iter().map(|(pk, name, admin)| {
            serde_json::json!({"idPubkey": pk, "name": name, "isAdmin": admin})
        }).collect();
        Ok(serde_json::json!({"members": result}))
    }

    /// Send a message to all group members (sendAll pattern).
    /// Params: { group_id: string, text: string }
    /// This wraps text in GroupMessage → KeychatMessage and sends to each member.
    async fn handle_send_group_message(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'group_id' required"))?.to_string();
        let text = params.get("text").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'text' required"))?.to_string();
        let subtype = params.get("subtype").and_then(|v| v.as_i64()).map(|v| v as i32);
        let ext = params.get("ext").and_then(|v| v.as_str()).map(|s| s.to_string());

        let account = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;

        // Verify group exists
        let _group = signal.get_group(&group_id).await?
            .ok_or_else(|| anyhow::anyhow!("Group not found: {}", group_id))?;

        let my_id_pubkey = account.nostr_pubkey_hex();

        // Build GroupMessage
        let gm = GroupMessage {
            message: text.clone(),
            pubkey: group_id.clone(),
            sig: None,
            subtype,
            ext,
        };

        // Wrap in KeychatMessage
        let km = KeychatMessage {
            msg_type: event_kinds::GROUP_SEND_TO_ALL_MESSAGE,
            c: message_type::GROUP.to_string(),
            msg: Some(serde_json::to_string(&gm)?),
            name: None,
            data: None,
        };
        let km_json = serde_json::to_string(&km)?;

        // Get all members except self
        let members = signal.get_group_members(&group_id).await?;
        let mut sent_count = 0;
        let mut event_ids = Vec::new();
        let mut errors = Vec::new();
        let mut member_rotations: Vec<serde_json::Value> = Vec::new();

        for (member_pubkey, _name, _is_admin) in &members {
            if member_pubkey == &my_id_pubkey {
                continue;
            }

            // Check if we have a peer session with this member (fallback to DB)
            if self.peers.get(member_pubkey).is_none() {
                let maybe_peer = if let Some(sig) = self.signal.as_ref() {
                    if let Ok(mappings) = sig.get_all_peer_mappings_full().await {
                        mappings.iter()
                            .find(|m| m.0 == *member_pubkey)
                            .map(|m| PeerSession {
                                nostr_pubkey: m.0.clone(),
                                curve25519_pk_hex: m.1.clone(),
                                device_id: m.2 as u32,
                                onetimekey: m.6.clone().filter(|s| !s.is_empty()),
                            })
                    } else { None }
                } else { None };
                if let Some(restored) = maybe_peer {
                    log::info!("Loaded group member {} from DB peer_mapping for group send", member_pubkey);
                    self.peers.insert(member_pubkey.clone(), restored);
                }
            }
            if self.peers.get(member_pubkey).is_none() {
                log::warn!("No peer session for group member {}, skipping", member_pubkey);
                errors.push(format!("No session: {}", member_pubkey));
                continue;
            }

            // Send using the existing send_message logic
            let send_params = serde_json::json!({
                "to": member_pubkey,
                "text": km_json,
            });
            match self.handle_send_message(send_params).await {
                Ok(result) => {
                    if let Some(eid) = result.get("event_id").and_then(|v| v.as_str()) {
                        event_ids.push(eid.to_string());
                    }
                    if let Some(nra) = result.get("new_receiving_address").and_then(|v| v.as_str()) {
                        member_rotations.push(serde_json::json!({
                            "member": member_pubkey,
                            "new_receiving_address": nra,
                        }));
                    }
                    sent_count += 1;
                }
                Err(e) => {
                    log::error!("Failed to send group message to {}: {}", member_pubkey, e);
                    errors.push(format!("{}: {}", member_pubkey, e));
                }
            }
        }

        log::info!("Sent group message to {}/{} members in group {}", sent_count, members.len() - 1, group_id);
        Ok(serde_json::json!({
            "sent": true,
            "group_id": group_id,
            "sent_count": sent_count,
            "total_members": members.len() - 1,
            "event_ids": event_ids,
            "errors": errors,
            "member_rotations": member_rotations,
        }))
    }

    /// Update group name.
    async fn handle_update_group_name(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'group_id' required"))?;
        let name = params.get("name").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'name' required"))?;
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        signal.update_group_name(group_id, name).await?;
        Ok(serde_json::json!({"updated": true}))
    }

    /// Update group status (enabled/disabled).
    async fn handle_update_group_status(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'group_id' required"))?;
        let status = params.get("status").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'status' required"))?;
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        signal.update_group_status(group_id, status).await?;
        Ok(serde_json::json!({"updated": true}))
    }

    /// Delete a group.
    async fn handle_delete_group(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'group_id' required"))?;
        let signal = self.signal.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Signal not initialized"))?;
        signal.delete_group(group_id).await?;
        Ok(serde_json::json!({"deleted": true}))
    }

    // -----------------------------------------------------------------------
    // MLS (large group)
    // -----------------------------------------------------------------------

    /// Initialize MLS for the current identity.
    /// Params: { db_path?: string }
    async fn handle_mls_init(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;
        let nostr_id = account.nostr_pubkey_hex();

        let db_path = params.get("db_path").and_then(|v| v.as_str())
            .unwrap_or("~/.openclaw/keychat-mls.db");
        let db_path = shellexpand::tilde(db_path).to_string();

        let mut mls = self.mls.take().unwrap_or_else(|| MlsManager::new(&db_path));
        mls.init_identity(&nostr_id).await?;
        self.mls = Some(mls);

        log::info!("MLS initialized for {}", nostr_id);
        Ok(serde_json::json!({"initialized": true, "nostr_id": nostr_id}))
    }

    /// Create a key package for publishing.
    async fn handle_mls_create_key_package(&mut self, _params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;
        let result = mls.create_key_package(&nostr_id)?;
        mls.save_after_key_package(&nostr_id).await?;
        Ok(serde_json::to_value(result)?)
    }

    /// Create an MLS group.
    /// Params: { group_id: string, name: string, description?: string, admin_pubkeys?: [string], relays?: [string], status?: string }
    async fn handle_mls_create_group(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;
        let name = params.get("name").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("name required"))?;
        let description = params.get("description").and_then(|v| v.as_str()).unwrap_or("");
        let admin_pubkeys: Vec<String> = params.get("admin_pubkeys")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_else(|| vec![nostr_id.clone()]);
        let relays: Vec<String> = params.get("relays")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let status = params.get("status").and_then(|v| v.as_str()).unwrap_or("enabled");

        mls.create_group(&nostr_id, group_id, name, description, admin_pubkeys, relays, status).await?;
        Ok(serde_json::json!({"created": true, "group_id": group_id}))
    }

    /// Add members to an MLS group.
    /// Params: { group_id: string, key_packages: [string] (hex) }
    async fn handle_mls_add_members(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;
        let key_packages: Vec<String> = params.get("key_packages")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow::anyhow!("key_packages required"))?;

        let result = mls.add_members(&nostr_id, group_id, key_packages)?;
        Ok(serde_json::to_value(result)?)
    }

    /// Merge pending commit after add_members or other operations.
    /// Params: { group_id: string }
    async fn handle_mls_self_commit(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;

        mls.self_commit(&nostr_id, group_id)?;
        Ok(serde_json::json!({"committed": true}))
    }

    /// Join a group from a Welcome message.
    /// Params: { group_id: string, welcome: string (base64) }
    async fn handle_mls_join_group(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;
        let welcome_b64 = params.get("welcome").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("welcome (base64) required"))?;
        let welcome_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            welcome_b64,
        )?;

        let info = mls.join_group(&nostr_id, group_id, &welcome_bytes).await?;

        // Auto-subscribe to the group's listen key
        if let Some(transport) = &self.transport {
            transport.subscribe_additional_pubkeys(&[&info.listen_key]).await?;
            log::info!("Subscribed to MLS group listen key: {}", info.listen_key);
        }

        Ok(serde_json::to_value(info)?)
    }

    /// Encrypt a message for an MLS group.
    /// Params: { group_id: string, text: string }
    async fn handle_mls_create_message(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;
        let text = params.get("text").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("text required"))?;

        let result = mls.create_message(&nostr_id, group_id, text)?;
        Ok(serde_json::to_value(result)?)
    }

    /// Decrypt a received MLS group message.
    /// Params: { group_id: string, message: string }
    async fn handle_mls_decrypt_message(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;
        let message = params.get("message").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("message required"))?;

        let result = mls.decrypt_message(&nostr_id, group_id, message)?;
        Ok(serde_json::to_value(result)?)
    }

    /// Parse the type of an MLS message without consuming it.
    /// Params: { group_id: string, data: string }
    async fn handle_mls_parse_message_type(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_ref()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;
        let data = params.get("data").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("data required"))?;

        let msg_type = mls.parse_message_type(&nostr_id, group_id, data)?;
        Ok(serde_json::to_value(msg_type)?)
    }

    /// Process a commit message from another member.
    /// Params: { group_id: string, message: string }
    async fn handle_mls_process_commit(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;
        let message = params.get("message").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("message required"))?;

        let result = mls.process_commit(&nostr_id, group_id, message)?;

        // Resubscribe to the new listen key
        if let Some(transport) = &self.transport {
            transport.subscribe_additional_pubkeys(&[&result.listen_key]).await?;
            log::info!("Resubscribed to new MLS listen key: {}", result.listen_key);
        }

        Ok(serde_json::to_value(result)?)
    }

    /// Get the current listen key for an MLS group.
    /// Params: { group_id: string }
    async fn handle_mls_get_listen_key(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_ref()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;

        let listen_key = mls.get_listen_key(&nostr_id, group_id)?;
        Ok(serde_json::json!({"listen_key": listen_key}))
    }

    /// Get group info (name, members, etc.).
    /// Params: { group_id: string }
    async fn handle_mls_get_group_info(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_ref()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;

        let info = mls.get_group_info(&nostr_id, group_id)?;
        Ok(serde_json::to_value(info)?)
    }

    /// List all MLS groups.
    async fn handle_mls_get_groups(&self, _params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_ref()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let groups = mls.get_groups(&nostr_id)?;
        Ok(serde_json::json!({"groups": groups}))
    }

    /// Self-update key material in a group (sends greeting, etc.).
    /// Params: { group_id: string, extension?: object }
    async fn handle_mls_self_update(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;
        let extension = params.get("extension")
            .map(|v| serde_json::to_vec(v))
            .transpose()?
            .unwrap_or_default();

        let result = mls.self_update(&nostr_id, group_id, extension)?;
        Ok(serde_json::to_value(result)?)
    }

    /// Update group context extensions (name, description, etc.).
    /// Params: { group_id: string, name?: string, description?: string, admin_pubkeys?: [string], relays?: [string], status?: string }
    async fn handle_mls_update_group_extensions(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;
        let name = params.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
        let description = params.get("description").and_then(|v| v.as_str()).map(|s| s.to_string());
        let admin_pubkeys: Option<Vec<String>> = params.get("admin_pubkeys")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let relays: Option<Vec<String>> = params.get("relays")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let status = params.get("status").and_then(|v| v.as_str()).map(|s| s.to_string());

        let result = mls.update_group_context_extensions(
            &nostr_id, group_id, name, description, admin_pubkeys, relays, status,
        )?;
        Ok(serde_json::to_value(result)?)
    }

    /// Remove members from an MLS group.
    /// Params: { group_id: string, members: [string] (nostr pubkeys) }
    async fn handle_mls_remove_members(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;
        let members: Vec<String> = params.get("members")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow::anyhow!("members required"))?;

        let result = mls.remove_members(&nostr_id, group_id, members)?;
        Ok(serde_json::to_value(result)?)
    }

    /// Delete an MLS group.
    /// Params: { group_id: string }
    async fn handle_mls_delete_group(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;

        mls.delete_group(&nostr_id, group_id).await?;
        Ok(serde_json::json!({"deleted": true}))
    }

    /// Get sender of an encrypted message without consuming it.
    /// Params: { group_id: string, message: string }
    async fn handle_mls_get_sender(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_ref()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;
        let message = params.get("message").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("message required"))?;

        let sender = mls.get_sender(&nostr_id, group_id, message)?;
        Ok(serde_json::json!({"sender": sender}))
    }

    /// Get export secret keys for NIP-17 transport of MLS group messages.
    /// Params: { group_id: string }
    async fn handle_mls_get_export_secret_keys(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();
        let mls = self.mls.as_ref()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?;

        let keys = mls.get_export_secret_keys(&nostr_id, group_id)?;
        let listen_key = hex::encode(keys.public_key().xonly()?.serialize());
        Ok(serde_json::json!({
            "listen_key": listen_key,
            "secret_key_hex": keys.secret_key().to_secret_hex(),
        }))
    }

    /// Send a message to an MLS group via NIP-17 Gift Wrap.
    /// This is a convenience method: encrypt with MLS + publish to relay.
    /// Params: { group_id: string, text: string }
    async fn handle_mls_send_message(&mut self, params: serde_json::Value) -> Result<serde_json::Value> {
        let nostr_id = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?.nostr_pubkey_hex();

        let group_id = params.get("group_id").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("group_id required"))?.to_string();
        let text = params.get("text").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("text required"))?.to_string();

        // Step 1: MLS encrypt
        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;
        let result = mls.create_message(&nostr_id, &group_id, &text)?;

        // Step 2: Publish as kind:1059 to the listen key (same as Keychat app)
        let transport = self.transport.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected to relays"))?;

        let event_id = transport.send_mls_event(
            &result.listen_key,
            &result.encrypted_msg,
            None,
        ).await?;

        log::info!("Sent MLS group message to {} (event {})", group_id, event_id);
        Ok(serde_json::json!({
            "sent": true,
            "event_id": event_id,
            "listen_key": result.listen_key,
        }))
    }

    /// Publish pre-encrypted content (e.g., MLS commit) to a group's listen key.
    /// Params: { listen_key: string, content: string }
    async fn handle_mls_publish_to_group(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let listen_key = params.get("listen_key").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("listen_key required"))?;
        let content = params.get("content").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("content required"))?;

        let transport = self.transport.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected to relays"))?;

        let event_id = transport.send_mls_event(
            listen_key,
            content,
            None,
        ).await?;

        Ok(serde_json::json!({
            "event_id": event_id,
        }))
    }

    /// Create a KeyPackage, publish it as kind:10443, and return the result.
    /// This is the "generate + upload" flow. If a KeyPackage already exists on relay
    /// and is not expired, it can be skipped (handled by caller).
    async fn handle_mls_publish_key_package(&mut self, _params: serde_json::Value) -> Result<serde_json::Value> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account"))?;
        let nostr_id = account.nostr_pubkey_hex();
        let identity_keys = account.keys.clone();

        let mls = self.mls.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;
        let kp_result = mls.create_key_package(&nostr_id)?;
        mls.save_after_key_package(&nostr_id).await?;

        let transport = self.transport.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected to relays"))?;

        let event_id = transport.publish_key_package(&identity_keys, &kp_result.key_package).await?;

        log::info!("Published MLS KeyPackage (event {})", event_id);
        Ok(serde_json::json!({
            "event_id": event_id,
            "key_package": kp_result.key_package,
        }))
    }

    /// Fetch the latest KeyPackage for a pubkey from relays.
    /// Params: { pubkey: string }
    async fn handle_mls_fetch_key_package(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let pubkey = params.get("pubkey").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("pubkey required"))?;

        let transport = self.transport.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected to relays"))?;

        let kp = transport.fetch_key_package(pubkey).await?;
        Ok(serde_json::json!({
            "key_package": kp,
        }))
    }

    // -----------------------------------------------------------------------
    // Blossom auth (for media upload)
    // -----------------------------------------------------------------------

    /// Sign a kind:24242 Nostr event for Blossom server auth.
    /// Params: { content: string, tags: [[string]] }
    /// Returns: { event_json: string }
    async fn handle_sign_blossom_event(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        let account = self.account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No account initialized"))?;

        let content = params.get("content").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("'content' required"))?;
        let tags_value = params.get("tags")
            .ok_or_else(|| anyhow::anyhow!("'tags' required"))?;

        // Parse tags: [[string, string, ...], ...]
        let tags_arr = tags_value.as_array()
            .ok_or_else(|| anyhow::anyhow!("'tags' must be an array"))?;
        let mut tags = Vec::new();
        for tag_val in tags_arr {
            let tag_arr = tag_val.as_array()
                .ok_or_else(|| anyhow::anyhow!("each tag must be an array"))?;
            let tag_strings: Vec<String> = tag_arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            tags.push(nostr::Tag::parse(&tag_strings)?);
        }

        let event = nostr::EventBuilder::new(nostr::Kind::Custom(24242), content.to_string())
            .tags(tags)
            .sign(&account.keys)
            .await?;

        Ok(serde_json::json!({
            "event_json": event.as_json(),
        }))
    }

    /// Check relay health and reconnect/resubscribe if any relay is disconnected.
    async fn handle_relay_health_check(&self) -> Result<serde_json::Value> {
        let transport = self.transport.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not connected"))?;
        let reconnected = transport.check_relay_health().await?;
        Ok(serde_json::json!({
            "reconnected": reconnected,
        }))
    }
}

//! Signal Protocol manager — wraps keychat's signal-store for session management,
//! encryption, and decryption.

use anyhow::Result;
use nostr::hashes::{sha256, Hash};
use nostr::secp256k1::{self, Secp256k1};
use rand::rngs::OsRng;
use serde::Serialize;
use signal_store::libsignal_protocol::*;
use signal_store::{KeyChatSignalProtocolStore, LitePool};
use signal_store::sqlx::Row;
use std::collections::HashMap;
use std::time::SystemTime;

use crate::protocol::{KeychatAccount, QRUserModel};

/// Serializable pre-key bundle info for key exchange.
#[derive(Debug, Serialize)]
pub struct PrekeyBundleInfo {
    pub registration_id: u32,
    pub identity_key_hex: String,
    pub signed_prekey_id: u32,
    pub signed_prekey_public_hex: String,
    pub signed_prekey_signature_hex: String,
    pub prekey_id: u32,
    pub prekey_public_hex: String,
}

/// Encryption result with ratchet info.
pub struct EncryptResult {
    /// The ciphertext bytes (Signal protocol message serialized)
    pub ciphertext: Vec<u8>,
    /// New receiving address (derived from ratchet key pair), if rotated
    pub new_receiving_address: Option<String>,
    /// Message key hash (for deduplication)
    pub msg_key_hash: String,
    /// Previous alice addresses (for cleanup)
    pub alice_addrs: Option<Vec<String>>,
    /// Whether this is a pre-key message
    pub is_prekey: bool,
}

/// Decryption result.
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub msg_key_hash: String,
    pub alice_addrs: Option<Vec<String>>,
}

pub struct SignalManager {
    pool: LitePool,
    stores: HashMap<[u8; 33], KeyChatSignalProtocolStore>,
}

impl SignalManager {
    pub async fn new(db_path: &str) -> Result<Self> {
        if let Some(parent) = std::path::Path::new(db_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let pool = LitePool::open(db_path, Default::default()).await?;
        let mgr = Self {
            pool,
            stores: HashMap::new(),
        };
        mgr.ensure_peer_mapping_table().await?;
        mgr.ensure_address_peer_mapping_table().await?;
        mgr.ensure_processed_events_table().await?;
        mgr.ensure_group_tables().await?;
        mgr.prune_old_events(2000).await?;
        Ok(mgr)
    }

    /// Initialize the store for an account (public entry point).
    pub fn get_or_create_store_for(
        &mut self,
        account: &KeychatAccount,
    ) -> Result<()> {
        self.get_or_create_store(account)?;
        Ok(())
    }

    /// Get or create the Signal protocol store for an account.
    fn get_or_create_store(
        &mut self,
        account: &KeychatAccount,
    ) -> Result<&mut KeyChatSignalProtocolStore> {
        let (identity_key_bytes, private_key_bytes) = account.signal_identity_key_pair()?;
        self.get_or_create_store_for_keypair(&identity_key_bytes, &private_key_bytes)
    }

    /// Get or create a Signal store for an arbitrary keypair (ephemeral or account).
    fn get_or_create_store_for_keypair(
        &mut self,
        identity_key_bytes: &[u8; 33],
        private_key_bytes: &[u8; 32],
    ) -> Result<&mut KeyChatSignalProtocolStore> {
        if !self.stores.contains_key(identity_key_bytes) {
            let identity_key = IdentityKey::decode(identity_key_bytes)?;
            let private_key = PrivateKey::deserialize(private_key_bytes)?;
            let key_pair = IdentityKeyPair::new(identity_key, private_key);
            let reg_id = Self::registration_id_from_pubkey(identity_key_bytes);
            let store =
                KeyChatSignalProtocolStore::new(self.pool.clone(), key_pair, reg_id)?;
            self.stores.insert(*identity_key_bytes, store);
        }

        Ok(self.stores.get_mut(identity_key_bytes).unwrap())
    }

    /// Get an existing store by Signal public key hex (e.g. looked up from peer_mapping).
    pub fn get_store_by_signal_pubkey_hex(
        &mut self,
        signal_pubkey_hex: &str,
    ) -> Result<Option<&mut KeyChatSignalProtocolStore>> {
        let bytes = hex::decode(signal_pubkey_hex)?;
        let key: [u8; 33] = bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid signal pubkey length"))?;
        Ok(self.stores.get_mut(&key))
    }

    /// Derive a registration ID from the public key (same as keychat-app's getRegistrationId).
    fn registration_id_from_pubkey(pk: &[u8]) -> u32 {
        // Simple hash of first 4 bytes
        if pk.len() >= 4 {
            u32::from_le_bytes([pk[0], pk[1], pk[2], pk[3]])
        } else {
            1
        }
    }

    /// Generate a pre-key bundle for the account's own (fixed) Signal identity.
    /// Used when processing INCOMING hello requests.
    pub async fn generate_prekey_bundle(
        &mut self,
        account: &KeychatAccount,
    ) -> Result<PrekeyBundleInfo> {
        let (identity_key_bytes, private_key_bytes) = account.signal_identity_key_pair()?;
        self.generate_prekey_bundle_for_keypair(&identity_key_bytes, &private_key_bytes).await
    }

    /// Generate a pre-key bundle for an arbitrary Signal keypair.
    pub async fn generate_prekey_bundle_for_keypair(
        &mut self,
        identity_key_bytes: &[u8; 33],
        private_key_bytes: &[u8; 32],
    ) -> Result<PrekeyBundleInfo> {
        let store = self.get_or_create_store_for_keypair(identity_key_bytes, private_key_bytes)?;

        let identity_private = PrivateKey::deserialize(private_key_bytes)?;
        let (signed_id, signed_public, signed_sig, _signed_record) = store
            .signed_pre_key_store
            .generate_signed_key(identity_private)
            .await?;

        let (prekey_id, prekey_public, _prekey_record) =
            store.pre_key_store.generate_pre_key().await?;

        Ok(PrekeyBundleInfo {
            registration_id: Self::registration_id_from_pubkey(identity_key_bytes),
            identity_key_hex: hex::encode(identity_key_bytes),
            signed_prekey_id: signed_id,
            signed_prekey_public_hex: hex::encode(signed_public.serialize()),
            signed_prekey_signature_hex: hex::encode(&signed_sig),
            prekey_id,
            prekey_public_hex: hex::encode(prekey_public.serialize()),
        })
    }

    /// Generate a complete QRUserModel for a hello message using an EPHEMERAL Signal keypair.
    /// Each outgoing hello uses a fresh random Signal identity — this matches Keychat app behavior.
    /// Returns (QRUserModel, ephemeral_signal_pubkey_hex, ephemeral_signal_privkey_hex, onetimekey_hex).
    pub async fn generate_hello_bundle_ephemeral(
        &mut self,
        account: &KeychatAccount,
        name: &str,
    ) -> Result<(QRUserModel, String, String, String)> {
        // Generate fresh random Signal identity for this hello
        let (eph_pk, eph_sk) = KeychatAccount::generate_ephemeral_signal_keypair();
        let eph_pk_hex = hex::encode(&eph_pk);
        let eph_sk_hex = hex::encode(&eph_sk);

        let bundle = self.generate_prekey_bundle_for_keypair(&eph_pk, &eph_sk).await?;
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let nostr_id = account.nostr_pubkey_hex();

        let sign_content = KeychatAccount::get_sign_message(&nostr_id, &eph_pk_hex, time);
        let global_sign = account.schnorr_sign(&sign_content)?;

        // Generate a one-time receiving key so the peer can route their reply
        // (same approach as Keychat app: random Nostr keypair, pubkey as onetimekey)
        let otk_keys = nostr::Keys::generate();
        let onetimekey = otk_keys.public_key().to_hex();

        let model = QRUserModel {
            name: name.to_string(),
            pubkey: nostr_id,
            curve25519_pk_hex: eph_pk_hex.clone(),
            onetimekey: onetimekey.clone(),
            signed_id: bundle.signed_prekey_id,
            signed_public: bundle.signed_prekey_public_hex,
            signed_signature: bundle.signed_prekey_signature_hex,
            prekey_id: bundle.prekey_id,
            prekey_pubkey: bundle.prekey_public_hex,
            global_sign,
            relay: String::new(),
            time,
            avatar: None,
            lightning: None,
        };

        Ok((model, eph_pk_hex, eph_sk_hex, onetimekey))
    }

    /// Restore an ephemeral Signal store from saved keypair (used on startup).
    pub fn restore_ephemeral_store(
        &mut self,
        signal_pubkey_hex: &str,
        signal_privkey_hex: &str,
    ) -> Result<()> {
        if signal_pubkey_hex.is_empty() || signal_privkey_hex.is_empty() {
            return Ok(()); // No ephemeral key for this peer (legacy entry)
        }
        let pk_bytes: [u8; 33] = hex::decode(signal_pubkey_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signal pubkey length (got {} bytes, expected 33)", hex::decode(signal_pubkey_hex).map(|v| v.len()).unwrap_or(0)))?;
        let sk_bytes: [u8; 32] = hex::decode(signal_privkey_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signal privkey length"))?;
        self.get_or_create_store_for_keypair(&pk_bytes, &sk_bytes)?;
        Ok(())
    }

    /// Process a received pre-key bundle to establish a Signal session.
    /// This is called when we receive a hello message from a peer.
    pub async fn process_prekey_bundle_from_model(
        &mut self,
        account: &KeychatAccount,
        model: &QRUserModel,
        device_id: u32,
    ) -> Result<()> {
        let store = self.get_or_create_store(account)?;

        let remote_address = ProtocolAddress::new(model.curve25519_pk_hex.clone(), device_id.into());
        let identity_key = IdentityKey::decode(&hex::decode(&model.curve25519_pk_hex)?)?;
        let signed_prekey_public = PublicKey::deserialize(&hex::decode(&model.signed_public)?)?;
        let prekey_public = PublicKey::deserialize(&hex::decode(&model.prekey_pubkey)?)?;
        let reg_id = Self::registration_id_from_pubkey(&hex::decode(&model.curve25519_pk_hex)?);

        let bundle = PreKeyBundle::new(
            reg_id,
            device_id.into(),
            Some((model.prekey_id.into(), prekey_public)),
            model.signed_id.into(),
            signed_prekey_public,
            hex::decode(&model.signed_signature)?,
            identity_key,
        )?;

        let mut csprng = OsRng;
        process_prekey_bundle(
            &remote_address,
            &mut store.session_store,
            &mut store.identity_store,
            &bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        Ok(())
    }

    /// Process a received pre-key bundle from raw params (backward compat).
    pub async fn process_prekey_bundle(
        &mut self,
        account: &KeychatAccount,
        params: &serde_json::Value,
    ) -> Result<()> {
        let store = self.get_or_create_store(account)?;

        let remote_address_name = params
            .get("remote_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("remote_address required"))?;
        let device_id: u32 = params
            .get("device_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;
        let reg_id: u32 = params
            .get("registration_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;
        let identity_key_hex = params
            .get("identity_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("identity_key required"))?;
        let signed_prekey_id: u32 = params
            .get("signed_prekey_id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("signed_prekey_id required"))? as u32;
        let signed_prekey_public_hex = params
            .get("signed_prekey_public")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("signed_prekey_public required"))?;
        let signed_prekey_sig_hex = params
            .get("signed_prekey_signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("signed_prekey_signature required"))?;
        let prekey_id: u32 = params
            .get("prekey_id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("prekey_id required"))? as u32;
        let prekey_public_hex = params
            .get("prekey_public")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("prekey_public required"))?;

        let remote_address =
            ProtocolAddress::new(remote_address_name.to_string(), device_id.into());
        let identity_key = IdentityKey::decode(&hex::decode(identity_key_hex)?)?;
        let signed_prekey_public = PublicKey::deserialize(&hex::decode(signed_prekey_public_hex)?)?;
        let prekey_public = PublicKey::deserialize(&hex::decode(prekey_public_hex)?)?;

        let bundle = PreKeyBundle::new(
            reg_id,
            device_id.into(),
            Some((prekey_id.into(), prekey_public)),
            signed_prekey_id.into(),
            signed_prekey_public,
            hex::decode(signed_prekey_sig_hex)?,
            identity_key,
        )?;

        let mut csprng = OsRng;
        process_prekey_bundle(
            &remote_address,
            &mut store.session_store,
            &mut store.identity_store,
            &bundle,
            SystemTime::now(),
            &mut csprng,
        )
        .await?;

        Ok(())
    }

    /// Encrypt a plaintext message using Signal Protocol.
    /// Returns EncryptResult with ciphertext, new receiving address, and msg key hash.
    /// Encrypt using a specific local Signal store (looked up by our local signal pubkey hex).
    /// Falls back to account's default store if local_signal_pubkey is None.
    pub async fn encrypt_with_store(
        &mut self,
        account: &KeychatAccount,
        local_signal_pubkey_hex: Option<&str>,
        to_curve25519_pubkey: &str,
        plaintext: &str,
        device_id: u32,
    ) -> Result<EncryptResult> {
        let store = if let Some(lsk) = local_signal_pubkey_hex.filter(|s| !s.is_empty()) {
            let bytes = hex::decode(lsk)?;
            let key: [u8; 33] = bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid local signal pubkey len"))?;
            self.stores.get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("No Signal store for local key {}", lsk))?
        } else {
            self.get_or_create_store(account)?
        };
        let remote_address =
            ProtocolAddress::new(to_curve25519_pubkey.to_string(), device_id.into());

        let (ciphertext_msg, new_receiving, msg_key_hash, alice_addrs) = message_encrypt(
            plaintext.as_bytes(),
            &remote_address,
            &mut store.session_store,
            &mut store.identity_store,
            SystemTime::now(),
            None,
        )
        .await?;

        let is_prekey = matches!(
            ciphertext_msg.message_type(),
            CiphertextMessageType::PreKey
        );

        Ok(EncryptResult {
            ciphertext: ciphertext_msg.serialize().to_vec(),
            new_receiving_address: new_receiving,
            msg_key_hash,
            alice_addrs,
            is_prekey,
        })
    }

    pub async fn encrypt(
        &mut self,
        account: &KeychatAccount,
        to_curve25519_pubkey: &str,
        plaintext: &str,
        device_id: u32,
    ) -> Result<EncryptResult> {
        let store = self.get_or_create_store(account)?;
        let remote_address =
            ProtocolAddress::new(to_curve25519_pubkey.to_string(), device_id.into());

        let (ciphertext_msg, new_receiving, msg_key_hash, alice_addrs) = message_encrypt(
            plaintext.as_bytes(),
            &remote_address,
            &mut store.session_store,
            &mut store.identity_store,
            SystemTime::now(),
            None,
        )
        .await?;

        let is_prekey = matches!(
            ciphertext_msg.message_type(),
            CiphertextMessageType::PreKey
        );

        Ok(EncryptResult {
            ciphertext: ciphertext_msg.serialize().to_vec(),
            new_receiving_address: new_receiving,
            msg_key_hash,
            alice_addrs,
            is_prekey,
        })
    }

    /// Decrypt using a specific local Signal store.
    pub async fn decrypt_with_store(
        &mut self,
        account: &KeychatAccount,
        local_signal_pubkey_hex: Option<&str>,
        from_curve25519_pubkey: &str,
        ciphertext_bytes: &[u8],
        device_id: u32,
        room_id: u32,
        is_prekey: bool,
    ) -> Result<DecryptResult> {
        let store = if let Some(lsk) = local_signal_pubkey_hex.filter(|s| !s.is_empty()) {
            let bytes = hex::decode(lsk)?;
            let key: [u8; 33] = bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid local signal pubkey len"))?;
            self.stores.get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("No Signal store for local key {}", lsk))?
        } else {
            self.get_or_create_store(account)?
        };
        let remote_address =
            ProtocolAddress::new(from_curve25519_pubkey.to_string(), device_id.into());

        let ciphertext_msg = if is_prekey {
            CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(ciphertext_bytes)?)
        } else {
            CiphertextMessage::SignalMessage(SignalMessage::try_from(ciphertext_bytes)?)
        };

        let mut csprng = OsRng;
        let (plaintext, msg_key_hash, alice_addrs) = message_decrypt(
            &ciphertext_msg,
            &remote_address,
            &mut store.session_store,
            &mut store.identity_store,
            &mut store.pre_key_store,
            &store.signed_pre_key_store,
            &mut store.kyber_pre_key_store,
            &mut store.ratchet_key_store,
            room_id,
            &mut csprng,
        )
        .await?;

        Ok(DecryptResult {
            plaintext,
            msg_key_hash,
            alice_addrs,
        })
    }

    /// Decrypt a Signal Protocol message.
    pub async fn decrypt(
        &mut self,
        account: &KeychatAccount,
        from_curve25519_pubkey: &str,
        ciphertext_bytes: &[u8],
        device_id: u32,
        room_id: u32,
        is_prekey: bool,
    ) -> Result<DecryptResult> {
        let store = self.get_or_create_store(account)?;
        let remote_address =
            ProtocolAddress::new(from_curve25519_pubkey.to_string(), device_id.into());

        let ciphertext_msg = if is_prekey {
            CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(ciphertext_bytes)?)
        } else {
            CiphertextMessage::SignalMessage(SignalMessage::try_from(ciphertext_bytes)?)
        };

        let mut csprng = OsRng;
        let (plaintext, msg_key_hash, alice_addrs) = message_decrypt(
            &ciphertext_msg,
            &remote_address,
            &mut store.session_store,
            &mut store.identity_store,
            &mut store.pre_key_store,
            &store.signed_pre_key_store,
            &mut store.kyber_pre_key_store,
            &mut store.ratchet_key_store,
            room_id,
            &mut csprng,
        )
        .await?;

        Ok(DecryptResult {
            plaintext,
            msg_key_hash,
            alice_addrs,
        })
    }

    /// Get session info for a peer (for determining send-to address).
    pub async fn get_session(
        &self,
        account: &KeychatAccount,
        curve25519_pubkey: &str,
        device_id: u32,
    ) -> Result<Option<signal_store::SignalSession>> {
        let (identity_key_bytes, _) = account.signal_identity_key_pair()?;
        self.get_session_by_store_key(&identity_key_bytes, curve25519_pubkey, device_id).await
    }

    /// Get session using a specific local Signal store key.
    pub async fn get_session_by_local_key(
        &self,
        local_signal_pubkey_hex: &str,
        peer_signal_pubkey: &str,
        device_id: u32,
    ) -> Result<Option<signal_store::SignalSession>> {
        let bytes = hex::decode(local_signal_pubkey_hex)?;
        let key: [u8; 33] = bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid local signal pubkey len"))?;
        self.get_session_by_store_key(&key, peer_signal_pubkey, device_id).await
    }

    async fn get_session_by_store_key(
        &self,
        store_key: &[u8; 33],
        curve25519_pubkey: &str,
        device_id: u32,
    ) -> Result<Option<signal_store::SignalSession>> {
        let store = self
            .stores
            .get(store_key)
            .ok_or_else(|| anyhow::anyhow!("Store not initialized"))?;

        let session = store
            .session_store
            .get_session(curve25519_pubkey, &device_id.to_string())
            .await
            .map_err(|e| anyhow::anyhow!("get_session: {}", e))?;
        Ok(session)
    }

    /// Get the bob_address from a Signal session (for computing peer's receiving address).
    pub async fn get_bob_address(
        &self,
        account: &KeychatAccount,
        curve25519_pubkey: &str,
        device_id: u32,
    ) -> Result<Option<String>> {
        let session = self.get_session(account, curve25519_pubkey, device_id).await?;
        Ok(session.and_then(|s| s.bob_address))
    }

    /// Get bob_address using a specific local Signal store.
    pub async fn get_bob_address_by_local_key(
        &self,
        local_signal_pubkey_hex: &str,
        peer_signal_pubkey: &str,
        device_id: u32,
    ) -> Result<Option<String>> {
        let session = self.get_session_by_local_key(local_signal_pubkey_hex, peer_signal_pubkey, device_id).await?;
        Ok(session.and_then(|s| s.bob_address))
    }

    /// Get all receiving addresses (alice_addresses) from all sessions.
    /// Returns Vec<(session_address, seed_key, nostr_pubkey)> so caller can map to peer.
    pub async fn get_all_receiving_addresses(
        &self,
        account: &KeychatAccount,
    ) -> Result<Vec<(String, String, String)>> {
        // Query directly from DB to get session address + aliceAddresses together
        let rows: Vec<(String, String)> = signal_store::sqlx::query_as(
            "SELECT address, aliceAddresses FROM session WHERE aliceAddresses IS NOT NULL AND aliceAddresses != ''"
        )
        .fetch_all(self.pool.database())
        .await?;

        let mut result = Vec::new();
        const KEEP_PER_SESSION: usize = 3;
        for (session_addr, addrs_csv) in &rows {
            let seeds: Vec<&str> = addrs_csv.split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            // Keep only the last N (most recent) seeds per session
            let start = seeds.len().saturating_sub(KEEP_PER_SESSION);
            for seed_key in &seeds[start..] {
                // seed_key format: "private_hex-public_hex"
                match generate_seed_from_ratchetkey_pair(seed_key) {
                    Ok(nostr_pubkey) => {
                        result.push((session_addr.clone(), seed_key.to_string(), nostr_pubkey));
                    }
                    Err(e) => {
                        log::warn!("Failed to derive address from seed {}: {}", seed_key, e);
                    }
                }
            }
        }
        Ok(result)
    }

    /// Get all peer sessions from the DB.
    /// Returns Vec<(signal_pubkey, device_id_str)>
    pub async fn get_all_sessions_info(
        &self,
        account: &KeychatAccount,
    ) -> Result<Vec<(String, String)>> {
        let (identity_key_bytes, _) = account.signal_identity_key_pair()?;
        let store = self
            .stores
            .get(&identity_key_bytes)
            .ok_or_else(|| anyhow::anyhow!("Store not initialized"))?;

        // Default table name from signal-store
        let sql = "SELECT address, device FROM session ORDER BY id";
        let rows = signal_store::sqlx::query(sql)
            .fetch_all(self.pool.database())
            .await?;

        let mut result = Vec::new();
        for row in &rows {
            let address: String = row.get::<String, _>(0);
            let device: i64 = row.get::<i64, _>(1);
            result.push((address.to_string(), device.to_string()));
        }
        let _ = store; // suppress unused warning
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Peer mapping persistence
    // -----------------------------------------------------------------------

    async fn ensure_peer_mapping_table(&self) -> Result<()> {
        signal_store::sqlx::query(
            "CREATE TABLE IF NOT EXISTS peer_mapping (
                nostr_pubkey TEXT PRIMARY KEY,
                signal_pubkey TEXT NOT NULL,
                device_id INTEGER NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            )"
        )
        .execute(self.pool.database())
        .await?;
        // Add local_signal columns if missing (migration for existing DBs)
        let _ = signal_store::sqlx::query(
            "ALTER TABLE peer_mapping ADD COLUMN local_signal_pubkey TEXT"
        ).execute(self.pool.database()).await;
        let _ = signal_store::sqlx::query(
            "ALTER TABLE peer_mapping ADD COLUMN local_signal_privkey TEXT"
        ).execute(self.pool.database()).await;
        let _ = signal_store::sqlx::query(
            "ALTER TABLE peer_mapping ADD COLUMN signed_prekey_id INTEGER"
        ).execute(self.pool.database()).await;
        let _ = signal_store::sqlx::query(
            "ALTER TABLE peer_mapping ADD COLUMN onetimekey TEXT"
        ).execute(self.pool.database()).await;
        Ok(())
    }

    pub async fn save_peer_mapping(
        &self,
        nostr_pubkey: &str,
        signal_pubkey: &str,
        device_id: u32,
        name: &str,
    ) -> Result<()> {
        // Preserve any previously saved local (ephemeral) Signal keypair for this peer.
        // This avoids wiping the local store mapping when TS updates only remote metadata.
        let existing = signal_store::sqlx::query(
            "SELECT local_signal_pubkey, local_signal_privkey FROM peer_mapping WHERE nostr_pubkey = ?"
        )
        .bind(nostr_pubkey)
        .fetch_optional(self.pool.database())
        .await?;

        let (local_pk, local_sk) = if let Some(row) = existing {
            use signal_store::sqlx::Row;
            (
                row.try_get::<String, _>(0).ok().filter(|s| !s.is_empty()),
                row.try_get::<String, _>(1).ok().filter(|s| !s.is_empty()),
            )
        } else {
            (None, None)
        };

        self.save_peer_mapping_full(
            nostr_pubkey,
            signal_pubkey,
            device_id,
            name,
            local_pk.as_deref(),
            local_sk.as_deref(),
        )
        .await
    }

    /// Save peer mapping with optional local (ephemeral) Signal keypair.
    pub async fn save_peer_mapping_full(
        &self,
        nostr_pubkey: &str,
        signal_pubkey: &str,
        device_id: u32,
        name: &str,
        local_signal_pubkey: Option<&str>,
        local_signal_privkey: Option<&str>,
    ) -> Result<()> {
        self.save_peer_mapping_full_with_spk(
            nostr_pubkey, signal_pubkey, device_id, name,
            local_signal_pubkey, local_signal_privkey, None,
        ).await
    }

    pub async fn save_peer_mapping_full_with_spk(
        &self,
        nostr_pubkey: &str,
        signal_pubkey: &str,
        device_id: u32,
        name: &str,
        local_signal_pubkey: Option<&str>,
        local_signal_privkey: Option<&str>,
        signed_prekey_id: Option<u32>,
    ) -> Result<()> {
        self.save_peer_mapping_full_with_spk_otk(
            nostr_pubkey, signal_pubkey, device_id, name,
            local_signal_pubkey, local_signal_privkey, signed_prekey_id, None,
        ).await
    }

    pub async fn save_peer_mapping_full_with_spk_otk(
        &self,
        nostr_pubkey: &str,
        signal_pubkey: &str,
        device_id: u32,
        name: &str,
        local_signal_pubkey: Option<&str>,
        local_signal_privkey: Option<&str>,
        signed_prekey_id: Option<u32>,
        onetimekey: Option<&str>,
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        signal_store::sqlx::query(
            "INSERT OR REPLACE INTO peer_mapping (nostr_pubkey, signal_pubkey, device_id, name, created_at, local_signal_pubkey, local_signal_privkey, signed_prekey_id, onetimekey) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(nostr_pubkey)
        .bind(signal_pubkey)
        .bind(device_id as i64)
        .bind(name)
        .bind(now)
        .bind(local_signal_pubkey)
        .bind(local_signal_privkey)
        .bind(signed_prekey_id.map(|id| id as i64))
        .bind(onetimekey)
        .execute(self.pool.database())
        .await?;
        Ok(())
    }

    /// Look up peer nostr pubkey by signed_prekey_id (used to identify PreKey message sender).
    pub async fn lookup_peer_by_signed_prekey_id(&self, spk_id: u32) -> Result<Option<String>> {
        let row = signal_store::sqlx::query(
            "SELECT nostr_pubkey FROM peer_mapping WHERE signed_prekey_id = ? LIMIT 1"
        )
        .bind(spk_id as i64)
        .fetch_optional(self.pool.database())
        .await?;
        Ok(row.map(|r| {
            use signal_store::sqlx::Row;
            r.get::<String, _>(0)
        }))
    }

    /// Clear sensitive PreKey material after session establishment.
    /// Keeps nostr_pubkey ↔ signal_pubkey mapping for routing.
    pub async fn clear_prekey_material(&self, nostr_pubkey: &str) -> Result<()> {
        signal_store::sqlx::query(
            "UPDATE peer_mapping SET local_signal_pubkey = NULL, local_signal_privkey = NULL, signed_prekey_id = NULL WHERE nostr_pubkey = ?"
        )
        .bind(nostr_pubkey)
        .execute(self.pool.database())
        .await?;
        log::info!("Cleared PreKey material for peer {}", &nostr_pubkey[..16.min(nostr_pubkey.len())]);
        Ok(())
    }

    /// Get all peer mappings including local signal keys.
    /// Returns: Vec<(nostr_pubkey, signal_pubkey, device_id, name, local_signal_pubkey, local_signal_privkey)>
    pub async fn get_all_peer_mappings(&self) -> Result<Vec<(String, String, i64, String)>> {
        let full = self.get_all_peer_mappings_full().await?;
        Ok(full.into_iter().map(|(n, s, d, name, _, _, _)| (n, s, d, name)).collect())
    }

    /// Get all peer mappings with local signal key info.
    /// Returns (nostr_pubkey, signal_pubkey, device_id, name, local_signal_pubkey, local_signal_privkey, onetimekey).
    pub async fn get_all_peer_mappings_full(&self) -> Result<Vec<(String, String, i64, String, Option<String>, Option<String>, Option<String>)>> {
        let rows = signal_store::sqlx::query(
            "SELECT nostr_pubkey, signal_pubkey, device_id, name, local_signal_pubkey, local_signal_privkey, onetimekey FROM peer_mapping ORDER BY created_at"
        )
        .fetch_all(self.pool.database())
        .await?;
        let mut result = Vec::new();
        for row in &rows {
            let nostr_pk: String = row.get::<String, _>(0);
            let signal_pk: String = row.get::<String, _>(1);
            let device_id: i64 = row.get::<i64, _>(2);
            let name: String = row.get::<String, _>(3);
            let local_sig_pk: Option<String> = row.try_get::<String, _>(4).ok();
            let local_sig_sk: Option<String> = row.try_get::<String, _>(5).ok();
            let otk: Option<String> = row.try_get::<String, _>(6).ok();
            result.push((nostr_pk, signal_pk, device_id, name, local_sig_pk, local_sig_sk, otk));
        }
        Ok(result)
    }

    /// Clear onetimekey from DB after it's been used (one-time use).
    pub async fn clear_onetimekey(&self, nostr_pubkey: &str) -> Result<()> {
        signal_store::sqlx::query("UPDATE peer_mapping SET onetimekey = NULL WHERE nostr_pubkey = ?")
            .bind(nostr_pubkey)
            .execute(self.pool.database())
            .await?;
        Ok(())
    }

    pub async fn delete_peer_mapping(&self, nostr_pubkey: &str) -> Result<()> {
        signal_store::sqlx::query("DELETE FROM peer_mapping WHERE nostr_pubkey = ?")
            .bind(nostr_pubkey)
            .execute(self.pool.database())
            .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Address-to-peer mapping persistence
    // -----------------------------------------------------------------------

    async fn ensure_address_peer_mapping_table(&self) -> Result<()> {
        signal_store::sqlx::query(
            "CREATE TABLE IF NOT EXISTS address_peer_mapping (
                address TEXT PRIMARY KEY,
                peer_nostr_pubkey TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )"
        )
        .execute(self.pool.database())
        .await?;
        Ok(())
    }

    pub async fn save_address_mapping(&self, address: &str, peer_nostr_pubkey: &str) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        signal_store::sqlx::query(
            "INSERT OR REPLACE INTO address_peer_mapping (address, peer_nostr_pubkey, created_at) VALUES (?, ?, ?)"
        )
        .bind(address)
        .bind(peer_nostr_pubkey)
        .bind(now)
        .execute(self.pool.database())
        .await?;
        Ok(())
    }

    pub async fn get_all_address_mappings(&self) -> Result<Vec<(String, String)>> {
        let rows = signal_store::sqlx::query(
            "SELECT address, peer_nostr_pubkey FROM address_peer_mapping ORDER BY created_at"
        )
        .fetch_all(self.pool.database())
        .await?;
        let mut result = Vec::new();
        for row in &rows {
            let address: String = row.get::<String, _>(0);
            let peer: String = row.get::<String, _>(1);
            result.push((address, peer));
        }
        Ok(result)
    }

    pub async fn delete_address_mapping(&self, address: &str) -> Result<()> {
        signal_store::sqlx::query("DELETE FROM address_peer_mapping WHERE address = ?")
            .bind(address)
            .execute(self.pool.database())
            .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Processed events persistence
    // -----------------------------------------------------------------------

    async fn ensure_processed_events_table(&self) -> Result<()> {
        signal_store::sqlx::query(
            "CREATE TABLE IF NOT EXISTS processed_events (
                event_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL DEFAULT 0,
                processed_at INTEGER NOT NULL DEFAULT 0
            )"
        )
        .execute(self.pool.database())
        .await?;
        // Migration: add created_at column if missing (existing DBs)
        let _ = signal_store::sqlx::query(
            "ALTER TABLE processed_events ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0"
        )
        .execute(self.pool.database())
        .await;
        // Separate KV table for subscription watermark (like Keychat app's lastMessageAt)
        signal_store::sqlx::query(
            "CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            )"
        )
        .execute(self.pool.database())
        .await?;
        Ok(())
    }

    pub async fn mark_event_processed(&self, event_id: &str, created_at: Option<u64>) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let event_created_at = created_at.unwrap_or(0) as i64;
        signal_store::sqlx::query(
            "INSERT OR IGNORE INTO processed_events (event_id, created_at, processed_at) VALUES (?, ?, ?)"
        )
        .bind(event_id)
        .bind(event_created_at)
        .bind(now)
        .execute(self.pool.database())
        .await?;

        // Update subscription watermark: only advance forward, like Keychat app.
        // Uses event's created_at (not processing time).
        if event_created_at > 0 {
            let current: Option<(i64,)> = signal_store::sqlx::query_as(
                "SELECT value FROM kv_store WHERE key = 'last_seen'"
            )
            .fetch_optional(self.pool.database())
            .await?;
            let current_val = current.map(|(v,)| v).unwrap_or(0);
            if event_created_at > current_val {
                signal_store::sqlx::query(
                    "INSERT OR REPLACE INTO kv_store (key, value) VALUES ('last_seen', ?)"
                )
                .bind(event_created_at)
                .execute(self.pool.database())
                .await?;
            }
        }
        Ok(())
    }

    pub async fn is_event_processed(&self, event_id: &str) -> Result<bool> {
        let row = signal_store::sqlx::query(
            "SELECT 1 FROM processed_events WHERE event_id = ?"
        )
        .bind(event_id)
        .fetch_optional(self.pool.database())
        .await?;
        Ok(row.is_some())
    }

    /// Get subscription start time, mirroring Keychat app logic:
    /// last_seen (max created_at of processed events) minus 3 minutes buffer.
    /// This ensures out-of-order messages are not skipped; duplicates are
    /// filtered by is_event_processed().
    pub async fn last_processed_event_time(&self) -> Result<Option<u64>> {
        let row: Option<(i64,)> = signal_store::sqlx::query_as(
            "SELECT value FROM kv_store WHERE key = 'last_seen'"
        )
        .fetch_optional(self.pool.database())
        .await?;
        Ok(row.and_then(|(ts,)| {
            if ts > 0 {
                // Subtract 3 minutes buffer (like Keychat app)
                Some(ts.saturating_sub(180) as u64)
            } else {
                None
            }
        }))
    }

    pub async fn prune_old_events(&self, keep_count: i64) -> Result<()> {
        signal_store::sqlx::query(
            "DELETE FROM processed_events WHERE event_id NOT IN (SELECT event_id FROM processed_events ORDER BY processed_at DESC LIMIT ?)"
        )
        .bind(keep_count)
        .execute(self.pool.database())
        .await?;
        Ok(())
    }

    /// Delete a Signal session for a peer.
    pub async fn delete_session(
        &mut self,
        account: &KeychatAccount,
        signal_pubkey: &str,
        device_id: Option<u32>,
    ) -> Result<()> {
        let _ = self.get_or_create_store(account)?;
        if let Some(did) = device_id {
            signal_store::sqlx::query("DELETE FROM session WHERE address = ? AND device = ?")
                .bind(signal_pubkey)
                .bind(did as i64)
                .execute(self.pool.database())
                .await?;
        } else {
            signal_store::sqlx::query("DELETE FROM session WHERE address = ?")
                .bind(signal_pubkey)
                .execute(self.pool.database())
                .await?;
        }
        log::info!("Deleted session for {} (device: {:?})", signal_pubkey, device_id);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Group tables (small group / sendAll)
    // -----------------------------------------------------------------------

    async fn ensure_group_tables(&self) -> Result<()> {
        signal_store::sqlx::query(
            "CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                group_type TEXT NOT NULL DEFAULT 'sendAll',
                my_id_pubkey TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'enabled',
                created_at INTEGER NOT NULL
            )"
        )
        .execute(self.pool.database())
        .await?;

        signal_store::sqlx::query(
            "CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL,
                id_pubkey TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                is_admin INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'invited',
                created_at INTEGER NOT NULL,
                PRIMARY KEY (group_id, id_pubkey)
            )"
        )
        .execute(self.pool.database())
        .await?;
        Ok(())
    }

    pub async fn create_group(
        &self,
        group_id: &str,
        name: &str,
        my_id_pubkey: &str,
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        signal_store::sqlx::query(
            "INSERT OR REPLACE INTO groups (group_id, name, group_type, my_id_pubkey, version, status, created_at) VALUES (?, ?, 'sendAll', ?, ?, 'enabled', ?)"
        )
        .bind(group_id)
        .bind(name)
        .bind(my_id_pubkey)
        .bind(now)
        .bind(now)
        .execute(self.pool.database())
        .await?;
        Ok(())
    }

    pub async fn get_group(&self, group_id: &str) -> Result<Option<(String, String, String, String, i64)>> {
        let row = signal_store::sqlx::query(
            "SELECT group_id, name, my_id_pubkey, status, version FROM groups WHERE group_id = ?"
        )
        .bind(group_id)
        .fetch_optional(self.pool.database())
        .await?;
        Ok(row.map(|r| {
            (
                r.get::<String, _>(0),
                r.get::<String, _>(1),
                r.get::<String, _>(2),
                r.get::<String, _>(3),
                r.get::<i64, _>(4),
            )
        }))
    }

    pub async fn get_all_groups(&self) -> Result<Vec<(String, String, String, String, i64)>> {
        let rows = signal_store::sqlx::query(
            "SELECT group_id, name, my_id_pubkey, status, version FROM groups WHERE status = 'enabled' ORDER BY created_at"
        )
        .fetch_all(self.pool.database())
        .await?;
        Ok(rows.iter().map(|r| {
            (
                r.get::<String, _>(0),
                r.get::<String, _>(1),
                r.get::<String, _>(2),
                r.get::<String, _>(3),
                r.get::<i64, _>(4),
            )
        }).collect())
    }

    pub async fn update_group_name(&self, group_id: &str, name: &str) -> Result<()> {
        signal_store::sqlx::query("UPDATE groups SET name = ? WHERE group_id = ?")
            .bind(name)
            .bind(group_id)
            .execute(self.pool.database())
            .await?;
        Ok(())
    }

    pub async fn update_group_status(&self, group_id: &str, status: &str) -> Result<()> {
        signal_store::sqlx::query("UPDATE groups SET status = ? WHERE group_id = ?")
            .bind(status)
            .bind(group_id)
            .execute(self.pool.database())
            .await?;
        Ok(())
    }

    pub async fn delete_group(&self, group_id: &str) -> Result<()> {
        signal_store::sqlx::query("DELETE FROM group_members WHERE group_id = ?")
            .bind(group_id)
            .execute(self.pool.database())
            .await?;
        signal_store::sqlx::query("DELETE FROM groups WHERE group_id = ?")
            .bind(group_id)
            .execute(self.pool.database())
            .await?;
        Ok(())
    }

    pub async fn add_group_member(
        &self,
        group_id: &str,
        id_pubkey: &str,
        name: &str,
        is_admin: bool,
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        signal_store::sqlx::query(
            "INSERT OR REPLACE INTO group_members (group_id, id_pubkey, name, is_admin, status, created_at) VALUES (?, ?, ?, ?, 'invited', ?)"
        )
        .bind(group_id)
        .bind(id_pubkey)
        .bind(name)
        .bind(if is_admin { 1i64 } else { 0i64 })
        .bind(now)
        .execute(self.pool.database())
        .await?;
        Ok(())
    }

    pub async fn remove_group_member(&self, group_id: &str, id_pubkey: &str) -> Result<()> {
        signal_store::sqlx::query("DELETE FROM group_members WHERE group_id = ? AND id_pubkey = ?")
            .bind(group_id)
            .bind(id_pubkey)
            .execute(self.pool.database())
            .await?;
        Ok(())
    }

    pub async fn get_group_members(&self, group_id: &str) -> Result<Vec<(String, String, bool)>> {
        let rows = signal_store::sqlx::query(
            "SELECT id_pubkey, name, is_admin FROM group_members WHERE group_id = ? ORDER BY created_at"
        )
        .bind(group_id)
        .fetch_all(self.pool.database())
        .await?;
        Ok(rows.iter().map(|r| {
            (
                r.get::<String, _>(0),
                r.get::<String, _>(1),
                r.get::<i64, _>(2) != 0,
            )
        }).collect())
    }

    /// Check if a Signal session exists with a peer.
    pub async fn has_session(
        &self,
        account: &KeychatAccount,
        curve25519_pubkey: &str,
        device_id: u32,
    ) -> Result<bool> {
        let (identity_key_bytes, _) = account.signal_identity_key_pair()?;
        if let Some(store) = self.stores.get(&identity_key_bytes) {
            let addr = ProtocolAddress::new(curve25519_pubkey.to_string(), device_id.into());
            let exists = store
                .session_store
                .contains_session(&addr)
                .await
                .unwrap_or(false);
            Ok(exists)
        } else {
            Ok(false)
        }
    }
}

/// Derive a Nostr receiving address from a Signal ratchet key pair seed.
///
/// The `seed_key` format is `"{private_hex}-{public_hex}"` where:
/// - private_hex is a 32-byte curve25519 private key (hex)
/// - public_hex is a 33-byte curve25519 public key (hex, with 05 prefix)
///
/// Algorithm (matches keychat-app `api_nostr.rs` line 607-627):
/// 1. ECDH(private, public) → 32 bytes
/// 2. Prepend [0xFF; 32] → 64 bytes
/// 3. SHA256 hash → 32 bytes (secp256k1 secret key)
/// 4. Derive x-only public key → hex (Nostr receiving address)
pub fn generate_seed_from_ratchetkey_pair(seed_key: &str) -> Result<String> {
    let parts: Vec<&str> = seed_key.split('-').collect();
    if parts.len() != 2 {
        anyhow::bail!("seed_key must be 'private_hex-public_hex'");
    }

    let private_bytes = hex::decode(parts[0])?;
    let public_bytes = hex::decode(parts[1])?;

    // Create Signal keys
    let private_key = PrivateKey::deserialize(&private_bytes)?;
    let public_key = PublicKey::deserialize(&public_bytes)?;

    // ECDH agreement
    let ecdh_result = private_key.calculate_agreement(&public_key)?;

    // Prepend 32 bytes of 0xFF
    let mut data = vec![0xFFu8; 32];
    data.extend_from_slice(&ecdh_result);

    // SHA256 hash
    let hash = sha256::Hash::hash(&data);
    let hash_bytes: [u8; 32] = hash.to_byte_array();

    // Derive secp256k1 x-only public key
    let secp = Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&hash_bytes)?;
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let (xonly, _parity) = keypair.x_only_public_key();

    Ok(hex::encode(xonly.serialize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_seed_from_ratchetkey_pair() {
        let seed = "a84fae2fcd9d4df077641eef56ad173394a72743d4c1c7cffdd2e904f05efd5b-05bece2d0f565c4510d29faac55ea3962a888426e69a7ec2610ac54712e5b80142";
        let result = generate_seed_from_ratchetkey_pair(seed).unwrap();
        assert_eq!(result.len(), 64, "Should be 32 bytes hex-encoded");
        // Verify it's valid hex
        hex::decode(&result).unwrap();
        println!("Derived pubkey: {}", result);
    }
}

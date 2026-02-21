//! Keychat account/identity management and protocol message types.

use anyhow::Result;
use nostr::nips::nip06::FromMnemonic;
use nostr::nips::nip19::ToBech32;
use nostr::{Keys, SecretKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use signal_store::libsignal_protocol::{KeyPair, PrivateKey, PublicKey as SignalPublicKey};

// ---------------------------------------------------------------------------
// KeychatMessage types (mirrors keychat-app's KeyChatEventKinds)
// ---------------------------------------------------------------------------

pub mod event_kinds {
    pub const DM: i32 = 100;
    pub const DM_ADD_CONTACT_FROM_ALICE: i32 = 101;
    pub const DM_ADD_CONTACT_FROM_BOB: i32 = 102;

    // Group event kinds (mirrors keychat-app's KeyChatEventKinds)
    pub const GROUP_INVITE: i32 = 11;
    pub const GROUP_HI: i32 = 14;
    pub const GROUP_CHANGE_NICKNAME: i32 = 15;
    pub const GROUP_SELF_LEAVE: i32 = 16;
    pub const GROUP_DISSOLVE: i32 = 17;
    pub const GROUP_CHANGE_ROOM_NAME: i32 = 20;
    pub const SIGNAL_SEND_PROFILE: i32 = 48;
    pub const GROUP_SEND_TO_ALL_MESSAGE: i32 = 30;
    pub const GROUP_REMOVE_SINGLE_MEMBER: i32 = 32;
}

/// MessageType category — mirrors Dart's MessageType enum.
pub mod message_type {
    pub const SIGNAL: &str = "signal";
    pub const GROUP: &str = "group";
}

/// GroupMessage — the inner payload of a small group (sendAll) message.
/// Mirrors the Dart `GroupMessage` class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMessage {
    /// The actual message text
    pub message: String,
    /// Group unique identifier (toMainPubkey)
    pub pubkey: String,
    /// Signature (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// Subtype for system messages (groupHi, groupDissolve, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtype: Option<i32>,
    /// Extra data (e.g., new nickname, removed member pubkey)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<String>,
}

/// RoomProfile — group metadata shared during invite.
/// Mirrors the Dart `RoomProfile` class.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomProfile {
    /// Group public key (unique ID)
    pub pubkey: String,
    /// Group name
    pub name: String,
    /// Member list
    pub users: Vec<serde_json::Value>,
    /// Group type
    pub group_type: String,
    /// Version timestamp
    pub updated_at: i64,
    /// Original group pubkey (for migration)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_to_room_pub_key: Option<String>,
    /// Shared private key (for shareKey groups)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prikey: Option<String>,
    /// Signal pubkey for the group
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_pubkey: Option<String>,
    /// Extra data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<String>,
}

/// Keychat protocol message wrapper — mirrors the Dart `KeychatMessage` class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeychatMessage {
    /// Event kind (101 = hello from Alice, 102 = hello from Bob, 100 = DM, etc.)
    #[serde(rename = "type")]
    pub msg_type: i32,
    /// Category — "signal" for Signal Protocol messages
    pub c: String,
    /// Human-readable message text
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
    /// Structured data — JSON string of QRUserModel for hello, MsgReply for DM replies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Extra data field
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// QRUserModel — the identity bundle shared during hello/handshake.
/// Mirrors the Dart `QRUserModel` class.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QRUserModel {
    pub name: String,
    pub pubkey: String,
    pub curve25519_pk_hex: String,
    #[serde(default)]
    pub onetimekey: String,
    pub signed_id: u32,
    pub signed_public: String,
    pub signed_signature: String,
    pub prekey_id: u32,
    pub prekey_pubkey: String,
    pub global_sign: String,
    #[serde(default)]
    pub relay: String,
    #[serde(default = "default_time")]
    pub time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lightning: Option<String>,
}

fn default_time() -> i64 {
    -1
}

/// PrekeyMessageModel — wraps a message sent during pre-key (first) message exchange.
/// Mirrors the Dart `PrekeyMessageModel` class.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrekeyMessageModel {
    pub nostr_id: String,
    pub signal_id: String,
    pub time: i64,
    pub sig: String,
    pub name: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lightning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
}

// ---------------------------------------------------------------------------
// KeychatAccount
// ---------------------------------------------------------------------------

/// A Keychat account with both secp256k1 (Nostr) and curve25519 (Signal) keypairs.
pub struct KeychatAccount {
    pub keys: Keys,
    pub mnemonic: Option<String>,
    pub curve25519_sk: Vec<u8>,
    pub curve25519_pk: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct AccountInfo {
    pub pubkey_hex: String,
    pub pubkey_npub: String,
    pub prikey_nsec: String,
    pub curve25519_pk_hex: String,
    pub mnemonic: Option<String>,
}

impl KeychatAccount {
    pub fn generate() -> Result<Self> {
        let mnemonic = bip39::Mnemonic::generate(12)?;
        let mnemonic_str = mnemonic.to_string();
        Self::from_mnemonic(&mnemonic_str, None)
    }

    pub fn from_mnemonic(mnemonic: &str, password: Option<String>) -> Result<Self> {
        let keys = Keys::from_mnemonic_with_account(mnemonic, password.as_deref(), None)?;
        let (sk_bytes, pk_bytes) = generate_curve25519_keypair(mnemonic, password, None)?;
        Ok(Self {
            keys,
            mnemonic: Some(mnemonic.to_string()),
            curve25519_sk: sk_bytes,
            curve25519_pk: pk_bytes,
        })
    }

    pub fn from_private_key(privkey: &str) -> Result<Self> {
        let keys = Keys::parse(privkey)?;
        let pair = KeyPair::generate(&mut OsRng);
        Ok(Self {
            keys,
            mnemonic: None,
            curve25519_sk: pair.private_key.serialize(),
            curve25519_pk: pair.public_key.serialize().into(),
        })
    }

    pub fn public_info(&self) -> AccountInfo {
        AccountInfo {
            pubkey_hex: self.keys.public_key().to_string(),
            pubkey_npub: self.keys.public_key().to_bech32().unwrap_or_default(),
            prikey_nsec: self.keys.secret_key().to_bech32().unwrap_or_default(),
            curve25519_pk_hex: hex::encode(&self.curve25519_pk),
            mnemonic: self.mnemonic.clone(),
        }
    }

    pub fn signal_identity_key_pair(&self) -> Result<([u8; 33], [u8; 32])> {
        let pk: [u8; 33] = self
            .curve25519_pk
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid curve25519 public key length"))?;
        let sk: [u8; 32] = self
            .curve25519_sk
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid curve25519 private key length"))?;
        Ok((pk, sk))
    }

    /// Get the Nostr secp256k1 public key hex (without 02/03 prefix — just x-coordinate).
    pub fn nostr_pubkey_hex(&self) -> String {
        self.keys.public_key().to_string()
    }

    /// Get the Signal curve25519 public key hex (33 bytes with 05 prefix).
    pub fn signal_pubkey_hex(&self) -> String {
        hex::encode(&self.curve25519_pk)
    }

    /// Get the Signal curve25519 private key bytes.
    pub fn signal_private_key_bytes(&self) -> Vec<u8> {
        self.curve25519_sk.clone()
    }

    /// Generate a fresh random ephemeral Signal identity keypair.
    /// Used for outgoing hello requests — each peer gets a unique Signal identity.
    pub fn generate_ephemeral_signal_keypair() -> ([u8; 33], [u8; 32]) {
        let pair = KeyPair::generate(&mut OsRng);
        let pk_vec: Vec<u8> = pair.public_key.serialize().into();
        let pk: [u8; 33] = pk_vec.try_into().expect("signal pubkey 33 bytes");
        let sk_vec: Vec<u8> = pair.private_key.serialize();
        let sk: [u8; 32] = sk_vec.try_into().expect("signal privkey 32 bytes");
        (pk, sk)
    }

    /// Sign a message with Schnorr signature (using the Nostr secp256k1 key).
    pub fn schnorr_sign(&self, message: &str) -> Result<String> {
        use nostr::secp256k1::{Secp256k1, Message};
        use nostr::hashes::{sha256, Hash};

        let secp = Secp256k1::new();
        let secret_key = self.keys.secret_key();

        // Hash the message (same as keychat-app's signSchnorr with hash:true)
        let hash = sha256::Hash::hash(message.as_bytes());
        let msg = Message::from_digest(hash.to_byte_array());

        let keypair = nostr::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let sig = secp.sign_schnorr(&msg, &keypair);
        Ok(hex::encode(sig.as_ref()))
    }

    /// Get the globalSign content string: "Keychat-{nostrId}-{signalId}-{time}"
    pub fn get_sign_message(nostr_id: &str, signal_id: &str, time: i64) -> String {
        format!("Keychat-{}-{}-{}", nostr_id, signal_id, time)
    }
}

fn generate_curve25519_keypair(
    mnemonic_words: &str,
    password: Option<String>,
    account: Option<u32>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mnemonic =
        bip39::Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic_words)?;
    let seed = mnemonic.to_seed(password.unwrap_or_default());

    use bitcoin::bip32::{DerivationPath, Xpriv};
    let root_key = Xpriv::new_master(bitcoin::Network::Bitcoin, &seed)?;
    let account_idx = account.unwrap_or(0);
    let path: DerivationPath = format!("m/44'/1238'/{}'/0/0", account_idx).parse()?;
    let ctx = bitcoin::key::Secp256k1::new();
    let child_xprv = root_key.derive_priv(&ctx, &path)?;

    let private_key = PrivateKey::deserialize(&child_xprv.private_key.secret_bytes())?;
    let public_key = private_key.public_key()?;

    Ok((private_key.serialize(), public_key.serialize().into()))
}

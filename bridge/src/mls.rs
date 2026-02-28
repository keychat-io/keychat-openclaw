//! MLS (Messaging Layer Security) support for Keychat large groups.
//!
//! This module wraps Keychat's OpenMLS fork (kc crate) to provide:
//! - MLS store initialization per identity
//! - KeyPackage creation
//! - Group creation, joining (Welcome), deletion
//! - Message encrypt/decrypt with NIP-44 export_secret layer
//! - Commit processing (add/remove/update/GroupContextExtensions)
//! - Listen key (onetimekey) derivation

use anyhow::Result;
use std::collections::HashMap;
use std::sync::RwLock;

use kc::group_context_extension::NostrGroupDataExtension;
use kc::openmls_rust_persistent_crypto::{JsonCodec, OpenMlsRustPersistentCrypto};
use kc::user::{Group, MlsUser};
use nostr::nips::nip44;
use nostr::Keys;
use openmls::group::{GroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig};
use openmls::key_packages::KeyPackage;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::{
    BasicCredential, Capabilities, ContentType, Extension, ExtensionType, Extensions, KeyPackageIn,
    LeafNodeIndex, LeafNodeParameters, Member, MlsMessageBodyIn, MlsMessageIn,
    ProcessedMessageContent, Proposal, ProposalType, ProtocolVersion,
    RequiredCapabilitiesExtension, StagedWelcome, UnknownExtension,
};
use openmls_sqlite_storage::{Connection, SqliteStorageProvider};
use openmls_traits::types::Ciphersuite;
use openmls_traits::OpenMlsProvider;

use serde::{Deserialize, Serialize};

pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
pub const UNKNOWN_EXTENSION_TYPE: u16 = 0xF233;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsKeyPackageResult {
    pub key_package: String,
    pub mls_protocol_version: String,
    pub ciphersuite: String,
    pub extensions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsMessageResult {
    pub encrypted_msg: String,
    pub listen_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsDecryptedMessage {
    pub plaintext: String,
    pub sender: String,
    pub listen_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsGroupInfo {
    pub group_id: String,
    pub name: String,
    pub description: String,
    pub admin_pubkeys: Vec<String>,
    pub relays: Vec<String>,
    pub status: String,
    pub members: Vec<String>,
    pub listen_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MlsCommitType {
    Add,
    Update,
    Remove,
    GroupContextExtensions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsCommitResult {
    pub sender: String,
    pub commit_type: MlsCommitType,
    pub operated_members: Vec<String>,
    pub listen_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MlsMessageInType {
    Application,
    Proposal,
    Commit,
    Welcome,
    GroupInfo,
    KeyPackage,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsAddMembersResult {
    pub commit_msg: String,
    pub welcome: String, // base64 encoded
    pub listen_key: String,
}

// ---------------------------------------------------------------------------
// MlsManager — per-identity MLS state
// ---------------------------------------------------------------------------

/// Wraps an MlsUser from the kc crate.
struct MlsUserWrapper {
    mls_user: MlsUser,
}

/// Top-level MLS manager holding per-identity MLS users.
pub struct MlsManager {
    users: HashMap<String, MlsUserWrapper>,
    db_path: String,
}

impl MlsManager {
    pub fn new(db_path: &str) -> Self {
        Self {
            users: HashMap::new(),
            db_path: db_path.to_string(),
        }
    }

    /// Initialize MLS for a given nostr identity (secp256k1 pubkey hex).
    pub async fn init_identity(&mut self, nostr_id: &str) -> Result<()> {
        if self.users.contains_key(nostr_id) {
            return Ok(());
        }

        let connection = Connection::open(&self.db_path)?;
        let mut storage = SqliteStorageProvider::<JsonCodec, Connection>::new(connection);
        storage
            .initialize()
            .map_err(|e| anyhow::anyhow!("Failed to initialize MLS storage: {}", e))?;

        let provider = OpenMlsRustPersistentCrypto::new(storage).await;
        let mls_user = MlsUser::load(provider, nostr_id.to_string()).await?;

        self.users.insert(
            nostr_id.to_string(),
            MlsUserWrapper { mls_user },
        );

        log::info!("MLS initialized for identity: {}", nostr_id);
        Ok(())
    }

    fn get_user(&self, nostr_id: &str) -> Result<&MlsUserWrapper> {
        self.users
            .get(nostr_id)
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized for {}", nostr_id))
    }

    fn get_user_mut(&mut self, nostr_id: &str) -> Result<&mut MlsUserWrapper> {
        self.users
            .get_mut(nostr_id)
            .ok_or_else(|| anyhow::anyhow!("MLS not initialized for {}", nostr_id))
    }

    // -----------------------------------------------------------------------
    // KeyPackage
    // -----------------------------------------------------------------------

    pub fn create_key_package(&mut self, nostr_id: &str) -> Result<MlsKeyPackageResult> {
        let user = self.get_user_mut(nostr_id)?;
        let mut identity = user.mls_user.identity.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        let capabilities: Capabilities = identity.create_capabilities()?;
        let ciphersuite = identity.ciphersuite_value().to_string();
        let extensions = identity.extensions_value();
        let key_package = identity.add_key_package(CIPHERSUITE, &user.mls_user.provider, capabilities);
        let key_package_serialized = key_package.tls_serialize_detached()?;

        Ok(MlsKeyPackageResult {
            key_package: hex::encode(key_package_serialized),
            mls_protocol_version: "1.0".to_string(),
            ciphersuite,
            extensions,
        })
    }

    pub async fn save_after_key_package(&mut self, nostr_id: &str) -> Result<()> {
        let user = self.get_user_mut(nostr_id)?;
        user.mls_user.update(nostr_id.to_string(), true).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Group creation
    // -----------------------------------------------------------------------

    pub async fn create_group(
        &mut self,
        nostr_id: &str,
        group_id: &str,
        group_name: &str,
        description: &str,
        admin_pubkeys: Vec<String>,
        relays: Vec<String>,
        status: &str,
    ) -> Result<()> {
        let user = self.get_user_mut(nostr_id)?;

        let group_data = NostrGroupDataExtension::new(
            group_name.to_string(),
            description.to_string(),
            admin_pubkeys,
            relays,
            status.to_string(),
        );
        let serialized_group_data = group_data.tls_serialize_detached()?;

        let required_extension_types = &[ExtensionType::Unknown(UNKNOWN_EXTENSION_TYPE)];
        let required_capabilities = Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(required_extension_types, &[], &[]),
        );
        let extensions = vec![
            Extension::Unknown(
                UNKNOWN_EXTENSION_TYPE,
                UnknownExtension(serialized_group_data),
            ),
            required_capabilities,
        ];

        // Scope the identity read lock so it's dropped before `update()`
        let mls_group = {
            let identity = user.mls_user.identity.read()
                .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
            let capabilities: Capabilities = identity.create_capabilities()?;
            let group_create_config = MlsGroupCreateConfig::builder()
                .capabilities(capabilities)
                .use_ratchet_tree_extension(true)
                .with_group_context_extensions(
                    Extensions::from_vec(extensions)
                        .expect("Couldn't convert extensions vec to Object"),
                )
                .map_err(|e| anyhow::anyhow!("{}", e))?
                .build();

            MlsGroup::new_with_group_id(
                &user.mls_user.provider,
                &identity.signer,
                &group_create_config,
                GroupId::from_slice(group_id.as_bytes()),
                identity.credential_with_key.clone(),
            )?
        };

        let group = Group { mls_group };

        {
            let groups = user.mls_user.groups.read()
                .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
            if groups.contains_key(group_id) {
                anyhow::bail!("Group '{}' already exists", group_id);
            }
        }

        user.mls_user.groups.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?
            .insert(group_id.to_string(), group);
        user.mls_user.group_list.insert(group_id.to_string());
        user.mls_user.update(nostr_id.to_string(), false).await?;

        log::info!("MLS group created: {} ({})", group_name, group_id);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Add members
    // -----------------------------------------------------------------------

    pub fn add_members(
        &mut self,
        nostr_id: &str,
        group_id: &str,
        key_packages_hex: Vec<String>,
    ) -> Result<MlsAddMembersResult> {
        let user = self.get_user_mut(nostr_id)?;
        let mut kps: Vec<KeyPackage> = Vec::new();
        for kp_hex in key_packages_hex {
            let kp_bytes = hex::decode(&kp_hex)?;
            let kp_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let kp = kp_in
                .validate(user.mls_user.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            kps.push(kp);
        }

        let mut groups = user.mls_user.groups.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;
        let identity = user.mls_user.identity.read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;

        let (queued_msg, welcome, _) = group.mls_group.add_members(
            &user.mls_user.provider,
            &identity.signer,
            &kps,
        )?;

        let serialized_queued_msg: Vec<u8> = queued_msg.to_bytes()?;
        let (encrypted_content, listen_key) =
            encrypt_nip44_with_group(&user.mls_user, &group.mls_group, serialized_queued_msg)?;
        let serialized_welcome: Vec<u8> = welcome.to_bytes()?;

        Ok(MlsAddMembersResult {
            commit_msg: encrypted_content,
            welcome: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &serialized_welcome,
            ),
            listen_key,
        })
    }

    pub fn self_commit(&mut self, nostr_id: &str, group_id: &str) -> Result<()> {
        let user = self.get_user_mut(nostr_id)?;
        let mut groups = user.mls_user.groups.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;
        group.mls_group.merge_pending_commit(&user.mls_user.provider)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Join group (Welcome)
    // -----------------------------------------------------------------------

    pub async fn join_group(
        &mut self,
        nostr_id: &str,
        group_id: &str,
        welcome_bytes: &[u8],
    ) -> Result<MlsGroupInfo> {
        let user = self.get_user_mut(nostr_id)?;

        let mls_group_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let welcome_msg = MlsMessageIn::tls_deserialize_exact(welcome_bytes)?;
        let welcome = welcome_msg.into_welcome()
            .ok_or_else(|| anyhow::anyhow!("Expected a welcome message"))?;

        let staged_welcome = StagedWelcome::new_from_welcome(
            &user.mls_user.provider,
            &mls_group_config,
            welcome,
            None,
        ).map_err(|e| anyhow::anyhow!("Error creating StagedWelcome: {}", e))?;

        let extension = NostrGroupDataExtension::from_group_context(staged_welcome.group_context())
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        let mls_group = staged_welcome.into_group(&user.mls_user.provider)
            .map_err(|e| anyhow::anyhow!("Error creating group from StagedWelcome: {}", e))?;

        // Get members
        let members = get_group_members_from_mls_group(&mls_group)?;

        // Get listen key
        let listen_key = get_listen_key(&user.mls_user, &mls_group)?;

        let group = Group { mls_group };
        {
            let groups = user.mls_user.groups.read()
                .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
            if groups.contains_key(group_id) {
                anyhow::bail!("Group '{}' already exists", group_id);
            }
        }
        user.mls_user.groups.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?
            .insert(group_id.to_string(), group);
        user.mls_user.group_list.insert(group_id.to_string());
        user.mls_user.update(nostr_id.to_string(), false).await?;

        let name = String::from_utf8(extension.name).unwrap_or_default();
        let description = String::from_utf8(extension.description).unwrap_or_default();
        let admin_pubkeys = extension.admin_pubkeys.iter()
            .map(|b| String::from_utf8(b.clone()).unwrap_or_default())
            .collect();
        let relays = extension.relays.iter()
            .map(|b| String::from_utf8(b.clone()).unwrap_or_default())
            .collect();
        let status = String::from_utf8(extension.status).unwrap_or_default();

        log::info!("Joined MLS group '{}' ({})", name, group_id);
        Ok(MlsGroupInfo {
            group_id: group_id.to_string(),
            name,
            description,
            admin_pubkeys,
            relays,
            status,
            members,
            listen_key,
        })
    }

    // -----------------------------------------------------------------------
    // Message create/decrypt
    // -----------------------------------------------------------------------

    pub fn create_message(
        &mut self,
        nostr_id: &str,
        group_id: &str,
        msg: &str,
    ) -> Result<MlsMessageResult> {
        let user = self.get_user_mut(nostr_id)?;
        let mut groups = user.mls_user.groups.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;
        let identity = user.mls_user.identity.read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;

        let msg_out = group.mls_group
            .create_message(&user.mls_user.provider, &identity.signer, msg.as_bytes())
            .map_err(|e| anyhow::anyhow!("Error creating message: {}", e))?;
        let serialized_msg: Vec<u8> = msg_out.0.to_bytes()?;
        let (encrypted_content, listen_key) =
            encrypt_nip44_with_group(&user.mls_user, &group.mls_group, serialized_msg)?;

        Ok(MlsMessageResult {
            encrypted_msg: encrypted_content,
            listen_key,
        })
    }

    pub fn decrypt_message(
        &mut self,
        nostr_id: &str,
        group_id: &str,
        msg: &str,
    ) -> Result<MlsDecryptedMessage> {
        let user = self.get_user_mut(nostr_id)?;
        let mut groups = user.mls_user.groups.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;

        let (decrypted_content, listen_key) =
            decrypt_nip44_with_group(&user.mls_user, &group.mls_group, msg)?;

        let mls_msg = MlsMessageIn::tls_deserialize_exact(&decrypted_content)?;
        let processed_message = group.mls_group
            .process_message(
                &user.mls_user.provider,
                mls_msg.into_protocol_message()
                    .ok_or_else(|| anyhow::anyhow!("Unexpected message type"))?,
            )
            .map_err(|e| anyhow::anyhow!("Error decrypting message: {}", e))?;

        let sender = String::from_utf8(
            processed_message.0.credential().serialized_content().to_vec(),
        )?;

        if let ProcessedMessageContent::ApplicationMessage(app_msg) =
            processed_message.0.into_content()
        {
            let text = String::from_utf8(app_msg.into_bytes())?;
            Ok(MlsDecryptedMessage {
                plaintext: text,
                sender,
                listen_key,
            })
        } else {
            anyhow::bail!("Expected ApplicationMessage")
        }
    }

    // -----------------------------------------------------------------------
    // Parse message type
    // -----------------------------------------------------------------------

    pub fn parse_message_type(
        &self,
        nostr_id: &str,
        group_id: &str,
        data: &str,
    ) -> Result<MlsMessageInType> {
        let user = self.get_user(nostr_id)?;
        let groups = user.mls_user.groups.read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
        let group = groups.get(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;

        // Clone the MLS group to avoid consuming ratchet keys from the real group state.
        // Keychat app does the same: `self.decrypt_nip44(group.mls_group.clone(), data)`
        let group_clone = group.mls_group.clone();
        let (decrypted_content, _) =
            decrypt_nip44_with_group(&user.mls_user, &group_clone, data)?;
        let queued_msg = MlsMessageIn::tls_deserialize_exact(&decrypted_content)?;

        match queued_msg.extract() {
            MlsMessageBodyIn::PrivateMessage(pm) => match pm.content_type() {
                ContentType::Application => Ok(MlsMessageInType::Application),
                ContentType::Proposal => Ok(MlsMessageInType::Proposal),
                ContentType::Commit => Ok(MlsMessageInType::Commit),
            },
            MlsMessageBodyIn::Welcome(_) => Ok(MlsMessageInType::Welcome),
            MlsMessageBodyIn::GroupInfo(_) => Ok(MlsMessageInType::GroupInfo),
            MlsMessageBodyIn::KeyPackage(_) => Ok(MlsMessageInType::KeyPackage),
            _ => Ok(MlsMessageInType::Custom),
        }
    }

    // -----------------------------------------------------------------------
    // Commit processing
    // -----------------------------------------------------------------------

    pub fn process_commit(
        &mut self,
        nostr_id: &str,
        group_id: &str,
        queued_msg_encrypted: &str,
    ) -> Result<MlsCommitResult> {
        let user = self.get_user_mut(nostr_id)?;
        let mut groups = user.mls_user.groups.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;

        let (decrypted_content, _) =
            decrypt_nip44_with_group(&user.mls_user, &group.mls_group, queued_msg_encrypted)?;

        let queued_msg = MlsMessageIn::tls_deserialize_exact(&decrypted_content)?;
        let processed = group.mls_group.process_message(
            &user.mls_user.provider,
            queued_msg.into_protocol_message()
                .ok_or_else(|| anyhow::anyhow!("Unexpected message type"))?,
        )?;

        let sender = String::from_utf8(
            processed.0.credential().serialized_content().to_vec(),
        )?;

        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            processed.0.into_content()
        {
            let mut commit_type = MlsCommitType::Update;
            let mut operated_members: Vec<String> = Vec::new();

            let proposals: Vec<_> = staged_commit.queued_proposals().collect();
            if !proposals.is_empty() {
                let proposal_type = proposals[0].proposal().proposal_type();
                match proposal_type {
                    ProposalType::Add => {
                        commit_type = MlsCommitType::Add;
                        for proposal in &proposals {
                            if let Proposal::Add(add) = proposal.proposal() {
                                let added = String::from_utf8(
                                    add.key_package().leaf_node().credential()
                                        .serialized_content().to_vec(),
                                )?;
                                operated_members.push(added);
                            }
                        }
                    }
                    ProposalType::Remove => {
                        commit_type = MlsCommitType::Remove;
                        let members: Vec<Member> = group.mls_group.members().collect();
                        for proposal in &proposals {
                            if let Proposal::Remove(removed) = proposal.proposal() {
                                if let Some(member_str) =
                                    leaf_node_index_to_string(removed.removed(), &members)?
                                {
                                    operated_members.push(member_str);
                                }
                            }
                        }
                    }
                    ProposalType::GroupContextExtensions => {
                        commit_type = MlsCommitType::GroupContextExtensions;
                    }
                    _ => {}
                }
            }

            group.mls_group
                .merge_staged_commit(&user.mls_user.provider, *staged_commit)?;

            // Get new listen key after merge
            let listen_key = get_listen_key(&user.mls_user, &group.mls_group)?;

            Ok(MlsCommitResult {
                sender,
                commit_type,
                operated_members,
                listen_key,
            })
        } else {
            anyhow::bail!("Expected a StagedCommit")
        }
    }

    // -----------------------------------------------------------------------
    // Get listen key
    // -----------------------------------------------------------------------

    pub fn get_listen_key(&self, nostr_id: &str, group_id: &str) -> Result<String> {
        let user = self.get_user(nostr_id)?;
        let groups = user.mls_user.groups.read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
        let group = groups.get(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;
        get_listen_key(&user.mls_user, &group.mls_group)
    }

    // -----------------------------------------------------------------------
    // Get group info
    // -----------------------------------------------------------------------

    pub fn get_group_info(&self, nostr_id: &str, group_id: &str) -> Result<MlsGroupInfo> {
        let user = self.get_user(nostr_id)?;
        let groups = user.mls_user.groups.read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
        let group = groups.get(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;

        let extension = NostrGroupDataExtension::from_group(&group.mls_group)?;
        let members = get_group_members_from_mls_group(&group.mls_group)?;
        let listen_key = get_listen_key(&user.mls_user, &group.mls_group)?;

        Ok(MlsGroupInfo {
            group_id: group_id.to_string(),
            name: String::from_utf8(extension.name).unwrap_or_default(),
            description: String::from_utf8(extension.description).unwrap_or_default(),
            admin_pubkeys: extension.admin_pubkeys.iter()
                .map(|b| String::from_utf8(b.clone()).unwrap_or_default())
                .collect(),
            relays: extension.relays.iter()
                .map(|b| String::from_utf8(b.clone()).unwrap_or_default())
                .collect(),
            status: String::from_utf8(extension.status).unwrap_or_default(),
            members,
            listen_key,
        })
    }

    // -----------------------------------------------------------------------
    // Get all groups
    // -----------------------------------------------------------------------

    pub fn get_groups(&self, nostr_id: &str) -> Result<Vec<String>> {
        let user = self.get_user(nostr_id)?;
        Ok(user.mls_user.group_list.iter().cloned().collect())
    }

    // -----------------------------------------------------------------------
    // Self update
    // -----------------------------------------------------------------------

    pub fn self_update(
        &mut self,
        nostr_id: &str,
        group_id: &str,
        extensions_bytes: Vec<u8>,
    ) -> Result<MlsMessageResult> {
        let user = self.get_user_mut(nostr_id)?;
        let mut groups = user.mls_user.groups.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;
        let identity = user.mls_user.identity.read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;

        let extension = Extension::Unknown(UNKNOWN_EXTENSION_TYPE, UnknownExtension(extensions_bytes));
        let leaf_extensions = Extensions::single(extension);

        let commit_bundle = group.mls_group.self_update(
            &user.mls_user.provider,
            &identity.signer,
            LeafNodeParameters::builder()
                .with_extensions(leaf_extensions)
                .build(),
        )?;
        let queued_msg = commit_bundle.commit();
        let serialized_msg: Vec<u8> = queued_msg.to_bytes()?;
        let (encrypted_content, listen_key) =
            encrypt_nip44_with_group(&user.mls_user, &group.mls_group, serialized_msg)?;

        Ok(MlsMessageResult {
            encrypted_msg: encrypted_content,
            listen_key,
        })
    }

    // -----------------------------------------------------------------------
    // Update group context extensions
    // -----------------------------------------------------------------------

    pub fn update_group_context_extensions(
        &mut self,
        nostr_id: &str,
        group_id: &str,
        group_name: Option<String>,
        description: Option<String>,
        admin_pubkeys: Option<Vec<String>>,
        relays: Option<Vec<String>>,
        status: Option<String>,
    ) -> Result<MlsMessageResult> {
        let user = self.get_user_mut(nostr_id)?;
        let mut groups = user.mls_user.groups.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;
        let identity = user.mls_user.identity.read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;

        let mut group_data = NostrGroupDataExtension::from_group(&group.mls_group)?;

        if let Some(name) = group_name {
            group_data.set_name(name);
        }
        if let Some(desc) = description {
            group_data.set_description(desc);
        }
        if let Some(admins) = admin_pubkeys {
            group_data.set_admin_pubkeys(admins);
        }
        if let Some(r) = relays {
            group_data.set_relays(r);
        }
        if let Some(s) = status {
            group_data.set_status(s);
        }

        let serialized_group_data = group_data.tls_serialize_detached()?;
        let required_extension_types = &[ExtensionType::Unknown(UNKNOWN_EXTENSION_TYPE)];
        let required_capabilities = Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(required_extension_types, &[], &[]),
        );
        let extensions = vec![
            Extension::Unknown(
                UNKNOWN_EXTENSION_TYPE,
                UnknownExtension(serialized_group_data),
            ),
            required_capabilities,
        ];

        let update_result = group.mls_group.update_group_context_extensions(
            &user.mls_user.provider,
            Extensions::from_vec(extensions).expect("Couldn't convert extensions"),
            &identity.signer,
        )?;
        let queued_msg = update_result.0;
        let serialized_msg: Vec<u8> = queued_msg.to_bytes()?;
        let (encrypted_content, listen_key) =
            encrypt_nip44_with_group(&user.mls_user, &group.mls_group, serialized_msg)?;

        Ok(MlsMessageResult {
            encrypted_msg: encrypted_content,
            listen_key,
        })
    }

    // -----------------------------------------------------------------------
    // Remove members
    // -----------------------------------------------------------------------

    pub fn remove_members(
        &mut self,
        nostr_id: &str,
        group_id: &str,
        member_nostr_ids: Vec<String>,
    ) -> Result<MlsMessageResult> {
        let user = self.get_user_mut(nostr_id)?;
        let mut groups = user.mls_user.groups.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;
        let identity = user.mls_user.identity.read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;

        // Find leaf node indices for the members to remove
        let members: Vec<Member> = group.mls_group.members().collect();
        let mut leaf_nodes: Vec<LeafNodeIndex> = Vec::new();
        for member_id in &member_nostr_ids {
            for member in &members {
                let credential_str = String::from_utf8(
                    member.credential.serialized_content().to_vec(),
                )?;
                if credential_str == *member_id {
                    leaf_nodes.push(member.index);
                    break;
                }
            }
        }

        let (queued_msg, _, _) = group.mls_group.remove_members(
            &user.mls_user.provider,
            &identity.signer,
            &leaf_nodes,
        )?;
        let serialized_msg: Vec<u8> = queued_msg.to_bytes()?;
        let (encrypted_content, listen_key) =
            encrypt_nip44_with_group(&user.mls_user, &group.mls_group, serialized_msg)?;

        Ok(MlsMessageResult {
            encrypted_msg: encrypted_content,
            listen_key,
        })
    }

    // -----------------------------------------------------------------------
    // Delete group
    // -----------------------------------------------------------------------

    pub async fn delete_group(&mut self, nostr_id: &str, group_id: &str) -> Result<()> {
        let user = self.get_user_mut(nostr_id)?;
        {
            let mut groups = user.mls_user.groups.write()
                .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
            if let Some(group) = groups.get_mut(group_id) {
                group.mls_group.delete(&user.mls_user.provider.storage)?;
            }
            groups.remove(group_id);
        }
        user.mls_user.group_list.remove(group_id);
        user.mls_user.update(nostr_id.to_string(), false).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Get sender from encrypted msg (without consuming the message)
    // -----------------------------------------------------------------------

    pub fn get_sender(
        &self,
        nostr_id: &str,
        group_id: &str,
        queued_msg_encrypted: &str,
    ) -> Result<Option<String>> {
        let user = self.get_user(nostr_id)?;
        let mut groups = user.mls_user.groups.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock"))?;
        let group = groups.get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;

        let (decrypted_content, _) =
            decrypt_nip44_with_group(&user.mls_user, &group.mls_group, queued_msg_encrypted)?;
        let msg = MlsMessageIn::tls_deserialize_exact(&decrypted_content)?;
        let leaf_node_index = group.mls_group
            .sender_leaf_node_index(
                &user.mls_user.provider,
                msg.into_protocol_message()
                    .ok_or_else(|| anyhow::anyhow!("Unexpected message type"))?,
            )
            .map_err(|e| anyhow::anyhow!("Error getting sender: {}", e))?;

        let members: Vec<Member> = group.mls_group.members().collect();
        leaf_node_index_to_string(leaf_node_index, &members)
    }

    // -----------------------------------------------------------------------
    // Get export secret (for NIP-17 transport)
    // -----------------------------------------------------------------------

    pub fn get_export_secret_keys(&self, nostr_id: &str, group_id: &str) -> Result<Keys> {
        let user = self.get_user(nostr_id)?;
        let groups = user.mls_user.groups.read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock"))?;
        let group = groups.get(group_id)
            .ok_or_else(|| anyhow::anyhow!("No group with id {} known", group_id))?;
        keypair_from_export_secret(&user.mls_user, &group.mls_group)
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn keypair_from_export_secret(mls_user: &MlsUser, group: &MlsGroup) -> Result<Keys> {
    let export_secret = group.export_secret(&mls_user.provider, "nostr", b"nostr", 32)?;
    let export_secret_hex = hex::encode(&export_secret);
    let keypair = Keys::parse(&export_secret_hex)?;
    Ok(keypair)
}

fn get_listen_key(mls_user: &MlsUser, group: &MlsGroup) -> Result<String> {
    let keypair = keypair_from_export_secret(mls_user, group)?;
    let public_key = keypair.public_key();
    let listen_key = hex::encode(public_key.xonly()?.serialize());
    Ok(listen_key)
}

fn encrypt_nip44_with_group(
    mls_user: &MlsUser,
    group: &MlsGroup,
    serialized_msg: Vec<u8>,
) -> Result<(String, String)> {
    let keypairs = keypair_from_export_secret(mls_user, group)?;
    let public_key = keypairs.public_key();
    let listen_key = hex::encode(public_key.xonly()?.serialize());
    let encrypted_content = nip44::encrypt(
        keypairs.secret_key(),
        &public_key,
        &serialized_msg,
        nip44::Version::V2,
    )?;
    Ok((encrypted_content, listen_key))
}

fn decrypt_nip44_with_group(
    mls_user: &MlsUser,
    group: &MlsGroup,
    msg: &str,
) -> Result<(Vec<u8>, String)> {
    let keypairs = keypair_from_export_secret(mls_user, group)?;
    let public_key = keypairs.public_key();
    let listen_key = hex::encode(public_key.xonly()?.serialize());
    let serialized_msg = msg.as_bytes().to_vec();
    let decrypted_content =
        nip44::decrypt_to_bytes(keypairs.secret_key(), &public_key, &serialized_msg)?;
    Ok((decrypted_content, listen_key))
}

fn get_group_members_from_mls_group(group: &MlsGroup) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for member in group.members() {
        let pubkey = String::from_utf8(
            BasicCredential::try_from(member.credential)
                .map_err(|e| anyhow::anyhow!("{}", e))?
                .identity()
                .to_vec(),
        )?;
        result.push(pubkey);
    }
    Ok(result)
}

fn leaf_node_index_to_string(
    index: LeafNodeIndex,
    members: &[Member],
) -> Result<Option<String>> {
    for member in members {
        if member.index == index {
            let s = String::from_utf8(member.credential.serialized_content().to_vec())?;
            return Ok(Some(s));
        }
    }
    Ok(None)
}

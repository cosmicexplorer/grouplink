/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! Wrap all stateful [libsignal_protocol] operations in immutable stateless objects!

/// [prost] structs for serializing session information. This is directly used in serialized
/// messages between identities.
pub mod proto {
  /* Ensure the generated identity.proto outputs are available under [super::identity] within the
   * sub-module also named "proto". */
  pub use crate::identity::proto as identity;
  mod proto {
    include!(concat!(env!("OUT_DIR"), "/grouplink.proto.session.rs"));
  }
  #[doc(inline)]
  pub use proto::*;
}

use crate::error::{Error, ProtobufCodingFailure};
use crate::identity::{
  CryptographicIdentity, ExternalIdentity, SealedSenderIdentity, SenderCert, Spontaneous,
};
use crate::store::{Persistent, Store};
use crate::util::encode_proto_message;

use libsignal_protocol as signal;
use prost::Message;
use rand::{self, CryptoRng, Rng};

#[cfg(doc)]
use libsignal_protocol::{PreKeyStore, SignedPreKeyStore};

use std::convert::{TryFrom, TryInto};
use std::time::SystemTime;

/// Specify the parameters to create a new [SignedPreKey].
#[derive(Debug, Clone, Copy)]
pub struct SignedPreKeyRequest {
  /// Specifies this particular signed pre-key in the local [SignedPreKeyStore]. Randomly generated
  /// upon creation of a [Self].
  pub id: signal::SignedPreKeyId,
  /// The cryptographic public/private key pair represented by the signed pre-key to
  /// create. Randomly generated upon creation of a [Self].
  pub pair: signal::IdentityKeyPair,
}

impl Spontaneous<()> for SignedPreKeyRequest {
  fn generate<R: CryptoRng + Rng>(_params: (), r: &mut R) -> Self {
    let pair = signal::IdentityKeyPair::generate(r);
    let id: signal::SignedPreKeyId = Box::new(r).gen::<u32>().into();
    Self { id, pair }
  }
}

/// Represents a signed pre-key as per the [X3DH] key agreement protocol.
///
/// TODO: this object should be downloaded from a keyserver for the identity instead of regenerated
/// on the spot!
///
/// [X3DH]: https://signal.org/docs/specifications/x3dh/#publishing-keys
#[derive(Debug, Clone)]
pub struct SignedPreKey {
  /// From [SignedPreKeyRequest::id].
  pub id: signal::SignedPreKeyId,
  /// From [SignedPreKeyRequest::pair].
  pub pair: signal::IdentityKeyPair,
  /// Opaque signature which is checked every time a [PreKeyBundle] is created using this signed
  /// pre-key.
  pub signature: Box<[u8]>,
}

fn get_timestamp() -> u64 {
  SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .expect("timestamp calculation will never fail")
    .as_secs()
}

impl SignedPreKey {
  /// Mutate `id_store` and `signed_prekey_store` to instantiate a [signal::SignedPreKeyRecord].
  ///
  /// Used in [generate_signed_pre_key].
  pub async fn intern<
    Record,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    SPK: signal::SignedPreKeyStore + Persistent<Record>,
    R: CryptoRng + Rng,
  >(
    params: SignedPreKeyRequest,
    id_store: &mut ID,
    signed_prekey_store: &mut SPK,
    csprng: &mut R,
  ) -> Result<Self, Error> {
    let SignedPreKeyRequest { id, pair } = params;

    let pub_signed_prekey: Box<[u8]> = pair.public_key().serialize();

    let pub_sign = id_store
      .get_identity_key_pair(None)
      .await?
      .private_key()
      .calculate_signature(&pub_signed_prekey, csprng)?;
    id_store.persist().await?;

    let inner =
      signal::SignedPreKeyRecord::new(id.into(), get_timestamp(), &pair.into(), &pub_sign);
    signed_prekey_store
      .save_signed_pre_key(id.into(), &inner, None)
      .await?;
    signed_prekey_store.persist().await?;

    Ok(Self {
      id,
      pair,
      signature: pub_sign,
    })
  }
}

/// Create a new signed pre-key from random bits as per the [X3DH] key agreement protocol.
///
///```
/// # fn main() -> Result<(), grouplink::error::Error> {
/// use grouplink::*;
/// use std::path::PathBuf;
/// # use std::env::set_current_dir;
/// # use tempdir::TempDir;
/// # let tmp_dir = TempDir::new("doctest-cwd").unwrap();
/// # set_current_dir(tmp_dir.path()).unwrap();
/// # use futures::executor::block_on;
/// # block_on(async {
///
/// // Create a new identity.
/// let alice = generate_identity();
///
/// // Create a mutable store.
/// let mut alice_store =
///   initialize_file_backed_store(DirectoryStoreRequest {
///     path: PathBuf::from("alice"), // Subdirectory of cwd.
///     id: alice.crypto,
///     behavior: ExtractionBehavior::OverwriteWithDefault,
///   }).await?;
///
/// // Create a new signed pre-key from random bits.
/// # #[allow(unused_variables)]
/// let signed_pre_key = generate_signed_pre_key(&mut alice_store).await?;
/// # Ok(())
/// # })
/// # }
///```
/// [X3DH]: https://signal.org/docs/specifications/x3dh/#publishing-keys
pub async fn generate_signed_pre_key<
  Record,
  S: signal::SessionStore + Persistent<Record>,
  PK: signal::PreKeyStore + Persistent<Record>,
  SPK: signal::SignedPreKeyStore + Persistent<Record>,
  ID: signal::IdentityKeyStore + Persistent<Record>,
  Sender: signal::SenderKeyStore + Persistent<Record>,
>(
  store: &mut Store<Record, S, PK, SPK, ID, Sender>,
) -> Result<SignedPreKey, Error> {
  let req = SignedPreKeyRequest::generate((), &mut rand::thread_rng());
  SignedPreKey::intern(
    req,
    &mut store.identity_store,
    &mut store.signed_pre_key_store,
    &mut rand::thread_rng(),
  )
  .await
}

/// Specify the parameters to create a new [OneTimePreKey].
#[derive(Debug, Clone, Copy)]
pub struct OneTimePreKeyRequest {
  /// Specifies this particular one-time pre-key in the local [PreKeyStore]. Randomly generated
  /// upon creation of a [Self].
  pub id: signal::PreKeyId,
  /// The cryptographic public/private key pair represented by the one-time pre-key to
  /// create. Randomly generated upon creation of a [Self].
  pub pair: signal::IdentityKeyPair,
}

impl Spontaneous<()> for OneTimePreKeyRequest {
  fn generate<R: CryptoRng + Rng>(_params: (), r: &mut R) -> Self {
    let pair = signal::IdentityKeyPair::generate(r);
    let id: signal::PreKeyId = Box::new(r).gen::<u32>().into();
    Self { id, pair }
  }
}

/// Represents a one-time pre-key as per the [X3DH] key agreement protocol.
///
/// As the name implies, one is created and consumed for each [PreKeyBundle].
///
/// [X3DH]: https://signal.org/docs/specifications/x3dh/#publishing-keys
#[derive(Debug, Clone, Copy)]
pub struct OneTimePreKey {
  /// From [OneTimePreKeyRequest::id].
  pub id: signal::PreKeyId,
  /// From [OneTimePreKeyRequest::pair].
  pub pair: signal::IdentityKeyPair,
}

impl OneTimePreKey {
  /// Mutate `store` to instantiate a [signal::PreKeyRecord].
  ///
  /// Used in [generate_one_time_pre_key].
  pub async fn intern<Record, PK: signal::PreKeyStore + Persistent<Record>>(
    params: OneTimePreKeyRequest,
    store: &mut PK,
  ) -> Result<Self, Error> {
    let OneTimePreKeyRequest { id, pair } = params;
    let inner = signal::PreKeyRecord::new(id.into(), &pair.into());
    store.save_pre_key(id.into(), &inner, None).await?;
    store.persist().await?;
    Ok(Self { id, pair })
  }
}

/// Create a new one-time pre-key from random bits as per the [X3DH] key agreement protocol.
///
///```
/// # fn main() -> Result<(), grouplink::error::Error> {
/// use grouplink::*;
/// use std::path::PathBuf;
/// # use std::env::set_current_dir;
/// # use tempdir::TempDir;
/// # let tmp_dir = TempDir::new("doctest-cwd").unwrap();
/// # set_current_dir(tmp_dir.path()).unwrap();
/// # use futures::executor::block_on;
/// # block_on(async {
///
/// // Create a new identity.
/// let alice = generate_identity();
///
/// // Create a mutable store.
/// let mut alice_store =
///   initialize_file_backed_store(DirectoryStoreRequest {
///     path: PathBuf::from("alice"), // Subdirectory of cwd.
///     id: alice.crypto,
///     behavior: ExtractionBehavior::OverwriteWithDefault,
///   }).await?;
///
/// // Create a new one-time pre-key from random bits.
/// # #[allow(unused_variables)]
/// let one_time_pre_key = generate_one_time_pre_key(&mut alice_store).await?;
/// # Ok(())
/// # })
/// # }
///```
/// [X3DH]: https://signal.org/docs/specifications/x3dh/#publishing-keys
pub async fn generate_one_time_pre_key<
  Record,
  S: signal::SessionStore + Persistent<Record>,
  PK: signal::PreKeyStore + Persistent<Record>,
  SPK: signal::SignedPreKeyStore + Persistent<Record>,
  ID: signal::IdentityKeyStore + Persistent<Record>,
  Sender: signal::SenderKeyStore + Persistent<Record>,
>(
  store: &mut Store<Record, S, PK, SPK, ID, Sender>,
) -> Result<OneTimePreKey, Error> {
  let req = OneTimePreKeyRequest::generate((), &mut rand::thread_rng());
  OneTimePreKey::intern(req, &mut store.pre_key_store).await
}

/// Specify the parameters to create a new [PreKeyBundle].
#[derive(Debug, Clone)]
pub struct PreKeyBundleRequest {
  /// Specifies the external-facing identity whom the [PreKeyBundle] lets you start a new message
  /// chain with.
  pub destination: ExternalIdentity,
  /// Produced by [generate_signed_pre_key].
  ///
  /// TODO: likely downloaded from some sort of keyserver???
  pub signed: SignedPreKey,
  /// Produced by [generate_one_time_pre_key].
  pub one_time: OneTimePreKey,
  /// The private cryptographic information needed to sign this pre-key bundle to verify it came
  /// from this identity.
  pub identity: CryptographicIdentity,
}

impl PreKeyBundleRequest {
  /// Read from `store` to create a [PreKeyBundleRequest] instance representing the
  /// store's identity.
  ///
  /// Used in [generate_pre_key_bundle].
  pub async fn create<Record, ID: signal::IdentityKeyStore + Persistent<Record>>(
    destination: ExternalIdentity,
    signed: SignedPreKey,
    one_time: OneTimePreKey,
    store: &ID,
  ) -> Result<Self, Error> {
    let seed = store.get_local_registration_id(None).await?;
    let inner = store.get_identity_key_pair(None).await?;
    let identity = CryptographicIdentity { inner, seed };
    Ok(Self {
      destination,
      signed,
      one_time,
      identity,
    })
  }
}

/// Represents a pre-key bundle as per the [X3DH] key agreement protocol.
///
/// This object is generated from a [SignedPreKey] and a [OneTimePreKey].
///
/// [X3DH]: https://signal.org/docs/specifications/x3dh/#publishing-keys
#[derive(Debug, Clone)]
pub struct PreKeyBundle {
  /// From [PreKeyBundleRequest::destination].
  pub destination: ExternalIdentity,
  /// Underlying concept exposed by [libsignal_protocol].
  pub inner: signal::PreKeyBundle,
}

/// This is laborious and cannot be `derive`d because [signal::PreKeyBundle] does not implement
/// [PartialEq] itself.
impl PartialEq for PreKeyBundle {
  fn eq(&self, other: &Self) -> bool {
    (self.destination == other.destination)
      && (self.inner.registration_id().ok() == other.inner.registration_id().ok())
      && (self.inner.device_id().ok() == other.inner.device_id().ok())
      && (self.inner.pre_key_id().ok() == other.inner.pre_key_id().ok())
      && (self.inner.pre_key_public().ok() == other.inner.pre_key_public().ok())
      && (self.inner.signed_pre_key_id().ok() == other.inner.signed_pre_key_id().ok())
      && (self.inner.signed_pre_key_public().ok() == other.inner.signed_pre_key_public().ok())
      && (self.inner.signed_pre_key_signature().ok() == other.inner.signed_pre_key_signature().ok())
      && (self.inner.identity_key().ok() == other.inner.identity_key().ok())
  }
}

impl Eq for PreKeyBundle {}

impl PreKeyBundle {
  /// Generates a new pre-key bundle from the specifications of `request`.
  pub fn new(request: PreKeyBundleRequest) -> Result<Self, Error> {
    let PreKeyBundleRequest {
      destination,
      signed,
      one_time,
      identity: CryptographicIdentity { inner, seed },
    } = request;
    let inner = signal::PreKeyBundle::new(
      seed.into(),
      destination.device_id.into(),
      Some((one_time.id.into(), *one_time.pair.public_key())),
      signed.id.into(),
      *signed.pair.public_key(),
      signed.signature.to_vec(),
      *inner.identity_key(),
    )?;
    Ok(Self { destination, inner })
  }

  /// Mutates `session_store` and `id_store` to register the current bundle's contents to the
  /// underlying [libsignal_protocol] stores.
  ///
  /// Consumes the current bundle instance. When this bundle is consumed, a new message chain is
  /// created so that [encrypt_followup_message] can now be called instead of
  /// [encrypt_initial_message].
  pub async fn process<
    Record,
    S: signal::SessionStore + Persistent<Record>,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    R: CryptoRng + Rng,
  >(
    self,
    session_store: &mut S,
    id_store: &mut ID,
    csprng: &mut R,
  ) -> Result<(), Error> {
    signal::process_prekey_bundle(
      &self.destination.into(),
      session_store,
      id_store,
      &self.inner,
      csprng,
      None,
    )
    .await?;
    session_store.persist().await?;
    id_store.persist().await?;
    Ok(())
  }
}

/// Create a new pre-key bundle from a signed pre-key and a one-time pre-key as per the [X3DH] key
/// agreement protocol.
///
/// The prerequisite keys can be generated with [generate_signed_pre_key] and
/// [generate_one_time_pre_key]:
///```
/// # fn main() -> Result<(), grouplink::error::Error> {
/// use grouplink::*;
/// use std::path::PathBuf;
/// # use std::env::set_current_dir;
/// # use tempdir::TempDir;
/// # let tmp_dir = TempDir::new("doctest-cwd").unwrap();
/// # set_current_dir(tmp_dir.path()).unwrap();
/// # use futures::executor::block_on;
/// # block_on(async {
///
/// // Create a new identity.
/// let alice = generate_identity();
///
/// // Create a mutable store.
/// let mut alice_store =
///   initialize_file_backed_store(DirectoryStoreRequest {
///     path: PathBuf::from("alice"), // Subdirectory of cwd.
///     id: alice.crypto,
///     behavior: ExtractionBehavior::OverwriteWithDefault,
///   }).await?;
///
/// // Create a new signed pre-key from random bits.
/// let signed_pre_key = generate_signed_pre_key(&mut alice_store).await?;
/// // Create a new one-time pre-key from random bits.
/// let one_time_pre_key = generate_one_time_pre_key(&mut alice_store).await?;
///
/// // Create a new pre-key bundle from the given keys.
/// # #[allow(unused_variables)]
/// let pre_key_bundle = generate_pre_key_bundle(alice.external.clone(),
///                                              signed_pre_key,
///                                              one_time_pre_key,
///                                              &mut alice_store).await?;
/// # Ok(())
/// # })
/// # }
///```
/// [X3DH]: https://signal.org/docs/specifications/x3dh/#publishing-keys
pub async fn generate_pre_key_bundle<
  Record,
  S: signal::SessionStore + Persistent<Record>,
  PK: signal::PreKeyStore + Persistent<Record>,
  SPK: signal::SignedPreKeyStore + Persistent<Record>,
  ID: signal::IdentityKeyStore + Persistent<Record>,
  Sender: signal::SenderKeyStore + Persistent<Record>,
>(
  external: ExternalIdentity,
  spk: SignedPreKey,
  opk: OneTimePreKey,
  store: &Store<Record, S, PK, SPK, ID, Sender>,
) -> Result<PreKeyBundle, Error> {
  let req = PreKeyBundleRequest::create(external, spk, opk, &store.identity_store).await?;
  Ok(PreKeyBundle::new(req)?)
}

impl TryFrom<PreKeyBundle> for proto::PreKeyBundle {
  type Error = Error;
  fn try_from(value: PreKeyBundle) -> Result<Self, Error> {
    let PreKeyBundle { destination, inner } = value;
    Ok(proto::PreKeyBundle {
      destination: Some(destination.into()),
      registration_id: Some(inner.registration_id()?),
      pre_key_id: inner.pre_key_id()?.map(|id| id.into()),
      pre_key_public: inner
        .pre_key_public()?
        .map(|key| key.serialize().into_vec()),
      signed_pre_key_id: Some(inner.signed_pre_key_id()?.into()),
      signed_pre_key_public: Some(inner.signed_pre_key_public()?.serialize().into_vec()),
      signed_pre_key_signature: Some(inner.signed_pre_key_signature()?.to_vec()),
      identity_key: Some(inner.identity_key()?.serialize().into_vec()),
    })
  }
}

impl TryFrom<PreKeyBundle> for Box<[u8]> {
  type Error = Error;
  fn try_from(value: PreKeyBundle) -> Result<Self, Error> {
    let proto_message: proto::PreKeyBundle = value.try_into()?;
    Ok(encode_proto_message(proto_message))
  }
}

impl TryFrom<proto::PreKeyBundle> for PreKeyBundle {
  type Error = Error;
  fn try_from(value: proto::PreKeyBundle) -> Result<Self, Error> {
    let proto::PreKeyBundle {
      destination,
      registration_id,
      pre_key_id,
      pre_key_public,
      signed_pre_key_id,
      signed_pre_key_public,
      signed_pre_key_signature,
      identity_key,
    } = value.clone();
    let destination: ExternalIdentity = destination
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
          format!("failed to find `destination` field!"),
          format!("{:?}", value),
        ))
      })?
      .try_into()?;
    let registration_id: u32 = registration_id.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
        format!("failed to find `registration_id` field!"),
        format!("{:?}", value),
      ))
    })?;
    let pre_key_id: Option<signal::PreKeyId> = pre_key_id.map(|key| key.into());
    let pre_key_public: Option<signal::PublicKey> = match pre_key_public {
      Some(key) => Some(signal::PublicKey::try_from(key.as_ref())?),
      None => None,
    };
    let pre_key: Option<(signal::PreKeyId, signal::PublicKey)> = match (pre_key_id, pre_key_public)
    {
      (Some(id), Some(key)) => Some((id, key)),
      (None, None) => None,
      _ => {
        return Err(Error::ProtobufDecodingError(ProtobufCodingFailure::FieldCompositionWasIncorrect(
          format!("if either the fields `pre_key_id` or `pre_key_public` are provided, then *BOTH* must be provided!"),
          format!("{:?}", value)
        )))
      }
    };
    let signed_pre_key_id: signal::SignedPreKeyId = signed_pre_key_id
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
          format!("failed to find `signed_pre_key_id` field!"),
          format!("{:?}", value),
        ))
      })?
      .into();
    let signed_pre_key_public: signal::PublicKey = signed_pre_key_public.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
        format!("failed to find `signed_pre_key_public` field!"),
        format!("{:?}", value),
      ))
    })?[..]
      .try_into()?;
    let signed_pre_key_signature: Vec<u8> = signed_pre_key_signature
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
          format!("failed to find `signed_pre_key_signature` field!"),
          format!("{:?}", value),
        ))
      })?
      .to_vec();
    let identity_key: signal::IdentityKey = identity_key.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
        format!("failed to find `identity_key` field!"),
        format!("{:?}", value),
      ))
    })?[..]
      .try_into()?;
    Ok(Self {
      destination: destination.clone(),
      inner: signal::PreKeyBundle::new(
        registration_id,
        destination.device_id.into(),
        pre_key,
        signed_pre_key_id,
        signed_pre_key_public,
        signed_pre_key_signature,
        identity_key,
      )?,
    })
  }
}

impl TryFrom<&[u8]> for PreKeyBundle {
  type Error = Error;
  fn try_from(value: &[u8]) -> Result<Self, Error> {
    let proto_message = proto::PreKeyBundle::decode(value)?;
    Self::try_from(proto_message)
  }
}

/// Specify the parameters to create a new [SealedSenderMessage] to **securely transfer the identity
/// of [Self::bundle] to another user.**
///
/// This concept does not exist in the base [libsignal_protocol] crate's "sealed sender" messages or
/// in its [libsignal_protocol::CiphertextMessageType] because the Signal client app's HTTPS
/// transport security with the Signal backend server is used to perform this particular encryption.
///
/// For the [grouplink protocol](crate), we want to be able to encrypt this message as a uniform
/// serializable [SealedSenderMessage] instance in a way that the target user can asynchronously
/// decrypt and read. *See [SealedSenderMessage::intern_pre_key_bundle].*
#[derive(Debug, Clone)]
pub struct SealedSenderPreKeyBundleRequest {
  /// Gets directly encoded into [SealedSenderMessageRequest::bundle] (after being encrypted in
  /// transit).
  pub bundle: PreKeyBundle,
  /// Newly generated certificate with cryptographic information to encrypt this message's sender.
  pub sender_cert: SenderCert,
  pub destination: ExternalIdentity,
}

/// Specify the parameters to create a new [SealedSenderMessage] **to kick off a new
/// message chain.**
///
/// This is currently implemented by handing off to
/// a [SealedSenderFollowupMessageRequest] instance.
#[derive(Debug, Clone)]
pub struct SealedSenderMessageRequest<'a> {
  /// Bundle for the recipient to then [PreKeyBundle::process] to **create a new message chain from
  /// a completed [X3DH] key agreement.**
  ///
  /// Contains the [PreKeyBundle::destination] to send to.
  ///
  /// [X3DH]: https://signal.org/docs/specifications/x3dh/#publishing-keys
  pub bundle: PreKeyBundle,
  /// Newly generated certificate with cryptographic information to encrypt this message's sender.
  pub sender_cert: SenderCert,
  /// The message to encrypt! This message will be the first in the message chain.
  pub plaintext: &'a [u8],
}

/// Specify the parameters to create a new [SealedSenderMessage] **to continue an existing
/// message chain.**
#[derive(Debug, Clone)]
pub struct SealedSenderFollowupMessageRequest<'a> {
  /// The external-facing identity to send to. This is *not* encrypted.
  pub target: ExternalIdentity,
  /// Newly generated certificate with cryptographic information to encrypt this message's sender.
  pub sender_cert: SenderCert,
  /// The message to encrypt! This message will iterate a [KDF] corresponding to this message chain.
  ///
  /// [KDF]: https://signal.org/docs/specifications/doubleratchet/#kdf-chains
  pub plaintext: &'a [u8],
}

/// Send an encrypted message without revealing the identity of its author except to the
/// intended recipient! *See [Sealed Sender messages in Signal].*
///
/// [Sealed Sender messages in Signal]: https://signal.org/blog/sealed-sender/
#[derive(Debug, Clone)]
pub struct SealedSenderMessage {
  /// From [SenderCert::trust_root].
  pub trust_root: signal::PublicKey,
  /// The opaque message ciphertext.
  pub encrypted_message: Box<[u8]>,
}

/// This cannot be `derive`d because [Box::<[u8]>] does not implement [PartialEq] itself.
impl PartialEq for SealedSenderMessage {
  fn eq(&self, other: &Self) -> bool {
    (self.trust_root == other.trust_root)
      && (self.encrypted_message.as_ref() == other.encrypted_message.as_ref())
  }
}

impl Eq for SealedSenderMessage {}

impl SealedSenderMessage {
  /// Mutate `session_store` and `id_store` to **decrypt a sealed-sender message which produces
  /// a new [PreKeyBundle].**
  ///
  /// Used in [encrypt_pre_key_bundle_message].
  pub async fn intern_pre_key_bundle<
    Record,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    R: CryptoRng + Rng,
  >(
    request: SealedSenderPreKeyBundleRequest,
    id_store: &mut ID,
    csprng: &mut R,
  ) -> Result<Self, Error> {
    let SealedSenderPreKeyBundleRequest {
      bundle,
      sender_cert: SenderCert {
        inner: sender_cert,
        trust_root,
      },
      destination,
    } = request;

    let dest: signal::ProtocolAddress = destination.into();
    let encoded_bundle: Box<[u8]> = bundle.try_into()?;

    let usmc = signal::UnidentifiedSenderMessageContent::new(
      signal::CiphertextMessageType::EncryptedPreKeyBundle,
      sender_cert,
      signal::encrypt_pre_key_bundle_message(&dest, encoded_bundle.into_vec(), id_store, csprng)
        .await?,
      signal::ContentHint::Default,
      None,
    )?;
    let encrypted_message =
      signal::sealed_sender_multi_recipient_encrypt(&[&dest], &usmc, id_store, None, csprng)
        .await?
        .into_boxed_slice();
    id_store.persist().await?;

    Ok(Self {
      trust_root,
      encrypted_message,
    })
  }

  /// Mutate `session_store` and `id_store` to **register a sealed-sender message for a new
  /// message chain** with the underlying [libsignal_protocol] crate.
  ///
  /// Used in [encrypt_initial_message].
  pub async fn intern<
    'a,
    Record,
    S: signal::SessionStore + Persistent<Record>,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    R: CryptoRng + Rng,
  >(
    request: SealedSenderMessageRequest<'a>,
    session_store: &mut S,
    id_store: &mut ID,
    csprng: &mut R,
  ) -> Result<Self, Error> {
    let SealedSenderMessageRequest {
      bundle,
      sender_cert,
      plaintext,
    } = request;

    let target = bundle.destination.clone();
    bundle.process(session_store, id_store, csprng).await?;

    Self::intern_followup(
      SealedSenderFollowupMessageRequest {
        target,
        sender_cert,
        plaintext,
      },
      session_store,
      id_store,
      csprng,
    )
    .await
  }

  /// Mutate `session_store` and `id_store` to **register a sealed-sender message for an existing
  /// message chain** with the underlying [libsignal_protocol] crate.
  ///
  /// Used in [encrypt_followup_message] and [Self::intern].
  pub async fn intern_followup<
    'a,
    Record,
    S: signal::SessionStore + Persistent<Record>,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    R: CryptoRng + Rng,
  >(
    request: SealedSenderFollowupMessageRequest<'a>,
    session_store: &mut S,
    id_store: &mut ID,
    csprng: &mut R,
  ) -> Result<Self, Error> {
    let SealedSenderFollowupMessageRequest {
      target: destination,
      sender_cert: SenderCert {
        inner: sender_cert,
        trust_root,
      },
      plaintext,
    } = request;

    let encrypted_message = signal::sealed_sender_encrypt(
      &destination.into(),
      &sender_cert,
      plaintext,
      session_store,
      id_store,
      None,
      csprng,
    )
    .await?
    .into_boxed_slice();
    session_store.persist().await?;
    id_store.persist().await?;

    Ok(Self {
      trust_root,
      encrypted_message,
    })
  }
}

/// ???
///
///```
///```
pub async fn encrypt_pre_key_bundle_message<
  Record,
  S: signal::SessionStore + Persistent<Record>,
  PK: signal::PreKeyStore + Persistent<Record>,
  SPK: signal::SignedPreKeyStore + Persistent<Record>,
  ID: signal::IdentityKeyStore + Persistent<Record>,
  Sender: signal::SenderKeyStore + Persistent<Record>,
>(
  req: SealedSenderPreKeyBundleRequest,
  store: &mut Store<Record, S, PK, SPK, ID, Sender>,
) -> Result<SealedSenderMessage, Error> {
  SealedSenderMessage::intern_pre_key_bundle::<Record, ID, _>(
    req,
    &mut store.identity_store,
    &mut rand::thread_rng(),
  )
  .await
}

/// Encrypt a [SealedSenderMessage] by invoking [PreKeyBundle::process]. **This will kick off
/// a new message chain.**
///
///```
/// # fn main() -> Result<(), grouplink::error::Error> {
/// use grouplink::*;
/// # use futures::executor::block_on;
/// use std::path::PathBuf;
/// # use std::env::set_current_dir;
/// # use tempdir::TempDir;
/// # let tmp_dir = TempDir::new("doctest-cwd").unwrap();
/// # set_current_dir(tmp_dir.path()).unwrap();
/// # block_on(async {
///
/// // Create a new identity.
/// let alice = generate_identity();
/// let alice_client = generate_sealed_sender_identity(alice.external.clone());
///
/// // Create a mutable store.
/// let mut alice_store =
///   initialize_file_backed_store(DirectoryStoreRequest {
///     path: PathBuf::from("alice"), // Subdirectory of cwd.
///     id: alice.crypto,
///     behavior: ExtractionBehavior::OverwriteWithDefault,
///   }).await?;
///
/// // Create a destination identity.
/// let bob = generate_identity();
/// let mut bob_store =
///   initialize_file_backed_store(DirectoryStoreRequest {
///     path: PathBuf::from("bob"), // Subdirectory of cwd.
///     id: bob.crypto,
///     behavior: ExtractionBehavior::OverwriteWithDefault,
///   }).await?;
///
/// // Alice sends a message to Bob to kick off a message chain, which requires a pre-key bundle.
/// // See https://signal.org/docs/specifications/x3dh/#publishing-keys.
/// let bob_signed_pre_key = generate_signed_pre_key(&mut bob_store).await?;
/// let bob_one_time_pre_key = generate_one_time_pre_key(&mut bob_store).await?;
///
/// // Generate the pre-key bundle.
/// let bob_pre_key_bundle = generate_pre_key_bundle(bob.external.clone(),
///                                                  bob_signed_pre_key,
///                                                  bob_one_time_pre_key,
///                                                  &bob_store).await?;
///
/// // Encrypt a message.
/// # #[allow(unused_variables)]
/// let initial_message = encrypt_initial_message(
///   SealedSenderMessageRequest {
///     bundle: bob_pre_key_bundle,
///     sender_cert: generate_sender_cert(alice_client.stripped_e164(), alice.crypto,
///                                       SenderCertTTL::default())?,
///     plaintext: "asdf".as_bytes(),
///   },
///   &mut alice_store,
/// ).await?;
///
/// # Ok(())
/// # }) // async
/// # }
///```
pub async fn encrypt_initial_message<
  Record,
  S: signal::SessionStore + Persistent<Record>,
  PK: signal::PreKeyStore + Persistent<Record>,
  SPK: signal::SignedPreKeyStore + Persistent<Record>,
  ID: signal::IdentityKeyStore + Persistent<Record>,
  Sender: signal::SenderKeyStore + Persistent<Record>,
>(
  req: SealedSenderMessageRequest<'_>,
  store: &mut Store<Record, S, PK, SPK, ID, Sender>,
) -> Result<SealedSenderMessage, Error> {
  SealedSenderMessage::intern(
    req,
    &mut store.session_store,
    &mut store.identity_store,
    &mut rand::thread_rng(),
  )
  .await
}

/// Encrypt a [SealedSenderMessage]. **This will use an existing message chain.**
///
/// An *existing* message chain can be initialized by calling [encrypt_initial_message] and then
/// [decrypt_message]:
///```
/// # fn main() -> Result<(), grouplink::error::Error> {
/// use grouplink::*;
/// # use futures::executor::block_on;
/// use std::path::PathBuf;
/// # use std::env::set_current_dir;
/// # use tempdir::TempDir;
/// # let tmp_dir = TempDir::new("doctest-cwd").unwrap();
/// # set_current_dir(tmp_dir.path()).unwrap();
/// # block_on(async {
///
/// // Create a new identity.
/// let alice = generate_identity();
/// let alice_client = generate_sealed_sender_identity(alice.external.clone());
///
/// // Create a mutable store.
/// let mut alice_store =
///   initialize_file_backed_store(DirectoryStoreRequest {
///     path: PathBuf::from("alice"), // Subdirectory of cwd.
///     id: alice.crypto,
///     behavior: ExtractionBehavior::OverwriteWithDefault,
///   }).await?;
///
/// // Create a destination identity.
/// let bob = generate_identity();
/// let bob_client = generate_sealed_sender_identity(bob.external.clone());
/// let mut bob_store =
///   initialize_file_backed_store(DirectoryStoreRequest {
///     path: PathBuf::from("bob"), // Subdirectory of cwd.
///     id: bob.crypto,
///     behavior: ExtractionBehavior::OverwriteWithDefault,
///   }).await?;
///
/// // Alice sends a message to Bob to kick off a message chain, which requires a pre-key bundle.
/// // See https://signal.org/docs/specifications/x3dh/#publishing-keys.
/// let bob_signed_pre_key = generate_signed_pre_key(&mut bob_store).await?;
/// let bob_one_time_pre_key = generate_one_time_pre_key(&mut bob_store).await?;
///
/// // Generate the pre-key bundle.
/// let bob_pre_key_bundle = generate_pre_key_bundle(bob.external.clone(),
///                                                  bob_signed_pre_key,
///                                                  bob_one_time_pre_key,
///                                                  &bob_store).await?;
///
/// // Encrypt a message.
/// let initial_message = encrypt_initial_message(
///   SealedSenderMessageRequest {
///     bundle: bob_pre_key_bundle,
///     sender_cert: generate_sender_cert(alice_client.stripped_e164(), alice.crypto,
///                                       SenderCertTTL::default())?,
///     plaintext: "asdf".as_bytes(),
///   },
///   &mut alice_store,
/// ).await?;
///
/// // Decrypt the sealed-sender message.
/// let message_result = decrypt_message(
///   SealedSenderDecryptionRequest {
///     inner: initial_message,
///     local_identity: bob_client.clone(),
///   },
///   &mut bob_store,
/// ).await?;
///
/// assert!(message_result.sender == alice_client.stripped_e164());
/// assert!("asdf" == std::str::from_utf8(message_result.plaintext.as_ref()).unwrap());
///
/// // Now send a message back to Alice.
/// # #[allow(unused_variables)]
/// let bob_follow_up = encrypt_followup_message(
///   SealedSenderFollowupMessageRequest {
///     target: alice.external.clone(),
///     sender_cert: generate_sender_cert(bob_client.stripped_e164(), bob.crypto,
///                                       SenderCertTTL::default())?,
///     plaintext: "oh ok".as_bytes(),
///   },
///   &mut bob_store,
/// ).await?;
///
/// # Ok(())
/// # }) // async
/// # }
///```
pub async fn encrypt_followup_message<
  Record,
  S: signal::SessionStore + Persistent<Record>,
  PK: signal::PreKeyStore + Persistent<Record>,
  SPK: signal::SignedPreKeyStore + Persistent<Record>,
  ID: signal::IdentityKeyStore + Persistent<Record>,
  Sender: signal::SenderKeyStore + Persistent<Record>,
>(
  req: SealedSenderFollowupMessageRequest<'_>,
  store: &mut Store<Record, S, PK, SPK, ID, Sender>,
) -> Result<SealedSenderMessage, Error> {
  SealedSenderMessage::intern_followup(
    req,
    &mut store.session_store,
    &mut store.identity_store,
    &mut rand::thread_rng(),
  )
  .await
}

impl From<SealedSenderMessage> for proto::SealedSenderMessage {
  fn from(value: SealedSenderMessage) -> Self {
    let SealedSenderMessage {
      trust_root,
      encrypted_message,
    } = value;
    proto::SealedSenderMessage {
      trust_root_public_key: Some(trust_root.serialize().into_vec()),
      encrypted_sealed_sender_message: Some(encrypted_message.into_vec()),
    }
  }
}

impl From<SealedSenderMessage> for Box<[u8]> {
  fn from(value: SealedSenderMessage) -> Self {
    let proto_message: proto::SealedSenderMessage = value.into();
    encode_proto_message(proto_message)
  }
}

impl TryFrom<proto::SealedSenderMessage> for SealedSenderMessage {
  type Error = Error;
  fn try_from(value: proto::SealedSenderMessage) -> Result<Self, Error> {
    let proto::SealedSenderMessage {
      trust_root_public_key,
      encrypted_sealed_sender_message,
    } = value.clone();
    let trust_root_public_key = signal::PublicKey::try_from(
      trust_root_public_key
        .ok_or_else(|| {
          Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
            format!("failed to find `trust_root_public_key` field!"),
            format!("{:?}", value),
          ))
        })?
        .as_ref(),
    )?;
    let encrypted_sealed_sender_message: Box<[u8]> = encrypted_sealed_sender_message
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
          format!("failed to find `encrypted_sealed_sender_message` field!"),
          format!("{:?}", value),
        ))
      })?
      .into_boxed_slice();
    Ok(Self {
      trust_root: trust_root_public_key,
      encrypted_message: encrypted_sealed_sender_message,
    })
  }
}

impl TryFrom<&[u8]> for SealedSenderMessage {
  type Error = Error;
  fn try_from(value: &[u8]) -> Result<Self, Error> {
    let proto_message = proto::SealedSenderMessage::decode(value)?;
    Self::try_from(proto_message)
  }
}

/// Specify the parameters to decrypt a [SealedSenderMessage].
#[derive(Debug, Clone)]
pub struct SealedSenderDecryptionRequest {
  /// The message to decrypt.
  pub inner: SealedSenderMessage,
  /// The augmented external-facing identity which disambiguates this client from others
  /// representing the same identity. *See [SealedSenderIdentity].*
  pub local_identity: SealedSenderIdentity,
}

/// The result of decrypting a [SealedSenderMessage].
#[derive(Debug, Clone)]
pub struct SealedSenderMessageResult {
  /// The augmented external-facing identity who sent the message, encrypted in the message itself.
  pub sender: SealedSenderIdentity,
  /// The decrypted original input provided to [SealedSenderFollowupMessageRequest::plaintext].
  pub plaintext: Box<[u8]>,
}

impl SealedSenderMessageResult {
  async fn intern_pre_key_bundle<
    Record,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    S: signal::SessionStore + Persistent<Record>,
    PK: signal::PreKeyStore + Persistent<Record>,
    SPK: signal::SignedPreKeyStore + Persistent<Record>,
  >(
    message: SealedSenderDecryptionRequest,
    id_store: &mut ID,
    session_store: &mut S,
    pre_key_store: &mut PK,
    signed_pre_key_store: &mut SPK,
  ) -> Result<Self, Error> {
    let SealedSenderDecryptionRequest {
      inner: SealedSenderMessage {
        trust_root,
        encrypted_message,
      },
      local_identity:
        SealedSenderIdentity {
          inner:
            ExternalIdentity {
              name: local_uuid,
              device_id: local_device_id,
            },
          e164: local_e164,
        },
    } = message;

    let signal::SealedSenderDecryptionResult {
      sender_uuid,
      sender_e164,
      device_id: sender_device_id,
      message: plaintext,
    } = signal::sealed_sender_decrypt(
      encrypted_message.as_ref(),
      &trust_root,
      get_timestamp(),
      local_e164,
      local_uuid,
      local_device_id.into(),
      id_store,
      session_store,
      pre_key_store,
      signed_pre_key_store,
      None,
    )
    .await?;
    id_store.persist().await?;
    session_store.persist().await?;
    pre_key_store.persist().await?;
    signed_pre_key_store.persist().await?;

    let sender = SealedSenderIdentity {
      inner: ExternalIdentity {
        name: sender_uuid,
        device_id: sender_device_id.into(),
      },
      e164: sender_e164,
    };
    Ok(Self {
      sender,
      plaintext: plaintext.into_boxed_slice(),
    })
  }

  /// Mutate `id_store`, `session_store`, `pre_key_store`, and `signed_pre_key_store` to to decrypt
  /// `message`.
  ///
  /// Used in [decrypt_message].
  pub async fn intern<
    Record,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    S: signal::SessionStore + Persistent<Record>,
    PK: signal::PreKeyStore + Persistent<Record>,
    SPK: signal::SignedPreKeyStore + Persistent<Record>,
  >(
    message: SealedSenderDecryptionRequest,
    id_store: &mut ID,
    session_store: &mut S,
    pre_key_store: &mut PK,
    signed_pre_key_store: &mut SPK,
  ) -> Result<Self, Error> {
    let SealedSenderDecryptionRequest {
      inner: SealedSenderMessage {
        trust_root,
        encrypted_message,
      },
      local_identity:
        SealedSenderIdentity {
          inner:
            ExternalIdentity {
              name: local_uuid,
              device_id: local_device_id,
            },
          e164: local_e164,
        },
    } = message;

    let signal::SealedSenderDecryptionResult {
      sender_uuid,
      sender_e164,
      device_id: sender_device_id,
      message: plaintext,
    } = signal::sealed_sender_decrypt(
      encrypted_message.as_ref(),
      &trust_root,
      get_timestamp(),
      local_e164,
      local_uuid,
      local_device_id.into(),
      id_store,
      session_store,
      pre_key_store,
      signed_pre_key_store,
      None,
    )
    .await?;
    id_store.persist().await?;
    session_store.persist().await?;
    pre_key_store.persist().await?;
    signed_pre_key_store.persist().await?;

    let sender = SealedSenderIdentity {
      inner: ExternalIdentity {
        name: sender_uuid,
        device_id: sender_device_id.into(),
      },
      e164: sender_e164,
    };
    Ok(Self {
      sender,
      plaintext: plaintext.into_boxed_slice(),
    })
  }
}

pub async fn decrypt_pre_key_message<
  Record,
  S: signal::SessionStore + Persistent<Record>,
  PK: signal::PreKeyStore + Persistent<Record>,
  SPK: signal::SignedPreKeyStore + Persistent<Record>,
  ID: signal::IdentityKeyStore + Persistent<Record>,
  Sender: signal::SenderKeyStore + Persistent<Record>,
>(
  req: SealedSenderDecryptionRequest,
  store: &mut Store<Record, S, PK, SPK, ID, Sender>,
) -> Result<SealedSenderMessageResult, Error> {
  SealedSenderMessageResult::intern_pre_key_bundle(
    req,
    &mut store.identity_store,
    &mut store.session_store,
    &mut store.pre_key_store,
    &mut store.signed_pre_key_store,
  )
  .await
}

/// Decrypt a [SealedSenderMessage]. **This will use an existing message chain.**
///
/// An *existing* message chain can be initialized by calling [encrypt_initial_message] or
/// [encrypt_followup_message]:
///```
/// # fn main() -> Result<(), grouplink::error::Error> {
/// use grouplink::*;
/// # use futures::executor::block_on;
/// use std::path::PathBuf;
/// # use std::env::set_current_dir;
/// # use tempdir::TempDir;
/// # let tmp_dir = TempDir::new("doctest-cwd").unwrap();
/// # set_current_dir(tmp_dir.path()).unwrap();
/// # block_on(async {
///
/// // Create a new identity.
/// let alice = generate_identity();
/// let alice_client = generate_sealed_sender_identity(alice.external.clone());
///
/// // Create a mutable store.
/// let mut alice_store =
///   initialize_file_backed_store(DirectoryStoreRequest {
///     path: PathBuf::from("alice"), // Subdirectory of cwd.
///     id: alice.crypto,
///     behavior: ExtractionBehavior::OverwriteWithDefault,
///   }).await?;
///
/// // Create a destination identity.
/// let bob = generate_identity();
/// let bob_client = generate_sealed_sender_identity(bob.external.clone());
/// let mut bob_store =
///   initialize_file_backed_store(DirectoryStoreRequest {
///     path: PathBuf::from("bob"), // Subdirectory of cwd.
///     id: bob.crypto,
///     behavior: ExtractionBehavior::OverwriteWithDefault,
///   }).await?;
///
/// // Alice sends a message to Bob to kick off a message chain, which requires a pre-key bundle.
/// // See https://signal.org/docs/specifications/x3dh/#publishing-keys.
/// let bob_signed_pre_key = generate_signed_pre_key(&mut bob_store).await?;
/// let bob_one_time_pre_key = generate_one_time_pre_key(&mut bob_store).await?;
///
/// // Generate the pre-key bundle.
/// let bob_pre_key_bundle = generate_pre_key_bundle(bob.external.clone(),
///                                                  bob_signed_pre_key,
///                                                  bob_one_time_pre_key,
///                                                  &bob_store).await?;
///
/// // Encrypt a message.
/// let initial_message = encrypt_initial_message(
///   SealedSenderMessageRequest {
///     bundle: bob_pre_key_bundle,
///     sender_cert: generate_sender_cert(alice_client.stripped_e164(), alice.crypto,
///                                       SenderCertTTL::default())?,
///     plaintext: "asdf".as_bytes(),
///   },
///   &mut alice_store,
/// ).await?;
///
/// // Decrypt the sealed-sender message.
/// let message_result = decrypt_message(
///   SealedSenderDecryptionRequest {
///     inner: initial_message,
///     local_identity: bob_client.clone(),
///   },
///   &mut bob_store,
/// ).await?;
///
/// assert!(message_result.sender == alice_client.stripped_e164());
/// assert!("asdf" == std::str::from_utf8(message_result.plaintext.as_ref()).unwrap());
/// # Ok(())
/// # }) // async
/// # }
///```
pub async fn decrypt_message<
  Record,
  S: signal::SessionStore + Persistent<Record>,
  PK: signal::PreKeyStore + Persistent<Record>,
  SPK: signal::SignedPreKeyStore + Persistent<Record>,
  ID: signal::IdentityKeyStore + Persistent<Record>,
  Sender: signal::SenderKeyStore + Persistent<Record>,
>(
  req: SealedSenderDecryptionRequest,
  store: &mut Store<Record, S, PK, SPK, ID, Sender>,
) -> Result<SealedSenderMessageResult, Error> {
  SealedSenderMessageResult::intern(
    req,
    &mut store.identity_store,
    &mut store.session_store,
    &mut store.pre_key_store,
    &mut store.signed_pre_key_store,
  )
  .await
}

#[cfg(test)]
pub mod proptest_strategies {
  use super::*;
  use crate::{
    error::Error,
    identity::proptest_strategies::*,
    store::{proptest_strategies::*, *},
  };

  use futures::executor::block_on;
  use proptest::arbitrary::Arbitrary;
  use proptest::prelude::*;

  impl Arbitrary for SignedPreKeyRequest {
    type Parameters = ();
    type Strategy = SpontaneousParamsTree<(), Self>;
    fn arbitrary_with(args: ()) -> Self::Strategy {
      SpontaneousParamsTree::new(args)
    }
  }

  impl Arbitrary for OneTimePreKeyRequest {
    type Parameters = ();
    type Strategy = SpontaneousParamsTree<(), Self>;
    fn arbitrary_with(args: ()) -> Self::Strategy {
      SpontaneousParamsTree::new(args)
    }
  }

  pub async fn generate_signed_pre_key_wrapped(
    store: InMemStoreWrapper,
    req: SignedPreKeyRequest,
  ) -> Result<SignedPreKey, Error> {
    let Store {
      ref mut identity_store,
      ref mut signed_pre_key_store,
      ..
    } = *store.write();
    SignedPreKey::intern(
      req,
      identity_store,
      signed_pre_key_store,
      &mut rand::thread_rng(),
    )
    .await
  }

  prop_compose! {
    pub fn signed_pre_key(store: InMemStoreWrapper)(
      req in any::<SignedPreKeyRequest>()
    ) -> SignedPreKey {
      let store = store.clone();
      block_on(generate_signed_pre_key_wrapped(store, req)).unwrap()
    }
  }

  pub async fn generate_one_time_pre_key_wrapped(
    store: InMemStoreWrapper,
    req: OneTimePreKeyRequest,
  ) -> Result<OneTimePreKey, Error> {
    let Store {
      ref mut pre_key_store,
      ..
    } = *store.write();
    OneTimePreKey::intern(req, pre_key_store).await
  }

  prop_compose! {
    pub fn one_time_pre_key(store: InMemStoreWrapper)(
      req in any::<OneTimePreKeyRequest>()
    ) -> OneTimePreKey {
      let store = store.clone();
      block_on(generate_one_time_pre_key_wrapped(store, req)).unwrap()
    }
  }

  pub async fn generate_pre_key_bundle_wrapped(
    store: InMemStoreWrapper,
    external: ExternalIdentity,
    spk: SignedPreKey,
    opk: OneTimePreKey,
  ) -> Result<PreKeyBundle, Error> {
    let Store {
      ref identity_store, ..
    } = *store.read();
    let req = PreKeyBundleRequest::create(external, spk, opk, identity_store).await?;
    Ok(PreKeyBundle::new(req)?)
  }

  prop_compose! {
    pub fn pre_key_bundle(store: InMemStoreWrapper, external: ExternalIdentity)(
      spk in signed_pre_key(store.clone()),
      opk in one_time_pre_key(store.clone())
    ) -> PreKeyBundle {
      let store = store.clone();
      let external = external.clone();
      block_on(generate_pre_key_bundle_wrapped(store, external, spk, opk)).unwrap()
    }
  }
}

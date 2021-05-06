/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???
//!
//!```
//! # fn main() -> Result<(), grouplink::error::Error> {
//! use grouplink::{identity::*, session::*, store::{file_persistence::*, conversions::*, *}};
//! use grouplink::session::PreKeyBundle;
//! use libsignal_protocol::*;
//! use rand::{self, Rng};
//! use uuid::Uuid;
//! use futures::executor::block_on;
//! use std::convert::{TryFrom, TryInto};
//! use std::path::PathBuf;
//!
//! // Create a new identity.
//! let alice = Identity::generate((), &mut rand::thread_rng());
//! let alice_address: ProtocolAddress = alice.external.clone().into();
//!
//! // Create a mutable store.
//! let alice_store_request = DirectoryStoreRequest {
//!   path: PathBuf::from("/home/cosmicexplorer/alice"),
//!   id: alice.crypto,
//!  };
//! let mut alice_store =
//!   block_on(FileStore::initialize_file_backed_store_with_default(
//!              alice_store_request.into_layout()?))?;
//!
//! // Create a destination identity.
//! let bob = Identity::generate((), &mut rand::thread_rng());
//! let bob_address: ProtocolAddress = bob.external.clone().into();
//! let bob_store_request = DirectoryStoreRequest {
//!   path: PathBuf::from("/home/cosmicexplorer/bob"),
//!   id: bob.crypto,
//! };
//! let mut bob_store =
//!   block_on(FileStore::initialize_file_backed_store_with_default(
//!              bob_store_request.into_layout()?))?;
//!
//! // Alice sends a message to Bob to kick off a message chain, which requires a pre-key bundle.
//! // See https://signal.org/docs/specifications/x3dh/#publishing-keys.
//! let bob_signed_pre_key =
//!   block_on(SignedPreKey::intern(
//!              SignedPreKeyRequest::generate((), &mut rand::thread_rng()),
//!              &mut bob_store.identity_store,
//!              &mut bob_store.signed_pre_key_store,
//!              &mut rand::thread_rng()))?;
//! let bob_one_time_pre_key =
//!   block_on(OneTimePreKey::intern(
//!              OneTimePreKeyRequest::generate((), &mut rand::thread_rng()),
//!              &mut bob_store.pre_key_store))?;
//!
//! // Generate the pre-key bundle.
//! let bob_pre_key_bundle = PreKeyBundle::new(
//!   block_on(PreKeyBundleRequest::create(bob.external.clone(),
//!                                        bob_signed_pre_key,
//!                                        bob_one_time_pre_key,
//!                                        &bob_store.identity_store))?)?;
//! let encoded_pre_key_bundle: Box<[u8]> = bob_pre_key_bundle.try_into()?;
//! let decoded_pre_key_bundle = PreKeyBundle::try_from(encoded_pre_key_bundle.as_ref())?;
//!
//! // Encrypt a message.
//! let ptext: Box<[u8]> = Box::new(b"asdf".to_owned());
//! let initial_message =
//!   block_on(InitialOutwardMessage::intern(
//!              InitialOutwardMessageRequest {
//!                bundle: decoded_pre_key_bundle,
//!                plaintext: &ptext,
//!              },
//!              &mut alice_store.session_store,
//!              &mut alice_store.identity_store,
//!              &mut rand::thread_rng()))?;
//!
//! // Decrypt the ciphertext.
//! let session_request = SessionInitiatingMessageRequest {
//!                         outward: initial_message,
//!                       };
//! let encoded_session_initiation_request: Box<[u8]> = session_request.into();
//! let decoded_session_initiation_request =
//!   SessionInitiatingMessageRequest::try_from(encoded_session_initiation_request.as_ref())?;
//! let session_initial_message =
//!   block_on(SessionInitiatingMessage::intern(decoded_session_initiation_request,
//!                                             alice.external.clone(),
//!                                             &mut bob_store.session_store,
//!                                             &mut bob_store.identity_store,
//!                                             &mut bob_store.pre_key_store,
//!                                             &mut bob_store.signed_pre_key_store,
//!                                             &mut rand::thread_rng(),
//!                                        ))?;
//!
//! assert!(session_initial_message.plaintext.as_ref() == ptext.as_ref());
//! assert!("asdf" == std::str::from_utf8(session_initial_message.plaintext.as_ref()).unwrap());
//!
//! //?
//! let bob_text = "oh ok";
//! let bob_follow_up =
//!   block_on(FollowUpMessage::intern(
//!              FollowUpMessageRequest {
//!                target: alice.external.clone(),
//!                plaintext: bob_text.as_bytes(),
//!              },
//!              &mut bob_store.session_store,
//!              &mut bob_store.identity_store))?;
//! let encoded_follow_up_message: Box<[u8]> = bob_follow_up.into();
//! let decoded_follow_up_message =
//!   FollowUpMessage::try_from(encoded_follow_up_message.as_ref())?;
//! let alice_incoming = block_on(DecryptedMessage::intern(
//!   decoded_follow_up_message,
//!   bob.external.clone(),
//!   &mut alice_store.session_store,
//!   &mut alice_store.identity_store,
//!   &mut alice_store.pre_key_store,
//!   &mut alice_store.signed_pre_key_store,
//!   &mut rand::thread_rng(),
//! ))?.plaintext;
//!
//! assert!(&alice_incoming[..] == bob_text.as_bytes());
//! assert!("oh ok" == std::str::from_utf8(alice_incoming.as_ref()).unwrap());
//!
//! # Ok(())
//! # }
//!```

pub mod proto {
  /* Ensure the generated identity.proto outputs are available under [super::identity] within the
   * sub-module also named "proto". */
  pub use crate::identity::proto as identity;
  mod proto {
    include!(concat!(env!("OUT_DIR"), "/grouplink.proto.session.rs"));
  }
  pub use proto::*;
}

use crate::error::{Error, ProtobufCodingFailure};
use crate::identity::{CryptographicIdentity, ExternalIdentity, Spontaneous};
use crate::store::Persistent;
use crate::util::encode_proto_message;

use libsignal_protocol as signal;
use prost::Message;
use rand::{self, CryptoRng, Rng};

use std::convert::{TryFrom, TryInto};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy)]
pub struct SignedPreKeyRequest {
  pub id: signal::SignedPreKeyId,
  pub pair: signal::IdentityKeyPair,
}

impl Spontaneous<()> for SignedPreKeyRequest {
  fn generate<R: CryptoRng + Rng>(_params: (), r: &mut R) -> Self {
    let pair = signal::IdentityKeyPair::generate(r);
    let id: signal::SignedPreKeyId = Box::new(r).gen::<u32>().into();
    Self { id, pair }
  }
}

#[derive(Debug, Clone)]
pub struct SignedPreKey {
  pub id: signal::SignedPreKeyId,
  pub pair: signal::IdentityKeyPair,
  pub signature: Box<[u8]>,
}

impl SignedPreKey {
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

    let timestamp: u64 = SystemTime::now()
      .duration_since(SystemTime::UNIX_EPOCH)
      .expect("timestamp calculation will never fail")
      .as_secs();
    let pub_signed_prekey: Box<[u8]> = pair.public_key().serialize();

    let pub_sign = id_store
      .get_identity_key_pair(None)
      .await?
      .private_key()
      .calculate_signature(&pub_signed_prekey, csprng)?;
    id_store.persist().await?;

    let inner = signal::SignedPreKeyRecord::new(id.into(), timestamp, &pair.into(), &pub_sign);
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

#[derive(Debug, Clone, Copy)]
pub struct OneTimePreKeyRequest {
  pub id: signal::PreKeyId,
  pub pair: signal::IdentityKeyPair,
}

impl Spontaneous<()> for OneTimePreKeyRequest {
  fn generate<R: CryptoRng + Rng>(_params: (), r: &mut R) -> Self {
    let pair = signal::IdentityKeyPair::generate(r);
    let id: signal::PreKeyId = Box::new(r).gen::<u32>().into();
    Self { id, pair }
  }
}

#[derive(Debug, Clone, Copy)]
pub struct OneTimePreKey {
  pub id: signal::PreKeyId,
  pub pair: signal::IdentityKeyPair,
}

impl OneTimePreKey {
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

#[derive(Debug, Clone)]
pub struct PreKeyBundleRequest {
  pub destination: ExternalIdentity,
  pub signed: SignedPreKey,
  pub one_time: OneTimePreKey,
  pub identity: CryptographicIdentity,
}

impl PreKeyBundleRequest {
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

#[derive(Debug, Clone)]
pub struct PreKeyBundle {
  pub destination: ExternalIdentity,
  pub inner: signal::PreKeyBundle,
}

impl PreKeyBundle {
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
}

impl TryFrom<PreKeyBundle> for proto::PreKeyBundle {
  type Error = Error;
  fn try_from(value: PreKeyBundle) -> Result<Self, Error> {
    let PreKeyBundle { destination, inner } = value;
    Ok(proto::PreKeyBundle {
      destination: Some(destination.into()),
      registration_id: Some(inner.registration_id()?),
      device_id: Some(inner.device_id()?),
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
      device_id,
      pre_key_id,
      pre_key_public,
      signed_pre_key_id,
      signed_pre_key_public,
      signed_pre_key_signature,
      identity_key,
    } = value;
    let destination: ExternalIdentity = destination
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
          "failed to find `destination` field!"
        )))
      })?
      .try_into()?;
    let registration_id: u32 = registration_id.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `registration_id` field!"
      )))
    })?;
    let device_id: u32 = device_id.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `device_id` field!"
      )))
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
        )))
      }
    };
    let signed_pre_key_id: signal::SignedPreKeyId = signed_pre_key_id
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
          "failed to find `signed_pre_key_id` field!"
        )))
      })?
      .into();
    let signed_pre_key_public: signal::PublicKey = signed_pre_key_public.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `signed_pre_key_public` field!"
      )))
    })?[..]
      .try_into()?;
    let signed_pre_key_signature: Vec<u8> = signed_pre_key_signature
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
          "failed to find `signed_pre_key_signature` field!"
        )))
      })?
      .to_vec();
    let identity_key: signal::IdentityKey = identity_key.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `identity_key` field!"
      )))
    })?[..]
      .try_into()?;
    Ok(Self {
      destination,
      inner: signal::PreKeyBundle::new(
        registration_id,
        device_id,
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

#[derive(Debug, Clone)]
pub struct InitialOutwardMessageRequest<'a> {
  pub bundle: PreKeyBundle,
  pub plaintext: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct InitialOutwardMessage {
  pub inner: signal::PreKeySignalMessage,
}

impl InitialOutwardMessage {
  pub async fn intern<
    'a,
    'b,
    'c,
    'd,
    Record,
    S: signal::SessionStore + Persistent<Record>,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    R: Rng + CryptoRng,
  >(
    params: InitialOutwardMessageRequest<'a>,
    session_store: &'b mut S,
    id_store: &'c mut ID,
    csprng: &'d mut R,
  ) -> Result<Self, Error> {
    let InitialOutwardMessageRequest {
      bundle: PreKeyBundle { destination, inner },
      plaintext,
    } = params;

    signal::process_prekey_bundle(
      &destination.clone().into(),
      session_store,
      id_store,
      &inner,
      csprng,
      None,
    )
    .await?;
    session_store.persist().await?;
    id_store.persist().await?;

    let outgoing_message: signal::CiphertextMessage = signal::message_encrypt(
      plaintext,
      &destination.clone().into(),
      session_store,
      id_store,
      None,
    )
    .await?;
    session_store.persist().await?;
    id_store.persist().await?;

    let inner = signal::PreKeySignalMessage::try_from(outgoing_message.serialize())?;
    Ok(Self { inner })
  }
}

#[derive(Debug, Clone)]
pub struct SessionInitiatingMessageRequest {
  pub outward: InitialOutwardMessage,
}

impl From<SessionInitiatingMessageRequest> for proto::SessionInitiatingMessageRequest {
  fn from(value: SessionInitiatingMessageRequest) -> Self {
    let SessionInitiatingMessageRequest {
      outward: InitialOutwardMessage {
        inner: signal_pre_key_message,
      },
    } = value;
    proto::SessionInitiatingMessageRequest {
      encrypted_pre_key_message: Some(signal_pre_key_message.as_ref().to_vec()),
    }
  }
}

impl From<SessionInitiatingMessageRequest> for Box<[u8]> {
  fn from(value: SessionInitiatingMessageRequest) -> Self {
    let proto_message: proto::SessionInitiatingMessageRequest = value.into();
    encode_proto_message(proto_message)
  }
}

impl TryFrom<proto::SessionInitiatingMessageRequest> for SessionInitiatingMessageRequest {
  type Error = Error;
  fn try_from(value: proto::SessionInitiatingMessageRequest) -> Result<Self, Error> {
    let proto::SessionInitiatingMessageRequest {
      encrypted_pre_key_message,
    } = value;
    let encoded_pre_key_message: Vec<u8> = encrypted_pre_key_message.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `encrypted_pre_key_message` field!"
      )))
    })?;
    let decoded_pre_key_message =
      signal::PreKeySignalMessage::try_from(encoded_pre_key_message.as_ref())?;
    Ok(Self {
      outward: InitialOutwardMessage {
        inner: decoded_pre_key_message,
      },
    })
  }
}

impl TryFrom<&[u8]> for SessionInitiatingMessageRequest {
  type Error = Error;
  fn try_from(value: &[u8]) -> Result<Self, Error> {
    let proto_message = proto::SessionInitiatingMessageRequest::decode(value)?;
    Self::try_from(proto_message)
  }
}

#[derive(Debug, Clone)]
pub struct SessionInitiatingMessage {
  pub plaintext: Box<[u8]>,
}

impl SessionInitiatingMessage {
  pub async fn intern<
    Record,
    S: signal::SessionStore + Persistent<Record>,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    PK: signal::PreKeyStore + Persistent<Record>,
    SPK: signal::SignedPreKeyStore + Persistent<Record>,
    R: Rng + CryptoRng,
  >(
    request: SessionInitiatingMessageRequest,
    sender: ExternalIdentity,
    session_store: &mut S,
    id_store: &mut ID,
    prekey_store: &mut PK,
    signed_prekey_store: &mut SPK,
    csprng: &mut R,
  ) -> Result<Self, Error> {
    let SessionInitiatingMessageRequest {
      outward: InitialOutwardMessage { inner },
    } = request;
    let decrypted: Box<[u8]> = signal::message_decrypt(
      &signal::CiphertextMessage::PreKeySignalMessage(inner),
      &sender.clone().into(),
      session_store,
      id_store,
      prekey_store,
      signed_prekey_store,
      csprng,
      None,
    )
    .await?
    .into_boxed_slice();
    session_store.persist().await?;
    id_store.persist().await?;
    prekey_store.persist().await?;
    signed_prekey_store.persist().await?;
    Ok(Self {
      plaintext: decrypted,
    })
  }
}

#[derive(Debug, Clone)]
pub struct FollowUpMessageRequest<'a> {
  pub target: ExternalIdentity,
  pub plaintext: &'a [u8],
}

pub struct FollowUpMessage {
  pub inner: signal::SignalMessage,
}

impl FollowUpMessage {
  pub async fn intern<
    'a,
    Record,
    S: signal::SessionStore + Persistent<Record>,
    ID: signal::IdentityKeyStore + Persistent<Record>,
  >(
    request: FollowUpMessageRequest<'a>,
    session_store: &mut S,
    id_store: &mut ID,
  ) -> Result<Self, Error> {
    let FollowUpMessageRequest { target, plaintext } = request;
    let inner =
      signal::message_encrypt(plaintext, &target.into(), session_store, id_store, None).await?;
    session_store.persist().await?;
    id_store.persist().await?;
    match inner {
      signal::CiphertextMessage::SignalMessage(inner) => Ok(Self { inner }),
      x => unreachable!("expected the result of signal::message_encrypt() to return a normal message, but was: {:?}", x.message_type())
    }
  }
}

impl From<FollowUpMessage> for proto::FollowUpMessage {
  fn from(value: FollowUpMessage) -> Self {
    let FollowUpMessage { inner } = value;
    proto::FollowUpMessage {
      encrypted_signal_message: Some(inner.as_ref().to_vec()),
    }
  }
}

impl From<FollowUpMessage> for Box<[u8]> {
  fn from(value: FollowUpMessage) -> Self {
    let proto_message: proto::FollowUpMessage = value.into();
    encode_proto_message(proto_message)
  }
}

impl TryFrom<proto::FollowUpMessage> for FollowUpMessage {
  type Error = Error;
  fn try_from(value: proto::FollowUpMessage) -> Result<Self, Error> {
    let proto::FollowUpMessage {
      encrypted_signal_message,
    } = value;
    let encoded_signal_message: Vec<u8> = encrypted_signal_message.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `encrypted_signal_message` field!"
      )))
    })?;
    let decoded_signal_message = signal::SignalMessage::try_from(encoded_signal_message.as_ref())?;
    Ok(Self {
      inner: decoded_signal_message,
    })
  }
}

impl TryFrom<&[u8]> for FollowUpMessage {
  type Error = Error;
  fn try_from(value: &[u8]) -> Result<Self, Error> {
    let proto_message = proto::FollowUpMessage::decode(value)?;
    Self::try_from(proto_message)
  }
}

#[derive(Debug, Clone)]
pub struct DecryptedMessage {
  pub plaintext: Box<[u8]>,
}

impl DecryptedMessage {
  pub async fn intern<
    Record,
    S: signal::SessionStore + Persistent<Record>,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    PK: signal::PreKeyStore + Persistent<Record>,
    SPK: signal::SignedPreKeyStore + Persistent<Record>,
    R: Rng + CryptoRng,
  >(
    request: FollowUpMessage,
    sender: ExternalIdentity,
    session_store: &mut S,
    id_store: &mut ID,
    prekey_store: &mut PK,
    signed_prekey_store: &mut SPK,
    csprng: &mut R,
  ) -> Result<Self, Error> {
    let FollowUpMessage { inner } = request;
    let decrypted: Box<[u8]> = signal::message_decrypt(
      &signal::CiphertextMessage::SignalMessage(inner),
      &sender.clone().into(),
      session_store,
      id_store,
      prekey_store,
      signed_prekey_store,
      csprng,
      None,
    )
    .await?
    .into_boxed_slice();
    session_store.persist().await?;
    id_store.persist().await?;
    prekey_store.persist().await?;
    signed_prekey_store.persist().await?;
    Ok(Self {
      plaintext: decrypted,
    })
  }
}

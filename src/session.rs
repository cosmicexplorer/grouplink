/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???
//!
//!```
//! # fn main() -> Result<(), grouplink::error::Error> {
//! use grouplink::{identity::*, session::*};
//! use grouplink::session::PreKeyBundle;
//! use libsignal_protocol::*;
//! use rand::{self, Rng};
//! use uuid::Uuid;
//! use futures::executor::block_on;
//! use std::convert::{TryFrom, TryInto};
//!
//! // Create a new identity.
//! let crypto = CryptographicIdentity::generate((), &mut rand::thread_rng());
//! let external = ExternalIdentity::generate((), &mut rand::thread_rng());
//! let alice = Identity { crypto, external: external.clone() };
//! let alice_address: ProtocolAddress = alice.external.clone().into();
//!
//! // Create a mutable store.
//! let mut alice_store = Store::new(alice.crypto);
//!
//! // Create a destination identity.
//! let bob_crypto = CryptographicIdentity::generate((), &mut rand::thread_rng());
//! let bob_ext = ExternalIdentity::generate((), &mut rand::thread_rng());
//! let bob = Identity { crypto: bob_crypto, external: bob_ext };
//! let bob_address: ProtocolAddress = bob.external.clone().into();
//! let mut bob_store = Store::new(bob.crypto);
//!
//! // Alice sends a message to Bob to kick off a message chain, which requires a pre-key bundle.
//! // See https://signal.org/docs/specifications/x3dh/#publishing-keys.
//! let bob_signed_pre_key = block_on(SignedPreKey::intern(
//!                                     SignedPreKeyRequest::generate((), &mut rand::thread_rng()),
//!                                     &mut bob_store,
//!                                     &mut rand::thread_rng()))?;
//! let bob_one_time_pre_key = block_on(OneTimePreKey::intern(
//!                                       OneTimePreKeyRequest::generate(
//!                                         (), &mut rand::thread_rng()),
//!                                       &mut bob_store))?;
//!
//! // Generate the pre-key bundle.
//! let bob_pre_key_bundle = PreKeyBundle::new(
//!   block_on(PreKeyBundleRequest::create(bob.external.clone(),
//!                                        bob_signed_pre_key,
//!                                        bob_one_time_pre_key,
//!                                        &bob_store))?)?;
//!
//! // Encrypt a message.
//! let ptext: Box<[u8]> = Box::new(b"asdf".to_owned());
//! let initial_request = InitialOutwardMessageRequest {
//!                         bundle: bob_pre_key_bundle,
//!                         plaintext: &ptext,
//!                       };
//! let initial_message = block_on(InitialOutwardMessage::intern(initial_request,
//!                                                              &mut alice_store,
//!                                                              &mut rand::thread_rng()))?;
//!
//! // Decrypt the ciphertext.
//! let session_request = SessionInitiatingMessageRequest {
//!                         outward: initial_message,
//!                         sender: alice.external.clone(),
//!                       };
//! let encoded_session_initiation_request: Box<[u8]> = session_request.into();
//! let decoded_session_initiation_request =
//!   SessionInitiatingMessageRequest::try_from(encoded_session_initiation_request.as_ref())?;
//! let session_initial_message =
//!   block_on(SessionInitiatingMessage::intern(decoded_session_initiation_request,
//!                                             &mut bob_store,
//!                                             &mut rand::thread_rng(),
//!                                        ))?;
//!
//! assert!(session_initial_message.plaintext.as_ref() == ptext.as_ref());
//! assert!("asdf" == std::str::from_utf8(session_initial_message.plaintext.as_ref()).unwrap());
//!
//! //?
//! let bob_text = "oh ok";
//! let bob_follow_up_request = FollowUpMessageRequest {
//!                               target: alice.external.clone(),
//!                               sender: bob.external.clone(),
//!                               plaintext: bob_text.as_bytes(),
//!                             };
//! let bob_follow_up = block_on(FollowUpMessage::intern(bob_follow_up_request, &mut bob_store))?;
//! let encoded_follow_up_message: Box<[u8]> = bob_follow_up.into();
//! let decoded_follow_up_message =
//!   FollowUpMessage::try_from(encoded_follow_up_message.as_ref())?;
//! let alice_incoming = block_on(DecryptedMessage::intern(
//!   decoded_follow_up_message,
//!   &mut alice_store,
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
use crate::util::encode_proto_message;

use libsignal_protocol::{self as signal, IdentityKeyStore, PreKeyStore, SignedPreKeyStore};
use prost::Message;
use rand::{self, CryptoRng, Rng};

use std::convert::{TryFrom, TryInto};
use std::time::SystemTime;

/// ???
#[derive(Clone)]
pub struct Store(pub signal::InMemSignalProtocolStore);

fn no_store_creation_error<T>(r: Result<T, signal::SignalProtocolError>) -> T {
  r.expect("creation of the in-memory signal protocol store should succeed")
}

impl Store {
  pub fn new(crypto: CryptographicIdentity) -> Self {
    let CryptographicIdentity { inner, seed } = crypto;
    Self(no_store_creation_error(
      signal::InMemSignalProtocolStore::new(inner, seed),
    ))
  }
}

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
  pub async fn intern<R: CryptoRng + Rng>(
    params: SignedPreKeyRequest,
    store: &mut Store,
    csprng: &mut R,
  ) -> Result<Self, Error> {
    let SignedPreKeyRequest { id, pair } = params;
    let timestamp: u64 = SystemTime::now()
      .duration_since(SystemTime::UNIX_EPOCH)
      .expect("timestamp calculation will never fail")
      .as_secs();
    let pub_signed_prekey: Box<[u8]> = pair.public_key().serialize();
    let pub_sign = store
      .0
      .get_identity_key_pair(None)
      .await?
      .private_key()
      .calculate_signature(&pub_signed_prekey, csprng)?;
    let inner = signal::SignedPreKeyRecord::new(id.into(), timestamp, &pair.into(), &pub_sign);
    store.0.save_signed_pre_key(id.into(), &inner, None).await?;
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
  pub async fn intern(params: OneTimePreKeyRequest, store: &mut Store) -> Result<Self, Error> {
    let OneTimePreKeyRequest { id, pair } = params;
    let inner = signal::PreKeyRecord::new(id.into(), &pair.into());
    store.0.save_pre_key(id.into(), &inner, None).await?;
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
  pub async fn create(
    destination: ExternalIdentity,
    signed: SignedPreKey,
    one_time: OneTimePreKey,
    store: &Store,
  ) -> Result<Self, Error> {
    let seed = store.0.get_local_registration_id(None).await?;
    let inner = store.0.get_identity_key_pair(None).await?;
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
  pub async fn intern<'a, 'b, 'c, R: Rng + CryptoRng>(
    params: InitialOutwardMessageRequest<'a>,
    store: &'b mut Store,
    csprng: &'c mut R,
  ) -> Result<Self, Error> {
    let InitialOutwardMessageRequest {
      bundle: PreKeyBundle { destination, inner },
      plaintext,
    } = params;
    signal::process_prekey_bundle(
      &destination.clone().into(),
      &mut store.0.session_store,
      &mut store.0.identity_store,
      &inner,
      csprng,
      None,
    )
    .await?;
    let outgoing_message: signal::CiphertextMessage = signal::message_encrypt(
      plaintext,
      &destination.clone().into(),
      &mut store.0.session_store,
      &mut store.0.identity_store,
      None,
    )
    .await?;
    let inner = signal::PreKeySignalMessage::try_from(outgoing_message.serialize())?;
    Ok(Self { inner })
  }
}

#[derive(Debug, Clone)]
pub struct SessionInitiatingMessageRequest {
  pub outward: InitialOutwardMessage,
  pub sender: ExternalIdentity,
}

impl From<SessionInitiatingMessageRequest> for proto::SessionInitiatingMessageRequest {
  fn from(value: SessionInitiatingMessageRequest) -> Self {
    let SessionInitiatingMessageRequest {
      outward: InitialOutwardMessage {
        inner: signal_pre_key_message,
      },
      sender,
    } = value;
    proto::SessionInitiatingMessageRequest {
      sender: Some(sender.into()),
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
      sender,
      encrypted_pre_key_message,
    } = value;
    let sender: proto::identity::Address = sender.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `sender` field!"
      )))
    })?;
    let encoded_pre_key_message: Vec<u8> = encrypted_pre_key_message.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `encrypted_pre_key_message` field!"
      )))
    })?;
    let decoded_pre_key_message =
      signal::PreKeySignalMessage::try_from(encoded_pre_key_message.as_ref())?;
    Ok(Self {
      sender: sender.try_into()?,
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
  pub async fn intern<R: Rng + CryptoRng>(
    request: SessionInitiatingMessageRequest,
    store: &mut Store,
    csprng: &mut R,
  ) -> Result<Self, Error> {
    let SessionInitiatingMessageRequest {
      outward: InitialOutwardMessage { inner },
      sender,
    } = request;
    let decrypted: Box<[u8]> = signal::message_decrypt(
      &signal::CiphertextMessage::PreKeySignalMessage(inner),
      &sender.clone().into(),
      &mut store.0.session_store,
      &mut store.0.identity_store,
      &mut store.0.pre_key_store,
      &mut store.0.signed_pre_key_store,
      csprng,
      None,
    )
    .await?
    .into_boxed_slice();
    Ok(Self {
      plaintext: decrypted,
    })
  }
}

#[derive(Debug, Clone)]
pub struct FollowUpMessageRequest<'a> {
  pub target: ExternalIdentity,
  pub sender: ExternalIdentity,
  pub plaintext: &'a [u8],
}

pub struct FollowUpMessage {
  pub inner: signal::SignalMessage,
  pub sender: ExternalIdentity,
}

impl FollowUpMessage {
  pub async fn intern<'a>(
    request: FollowUpMessageRequest<'a>,
    store: &mut Store,
  ) -> Result<Self, Error> {
    let FollowUpMessageRequest {
      target,
      sender,
      plaintext,
    } = request;
    let inner = signal::message_encrypt(
      plaintext,
      &target.into(),
      &mut store.0.session_store,
      &mut store.0.identity_store,
      None,
    )
    .await?;
    match inner {
      signal::CiphertextMessage::SignalMessage(inner) => Ok(Self { inner, sender }),
      x => unreachable!("expected the result of signal::message_encrypt() to return a normal message, but was: {:?}", x.message_type())
    }
  }
}

impl From<FollowUpMessage> for proto::FollowUpMessage {
  fn from(value: FollowUpMessage) -> Self {
    let FollowUpMessage { inner, sender } = value;
    proto::FollowUpMessage {
      sender: Some(sender.into()),
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
      sender,
      encrypted_signal_message,
    } = value;
    let sender = sender.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `sender` field!"
      )))
    })?;
    let encoded_signal_message: Vec<u8> = encrypted_signal_message.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `encrypted_signal_message` field!"
      )))
    })?;
    let decoded_signal_message = signal::SignalMessage::try_from(encoded_signal_message.as_ref())?;
    Ok(Self {
      sender: sender.try_into()?,
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
  pub async fn intern<R: Rng + CryptoRng>(
    request: FollowUpMessage,
    store: &mut Store,
    csprng: &mut R,
  ) -> Result<Self, Error> {
    let FollowUpMessage { inner, sender } = request;
    let decrypted: Box<[u8]> = signal::message_decrypt(
      &signal::CiphertextMessage::SignalMessage(inner),
      &sender.clone().into(),
      &mut store.0.session_store,
      &mut store.0.identity_store,
      &mut store.0.pre_key_store,
      &mut store.0.signed_pre_key_store,
      csprng,
      None,
    )
    .await?
    .into_boxed_slice();
    Ok(Self {
      plaintext: decrypted,
    })
  }
}

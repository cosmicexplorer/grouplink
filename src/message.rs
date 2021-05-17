/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???
//!
//!```
//! # fn main() -> Result<(), grouplink::error::Error> {
//! use grouplink::{identity::*, session::*, message::*, store::{file_persistence::*, conversions::*, *}};
//! use libsignal_protocol as signal;
//! use rand::{self, Rng};
//! use uuid::Uuid;
//! use futures::executor::block_on;
//! use std::convert::{TryFrom, TryInto};
//! use std::path::PathBuf;
//!
//! // Create a new identity.
//! let alice = Identity::generate((), &mut rand::thread_rng());
//! let alice_sealed = SealedSenderIdentity::generate(alice.external.clone(),
//!                                                   &mut rand::thread_rng());
//! let alice_address: signal::ProtocolAddress = alice.external.clone().into();
//!
//! // Create a mutable store.
//! let alice_store_request = DirectoryStoreRequest {
//!   path: PathBuf::from("/home/cosmicexplorer/alice"),
//!   id: alice.crypto,
//!   behavior: ExtractionBehavior::OverwriteWithDefault,
//!  };
//! let mut alice_store =
//!   block_on(FileStore::initialize_file_backed_store_with_default(
//!              alice_store_request.into_layout()?))?;
//!
//! // Create a destination identity.
//! let bob = Identity::generate((), &mut rand::thread_rng());
//! let bob_sealed = SealedSenderIdentity::generate(bob.external.clone(),
//!                                                 &mut rand::thread_rng());
//! let bob_address: signal::ProtocolAddress = bob.external.clone().into();
//! let bob_store_request = DirectoryStoreRequest {
//!   path: PathBuf::from("/home/cosmicexplorer/bob"),
//!   id: bob.crypto,
//!   behavior: ExtractionBehavior::OverwriteWithDefault,
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
//! let encoded_pre_key_bundle: Box<[u8]> = Message::Bundle(bob_pre_key_bundle).try_into()?;
//!
//! // Encrypt a message.
//! let decoded_pre_key_bundle = match Message::try_from(encoded_pre_key_bundle.as_ref())? {
//!   Message::Bundle(x) => x,
//!   _ => unreachable!(),
//! };
//! let ptext: Box<[u8]> = Box::new(b"asdf".to_owned());
//!
//! // SEALED SENDER STUFF!
//!
//! let trust_root = signal::KeyPair::generate(&mut rand::thread_rng());
//! let server_key = signal::KeyPair::generate(&mut rand::thread_rng());
//!
//! let alice_server_cert =
//!     signal::ServerCertificate::new(1, server_key.public_key, &trust_root.private_key,
//!                                    &mut rand::thread_rng())?;
//! let bob_server_cert =
//!     signal::ServerCertificate::new(1, server_key.public_key, &trust_root.private_key,
//!                                    &mut rand::thread_rng())?;
//!
//! // Very far in the future.
//! let expires = 2605722925;
//!
//! let alice_sender_certificate = signal::SenderCertificate::new(
//!     alice.external.name.clone(),
//!     None,
//!     *alice.crypto.inner.public_key(),
//!     alice.external.device_id,
//!     expires,
//!     alice_server_cert,
//!     &server_key.private_key,
//!     &mut rand::thread_rng(),
//! )?;
//! let alice_sender_cert = SenderCert {
//!   inner: alice_sender_certificate,
//!   trust_root: trust_root.public_key,
//! };
//!
//! let bob_sender_certificate = signal::SenderCertificate::new(
//!     bob.external.name.clone(),
//!     None,
//!     *bob.crypto.inner.public_key(),
//!     bob.external.device_id,
//!     expires,
//!     bob_server_cert,
//!     &server_key.private_key,
//!     &mut rand::thread_rng(),
//! )?;
//! let bob_sender_cert = SenderCert {
//!   inner: bob_sender_certificate,
//!   trust_root: trust_root.public_key,
//! };
//!
//! let initial_message =
//!   block_on(SealedSenderMessage::intern(
//!              SealedSenderMessageRequest {
//!                bundle: decoded_pre_key_bundle,
//!                sender_cert: alice_sender_cert,
//!                ptext: &ptext,
//!              },
//!              &mut alice_store.session_store,
//!              &mut alice_store.identity_store,
//!              &mut rand::thread_rng(),
//!   ))?;
//! let encoded_sealed_sender_message: Box<[u8]> = Message::Sealed(initial_message).try_into()?;
//!
//! // Decrypt the sealed-sender message.
//! let decoded_sealed_sender_message = match Message::try_from(encoded_sealed_sender_message.as_ref())? {
//!   Message::Sealed(x) => x,
//!   _ => unreachable!(),
//! };
//! let message_result =
//!   block_on(SealedSenderMessageResult::intern(
//!              SealedSenderDecryptionRequest {
//!                inner: decoded_sealed_sender_message,
//!                local_identity: bob_sealed,
//!              },
//!              &mut bob_store.identity_store,
//!              &mut bob_store.session_store,
//!              &mut bob_store.pre_key_store,
//!              &mut bob_store.signed_pre_key_store,
//!   ))?;
//!
//! assert!(message_result.plaintext.as_ref() == ptext.as_ref());
//! assert!("asdf" == std::str::from_utf8(message_result.plaintext.as_ref()).unwrap());
//!
//! //?
//! let bob_text = "oh ok";
//! let bob_follow_up =
//!   block_on(SealedSenderMessage::intern_followup(
//!              SealedSenderFollowupMessageRequest {
//!                target: message_result.sender.inner,
//!                sender_cert: bob_sender_cert,
//!                ptext: bob_text.as_bytes(),
//!              },
//!              &mut bob_store.session_store,
//!              &mut bob_store.identity_store,
//!              &mut rand::thread_rng()))?;
//! let encoded_follow_up_message: Box<[u8]> = Message::Sealed(bob_follow_up).try_into()?;
//!
//! let decoded_follow_up_message = match Message::try_from(encoded_follow_up_message.as_ref())? {
//!   Message::Sealed(x) => x,
//!   _ => unreachable!(),
//! };
//! let alice_incoming =
//!   block_on(SealedSenderMessageResult::intern(
//!     SealedSenderDecryptionRequest {
//!       inner: decoded_follow_up_message,
//!       local_identity: alice_sealed,
//!     },
//!     &mut alice_store.identity_store,
//!     &mut alice_store.session_store,
//!     &mut alice_store.pre_key_store,
//!     &mut alice_store.signed_pre_key_store,
//!   ))?.plaintext;
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
  pub use crate::session::proto as session;
  mod proto {
    include!(concat!(env!("OUT_DIR"), "/grouplink.proto.message.rs"));
  }
  pub use proto::*;
}

use crate::error::{Error, ProtobufCodingFailure};
use crate::session::{PreKeyBundle, SealedSenderMessage};
use crate::util::encode_proto_message;

use prost::Message as _;

use std::convert::{TryFrom, TryInto};

#[derive(Debug, Clone)]
pub enum Message {
  Bundle(PreKeyBundle),
  Sealed(SealedSenderMessage),
}

impl TryFrom<Message> for proto::Message {
  type Error = Error;
  fn try_from(value: Message) -> Result<Self, Error> {
    Ok(proto::Message {
      r#type: Some(match value {
        Message::Bundle(pre_key_bundle) => proto::message::Type::Bundle(pre_key_bundle.try_into()?),
        Message::Sealed(sealed_sender_message) => {
          proto::message::Type::SealedSenderMessage(sealed_sender_message.try_into()?)
        }
      }),
    })
  }
}

impl TryFrom<Message> for Box<[u8]> {
  type Error = Error;
  fn try_from(value: Message) -> Result<Self, Error> {
    let proto_message: proto::Message = value.try_into()?;
    Ok(encode_proto_message(proto_message))
  }
}

impl TryFrom<proto::Message> for Message {
  type Error = Error;
  fn try_from(value: proto::Message) -> Result<Self, Error> {
    let proto::Message { r#type: inner } = value.clone();
    let inner = inner.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
        format!("failed to find the `type` field!"),
        format!("{:?}", value),
      ))
    })?;
    Ok(match inner {
      proto::message::Type::Bundle(pre_key_bundle) => Message::Bundle(pre_key_bundle.try_into()?),
      proto::message::Type::SealedSenderMessage(sealed_sender_message) => {
        Message::Sealed(sealed_sender_message.try_into()?)
      }
    })
  }
}

impl TryFrom<&[u8]> for Message {
  type Error = Error;
  fn try_from(value: &[u8]) -> Result<Self, Error> {
    let proto_message = proto::Message::decode(value)?;
    Self::try_from(proto_message)
  }
}

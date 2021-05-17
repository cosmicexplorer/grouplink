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
//! let alice = generate_identity();
//! let alice_sealed = generate_sealed_sender_identity(alice.external.clone());
//! let alice_address: signal::ProtocolAddress = alice.external.clone().into();
//!
//! // Create a mutable store.
//! let mut alice_store =
//!   block_on(initialize_file_backed_store(DirectoryStoreRequest {
//!     path: PathBuf::from("/home/cosmicexplorer/alice"),
//!     id: alice.crypto,
//!     behavior: ExtractionBehavior::OverwriteWithDefault,
//!   }))?;
//!
//! // Create a destination identity.
//! let bob = generate_identity();
//! let bob_sealed = generate_sealed_sender_identity(bob.external.clone());
//! let bob_address: signal::ProtocolAddress = bob.external.clone().into();
//! let mut bob_store =
//!   block_on(initialize_file_backed_store(DirectoryStoreRequest {
//!     path: PathBuf::from("/home/cosmicexplorer/bob"),
//!     id: bob.crypto,
//!     behavior: ExtractionBehavior::OverwriteWithDefault,
//!   }))?;
//!
//! // Alice sends a message to Bob to kick off a message chain, which requires a pre-key bundle.
//! // See https://signal.org/docs/specifications/x3dh/#publishing-keys.
//! let bob_signed_pre_key = block_on(generate_signed_pre_key(&mut bob_store))?;
//! let bob_one_time_pre_key = block_on(generate_one_time_pre_key(&mut bob_store))?;
//!
//! // Generate the pre-key bundle.
//! let bob_pre_key_bundle =
//!   block_on(generate_pre_key_bundle(bob.external.clone(),
//!                                    bob_signed_pre_key,
//!                                    bob_one_time_pre_key,
//!                                    &bob_store))?;
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
//! let alice_sender_cert = generate_sender_cert(alice.clone(), SenderCertTTL::default())?;
//! let bob_sender_cert = generate_sender_cert(bob.clone(), SenderCertTTL::default())?;
//!
//! let initial_message =
//!   block_on(encrypt_sealed_sender_initial_message(
//!              SealedSenderMessageRequest {
//!                bundle: decoded_pre_key_bundle,
//!                sender_cert: alice_sender_cert,
//!                ptext: &ptext,
//!              },
//!              &mut alice_store,
//!   ))?;
//! let encoded_sealed_sender_message: Box<[u8]> = Message::Sealed(initial_message).try_into()?;
//!
//! // Decrypt the sealed-sender message.
//! let decoded_sealed_sender_message = match Message::try_from(encoded_sealed_sender_message.as_ref())? {
//!   Message::Sealed(x) => x,
//!   _ => unreachable!(),
//! };
//! let message_result =
//!   block_on(decrypt_sealed_sender_message(
//!              SealedSenderDecryptionRequest {
//!                inner: decoded_sealed_sender_message,
//!                local_identity: bob_sealed,
//!              },
//!              &mut bob_store,
//!   ))?;
//!
//! assert!(message_result.plaintext.as_ref() == ptext.as_ref());
//! assert!("asdf" == std::str::from_utf8(message_result.plaintext.as_ref()).unwrap());
//!
//! //?
//! let bob_text = "oh ok";
//! let bob_follow_up =
//!   block_on(encrypt_sealed_sender_followup_message(
//!              SealedSenderFollowupMessageRequest {
//!                target: message_result.sender.inner,
//!                sender_cert: bob_sender_cert,
//!                ptext: bob_text.as_bytes(),
//!              },
//!              &mut bob_store))?;
//! let encoded_follow_up_message: Box<[u8]> = Message::Sealed(bob_follow_up).try_into()?;
//!
//! let decoded_follow_up_message = match Message::try_from(encoded_follow_up_message.as_ref())? {
//!   Message::Sealed(x) => x,
//!   _ => unreachable!(),
//! };
//! let alice_incoming =
//!   block_on(decrypt_sealed_sender_message(
//!     SealedSenderDecryptionRequest {
//!       inner: decoded_follow_up_message,
//!       local_identity: alice_sealed,
//!     },
//!     &mut alice_store,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

/* #[cfg(test)] */
/* pub mod proptest_strategies { */
/*   use super::*; */
/*   use crate::store::{in_memory_store::*, proptest_strategies::*}; */

/*   use proptest::prelude::*; */

/*   use std::convert::{TryFrom, TryInto}; */
/* } */

#[cfg(test)]
pub mod test {
  /* use super::{proptest_strategies::*, *}; */
  use super::*;
  use crate::identity::Identity;
  use crate::session::{proptest_strategies::*, *};
  use crate::store::proptest_strategies::*;

  use futures::executor::block_on;
  use proptest::prelude::*;

  use std::convert::{TryFrom, TryInto};

  proptest! {
    #[test]
    fn test_serde_message_bundle(id in any::<Identity>(),
                                 spk_req in any::<SignedPreKeyRequest>(),
                                 opk_req in any::<OneTimePreKeyRequest>()) {
      let store = generate_store_wrapper(id.crypto);
      let spk = block_on(generate_signed_pre_key_wrapped(store.clone(), spk_req)).unwrap();
      let opk = block_on(generate_one_time_pre_key_wrapped(store.clone(), opk_req)).unwrap();
      let pkb = block_on(generate_pre_key_bundle_wrapped(store, id.external, spk, opk)).unwrap();
      let message_bundle = Message::Bundle(pkb);
      let encoded_pre_key_bundle: Box<[u8]> = message_bundle.clone().try_into().unwrap();
      let resurrected = Message::try_from(encoded_pre_key_bundle.as_ref()).unwrap();
      prop_assert_eq!(message_bundle, resurrected);
    }
  }
}

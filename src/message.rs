/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???
//!
//!```
//! # fn main() -> Result<(), grouplink::error::Error> {
//! use grouplink::{identity::*, session::*, message::*, store::file_persistence::*};
//! # use futures::executor::block_on;
//! use std::{convert::{TryFrom, TryInto}, path::PathBuf};
//! # block_on(async {
//!
//! // Create a new identity.
//! let alice = generate_identity();
//! let alice_client = generate_sealed_sender_identity(alice.external.clone());
//!
//! // Create a mutable store.
//! let mut alice_store =
//!   initialize_file_backed_store(DirectoryStoreRequest {
//!     path: PathBuf::from("/home/cosmicexplorer/alice"),
//!     id: alice.crypto,
//!     behavior: ExtractionBehavior::OverwriteWithDefault,
//!   }).await?;
//!
//! // Create a destination identity.
//! let bob = generate_identity();
//! let bob_client = generate_sealed_sender_identity(bob.external.clone());
//! let mut bob_store =
//!   initialize_file_backed_store(DirectoryStoreRequest {
//!     path: PathBuf::from("/home/cosmicexplorer/bob"),
//!     id: bob.crypto,
//!     behavior: ExtractionBehavior::OverwriteWithDefault,
//!   }).await?;
//!
//! // Alice sends a message to Bob to kick off a message chain, which requires a pre-key bundle.
//! // See https://signal.org/docs/specifications/x3dh/#publishing-keys.
//! let bob_signed_pre_key = generate_signed_pre_key(&mut bob_store).await?;
//! let bob_one_time_pre_key = generate_one_time_pre_key(&mut bob_store).await?;
//!
//! // Generate the pre-key bundle.
//! let bob_pre_key_bundle = generate_pre_key_bundle(bob.external.clone(),
//!                                                  bob_signed_pre_key,
//!                                                  bob_one_time_pre_key,
//!                                                  &bob_store).await?;
//! let encoded_pre_key_bundle: Box<[u8]> = Message::Bundle(bob_pre_key_bundle).try_into()?;
//!
//! // Encrypt a message.
//! let initial_message = encrypt_initial_message(
//!   SealedSenderMessageRequest {
//!     bundle: Message::try_from(encoded_pre_key_bundle.as_ref())?.assert_bundle()?,
//!     sender_cert: generate_sender_cert(alice_client.stripped_e164(), alice.crypto,
//!                                       SenderCertTTL::default())?,
//!     ptext: "asdf".as_bytes(),
//!   },
//!   &mut alice_store,
//! ).await?;
//! let encoded_sealed_sender_message: Box<[u8]> = Message::Sealed(initial_message).try_into()?;
//!
//! // Decrypt the sealed-sender message.
//! let message_result = decrypt_message(
//!   SealedSenderDecryptionRequest {
//!     inner: Message::try_from(encoded_sealed_sender_message.as_ref())?.assert_sealed()?,
//!     local_identity: bob_client.clone(),
//!   },
//!   &mut bob_store,
//! ).await?;
//!
//! assert!(message_result.sender == alice_client.stripped_e164());
//! assert!("asdf" == std::str::from_utf8(message_result.plaintext.as_ref()).unwrap());
//!
//! // Now send a message back to Alice.
//! let bob_follow_up = encrypt_followup_message(
//!   SealedSenderFollowupMessageRequest {
//!     target: message_result.sender.inner,
//!     sender_cert: generate_sender_cert(bob_client.stripped_e164(), bob.crypto,
//!                                       SenderCertTTL::default())?,
//!     ptext: "oh ok".as_bytes(),
//!   },
//!   &mut bob_store,
//! ).await?;
//! let encoded_follow_up_message: Box<[u8]> = Message::Sealed(bob_follow_up).try_into()?;
//!
//! let alice_incoming = decrypt_message(
//!   SealedSenderDecryptionRequest {
//!     inner: Message::try_from(encoded_follow_up_message.as_ref())?.assert_sealed()?,
//!     local_identity: alice_client.clone(),
//!   },
//!   &mut alice_store,
//! ).await?;
//!
//! assert!(alice_incoming.sender == bob_client.stripped_e164());
//! assert!("oh ok" == std::str::from_utf8(alice_incoming.plaintext.as_ref()).unwrap());
//!
//! # Ok(())
//! # }) // async
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

use displaydoc::Display;
use prost::Message as _;
use thiserror::Error;

use std::convert::{TryFrom, TryInto};

#[derive(Debug, Error, Display)]
pub enum MessageError {
  /// message {0:?} must be a bundle
  WasNotBundle(Message),
  /// message {0:?} must be a sealed-sender message
  WasNotSealed(Message),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
  Bundle(PreKeyBundle),
  Sealed(SealedSenderMessage),
}

impl Message {
  pub fn assert_bundle(self) -> Result<PreKeyBundle, MessageError> {
    match self.clone() {
      Self::Bundle(x) => Ok(x),
      _ => Err(MessageError::WasNotBundle(self)),
    }
  }
  pub fn assert_sealed(self) -> Result<SealedSenderMessage, MessageError> {
    match self.clone() {
      Self::Sealed(x) => Ok(x),
      _ => Err(MessageError::WasNotSealed(self)),
    }
  }
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

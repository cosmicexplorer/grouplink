/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! Define the atomic types of communications between individual [identity](crate::identity)
//! instances in the [grouplink protocol](crate).

/// [prost] structs for serializing a [Message].
pub mod proto {
  /* Ensure the generated identity.proto outputs are available under [super::identity] within the
   * sub-module also named "proto". */
  pub use crate::identity::proto as identity;
  pub use crate::session::proto as session;
  mod proto {
    #![allow(missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/grouplink.proto.message.rs"));
  }
  #[doc(inline)]
  pub use proto::*;
}

use crate::error::{Error, ProtobufCodingFailure};
use crate::session::{PreKeyBundle, SealedSenderMessage};
use crate::util::encode_proto_message;

use displaydoc::Display;
use prost::Message as _;
use thiserror::Error;

use std::convert::{TryFrom, TryInto};

/// Types of errors that can occur while processing an incoming [Message].
#[derive(Debug, Error, Display)]
pub enum MessageError {
  /// message {0:?} was expected to be a [Message::Bundle]
  WasNotBundle(Message),
  /// message {0:?} was expected to be a [Message::Sealed]
  WasNotSealed(Message),
}

/// Types of incoming messages which a [grouplink](crate) client needs to be able to handle.
///
/// Note that these are a subset of message types available in [libsignal_protocol] which can be
/// effectively represented inline with the message contents, in a `gpg`-like way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
  /// All of the information needed to perform an [X3DH] asynchronous key agreement.
  ///
  /// [X3DH]: https://signal.org/docs/specifications/x3dh/#publishing-keys
  Bundle(PreKeyBundle),
  /// A message from another user, which may start a new [Double Ratchet] chain or re-use an
  /// existing conversation.
  ///
  /// [Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/#kdf-chains
  Sealed(SealedSenderMessage),
}

impl Message {
  #[doc(hidden)]
  pub fn assert_bundle(self) -> Result<PreKeyBundle, MessageError> {
    match self.clone() {
      Self::Bundle(x) => Ok(x),
      _ => Err(MessageError::WasNotBundle(self)),
    }
  }
  #[doc(hidden)]
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

#[cfg(test)]
pub mod test {
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

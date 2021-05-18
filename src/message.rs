/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

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

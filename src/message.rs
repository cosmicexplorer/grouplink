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
use crate::session::{
  address_exposed::{FollowUpMessage, SessionInitiatingMessageRequest},
  PreKeyBundle,
};
use crate::util::encode_proto_message;

use prost::Message as _;

use std::convert::{TryFrom, TryInto};

#[derive(Debug, Clone)]
pub enum Message {
  Bundle(PreKeyBundle),
  Initial(SessionInitiatingMessageRequest),
  FollowUp(FollowUpMessage),
}

impl TryFrom<Message> for proto::Message {
  type Error = Error;
  fn try_from(value: Message) -> Result<Self, Error> {
    Ok(proto::Message {
      r#type: Some(match value {
        Message::Bundle(pre_key_bundle) => proto::message::Type::Bundle(pre_key_bundle.try_into()?),
        Message::Initial(init_message_req) => {
          proto::message::Type::Initial(init_message_req.into())
        }
        Message::FollowUp(follow_up) => proto::message::Type::FollowUp(follow_up.into()),
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
    let proto::Message { r#type: inner } = value;
    let inner = inner.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find the `type` field!"
      )))
    })?;
    Ok(match inner {
      proto::message::Type::Bundle(pre_key_bundle) => Message::Bundle(pre_key_bundle.try_into()?),
      proto::message::Type::Initial(init_message_req) => {
        Message::Initial(init_message_req.try_into()?)
      }
      proto::message::Type::FollowUp(follow_up) => Message::FollowUp(follow_up.try_into()?),
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

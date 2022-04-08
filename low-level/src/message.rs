/* Copyright 2021-2022 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! Define the atomic types of communications between individual [identity](crate::identity)
//! instances in the [grouplink protocol](crate).

/// [prost] structs for serializing a [Message].
pub mod proto {
  /* Ensure the generated identity.proto outputs are available under [super::identity] within the
   * sub-module also named "proto". */
  pub use crate::identity::proto as identity;
  pub use crate::session::proto as session;
  #[doc(inline)]
  pub use proto::*;
  mod proto {
    #![allow(missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/grouplink.proto.message.rs"));
  }
}

use crate::error::ProtobufCodingFailure;
use crate::session::{PreKeyBundle, SealedSenderMessage};

use displaydoc::Display;
use thiserror::Error;

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

pub use serde_impl::*;
mod serde_impl {
  use super::*;
  use crate::{error::Error, serde};
  use std::convert::{TryFrom, TryInto};

  pub use message::*;
  mod message {
    use super::*;

    impl serde::Schema for proto::Message {
      type Source = Message;
    }

    impl From<Message> for proto::Message {
      fn from(value: Message) -> Self {
        proto::Message {
          r#type: Some(match value {
            Message::Bundle(pre_key_bundle) => proto::message::Type::Bundle(
              pre_key_bundle
                .try_into()
                .expect("expected pre_key_bundle in bundle message"),
            ),
            Message::Sealed(sealed_sender_message) => proto::message::Type::SealedSenderMessage(
              sealed_sender_message
                .try_into()
                .expect("expected sealed_sender_message in sealed message"),
            ),
          }),
        }
      }
    }

    impl TryFrom<proto::Message> for Message {
      type Error = Error;
      fn try_from(value: proto::Message) -> Result<Self, Error> {
        let proto::Message { r#type: inner } = value.clone();
        let inner = inner.ok_or_else(|| {
          Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
            "failed to find the `type` field!".to_string(),
            format!("{:?}", value),
          ))
        })?;
        Ok(match inner {
          proto::message::Type::Bundle(pre_key_bundle) => {
            Message::Bundle(pre_key_bundle.try_into()?)
          }
          proto::message::Type::SealedSenderMessage(sealed_sender_message) => {
            Message::Sealed(sealed_sender_message.try_into()?)
          }
        })
      }
    }
  }
}

/* #[cfg(test)] */
/* pub mod test { */
/*   use super::*; */
/*   use crate::identity::{ */
/*     generate_sealed_sender_identity, generate_sender_cert, Identity, SenderCertTTL, */
/*   }; */
/*   use crate::session::{proptest_strategies::*, *}; */
/*   use crate::store::proptest_strategies::*; */

/*   use futures::executor::block_on; */
/*   use proptest::prelude::*; */

/*   use std::convert::{TryFrom, TryInto}; */

/*   proptest! { */
/*     #[test] */
/*     fn test_serde_message_bundle(id in any::<Identity>(), */
/*                                  spk_req in any::<SignedPreKeyRequest>(), */
/*                                  opk_req in any::<OneTimePreKeyRequest>()) { */
/*       let store = generate_store_wrapper(id.crypto); */
/*       let spk = block_on(generate_signed_pre_key_wrapped(store.clone(), spk_req)).unwrap(); */
/*       let opk = block_on(generate_one_time_pre_key_wrapped(store.clone(), opk_req)).unwrap(); */
/*       let pkb = block_on(generate_pre_key_bundle_wrapped( */
/*         store.clone(), id.external.clone(), spk, opk) */
/*       ).unwrap(); */
/*       let message_bundle: Message = Message::Sealed(block_on(encrypt_pre_key_bundle_message( */
/*         SealedSenderPreKeyBundleRequest { */
/*           bundle: pkb, */
/*           sender_cert: generate_sender_cert( */
/*             generate_sealed_sender_identity(id.external.clone()).stripped_e164(), */
/*             id.crypto, */
/*             SenderCertTTL::default()).unwrap(), */
/*         }, */
/*         &mut *store.write(), */
/*       )).unwrap()); */
/*       let encoded_pre_key_bundle: Box<[u8]> = message_bundle.clone().try_into().unwrap(); */
/*       let resurrected = Message::try_from(encoded_pre_key_bundle.as_ref()).unwrap(); */
/*       prop_assert_eq!(message_bundle, resurrected); */
/*     } */
/*   } */
/* } */

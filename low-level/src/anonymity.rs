/* Copyright 2022 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! Anonymize message metadata with [Double Ratchet header encryption].
//!
//! Implemented via the [Pond protocol].
//!
//! [Double Ratchet header encryption]: https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption
//! [Pond protocol]: #pond-protocol
//!
//! # Overview
//!
//! Signal's Double Ratchet message conversation model introduces a separation between the phase of
//! *initiating* a conversation and then *responding* to it. This contrasts to e.g. PGP-signed email
//! relying upon Web of Trust, which requires that each participant provide a cryptographic
//! guarantee that they possess the private key to a specific well-known public key that they widely
//! associate with their name. Web of Trust not only takes massive time and effort to maintain, but
//! it precludes the possibility of anonymity while using encryption. **Unfortunately, Signal itself
//! also produces a form of this failure, by requiring that you identify yourself with a single
//! working phone number.**
//!
//! Web of Trust/PGP may be thought of as "stateless" in a way that Signal is not--in this case,
//! Signal's ratcheting state improves security, introducing forward secrecy. We would like to
//! extend this advantage by using the ratcheting KDF state to generate secret *header keys* which
//! are used to anonymize the metadata of each message. While **tor does this through a network of
//! relays** to stimy the tracking of individual packets in and out, we can **use the pre-negotiated
//! stateful message chain to deterministically ensure the anonymity of our messages!**
//!
//! # Header Encryption
//!
//! Signal's Double Ratchet spec contains a [section describing *header encryption*][Double Ratchet
//! header encryption], which can be used to implement the above. One of the subsequent requirements
//! noted to apply this method is **associating messages to sessions.** The Pond protocol is
//! suggested as a way to perform this.
//!
//! ## Pond Protocol
//!
//! The [Pond protocol][pond paper] is a group signature scheme, which affords anonymity to signers
//! while enabling the association of messages to sessions as specified above. There is an
//! [unmaintained implementation of the Pond protocol in go][pond impl] as prior art to refer to
//! here. We should be able to adapt this code to rust (along with their test suite!) to produce
//! header-encrypted Signal message chains.
//!
//! [pond paper]: https://crypto.stanford.edu/~dabo/papers/groupsigs.pdf
//! [pond impl]: https://github.com/agl/pond
//!
//! # Architecture
//!
//! This subcrate should extend the API of [crate::message] to cover the Pond protocol's use case:
//! to send and receive anonymized messages. [crate::message] refers to concrete identities which
//! need to be encrypted for anonymity, which should be implemented in this module.

/// [prost] structs for serializing an [AnonymousMessage].
pub mod proto {
  /* Ensure the generated dependency .proto outputs are available within the
   * sub-module also named "proto". */
  pub use crate::identity::proto as identity;
  pub use crate::message::proto as message;
  pub use crate::session::proto as session;
  mod proto {
    #![allow(missing_docs)]
    include!(concat!(env!("OUT_DIR"), "/grouplink.proto.anonymity.rs"));
  }
  #[doc(inline)]
  pub use proto::*;
}

use crate::error::ProtobufCodingFailure;
use crate::message::Message;

use displaydoc::Display;
use thiserror::Error;

/// TODO
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousMessage;

/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! This crate wraps [libsignal_protocol] and offers asynchronous message encryption and signature
//! operations over arbitrary input files. It is intended to serve as a replacement for `gpg`.
//!
//! An end-to-end example of a secure bidirectional conversation between two individuals
//! *`alice`* and *`bob`*:
//!```
//! # fn main() -> Result<(), grouplink::error::Error> {
//! use grouplink::{*, store::file_persistence::*};
//! # use futures::executor::block_on;
//! use std::{convert::{TryFrom, TryInto}, path::PathBuf};
//! # use std::env::set_current_dir;
//! # use tempdir::TempDir;
//! # let tmp_dir = TempDir::new("doctest-cwd").unwrap();
//! # set_current_dir(tmp_dir.path()).unwrap();
//! # block_on(async {
//!
//! // Create a new identity.
//! let alice = generate_identity();
//! let alice_client = generate_sealed_sender_identity(alice.external.clone());
//!
//! // Create a mutable store.
//! let mut alice_store =
//!   initialize_file_backed_store(DirectoryStoreRequest {
//!     path: PathBuf::from("alice"), // Subdirectory of cwd.
//!     id: alice.crypto,
//!     behavior: ExtractionBehavior::OverwriteWithDefault,
//!   }).await?;
//!
//! // Create a destination identity.
//! let bob = generate_identity();
//! let bob_client = generate_sealed_sender_identity(bob.external.clone());
//! let mut bob_store =
//!   initialize_file_backed_store(DirectoryStoreRequest {
//!     path: PathBuf::from("bob"), // Subdirectory of cwd.
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

/* Warn for missing docs in general, and hard require crate-level docs. */
#![warn(missing_docs)]
#![deny(missing_crate_level_docs)]
/* #![deny(warnings)] */
/* Taken from the `libsignal_protocol` crate. */
#![deny(unsafe_code)]
/* Make all doctests fail if they produce any warnings. */
#![doc(test(attr(deny(warnings))))]
/* Enable all clippy lints except for many of the pedantic ones. It's a shame this needs to be
 * copied and pasted across crates, but there doesn't appear to be a way to include inner attributes
 * from a common source. */
#![deny(
  clippy::all,
  clippy::default_trait_access,
  clippy::expl_impl_clone_on_copy,
  clippy::if_not_else,
  clippy::needless_continue,
  clippy::unseparated_literal_suffix,
  clippy::used_underscore_binding
)]
/* It is often more clear to show that nothing is being moved. */
#![allow(clippy::match_ref_pats)]
/* Subjective style. */
#![allow(
  clippy::len_without_is_empty,
  clippy::redundant_field_names,
  clippy::too_many_arguments
)]
/* Default isn't as big a deal as people seem to think it is. */
#![allow(clippy::new_without_default, clippy::new_ret_no_self)]
/* Arc<Mutex> can be more clear than needing to grok Orderings: */
#![allow(clippy::mutex_atomic)]

pub mod error;
pub mod identity;
pub mod message;
pub mod session;
pub mod store;
mod util;

pub use identity::{
  generate_identity, generate_sealed_sender_identity, generate_sender_cert, Identity, SenderCert,
  SenderCertTTL,
};
pub use message::Message;
pub use session::{
  decrypt_message, encrypt_followup_message, encrypt_initial_message, generate_one_time_pre_key,
  generate_pre_key_bundle, generate_signed_pre_key, SealedSenderDecryptionRequest,
  SealedSenderFollowupMessageRequest, SealedSenderMessageRequest,
};

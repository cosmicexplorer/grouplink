/* Copyright 2021-2022 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! This crate exposes a high-level API for encrypted messaging using the [Signal] Protocol. In
//! particular, it relies on [grouplink_low_level] to send and receive encrypted messages in
//! a secure session without needing to route through a remote server.
//!
//! [Signal]: https://signal.org

/* Turn all warnings into errors! */
/* #![deny(warnings)] */
/* Warn for missing docs in general, and hard require crate-level docs. */
/* #![warn(missing_docs)] */
#![warn(rustdoc::missing_crate_level_docs)]
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

pub mod anonymity;
pub mod error;
pub mod identity_db;
pub mod key_info;
pub mod sessions;

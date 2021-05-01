/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

#![deny(warnings)]
#![deny(unsafe_code)]
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
  /* TODO: Falsely triggers for async/await:
   *   see https://github.com/rust-lang/rust-clippy/issues/5360 */
  /* clippy::used_underscore_binding */
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

use std::io;

pub fn main() -> io::Result<()> {
  Ok(())
}

#[cfg(test)]
mod test {
  use libsignal_protocol::{IdentityKeyPair, Serializable};
  use rand::rngs::OsRng;

  use std::{convert::TryFrom, io};

  #[test]
  fn re_serialize_identity_pair() -> io::Result<()> {
    let id = IdentityKeyPair::generate(&mut OsRng);
    println!("init: {:?}", &id);
    let buf = id.serialize();
    println!("serialized: {:?}", &buf);
    let orig_id = IdentityKeyPair::try_from(buf.as_ref())
      .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))?;
    println!("deserialized: {:?}", orig_id);
    assert_eq!(id, orig_id);
    assert_eq!(id.public_key(), &id.private_key().public_key());
    Ok(())
  }
}

/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???

use crate::identity::CryptographicIdentity;

use libsignal_protocol as signal;

/// ???
#[derive(Clone)]
pub struct Store(pub signal::InMemSignalProtocolStore);

fn no_store_creation_error<T>(r: Result<T, signal::SignalProtocolError>) -> T {
  r.expect("creation of the in-memory signal protocol store should succeed")
}

impl Store {
  pub fn new(crypto: CryptographicIdentity) -> Self {
    let CryptographicIdentity { inner, seed } = crypto;
    Self(no_store_creation_error(
      signal::InMemSignalProtocolStore::new(inner, seed),
    ))
  }
}

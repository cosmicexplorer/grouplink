/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???

use crate::error::Error;
use crate::identity::CryptographicIdentity;

use libsignal_protocol as signal;

/// ???
#[derive(Debug, Clone)]
pub struct Store(pub signal::InMemSignalProtocolStore);

impl Store {
  pub fn new(crypto: CryptographicIdentity) -> Result<Self, Error> {
    let CryptographicIdentity { inner, seed } = crypto;
    Ok(Self(signal::InMemSignalProtocolStore::new(inner, seed)?))
  }
}

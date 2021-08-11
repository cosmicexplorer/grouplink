use grouplink::{
  error::Error as LibraryError,
  identity,
  serde::{self, *},
  signal,
};

use displaydoc::Display;
use thiserror::Error;

#[derive(Debug, Display, Error)]
pub enum Error {
  /// grouplink error: {0}
  Library(#[from] LibraryError),
}

pub trait KeyVariant {
  fn deserialize_key(bytes: &[u8]) -> Result<Self, Error>
  where
    Self: Sized;
}

impl KeyVariant for identity::Identity {
  fn deserialize_key(bytes: &[u8]) -> Result<Self, Error>
  where
    Self: Sized,
  {
    Ok(serde::Protobuf::<
      identity::Identity,
      identity::proto::PrivateKey,
    >::deserialize(bytes)?)
  }
}
impl KeyVariant for identity::PublicIdentity {
  fn deserialize_key(bytes: &[u8]) -> Result<Self, Error>
  where
    Self: Sized,
  {
    Ok(serde::Protobuf::<
      identity::PublicIdentity,
      identity::proto::PublicKey,
    >::deserialize(bytes)?)
  }
}

pub trait KeyInfoOperation<KeyType>
where
  KeyType: KeyVariant,
{
  type OutType;
  fn execute(identity: KeyType) -> Self::OutType;
}

pub struct ExtractFingerprint;

impl KeyInfoOperation<identity::Identity> for ExtractFingerprint {
  type OutType = serde::KeyFingerprint<signal::IdentityKeyPair>;
  fn execute(identity: identity::Identity) -> Self::OutType {
    serde::KeyFingerprint::<signal::IdentityKeyPair>::new(identity.crypto.inner)
  }
}
impl KeyInfoOperation<identity::PublicIdentity> for ExtractFingerprint {
  type OutType = serde::KeyFingerprint<signal::IdentityKey>;
  fn execute(identity: identity::PublicIdentity) -> Self::OutType {
    serde::KeyFingerprint::<signal::IdentityKey>::new(identity.public_key.0)
  }
}

pub struct ExtractPublicKey;

impl KeyInfoOperation<identity::Identity> for ExtractPublicKey {
  type OutType = identity::PublicIdentity;
  fn execute(identity: identity::Identity) -> Self::OutType {
    identity.into()
  }
}

pub struct Key<T>(pub T);

impl<T> Key<T>
where
  T: KeyVariant,
{
  pub fn from_protobuf(bytes: &[u8]) -> Result<Self, Error> {
    Ok(Self(T::deserialize_key(bytes)?))
  }

  pub fn perform_operation<O>(self, op: O) -> O::OutType
  where
    O: KeyInfoOperation<T>,
  {
    O::execute(self.0)
  }
}

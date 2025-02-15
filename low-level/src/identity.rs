/* Copyright 2021-2022 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! Define the atomic forms of identity in the [grouplink protocol](crate).
//!
//! This covers objects with private key information as well as public key information.

/// [prost] structs for serializing types of identities so they can be revived in a persistent
/// [store](crate::store).
pub mod proto {
  include!(concat!(env!("OUT_DIR"), "/grouplink.proto.identity.rs"));
}

use crate::error::{Error, ProtobufCodingFailure};

use displaydoc::Display;
use libsignal_protocol as signal;
use rand::{self, CryptoRng, Rng};
use thiserror::Error;
use uuid::Uuid;

#[cfg(doc)]
use libsignal_protocol::{IdentityKeyStore, ProtocolAddress};

use std::{
  default, fmt,
  time::{Duration, SystemTime, SystemTimeError},
};

/// Types of errors that can occur when validating certain fields of atomic identities.
#[derive(Debug, Error, Display)]
pub enum IdentityError {
  /// expiration ttl {1:?} was too long given the current time {0:?}
  ExpirationIsTooFarInTheFuture(SystemTime, Duration),
  /// a system time error {0} was raised internally
  SystemTime(#[from] SystemTimeError),
}

/// Define a struct that can be created from cryptographically-random bits.
#[cfg(not(test))]
pub trait Spontaneous<Params> {
  /// Create an instance of this object which is completely specified by the "static" `params` and
  /// the "dynamic" state of `csprng`.
  fn generate<R: CryptoRng + Rng>(params: Params, csprng: &mut R) -> Self;
}
#[cfg(test)]
pub trait Spontaneous<Params>: fmt::Debug + Clone {
  fn generate<R: CryptoRng + Rng>(params: Params, csprng: &mut R) -> Self;
}

/// Specifies the public and private key information associated with an identity.
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct CryptographicIdentity {
  /// The underlying identity construct from [libsignal_protocol].
  ///
  /// Returned by [IdentityKeyStore::get_identity_key_pair].
  pub inner: signal::IdentityKeyPair,
  /// Used to reliably construct KDFs for this identity.
  ///
  /// Returned by [IdentityKeyStore::get_local_registration_id].
  pub seed: crate::wrapper_types::SessionSeed,
}

impl Spontaneous<()> for CryptographicIdentity {
  fn generate<R: CryptoRng + Rng>(_params: (), csprng: &mut R) -> Self {
    let inner = signal::IdentityKeyPair::generate(csprng);
    let seed: crate::wrapper_types::SessionSeed = csprng.gen::<u32>().into();
    Self { inner, seed }
  }
}

/// Specifies the outward-facing "address" of an identity so others can send messages to it.
///
/// Fungible with [ProtocolAddress], with helper methods for consistent serialization with
/// "typeless" protobuf maps (see [ProtobufCodingFailure::MapStringCodingFailed]).
#[derive(Debug, Hash, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct ExternalIdentity {
  /// An arbitrary string of arbitrary length, typically representing a UUID. Unique per "identity".
  pub name: String,
  /// A wrapper for a small positive number used to disambiguate different clients which represent
  /// the same underlying identity.
  pub device_id: signal::DeviceId,
}

impl ExternalIdentity {
  /// Return a string which reproduces this exact object from [Self::from_unambiguous_string].
  pub fn as_unambiguous_string(&self) -> String {
    format!("{}/{}", self.name, self.device_id)
  }

  /// Deserialize from a string produced by [Self::as_unambiguous_string].
  pub fn from_unambiguous_string(s: &str) -> Result<Self, Error> {
    s.find('/')
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::MapStringCodingFailed(format!(
          "failed to decode an address from a string used as a protobuf map key! was: '{}'",
          s
        ), s.to_string()))
      })
      .and_then(|slash_index| {
        let address_str = &s[..slash_index];
        let id_str = &s[slash_index + 1..];
        let device_id: signal::DeviceId = id_str
          .parse::<u32>()
          .map_err(|e| {
            Error::ProtobufDecodingError(ProtobufCodingFailure::MapStringCodingFailed(format!(
              "failed ({:?}) to parse device id from a string used as a protobuf map key! was: '{}'",
              e, s
            ), s.to_string()))
          })?;
        Ok(Self {
          name: address_str.to_string(),
          device_id,
        })
      })
  }
}

impl fmt::Display for ExternalIdentity {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let address: signal::ProtocolAddress = self.clone().into();
    write!(f, "{}", address)
  }
}

impl From<signal::ProtocolAddress> for ExternalIdentity {
  fn from(value: signal::ProtocolAddress) -> ExternalIdentity {
    ExternalIdentity {
      name: value.name().to_string(),
      device_id: value.device_id(),
    }
  }
}

impl From<ExternalIdentity> for signal::ProtocolAddress {
  fn from(value: ExternalIdentity) -> signal::ProtocolAddress {
    let ExternalIdentity { name, device_id } = value;
    signal::ProtocolAddress::new(name, device_id)
  }
}

impl Spontaneous<()> for ExternalIdentity {
  fn generate<R: CryptoRng + Rng>(_params: (), csprng: &mut R) -> Self {
    let random_bytes: [u8; 16] = csprng.gen();
    let random_uuid: Uuid = Uuid::from_bytes(random_bytes);
    let random_device: signal::DeviceId = csprng.gen::<u32>();
    Self {
      name: random_uuid.to_string(),
      device_id: random_device,
    }
  }
}

/// Contains the cryptographic and external-facing components of a distinct identity.
///
/// Can be immediately generated at any time with [generate_identity].
#[derive(Debug, Hash, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct Identity {
  #[allow(missing_docs)]
  pub crypto: CryptographicIdentity,
  #[allow(missing_docs)]
  pub external: ExternalIdentity,
}

impl Spontaneous<()> for Identity {
  fn generate<R: CryptoRng + Rng>(_params: (), csprng: &mut R) -> Self {
    let crypto = CryptographicIdentity::generate((), csprng);
    let external = ExternalIdentity::generate((), csprng);
    Self { crypto, external }
  }
}

/// Produce an entirely new identity from random state.
///
/// This identity is "anonymous" as it has no relationship to any other identity ever produced:
///```
/// # fn main() -> Result<(), grouplink_low_level::error::Error> {
/// use grouplink_low_level::identity::*;
///
/// // Create a new identity.
/// let id = generate_identity();
/// // The identity is unique.
/// assert!(id != generate_identity());
/// # Ok(())
/// # }
///```
pub fn generate_identity() -> Identity {
  Identity::generate((), &mut rand::thread_rng())
}

impl fmt::Display for Identity {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Identity {{ external={}, crypto=<...> }}", self.external)
  }
}

#[derive(Debug, Hash, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct PublicCryptoIdentity(pub signal::IdentityKey);

impl From<CryptographicIdentity> for PublicCryptoIdentity {
  fn from(value: CryptographicIdentity) -> Self {
    Self(*value.inner.identity_key())
  }
}

#[derive(Debug, Hash, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct PublicIdentity {
  pub public_key: PublicCryptoIdentity,
  pub external: ExternalIdentity,
}

impl From<Identity> for PublicIdentity {
  fn from(value: Identity) -> Self {
    let Identity { crypto, external } = value;
    Self {
      public_key: crypto.into(),
      external,
    }
  }
}

/// An extension of [ExternalIdentity] which differentiates between different clients representing
/// the same identity.
#[derive(Debug, Hash, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct SealedSenderIdentity {
  /// The external-facing identity.
  pub inner: ExternalIdentity,
  /// An optional string which uniquely specifies this client, similar to
  /// [ExternalIdentity::device_id].
  ///
  /// Used by [Message::Sealed] to avoid sending sealed-sender messages to the current client
  /// by accident.
  pub e164: Option<String>,
}

impl SealedSenderIdentity {
  /// Remove the optional [Self::e164] field to avoid leaking that info to other identities.
  pub fn stripped_e164(&self) -> Self {
    let Self { inner, .. } = self;
    Self {
      inner: inner.clone(),
      e164: None,
    }
  }
}

impl Spontaneous<ExternalIdentity> for SealedSenderIdentity {
  fn generate<R: CryptoRng + Rng>(params: ExternalIdentity, csprng: &mut R) -> Self {
    let random_e164_bytes: [u8; 16] = csprng.gen();
    let random_e164: Uuid = Uuid::from_bytes(random_e164_bytes);
    Self {
      inner: params,
      e164: Some(random_e164.to_string()),
    }
  }
}

/// Produce a unique, anonymous client instance representing the given `external` identity.
///
/// Consumed by [generate_sender_cert]. Mix and match with [generate_identity] as needed:
///```
/// # fn main() -> Result<(), grouplink_low_level::error::Error> {
/// use grouplink_low_level::identity::*;
///
/// // Create a new identity.
/// let alice = generate_identity();
/// // Create a new client instance for this identity.
/// # #[allow(unused_variables)]
/// let alice_client = generate_sealed_sender_identity(alice.external.clone());
/// # Ok(())
/// # }
///```
pub fn generate_sealed_sender_identity(external: ExternalIdentity) -> SealedSenderIdentity {
  SealedSenderIdentity::generate(external, &mut rand::thread_rng())
}

#[cfg(test)]
impl Spontaneous<()> for SealedSenderIdentity {
  fn generate<R: CryptoRng + Rng>(_params: (), csprng: &mut R) -> Self {
    let ext = ExternalIdentity::generate((), csprng);
    Self::generate(ext, csprng)
  }
}

/// One-time certificate object to validate each [Message::Sealed].
///
/// In the Signal app, this corresponds to information handled by the backend server. In the
/// [grouplink](crate) model, this is generated for each new message to encrypt.
#[derive(Debug, Clone)]
pub struct ServerCert {
  /// Underlying [libsignal_protocol] concept this relies on.
  pub inner: signal::ServerCertificate,
  /// We generate a new unrelated [signal::KeyPair] instance for each [ServerCert].
  pub trust_root: signal::PublicKey,
}

fn generate_server_cert() -> Result<(ServerCert, signal::KeyPair), Error> {
  let trust_root = signal::KeyPair::generate(&mut rand::thread_rng());
  let server_key = signal::KeyPair::generate(&mut rand::thread_rng());
  let certificate_id: u32 = (&mut rand::thread_rng()).gen();
  Ok((
    ServerCert {
      inner: signal::ServerCertificate::new(
        certificate_id,
        server_key.public_key,
        &trust_root.private_key,
        &mut rand::thread_rng(),
      )?,
      trust_root: trust_root.public_key,
    },
    server_key,
  ))
}

/// One-time certificate object to validate each [Message::Sealed]. Requires a [ServerCert] to be
/// created first, which is done in [generate_sender_cert].
///
/// In the Signal app, this corresponds to information the frontend client would hand off to the
/// backend server to create a sealed-sender message. In the [grouplink](crate) model, this is newly
/// generated for each sealed-sender message to encrypt.
#[derive(Debug, Clone)]
pub struct SenderCert {
  /// Underlying [libsignal_protocol] concept this relies on.
  pub inner: signal::SenderCertificate,
  /// We generate a new unrelated [signal::KeyPair] instance for each [ServerCert] and therefore
  /// each [SenderCert]. See [ServerCert::trust_root].
  pub trust_root: signal::PublicKey,
}

/// Length of time which may pass before a [SenderCert] expires and cannot be used. Defaults to
/// 1 day.
#[derive(Debug, Copy, Clone)]
pub struct SenderCertTTL(pub Duration);

impl SenderCertTTL {
  /// Calculate the unix timestamp after which the [SenderCert] will be considered "expired" and may
  /// no longer be used to decrypt anything.
  pub fn calculate_expires_timestamp(self) -> Result<u64, IdentityError> {
    let now = SystemTime::now();
    if let Some(expiration) = now.checked_add(self.0) {
      Ok(expiration.duration_since(SystemTime::UNIX_EPOCH)?.as_secs())
    } else {
      Err(IdentityError::ExpirationIsTooFarInTheFuture(now, self.0))
    }
  }
}

impl default::Default for SenderCertTTL {
  fn default() -> Self {
    /* 1 day */
    Self(Duration::from_secs(60 * 60 * 24))
  }
}

/// Create a one-time sender certificate to send a sealed-sender message. See [Message::Sealed].
///
/// Consumes the result of [generate_sealed_sender_identity] and [generate_identity]:
///```
/// # fn main() -> Result<(), grouplink_low_level::error::Error> {
/// use grouplink_low_level::identity::*;
///
/// // Create a new identity.
/// let alice = generate_identity();
/// // Create a new client instance for this identity.
/// let alice_client = generate_sealed_sender_identity(alice.external.clone());
///
/// // Create a sender certificate to send sealed-sender messages.
/// # #[allow(unused_variables)]
/// let sender_cert = generate_sender_cert(alice_client.stripped_e164(), alice.crypto,
///                                        SenderCertTTL::default())?;
/// # Ok(())
/// # }
///```
pub fn generate_sender_cert(
  id: SealedSenderIdentity,
  crypto: CryptographicIdentity,
  ttl: SenderCertTTL,
) -> Result<SenderCert, Error> {
  let SealedSenderIdentity {
    inner: external,
    e164,
  } = id;
  let (ServerCert { inner, trust_root }, server_key) = generate_server_cert()?;
  Ok(SenderCert {
    inner: signal::SenderCertificate::new(
      external.name.clone(),
      e164,
      *crypto.inner.public_key(),
      external.device_id,
      ttl.calculate_expires_timestamp()?,
      inner,
      &server_key.private_key,
      &mut rand::thread_rng(),
    )?,
    trust_root,
  })
}

pub use serde_impl::*;
mod serde_impl {
  use super::*;
  use crate::{error::Error, serde};
  use std::convert::{AsRef, TryFrom, TryInto};

  pub use crypto_id::*;
  mod crypto_id {
    use super::*;

    impl serde::Schema for proto::CryptographicIdentity {
      type Source = CryptographicIdentity;
    }

    impl TryFrom<proto::CryptographicIdentity> for CryptographicIdentity {
      type Error = Error;
      fn try_from(proto_message: proto::CryptographicIdentity) -> Result<Self, Error> {
        let proto::CryptographicIdentity { inner, seed } = proto_message.clone();
        let inner_vec: Vec<u8> = inner.ok_or_else(|| {
          Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
            "failed to find `inner` field!".to_string(),
            format!("{:?}", proto_message),
          ))
        })?;
        let inner: &[u8] = inner_vec.as_ref();
        let inner: signal::IdentityKeyPair = inner.try_into()?;
        let seed: crate::wrapper_types::SessionSeed = seed
          .ok_or_else(|| {
            Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
              "failed to find `seed` field!".to_string(),
              format!("{:?}", proto_message),
            ))
          })?
          .into();
        Ok(Self { inner, seed })
      }
    }

    impl From<CryptographicIdentity> for proto::CryptographicIdentity {
      fn from(value: CryptographicIdentity) -> Self {
        proto::CryptographicIdentity {
          inner: Some(value.inner.serialize().into_vec()),
          seed: Some(value.seed.into()),
        }
      }
    }
  }

  pub use external_id::*;
  mod external_id {
    use super::*;

    impl serde::Schema for proto::Address {
      type Source = ExternalIdentity;
    }

    impl From<ExternalIdentity> for proto::Address {
      fn from(value: ExternalIdentity) -> proto::Address {
        let address: signal::ProtocolAddress = value.into();
        proto::Address {
          name: Some(address.name().to_string()),
          device_id: Some(address.device_id()),
        }
      }
    }

    impl TryFrom<proto::Address> for ExternalIdentity {
      type Error = Error;
      fn try_from(proto_message: proto::Address) -> Result<Self, Error> {
        let proto::Address { name, device_id } = proto_message.clone();
        let name = name.ok_or_else(|| {
          Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
            "failed to find `name` field!".to_string(),
            format!("{:?}", proto_message),
          ))
        })?;
        let device_id: signal::DeviceId = device_id.ok_or_else(|| {
          Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
            "failed to find `device_id` field!".to_string(),
            format!("{:?}", proto_message),
          ))
        })?;
        Ok(Self { name, device_id })
      }
    }
  }

  pub use id::*;
  mod id {
    use super::*;

    impl serde::Schema for proto::PrivateKey {
      type Source = Identity;
    }

    impl TryFrom<proto::PrivateKey> for Identity {
      type Error = Error;
      fn try_from(proto_message: proto::PrivateKey) -> Result<Self, Error> {
        let proto::PrivateKey { crypto, external } = proto_message.clone();
        let crypto: CryptographicIdentity = crypto
          .ok_or_else(|| {
            Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
              "failed to find `crypto` field!".to_string(),
              format!("{:?}", proto_message),
            ))
          })?
          .try_into()?;
        let external: ExternalIdentity = external
          .ok_or_else(|| {
            Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
              "failed to find `external` field!".to_string(),
              format!("{:?}", proto_message),
            ))
          })?
          .try_into()?;
        Ok(Self { crypto, external })
      }
    }

    impl From<Identity> for proto::PrivateKey {
      fn from(value: Identity) -> Self {
        let Identity { crypto, external } = value;
        proto::PrivateKey {
          crypto: Some(crypto.into()),
          external: Some(external.into()),
        }
      }
    }
  }

  pub use public_key::*;
  mod public_key {
    use super::*;

    impl serde::Schema for proto::PublicKey {
      type Source = PublicIdentity;
    }

    impl TryFrom<proto::PublicKey> for PublicIdentity {
      type Error = Error;
      fn try_from(proto_message: proto::PublicKey) -> Result<Self, Error> {
        let proto::PublicKey {
          public_key,
          external,
        } = proto_message.clone();
        let public_key_vec: Vec<u8> = public_key.ok_or_else(|| {
          Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
            "failed to find `public_key` field!".to_string(),
            format!("{:?}", proto_message),
          ))
        })?;
        let public_key: &[u8] = public_key_vec.as_ref();
        let public_key: signal::IdentityKey = public_key.try_into()?;
        let external: ExternalIdentity = external
          .ok_or_else(|| {
            Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
              "failed to find `external` field!".to_string(),
              format!("{:?}", proto_message),
            ))
          })?
          .try_into()?;
        Ok(Self {
          public_key: PublicCryptoIdentity(public_key),
          external,
        })
      }
    }

    impl From<PublicIdentity> for proto::PublicKey {
      fn from(value: PublicIdentity) -> Self {
        proto::PublicKey {
          public_key: Some(value.public_key.0.serialize().into_vec()),
          external: Some(value.external.into()),
        }
      }
    }
  }

  pub use sealed_sender_identity::*;
  mod sealed_sender_identity {
    use super::*;

    impl serde::Schema for proto::SealedSenderIdentity {
      type Source = SealedSenderIdentity;
    }

    impl TryFrom<proto::SealedSenderIdentity> for SealedSenderIdentity {
      type Error = Error;
      fn try_from(proto_message: proto::SealedSenderIdentity) -> Result<Self, Error> {
        let proto::SealedSenderIdentity { inner, e164 } = proto_message.clone();
        let inner: ExternalIdentity = inner
          .ok_or_else(|| {
            Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
              "failed to find `inner` field!".to_string(),
              format!("{:?}", proto_message),
            ))
          })?
          .try_into()?;
        Ok(Self { inner, e164 })
      }
    }

    impl From<SealedSenderIdentity> for proto::SealedSenderIdentity {
      fn from(value: SealedSenderIdentity) -> Self {
        proto::SealedSenderIdentity {
          inner: Some(value.inner.into()),
          e164: value.e164,
        }
      }
    }
  }

  pub use fingerprints::*;
  mod fingerprints {
    use crate::serde;
    use libsignal_protocol as signal;

    pub use public_key::*;
    mod public_key {
      use super::*;
      impl From<signal::IdentityKey>
        for serde::fingerprinting::FingerprintableBytes<signal::IdentityKey>
      {
        fn from(value: signal::IdentityKey) -> Self {
          Self::new(value.serialize())
        }
      }
      impl serde::fingerprinting::Fingerprintable for signal::IdentityKey {}
    }

    pub use private_key::*;
    mod private_key {
      use super::*;
      impl From<signal::IdentityKeyPair>
        for serde::fingerprinting::FingerprintableBytes<signal::IdentityKeyPair>
      {
        fn from(value: signal::IdentityKeyPair) -> Self {
          Self::new(value.serialize())
        }
      }
      impl serde::fingerprinting::Fingerprintable for signal::IdentityKeyPair {}
    }
  }
}

#[cfg(test)]
pub mod proptest_strategies {
  use super::*;

  use proptest::{
    arbitrary::Arbitrary,
    strategy::{NewTree, Strategy, ValueTree},
    test_runner::TestRunner,
  };

  #[derive(Clone)]
  pub struct SpontaneousParamsTree<Params: fmt::Debug + Clone, T: Spontaneous<Params>> {
    params: Params,
    inner: T,
  }

  impl<Params: fmt::Debug + Clone, T: Spontaneous<Params>> fmt::Debug
    for SpontaneousParamsTree<Params, T>
  {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      write!(f, "{{ params={:?} }}", self.params)
    }
  }

  impl<Params: fmt::Debug + Clone, T: Spontaneous<Params>> SpontaneousParamsTree<Params, T> {
    pub fn new(params: Params) -> Self {
      let p2 = params.clone();
      Self {
        params,
        inner: T::generate(p2, &mut rand::thread_rng()),
      }
    }
  }

  impl<Params: fmt::Debug + Clone, T: Spontaneous<Params>> ValueTree
    for SpontaneousParamsTree<Params, T>
  {
    type Value = T;
    fn current(&self) -> Self::Value {
      self.inner.clone()
    }
    fn simplify(&mut self) -> bool {
      false
    }
    fn complicate(&mut self) -> bool {
      false
    }
  }

  impl<Params: fmt::Debug + Clone, T: Spontaneous<Params>> Strategy
    for SpontaneousParamsTree<Params, T>
  {
    type Tree = Self;
    type Value = T;
    fn new_tree(&self, _runner: &mut TestRunner) -> NewTree<Self> {
      Ok(self.clone())
    }
  }

  impl Arbitrary for CryptographicIdentity {
    type Parameters = ();
    type Strategy = SpontaneousParamsTree<(), Self>;
    fn arbitrary_with(args: ()) -> Self::Strategy {
      SpontaneousParamsTree::new(args)
    }
  }
  impl Arbitrary for ExternalIdentity {
    type Parameters = ();
    type Strategy = SpontaneousParamsTree<(), Self>;
    fn arbitrary_with(args: ()) -> Self::Strategy {
      SpontaneousParamsTree::new(args)
    }
  }
  impl Arbitrary for Identity {
    type Parameters = ();
    type Strategy = SpontaneousParamsTree<(), Self>;
    fn arbitrary_with(args: ()) -> Self::Strategy {
      SpontaneousParamsTree::new(args)
    }
  }
}

#[cfg(test)]
pub mod test {
  use super::*;
  use crate::serde::{self, *};

  use proptest::prelude::*;

  proptest! {
    #[test]
    fn test_serde_external(external in any::<ExternalIdentity>()) {
      let protobuf = serde::Protobuf::<ExternalIdentity, proto::Address>::new(external.clone());
      let buf: Box<[u8]> = protobuf.serialize();
      let resurrected =
        serde::Protobuf::<ExternalIdentity, proto::Address>::deserialize(&buf).unwrap();
      prop_assert_eq!(external, resurrected);
    }
  }
}

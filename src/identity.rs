/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???

pub mod proto {
  include!(concat!(env!("OUT_DIR"), "/grouplink.proto.identity.rs"));
}

pub use libsignal_protocol as signal;
use prost::Message;
pub use rand;
use rand::{CryptoRng, Rng};
use uuid::Uuid;

use std::{
  convert::{AsRef, From, TryFrom},
  fmt,
};

use crate::error::Error;

pub trait SpontaneouslyGenerable<Params> {
  fn generate<R: CryptoRng + Rng>(params: Params, csprng: &mut R) -> Self;
}

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub(crate) struct CryptographicIdentity {
  inner: signal::IdentityKeyPair,
}

impl CryptographicIdentity {
  pub fn new(inner: signal::IdentityKeyPair) -> Self {
    Self { inner }
  }

  pub fn into_inner(self) -> signal::IdentityKeyPair {
    self.inner
  }
}

impl SpontaneouslyGenerable<()> for CryptographicIdentity {
  fn generate<R: CryptoRng + Rng>(_params: (), csprng: &mut R) -> Self {
    Self::new(signal::IdentityKeyPair::generate(csprng))
  }
}

impl AsRef<signal::IdentityKeyPair> for CryptographicIdentity {
  fn as_ref(&self) -> &signal::IdentityKeyPair {
    &self.inner
  }
}

impl From<CryptographicIdentity> for signal::IdentityKeyPair {
  fn from(value: CryptographicIdentity) -> signal::IdentityKeyPair {
    value.into_inner()
  }
}

impl From<signal::IdentityKeyPair> for CryptographicIdentity {
  fn from(value: signal::IdentityKeyPair) -> Self {
    Self::new(value)
  }
}

fn no_encoding_error(r: Result<(), prost::EncodeError>) -> () {
  r.expect("expect encoding into a vec to never fail")
}

fn encode_proto_message<M: Message>(m: M) -> Box<[u8]> {
  let mut serialized = Vec::<u8>::with_capacity(m.encoded_len());
  no_encoding_error(m.encode(&mut &mut serialized));
  serialized.into_boxed_slice()
}

#[derive(Debug, Hash, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub(crate) struct ExternalIdentity {
  pub name: String,
  pub device_id: signal::DeviceId,
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

impl From<ExternalIdentity> for proto::Address {
  fn from(value: ExternalIdentity) -> proto::Address {
    let address: signal::ProtocolAddress = value.into();
    proto::Address {
      name: Some(address.name().to_string()),
      device_id: Some(address.device_id().into()),
    }
  }
}

impl TryFrom<proto::Address> for ExternalIdentity {
  type Error = Error;
  fn try_from(proto_message: proto::Address) -> Result<Self, Error> {
    let name = proto_message
      .name
      .ok_or_else(|| Error::ProtobufDecodingError(format!("failed to find `name` field!")))?;
    let device_id: signal::DeviceId = proto_message
      .device_id
      .ok_or_else(|| Error::ProtobufDecodingError(format!("failed to find `device_id` field!")))?
      .into();
    Ok(Self { name, device_id })
  }
}

impl From<ExternalIdentity> for Box<[u8]> {
  fn from(value: ExternalIdentity) -> Box<[u8]> {
    let proto_message: proto::Address = value.into();
    encode_proto_message(proto_message)
  }
}

impl TryFrom<&[u8]> for ExternalIdentity {
  type Error = Error;
  fn try_from(value: &[u8]) -> Result<Self, Error> {
    let proto_message = proto::Address::decode(value)?;
    Self::try_from(proto_message)
  }
}

impl SpontaneouslyGenerable<()> for ExternalIdentity {
  fn generate<R: CryptoRng + Rng>(_params: (), csprng: &mut R) -> Self {
    let random_bytes: [u8; 16] = csprng.gen();
    let random_uuid: Uuid = Uuid::from_bytes(random_bytes);
    let random_device: signal::DeviceId = csprng.gen::<u32>().into();
    Self {
      name: random_uuid.to_string(),
      device_id: random_device,
    }
  }
}

/// ???
///
///```
/// # fn main() -> Result<(), grouplink::error::Error> {
/// use grouplink::identity::{Identity, SpontaneouslyGenerable};
/// use rand;
/// use std::convert::TryFrom;
///
/// // Create a new identity.
/// let id = Identity::generate((), &mut rand::thread_rng());
///
/// // Serialize the identity.
/// let buf: Box<[u8]> = id.clone().into();
/// // Deserialize the identity.
/// let resurrected = Identity::try_from(buf.as_ref())?;
///
/// assert!(id == resurrected);
/// # Ok(())
/// # }
///```
#[derive(Debug, Hash, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct Identity {
  pub(crate) crypto: CryptographicIdentity,
  pub(crate) external: ExternalIdentity,
}

impl SpontaneouslyGenerable<()> for Identity {
  fn generate<R: CryptoRng + Rng>(_params: (), csprng: &mut R) -> Self {
    let crypto = CryptographicIdentity::generate((), csprng);
    let external = ExternalIdentity::generate((), csprng);
    Self { crypto, external }
  }
}

impl From<Identity> for proto::Identity {
  fn from(value: Identity) -> Self {
    let Identity { crypto, external } = value;
    let signal_key: signal::IdentityKeyPair = crypto.into();
    proto::Identity {
      signal_key_pair: Some(signal_key.serialize().into_vec()),
      address: Some(proto::Address::from(external)),
    }
  }
}

impl TryFrom<proto::Identity> for Identity {
  type Error = Error;
  fn try_from(proto_message: proto::Identity) -> Result<Self, Error> {
    let encoded_key_pair: Vec<u8> = proto_message.signal_key_pair.ok_or_else(|| {
      Error::ProtobufDecodingError(format!("failed to find `signal_key_pair` field!"))
    })?;
    let decoded_key_pair = signal::IdentityKeyPair::try_from(encoded_key_pair.as_ref())?;
    let address: proto::Address = proto_message.address.ok_or_else(|| {
      Error::ProtobufDecodingError(format!("failed to find `signal_address` field!"))
    })?;
    Ok(Self {
      crypto: CryptographicIdentity::new(decoded_key_pair),
      external: ExternalIdentity::try_from(address)?,
    })
  }
}

impl TryFrom<&[u8]> for Identity {
  type Error = Error;
  fn try_from(value: &[u8]) -> Result<Self, Error> {
    let proto_message = proto::Identity::decode(value)?;
    Self::try_from(proto_message)
  }
}

impl From<Identity> for Box<[u8]> {
  fn from(value: Identity) -> Box<[u8]> {
    let proto_message: proto::Identity = value.into();
    encode_proto_message(proto_message)
  }
}

impl fmt::Display for Identity {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Identity {{ external={}, crypto=<...> }}", self.external)
  }
}

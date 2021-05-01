/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???

pub mod proto {
  include!(concat!(env!("OUT_DIR"), "/grouplink.proto.identity.rs"));
}

pub use libsignal_protocol as signal;
use libsignal_protocol::{Deserializable, Serializable};
use prost::Message;
pub use rand;
use rand::{CryptoRng, Rng};

use std::{
  convert::{AsRef, From, TryFrom},
  fmt,
};

use crate::error::Error;

pub(crate) trait AnonymouslyGenerable<Params> {
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

impl AnonymouslyGenerable<()> for CryptographicIdentity {
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

fn encode_proto_message<M: Message>(m: M) -> Box<[u8]> {
  let mut serialized = Vec::<u8>::with_capacity(m.encoded_len());
  signal::unwrap::no_encoding_error(m.encode(&mut &mut serialized));
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
      device_id: Some(address.device_id()),
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
      .ok_or_else(|| Error::ProtobufDecodingError(format!("failed to find `device_id` field!")))?;
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

/// ???
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct AnonymousIdentityParams {
  pub name_length: usize,
}

impl AnonymouslyGenerable<AnonymousIdentityParams> for ExternalIdentity {
  fn generate<R: CryptoRng + Rng>(params: AnonymousIdentityParams, csprng: &mut R) -> Self {
    let AnonymousIdentityParams { name_length } = params;
    let random_name: String = rand::thread_rng()
      .sample_iter::<char, _>(rand::distributions::Alphanumeric)
      .take(name_length)
      .collect();
    let random_device: signal::DeviceId = csprng.gen::<signal::DeviceId>();
    Self {
      name: random_name,
      device_id: random_device,
    }
  }
}

/// ???
#[derive(Debug, Hash, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct Identity {
  pub(crate) crypto: CryptographicIdentity,
  pub(crate) external: ExternalIdentity,
}

impl AnonymouslyGenerable<AnonymousIdentityParams> for Identity {
  fn generate<R: CryptoRng + Rng>(params: AnonymousIdentityParams, csprng: &mut R) -> Self {
    let crypto = CryptographicIdentity::generate((), csprng);
    let external = ExternalIdentity::generate(params, csprng);
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
    eprintln!("1");
    let encoded_key_pair: Vec<u8> = proto_message.signal_key_pair.ok_or_else(|| {
      Error::ProtobufDecodingError(format!("failed to find `signal_key_pair` field!"))
    })?;
    eprintln!("2");
    let decoded_key_pair = signal::IdentityKeyPair::deserialize(&encoded_key_pair)?;
    eprintln!("3");
    let address: proto::Address = proto_message.address.ok_or_else(|| {
      Error::ProtobufDecodingError(format!("failed to find `signal_address` field!"))
    })?;
    eprintln!("4");
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
    eprintln!("6: {:?}", &value);
    let proto_message: proto::Identity = value.into();
    eprintln!("7: {:?}", &proto_message);
    encode_proto_message(proto_message)
  }
}

impl fmt::Display for Identity {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Identity {{ external={}, crypto=<...> }}", self.external)
  }
}

#[cfg(test)]
mod test {
  use rand::rngs::OsRng;

  use super::*;

  #[test]
  fn address_name_length_bound() {
    let name_length = 35;
    let addr_params = AnonymousIdentityParams { name_length };
    let id = Identity::generate(addr_params, &mut OsRng);
    let address: signal::ProtocolAddress = id.external.into();
    assert_eq!(address.name().len(), name_length);
  }

  #[test]
  fn reserialization() {
    let id = Identity::generate(AnonymousIdentityParams { name_length: 34 }, &mut OsRng);
    let buf: Box<[u8]> = id.clone().into();
    eprintln!("asdf: {:?}", &buf);
    let orig_id = Identity::try_from(buf.as_ref()).unwrap();
    assert_eq!(id, orig_id);
  }
}

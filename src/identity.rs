/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???

pub mod proto {
  include!(concat!(env!("OUT_DIR"), "/grouplink.proto.identity.rs"));
}

use crate::util::encode_proto_message;

use libsignal_protocol as signal;
use prost::Message;
use rand;
use rand::{CryptoRng, Rng};
use uuid::Uuid;

use std::{
  convert::{AsRef, From, TryFrom},
  fmt,
};

use crate::error::{Error, ProtobufCodingFailure};

pub trait Spontaneous<Params> {
  fn generate<R: CryptoRng + Rng>(params: Params, csprng: &mut R) -> Self;
}

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct CryptographicIdentity {
  pub inner: signal::IdentityKeyPair,
  pub seed: signal::SessionSeed,
}

impl Spontaneous<()> for CryptographicIdentity {
  fn generate<R: CryptoRng + Rng>(_params: (), csprng: &mut R) -> Self {
    let inner = signal::IdentityKeyPair::generate(csprng);
    let seed: signal::SessionSeed = csprng.gen::<u32>().into();
    Self { inner, seed }
  }
}

impl From<CryptographicIdentity> for proto::CryptographicIdentity {
  fn from(value: CryptographicIdentity) -> proto::CryptographicIdentity {
    let CryptographicIdentity { inner, seed } = value;
    proto::CryptographicIdentity {
      signal_key_pair: Some(inner.serialize().into_vec()),
      seed: Some(seed.into()),
    }
  }
}

impl TryFrom<proto::CryptographicIdentity> for CryptographicIdentity {
  type Error = Error;
  fn try_from(value: proto::CryptographicIdentity) -> Result<Self, Error> {
    let proto::CryptographicIdentity {
      signal_key_pair,
      seed,
    } = value;
    let encoded_key_pair: Vec<u8> = signal_key_pair.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `signal_key_pair` field!"
      )))
    })?;
    let decoded_key_pair = signal::IdentityKeyPair::try_from(encoded_key_pair.as_ref())?;
    let seed: signal::SessionSeed = seed
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
          "failed to find `seed` field!"
        )))
      })?
      .into();
    Ok(Self {
      inner: decoded_key_pair,
      seed,
    })
  }
}

impl TryFrom<&[u8]> for CryptographicIdentity {
  type Error = Error;
  fn try_from(value: &[u8]) -> Result<Self, Error> {
    let proto_message = proto::CryptographicIdentity::decode(value)?;
    Self::try_from(proto_message)
  }
}

impl From<CryptographicIdentity> for Box<[u8]> {
  fn from(value: CryptographicIdentity) -> Box<[u8]> {
    let proto_message: proto::CryptographicIdentity = value.into();
    encode_proto_message(proto_message)
  }
}

#[derive(Debug, Hash, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct ExternalIdentity {
  pub name: String,
  pub device_id: signal::DeviceId,
}

impl ExternalIdentity {
  pub fn as_unambiguous_string(&self) -> String {
    format!("{}/{}", self.name, self.device_id)
  }

  pub fn from_unambiguous_string(s: &str) -> Result<Self, Error> {
    s.find('/')
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::MapStringCodingFailed(format!(
          "failed to decode an address from a string used as a protobuf map key! was: '{}'",
          s
        )))
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
            )))
          })?
          .into();
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
    let proto::Address { name, device_id } = proto_message;
    let name = name.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `name` field!"
      )))
    })?;
    let device_id: signal::DeviceId = device_id
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
          "failed to find `device_id` field!"
        )))
      })?
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

impl Spontaneous<()> for ExternalIdentity {
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
/// use grouplink::identity::{Identity, ExternalIdentity, CryptographicIdentity, Spontaneous};
/// use rand;
/// use std::convert::TryFrom;
///
/// // Create a new identity.
/// let crypto = CryptographicIdentity::generate((), &mut rand::thread_rng());
/// let external = ExternalIdentity::generate((), &mut rand::thread_rng());
/// let id = Identity { crypto, external };
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
  pub crypto: CryptographicIdentity,
  pub external: ExternalIdentity,
}

impl Spontaneous<()> for Identity {
  fn generate<R: CryptoRng + Rng>(_params: (), csprng: &mut R) -> Self {
    let crypto = CryptographicIdentity::generate((), csprng);
    let external = ExternalIdentity::generate((), csprng);
    Self { crypto, external }
  }
}

impl From<Identity> for proto::Identity {
  fn from(value: Identity) -> Self {
    let Identity { crypto, external } = value;
    proto::Identity {
      key_pair: Some(crypto.into()),
      address: Some(proto::Address::from(external)),
    }
  }
}

impl TryFrom<proto::Identity> for Identity {
  type Error = Error;
  fn try_from(proto_message: proto::Identity) -> Result<Self, Error> {
    let proto::Identity { key_pair, address } = proto_message;
    let key_pair: proto::CryptographicIdentity = key_pair.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `key_pair` field!"
      )))
    })?;
    let address: proto::Address = address.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
        "failed to find `signal_address` field!"
      )))
    })?;
    Ok(Self {
      crypto: CryptographicIdentity::try_from(key_pair)?,
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

#[derive(Debug, Clone)]
pub struct SealedSenderIdentity {
  pub inner: ExternalIdentity,
  pub e164: Option<String>,
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

impl Spontaneous<()> for SealedSenderIdentity {
  fn generate<R: CryptoRng + Rng>(_params: (), csprng: &mut R) -> Self {
    let ext = ExternalIdentity::generate((), csprng);
    Self::generate(ext, csprng)
  }
}

#[derive(Debug, Clone)]
pub struct ServerCert {
  pub inner: signal::ServerCertificate,
  pub trust_root: signal::PublicKey,
}

#[derive(Debug, Clone)]
pub struct SenderCert {
  pub inner: signal::SenderCertificate,
  pub trust_root: signal::PublicKey,
}

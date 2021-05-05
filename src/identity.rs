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

fn no_encoding_error(r: Result<(), prost::EncodeError>) -> () {
  r.expect("expect encoding into a vec to never fail")
}

fn encode_proto_message<M: Message>(m: M) -> Box<[u8]> {
  let mut serialized = Vec::<u8>::with_capacity(m.encoded_len());
  no_encoding_error(m.encode(&mut &mut serialized));
  serialized.into_boxed_slice()
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

/// ???
///
///```
/// # fn main() -> Result<(), grouplink::error::Error> {
/// use grouplink::identity::*;
/// use libsignal_protocol as signal;
/// use rand::{self, Rng};
/// use uuid::Uuid;
/// use futures::executor::block_on;
/// use std::convert::TryFrom;
///
/// // Create a new identity.
/// let crypto = CryptographicIdentity::generate((), &mut rand::thread_rng());
/// let external = ExternalIdentity::generate((), &mut rand::thread_rng());
/// let id = Identity { crypto, external: external.clone() };
///
/// // Create a mutable store.
/// let mut store = Store::new(crypto);
///
/// // Create a destination identity.
/// let dest_crypto = CryptographicIdentity::generate((), &mut rand::thread_rng());
/// let dest_ext = ExternalIdentity::generate((), &mut rand::thread_rng());
/// let dest = Identity { crypto: dest_crypto, external: dest_ext };
///
/// // Create a server identity.
/// let trust_root = signal::IdentityKeyPair::generate(&mut rand::thread_rng());
/// let server_identity = signal::IdentityKeyPair::generate(&mut rand::thread_rng());
/// let server_id: u32 = Box::new(&mut rand::thread_rng()).gen();
/// let server_cert = signal::ServerCertificate::new(
///    server_id, *server_identity.public_key(), trust_root.private_key(), &mut rand::thread_rng(),
/// )?;
///
/// // Create a sender identity.
/// let sender_uuid_bytes: [u8; 16] = Box::new(&mut rand::thread_rng()).gen();
/// let sender_uuid = Uuid::from_bytes(sender_uuid_bytes);
/// let sender_cert = signal::SenderCertificate::new(
///   sender_uuid.to_string(), None,
///   *dest.crypto.inner.public_key(),
///   external.device_id,
///   0_u64,
///   server_cert,
///   id.crypto.inner.private_key(),
///   &mut rand::thread_rng(),
/// )?;
///
/// // Encrypt a sealed-sender message.
/// let ptext: Box<[u8]> = Box::new(b"asdf".to_owned());
/// let encrypted_message: Vec<u8> = block_on(signal::sealed_sender_encrypt(
///   &dest.external.clone().into(),
///   &sender_cert, ptext.as_ref(),
///   &mut store.0.session_store, &mut store.0.identity_store,
///   None,
///   &mut rand::thread_rng(),
/// ))?;
/// assert!(encrypted_message.len() > 0);
/// # Ok(())
/// # }
///```
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

#[derive(Debug, Hash, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct ExternalIdentity {
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

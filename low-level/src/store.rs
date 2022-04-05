/* Copyright 2021-2022 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! [Persistent] versions of underlying signal store implementations
//! e.g. [libsignal_protocol::IdentityKeyStore].

/// Generated protobuf struct definitions used for persisting a [Store] to disk or elsewhere.
pub mod proto {
  /* Ensure the generated identity.proto outputs are available under `super::identity` within the
   * private sub-module named `proto`. */
  pub use crate::identity::proto as identity;
  mod proto {
    include!(concat!(env!("OUT_DIR"), "/grouplink.proto.store.rs"));
  }
  #[doc(inline)]
  pub use proto::*;
}

use crate::error::Error;

use async_trait::async_trait;
use displaydoc::Display;
use libsignal_protocol as signal;
use thiserror::Error;

use std::marker::PhantomData;

#[cfg(doc)]
use std::path::PathBuf;

/// Define an object which can read itself from and write itself to some external persistent
/// location of type `Record`.
///
/// This trait wraps implementations of mutable stores like [libsignal_protocol::IdentityKeyStore]
/// in a way that can be committed to disk in between complex operations to avoid the possibility of
/// invalid states.
#[async_trait]
pub trait Persistent<Record> {
  type Error;
  /// Write this object to some external location like a hard disk.
  async fn persist(&mut self) -> Result<(), Self::Error>;
  /// Read this type from the location `record`.
  async fn extract(record: Record) -> Result<Self, Self::Error>
  where
    Self: Sized;
}

/// Defines a wrapper object for all types of mutable Signal stores.
///
/// Analogous to [libsignal_protocol::ProtocolStore] except that each store also implements
/// [Persistent].
#[derive(Debug, Clone)]
pub struct Store<
  Record,
  S: signal::SessionStore + Persistent<Record>,
  PK: signal::PreKeyStore + Persistent<Record>,
  SPK: signal::SignedPreKeyStore + Persistent<Record>,
  ID: signal::IdentityKeyStore + Persistent<Record>,
  Sender: signal::SenderKeyStore + Persistent<Record>,
> {
  /// Implements [signal::SessionStore] and [Persistent].
  pub session_store: S,
  /// Implements [signal::PreKeyStore] and [Persistent].
  pub pre_key_store: PK,
  /// Implements [signal::SignedPreKeyStore] and [Persistent].
  pub signed_pre_key_store: SPK,
  /// Implements [signal::IdentityKeyStore] and [Persistent].
  pub identity_store: ID,
  /// Implements [signal::SenderKeyStore] and [Persistent].
  pub sender_key_store: Sender,
  #[doc(hidden)]
  pub _record: PhantomData<Record>,
}

impl<
    Record,
    S: signal::SessionStore + Persistent<Record>,
    PK: signal::PreKeyStore + Persistent<Record>,
    SPK: signal::SignedPreKeyStore + Persistent<Record>,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    Sender: signal::SenderKeyStore + Persistent<Record>,
  > Store<Record, S, PK, SPK, ID, Sender>
{
  pub async fn owning_identity(&self) -> Result<signal::IdentityKeyPair, Error> {
    Ok(self.identity_store.get_identity_key_pair(None).await?)
  }
}

#[cfg(test)]
pub type StoreWrapper<Record, S, PK, SPK, ID, Sender> =
  std::sync::Arc<parking_lot::RwLock<Store<Record, S, PK, SPK, ID, Sender>>>;

/// Types of errors which may occur when en/decoding a mutable store to a [Persistent] location.
#[derive(Debug, Display, Error)]
pub enum StoreError {
  /// the stored identity {0:?} did not match the expected key pair {1:?}
  NonMatchingStoreIdentity(signal::IdentityKeyPair, signal::IdentityKeyPair),
  /// the stored seed {0:?} did not match the expected seed {1:?}
  NonMatchingStoreSeed(
    crate::wrapper_types::SessionSeed,
    crate::wrapper_types::SessionSeed,
  ),
}

/// Implement wrapper structs for in-memory signal stores e.g. [signal::IdentityKeyStore].
///
/// Due to orphan crate rules, we can't easily implement [Persistent] on
/// [signal::InMemIdentityKeyStore] as it is defined outside the current crate, hence these
/// boilerplate structs.
pub mod conversions {
  use super::proto;
  use crate::error::{Error, ProtobufCodingFailure};
  use crate::identity::ExternalIdentity;
  use crate::serde;

  use libsignal_protocol::{self as signal, ViaProtobuf};
  use uuid::Uuid;

  use std::borrow::Cow;
  use std::collections::HashMap;
  use std::convert::{TryFrom, TryInto};

  /* TODO: use property-based testing to validate these conversions (with TryFrom)! */
  /// Implements [signal::IdentityKeyStore].
  #[derive(Clone, Debug)]
  pub struct IdStore(pub signal::InMemIdentityKeyStore);

  /* proptest! { */
  /*   #[test] */
  /*   fn test_serde() { */

  /*   } */
  /* } */

  impl From<signal::InMemIdentityKeyStore> for IdStore {
    fn from(value: signal::InMemIdentityKeyStore) -> Self {
      Self(value)
    }
  }

  impl From<IdStore> for signal::InMemIdentityKeyStore {
    fn from(value: IdStore) -> Self {
      value.0
    }
  }

  impl serde::Schema for proto::IdentityKeyStore {
    type Source = IdStore;
  }

  impl TryFrom<proto::IdentityKeyStore> for signal::InMemIdentityKeyStore {
    type Error = Error;
    fn try_from(value: proto::IdentityKeyStore) -> Result<Self, Error> {
      let proto::IdentityKeyStore {
        signal_key_pair,
        session_seed,
        known_keys,
      } = value.clone();
      let encoded_signal_key_pair: Vec<u8> = signal_key_pair.ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
          "failed to find `signal_key_pair` field!".to_string(),
          format!("{:?}", value),
        ))
      })?;
      let decoded_signal_key_pair =
        signal::IdentityKeyPair::try_from(encoded_signal_key_pair.as_ref())?;
      let id: crate::wrapper_types::SessionSeed = session_seed
        .ok_or_else(|| {
          Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
            "failed to find `session_seed` field!".to_string(),
            format!("{:?}", value),
          ))
        })?
        .into();
      let known_keys: HashMap<signal::ProtocolAddress, signal::IdentityKey> = known_keys
        .into_iter()
        .map(|(address, id_bytes)| {
          let address: signal::ProtocolAddress =
            ExternalIdentity::from_unambiguous_string(&address)?.into();
          let id_key = signal::IdentityKey::try_from(id_bytes.as_ref())?;
          Ok((address, id_key))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(signal::InMemIdentityKeyStore::new_with_known_keys(
        decoded_signal_key_pair,
        id.into(),
        known_keys,
      ))
    }
  }

  impl TryFrom<proto::IdentityKeyStore> for IdStore {
    type Error = Error;
    fn try_from(value: proto::IdentityKeyStore) -> Result<Self, Error> {
      let store: signal::InMemIdentityKeyStore = value.try_into()?;
      Ok(store.into())
    }
  }

  impl From<signal::InMemIdentityKeyStore> for proto::IdentityKeyStore {
    fn from(value: signal::InMemIdentityKeyStore) -> Self {
      let signal::InMemIdentityKeyStore {
        key_pair,
        id,
        known_keys,
      } = value;
      let known_keys: HashMap<String, Vec<u8>> = known_keys
        .into_iter()
        .map(|(address, id_key)| {
          let address_str = ExternalIdentity::from(address).as_unambiguous_string();
          let id_bytes = id_key.serialize().into_vec();
          (address_str, id_bytes)
        })
        .collect();
      proto::IdentityKeyStore {
        signal_key_pair: Some(key_pair.serialize().into_vec()),
        session_seed: Some(id),
        known_keys,
      }
    }
  }

  impl From<IdStore> for proto::IdentityKeyStore {
    fn from(value: IdStore) -> Self {
      let store: signal::InMemIdentityKeyStore = value.into();
      store.into()
    }
  }

  /// Implements [signal::PreKeyStore].
  #[derive(Debug, Clone, Default)]
  pub struct PKStore(pub signal::InMemPreKeyStore);

  impl From<signal::InMemPreKeyStore> for PKStore {
    fn from(value: signal::InMemPreKeyStore) -> Self {
      Self(value)
    }
  }

  impl From<PKStore> for signal::InMemPreKeyStore {
    fn from(value: PKStore) -> Self {
      value.0
    }
  }

  impl serde::Schema for proto::PreKeyStore {
    type Source = PKStore;
  }

  impl TryFrom<proto::PreKeyStore> for signal::InMemPreKeyStore {
    type Error = Error;
    fn try_from(value: proto::PreKeyStore) -> Result<Self, Error> {
      let proto::PreKeyStore { pre_keys } = value;
      let pre_keys = pre_keys
        .into_iter()
        .map(|(id, record)| {
          let id: crate::wrapper_types::PreKeyId = id.into();
          let record = signal::PreKeyRecord::deserialize(&record)?;
          Ok((id, record))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(signal::InMemPreKeyStore {
        pre_keys: pre_keys
          .into_iter()
          .map(|(id, record)| (id.into(), record))
          .collect(),
      })
    }
  }

  impl TryFrom<proto::PreKeyStore> for PKStore {
    type Error = Error;
    fn try_from(value: proto::PreKeyStore) -> Result<Self, Error> {
      let store: signal::InMemPreKeyStore = value.try_into()?;
      Ok(store.into())
    }
  }

  impl From<signal::InMemPreKeyStore> for proto::PreKeyStore {
    fn from(value: signal::InMemPreKeyStore) -> Self {
      let signal::InMemPreKeyStore { pre_keys } = value;
      let pre_keys: HashMap<u32, Vec<u8>> = pre_keys
        .into_iter()
        .map(|(id, record)| {
          Ok((
            id,
            record
              .serialize()
              .expect("pre key record serialization error")
              .to_vec(),
          ))
        })
        .collect::<Result<HashMap<_, _>, Error>>()
        .expect("collecting pre key records error");
      proto::PreKeyStore { pre_keys }
    }
  }

  impl From<PKStore> for proto::PreKeyStore {
    fn from(value: PKStore) -> Self {
      let store: signal::InMemPreKeyStore = value.into();
      store.into()
    }
  }

  /// Implements [signal::SignedPreKeyStore].
  #[derive(Debug, Clone, Default)]
  pub struct SPKStore(pub signal::InMemSignedPreKeyStore);

  impl From<signal::InMemSignedPreKeyStore> for SPKStore {
    fn from(value: signal::InMemSignedPreKeyStore) -> Self {
      Self(value)
    }
  }

  impl From<SPKStore> for signal::InMemSignedPreKeyStore {
    fn from(value: SPKStore) -> Self {
      value.0
    }
  }

  impl serde::Schema for proto::SignedPreKeyStore {
    type Source = SPKStore;
  }

  impl TryFrom<proto::SignedPreKeyStore> for signal::InMemSignedPreKeyStore {
    type Error = Error;
    fn try_from(value: proto::SignedPreKeyStore) -> Result<Self, Error> {
      let proto::SignedPreKeyStore { signed_pre_keys } = value;
      let signed_pre_keys = signed_pre_keys
        .into_iter()
        .map(|(id, record)| {
          let id: crate::wrapper_types::SignedPreKeyId = id.into();
          let record = signal::SignedPreKeyRecord::deserialize(&record)?;
          Ok((id, record))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(signal::InMemSignedPreKeyStore {
        signed_pre_keys: signed_pre_keys
          .into_iter()
          .map(|(id, record)| (id.into(), record))
          .collect(),
      })
    }
  }

  impl TryFrom<proto::SignedPreKeyStore> for SPKStore {
    type Error = Error;
    fn try_from(value: proto::SignedPreKeyStore) -> Result<Self, Error> {
      let store: signal::InMemSignedPreKeyStore = value.try_into()?;
      Ok(store.into())
    }
  }

  impl From<signal::InMemSignedPreKeyStore> for proto::SignedPreKeyStore {
    fn from(value: signal::InMemSignedPreKeyStore) -> Self {
      let signal::InMemSignedPreKeyStore { signed_pre_keys } = value;
      let signed_pre_keys: HashMap<u32, Vec<u8>> = signed_pre_keys
        .into_iter()
        .map(|(id, record)| {
          Ok((
            id,
            record
              .serialize()
              .expect("spk record serialize failed")
              .to_vec(),
          ))
        })
        .collect::<Result<HashMap<_, _>, Error>>()
        .expect("spk record collection failed");
      proto::SignedPreKeyStore { signed_pre_keys }
    }
  }

  impl From<SPKStore> for proto::SignedPreKeyStore {
    fn from(value: SPKStore) -> Self {
      let store: signal::InMemSignedPreKeyStore = value.into();
      store.into()
    }
  }

  /// Implements [signal::SessionStore].
  #[derive(Debug, Clone, Default)]
  pub struct SStore(pub signal::InMemSessionStore<signal::StandardSessionStructure>);

  impl From<signal::InMemSessionStore<signal::StandardSessionStructure>> for SStore {
    fn from(value: signal::InMemSessionStore<signal::StandardSessionStructure>) -> Self {
      Self(value)
    }
  }

  impl From<SStore> for signal::InMemSessionStore<signal::StandardSessionStructure> {
    fn from(value: SStore) -> Self {
      value.0
    }
  }

  impl serde::Schema for proto::SessionStore {
    type Source = SStore;
  }

  impl TryFrom<proto::SessionStore>
    for signal::InMemSessionStore<signal::StandardSessionStructure>
  {
    type Error = Error;
    fn try_from(value: proto::SessionStore) -> Result<Self, Error> {
      let proto::SessionStore { sessions } = value;
      let sessions = sessions
        .into_iter()
        .map(|(address, record)| {
          let address: signal::ProtocolAddress =
            ExternalIdentity::from_unambiguous_string(&address)?.into();
          let record =
            signal::SessionRecord::<signal::StandardSessionStructure>::deserialize(&record)?;
          Ok((address, record))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(signal::InMemSessionStore::<signal::StandardSessionStructure> { sessions })
    }
  }

  impl TryFrom<proto::SessionStore> for SStore {
    type Error = Error;
    fn try_from(value: proto::SessionStore) -> Result<Self, Error> {
      let store: signal::InMemSessionStore<signal::StandardSessionStructure> =
        value.try_into()?;
      Ok(store.into())
    }
  }

  impl From<signal::InMemSessionStore<signal::StandardSessionStructure>>
    for proto::SessionStore
  {
    fn from(value: signal::InMemSessionStore<signal::StandardSessionStructure>) -> Self {
      let signal::InMemSessionStore::<signal::StandardSessionStructure> { sessions } = value;
      let sessions: HashMap<String, Vec<u8>> = sessions
        .into_iter()
        .map(|(address, record)| {
          let address_str = ExternalIdentity::from(address).as_unambiguous_string();
          Ok((address_str, record.serialize().to_vec()))
        })
        .collect::<Result<HashMap<_, _>, Error>>()
        .expect("sstore collect record error");
      proto::SessionStore { sessions }
    }
  }

  impl From<SStore> for proto::SessionStore {
    fn from(value: SStore) -> Self {
      let store: signal::InMemSessionStore<signal::StandardSessionStructure> = value.into();
      store.into()
    }
  }

  /// Implements [signal::SenderKeyStore].
  #[derive(Clone, Debug, Default)]
  pub struct SKStore(pub signal::InMemSenderKeyStore);

  impl From<signal::InMemSenderKeyStore> for SKStore {
    fn from(value: signal::InMemSenderKeyStore) -> Self {
      Self(value)
    }
  }

  impl From<SKStore> for signal::InMemSenderKeyStore {
    fn from(value: SKStore) -> Self {
      value.0
    }
  }

  impl serde::Schema for proto::SenderKeyStore {
    type Source = SKStore;
  }

  impl TryFrom<proto::SenderKeyStore> for signal::InMemSenderKeyStore {
    type Error = Error;
    fn try_from(value: proto::SenderKeyStore) -> Result<Self, Error> {
      let proto::SenderKeyStore { keys } = value.clone();
      let keys = keys
        .into_iter()
        .map(|(merged_address_uuid, record)| {
          let colon_index = merged_address_uuid.find(':').ok_or_else(|| {
            Error::ProtobufDecodingError(ProtobufCodingFailure::MapStringCodingFailed(format!(
              "failed to decode an address and uuid from a string used as a protobuf map key! was: '{}'",
              merged_address_uuid
            ), format!("{:?}", value)))
          })?;
          let address: signal::ProtocolAddress =
            ExternalIdentity::from_unambiguous_string(
              &merged_address_uuid[..colon_index],
            )?.into();
          let uuid: Uuid = Uuid::parse_str(&merged_address_uuid[colon_index + 1..])
            .map_err(|e| {
              Error::ProtobufDecodingError(ProtobufCodingFailure::MapStringCodingFailed(format!(
                "failed ({:?}) to parse uuid from a string used as a protobuf map key! was: '{}'",
                e, merged_address_uuid
              ), format!("{:?}", value)))
            })?;
          let record = signal::SenderKeyRecord::deserialize(&record)?;
          Ok(((Cow::Owned(address), uuid), record))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(signal::InMemSenderKeyStore { keys })
    }
  }

  impl TryFrom<proto::SenderKeyStore> for SKStore {
    type Error = Error;
    fn try_from(value: proto::SenderKeyStore) -> Result<Self, Error> {
      let store: signal::InMemSenderKeyStore = value.try_into()?;
      Ok(store.into())
    }
  }

  impl From<signal::InMemSenderKeyStore> for proto::SenderKeyStore {
    fn from(value: signal::InMemSenderKeyStore) -> Self {
      let signal::InMemSenderKeyStore { keys } = value;
      let keys: HashMap<String, Vec<u8>> = keys
        .into_iter()
        .map(|((address, uuid), record)| {
          let address_str = ExternalIdentity::from(address.into_owned()).as_unambiguous_string();
          let merged_address_uuid = format!("{}:{}", address_str, uuid.to_hyphenated().to_string());
          Ok((
            merged_address_uuid,
            record
              .serialize()
              .expect("skstore record serialize error")
              .to_vec(),
          ))
        })
        .collect::<Result<HashMap<_, _>, Error>>()
        .expect("skstore record collect error");
      proto::SenderKeyStore { keys }
    }
  }

  impl From<SKStore> for proto::SenderKeyStore {
    fn from(value: SKStore) -> Self {
      let store: signal::InMemSenderKeyStore = value.into();
      store.into()
    }
  }
}

/// Implementations of [Persistent] which persist to the local filesystem.
pub mod file_persistence {
  use super::conversions::{IdStore, PKStore, SKStore, SPKStore, SStore};
  use super::proto;
  use super::{Persistent, Store, StoreError};

  use crate::error::{Error, ProtobufCodingFailure};
  use crate::identity::CryptographicIdentity;
  use crate::serde::{self, *};

  use async_trait::async_trait;
  use libsignal_protocol::{self as signal, IdentityKeyStore};
  use uuid::Uuid;

  use std::default::Default;
  use std::fs;
  use std::marker::PhantomData;
  use std::path::PathBuf;

  /// Implements [signal::IdentityKeyStore] and [`Persistent::<PathBuf>`](super::Persistent::<PathBuf>).
  #[derive(Debug, Clone)]
  pub struct FileIdStore {
    /// Delegates to implement [signal::IdentityKeyStore].
    pub inner: IdStore,
    /// Where this store will persist itself to.
    pub path: PathBuf,
  }

  /* Forwards to inner. */
  #[async_trait(?Send)]
  impl signal::IdentityKeyStore for FileIdStore {
    async fn get_identity_key_pair(
      &self,
      ctx: signal::Context,
    ) -> Result<signal::IdentityKeyPair, signal::SignalProtocolError> {
      self.inner.0.get_identity_key_pair(ctx).await
    }
    async fn get_local_registration_id(
      &self,
      ctx: signal::Context,
    ) -> Result<u32, signal::SignalProtocolError> {
      self.inner.0.get_local_registration_id(ctx).await
    }
    async fn save_identity(
      &mut self,
      address: &signal::ProtocolAddress,
      identity: &signal::IdentityKey,
      ctx: signal::Context,
    ) -> Result<bool, signal::SignalProtocolError> {
      self.inner.0.save_identity(address, identity, ctx).await
    }
    async fn is_trusted_identity(
      &self,
      address: &signal::ProtocolAddress,
      identity: &signal::IdentityKey,
      direction: signal::Direction,
      ctx: signal::Context,
    ) -> Result<bool, signal::SignalProtocolError> {
      self
        .inner
        .0
        .is_trusted_identity(address, identity, direction, ctx)
        .await
    }
    async fn get_identity(
      &self,
      address: &signal::ProtocolAddress,
      ctx: signal::Context,
    ) -> Result<Option<signal::IdentityKey>, signal::SignalProtocolError> {
      self.inner.0.get_identity(address, ctx).await
    }
  }

  #[async_trait]
  impl Persistent<PathBuf> for FileIdStore {
    type Error = Error;
    async fn persist(&mut self) -> Result<(), Self::Error> {
      let bytes: Box<[u8]> =
        serde::Protobuf::<IdStore, proto::IdentityKeyStore>::new(self.inner.clone()).serialize();
      fs::write(&self.path, bytes)
        .map_err(|e| Error::ProtobufEncodingError(ProtobufCodingFailure::Io(e)))
    }
    async fn extract(record: PathBuf) -> Result<Self, Self::Error> {
      let bytes: Box<[u8]> = fs::read(&record)
        .map_err(|e| Error::ProtobufDecodingError(ProtobufCodingFailure::Io(e)))?
        .into_boxed_slice();
      let inner = serde::Protobuf::<IdStore, proto::IdentityKeyStore>::deserialize(&bytes)?;
      Ok(Self {
        inner,
        path: record,
      })
    }
  }

  /// Implements [signal::PreKeyStore] and [`Persistent::<PathBuf>`](super::Persistent::<PathBuf>).
  #[derive(Debug, Clone)]
  pub struct FilePreKeyStore {
    /// Delegates to implement [signal::PreKeyStore].
    pub inner: PKStore,
    /// Where this store will persist itself to.
    pub path: PathBuf,
  }

  impl FilePreKeyStore {
    #[allow(missing_docs)]
    pub fn new(inner: PKStore, path: PathBuf) -> Self {
      Self { inner, path }
    }
  }

  /* Forwards to inner. */
  #[async_trait(?Send)]
  impl signal::PreKeyStore for FilePreKeyStore {
    async fn get_pre_key(
      &self,
      prekey_id: u32,
      ctx: signal::Context,
    ) -> Result<signal::PreKeyRecord, signal::SignalProtocolError> {
      self.inner.0.get_pre_key(prekey_id, ctx).await
    }
    async fn save_pre_key(
      &mut self,
      prekey_id: u32,
      record: &signal::PreKeyRecord,
      ctx: signal::Context,
    ) -> Result<(), signal::SignalProtocolError> {
      self.inner.0.save_pre_key(prekey_id, record, ctx).await
    }
    async fn remove_pre_key(
      &mut self,
      prekey_id: u32,
      ctx: signal::Context,
    ) -> Result<(), signal::SignalProtocolError> {
      self.inner.0.remove_pre_key(prekey_id, ctx).await
    }
  }

  #[async_trait]
  impl Persistent<PathBuf> for FilePreKeyStore {
    type Error = Error;
    async fn persist(&mut self) -> Result<(), Self::Error> {
      let bytes: Box<[u8]> =
        serde::Protobuf::<PKStore, proto::PreKeyStore>::new(self.inner.clone()).serialize();
      fs::write(&self.path, bytes)
        .map_err(|e| Error::ProtobufEncodingError(ProtobufCodingFailure::Io(e)))
    }
    async fn extract(record: PathBuf) -> Result<Self, Self::Error> {
      let bytes: Box<[u8]> = fs::read(&record)
        .map_err(|e| Error::ProtobufDecodingError(ProtobufCodingFailure::Io(e)))?
        .into_boxed_slice();
      let inner = serde::Protobuf::<PKStore, proto::PreKeyStore>::deserialize(&bytes)?;
      Ok(Self {
        inner,
        path: record,
      })
    }
  }

  /// Implements [signal::SignedPreKeyStore] and [`Persistent::<PathBuf>`](super::Persistent::<PathBuf>).
  #[derive(Debug, Clone)]
  pub struct FileSignedPreKeyStore {
    /// Delegates to implement [signal::SignedPreKeyStore].
    pub inner: SPKStore,
    /// Where this store will persist itself to.
    pub path: PathBuf,
  }

  impl FileSignedPreKeyStore {
    #[allow(missing_docs)]
    pub fn new(inner: SPKStore, path: PathBuf) -> Self {
      Self { inner, path }
    }
  }

  /* Forwards to inner. */
  #[async_trait(?Send)]
  impl signal::SignedPreKeyStore for FileSignedPreKeyStore {
    async fn get_signed_pre_key(
      &self,
      signed_prekey_id: u32,
      ctx: signal::Context,
    ) -> Result<signal::SignedPreKeyRecord, signal::SignalProtocolError> {
      self.inner.0.get_signed_pre_key(signed_prekey_id, ctx).await
    }
    async fn save_signed_pre_key(
      &mut self,
      signed_prekey_id: u32,
      record: &signal::SignedPreKeyRecord,
      ctx: signal::Context,
    ) -> Result<(), signal::SignalProtocolError> {
      self
        .inner
        .0
        .save_signed_pre_key(signed_prekey_id, record, ctx)
        .await
    }
  }

  #[async_trait]
  impl Persistent<PathBuf> for FileSignedPreKeyStore {
    type Error = Error;
    async fn persist(&mut self) -> Result<(), Self::Error> {
      let bytes: Box<[u8]> =
        serde::Protobuf::<SPKStore, proto::SignedPreKeyStore>::new(self.inner.clone()).serialize();
      fs::write(&self.path, bytes)
        .map_err(|e| Error::ProtobufEncodingError(ProtobufCodingFailure::Io(e)))
    }
    async fn extract(record: PathBuf) -> Result<Self, Self::Error> {
      let bytes: Box<[u8]> = fs::read(&record)
        .map_err(|e| Error::ProtobufDecodingError(ProtobufCodingFailure::Io(e)))?
        .into_boxed_slice();
      let inner = serde::Protobuf::<SPKStore, proto::SignedPreKeyStore>::deserialize(&bytes)?;
      Ok(Self {
        inner,
        path: record,
      })
    }
  }

  /// Implements [signal::SessionStore] and [`Persistent::<PathBuf>`](super::Persistent::<PathBuf>).
  #[derive(Debug, Clone)]
  pub struct FileSessionStore {
    /// Delegates to implement [signal::SessionStore].
    pub inner: SStore,
    /// Where this store will persist itself to.
    pub path: PathBuf,
  }

  impl FileSessionStore {
    #[allow(missing_docs)]
    pub fn new(inner: SStore, path: PathBuf) -> Self {
      Self { inner, path }
    }
  }

  /* Forwards to inner. */
  #[async_trait(?Send)]
  impl signal::SessionStore for FileSessionStore {
    type S = signal::StandardSessionStructure;
    async fn load_session(
      &self,
      address: &signal::ProtocolAddress,
      ctx: signal::Context,
    ) -> Result<
      Option<signal::SessionRecord<signal::StandardSessionStructure>>,
      signal::SignalProtocolError,
    > {
      self.inner.0.load_session(address, ctx).await
    }
    async fn store_session(
      &mut self,
      address: &signal::ProtocolAddress,
      record: &signal::SessionRecord<signal::StandardSessionStructure>,
      ctx: signal::Context,
    ) -> Result<(), signal::SignalProtocolError> {
      self.inner.0.store_session(address, record, ctx).await
    }

    async fn load_existing_sessions(
      &self,
      addresses: &[&signal::ProtocolAddress],
      ctx: signal::Context,
    ) -> Result<
      Vec<signal::SessionRecord<signal::StandardSessionStructure>>,
      signal::SignalProtocolError,
    > {
      self.inner.0.load_existing_sessions(addresses, ctx).await
    }
  }

  #[async_trait]
  impl Persistent<PathBuf> for FileSessionStore {
    type Error = Error;
    async fn persist(&mut self) -> Result<(), Self::Error> {
      let bytes: Box<[u8]> =
        serde::Protobuf::<SStore, proto::SessionStore>::new(self.inner.clone()).serialize();
      fs::write(&self.path, bytes)
        .map_err(|e| Error::ProtobufEncodingError(ProtobufCodingFailure::Io(e)))
    }
    async fn extract(record: PathBuf) -> Result<Self, Self::Error> {
      let bytes: Box<[u8]> = fs::read(&record)
        .map_err(|e| Error::ProtobufDecodingError(ProtobufCodingFailure::Io(e)))?
        .into_boxed_slice();
      let inner = serde::Protobuf::<SStore, proto::SessionStore>::deserialize(&bytes)?;
      Ok(Self {
        inner,
        path: record,
      })
    }
  }

  /// Implements [signal::SenderKeyStore] and [`Persistent::<PathBuf>`](super::Persistent::<PathBuf>).
  #[derive(Debug, Clone)]
  pub struct FileSenderKeyStore {
    /// Delegates to implement [signal::SenderKeyStore].
    pub inner: SKStore,
    /// Where this store will persist itself to.
    pub path: PathBuf,
  }

  impl FileSenderKeyStore {
    #[allow(missing_docs)]
    pub fn new(inner: SKStore, path: PathBuf) -> Self {
      Self { inner, path }
    }
  }

  /* Forwards to inner. */
  #[async_trait(?Send)]
  impl signal::SenderKeyStore for FileSenderKeyStore {
    async fn store_sender_key(
      &mut self,
      sender: &signal::ProtocolAddress,
      distribution_id: Uuid,
      record: &signal::SenderKeyRecord,
      ctx: signal::Context,
    ) -> Result<(), signal::SignalProtocolError> {
      self
        .inner
        .0
        .store_sender_key(sender, distribution_id, record, ctx)
        .await
    }
    async fn load_sender_key(
      &mut self,
      sender: &signal::ProtocolAddress,
      distribution_id: Uuid,
      ctx: signal::Context,
    ) -> Result<Option<signal::SenderKeyRecord>, signal::SignalProtocolError> {
      self
        .inner
        .0
        .load_sender_key(sender, distribution_id, ctx)
        .await
    }
  }

  #[async_trait]
  impl Persistent<PathBuf> for FileSenderKeyStore {
    type Error = Error;
    async fn persist(&mut self) -> Result<(), Self::Error> {
      let bytes: Box<[u8]> =
        serde::Protobuf::<SKStore, proto::SenderKeyStore>::new(self.inner.clone()).serialize();
      fs::write(&self.path, bytes)
        .map_err(|e| Error::ProtobufEncodingError(ProtobufCodingFailure::Io(e)))
    }
    async fn extract(record: PathBuf) -> Result<Self, Self::Error> {
      let bytes: Box<[u8]> = fs::read(&record)
        .map_err(|e| Error::ProtobufDecodingError(ProtobufCodingFailure::Io(e)))?
        .into_boxed_slice();
      let inner = serde::Protobuf::<SKStore, proto::SenderKeyStore>::deserialize(&bytes)?;
      Ok(Self {
        inner,
        path: record,
      })
    }
  }

  /// Specialization of [super::Store] which persists every mutation to [PathBuf] locations.
  pub type FileStore = super::Store<
    PathBuf,
    FileSessionStore,
    FilePreKeyStore,
    FileSignedPreKeyStore,
    FileIdStore,
    FileSenderKeyStore,
  >;

  #[cfg(test)]
  pub type FileStoreWrapper = super::StoreWrapper<
    PathBuf,
    FileSessionStore,
    FilePreKeyStore,
    FileSignedPreKeyStore,
    FileIdStore,
    FileSenderKeyStore,
  >;

  /// Specify whether a store should use a default value when initialization if the persistent
  /// location has no entry yet.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum ExtractionBehavior {
    /// Error if the persistent location has no entry (i.e. the path does not exist).
    ReadOrError,
    /// Read from the persistent location if it exists, otherwise use a default value and write to
    /// the persistent location.
    ReadOrDefault,
    /// Disregard any entry at the persistent location and overwrite the persistent location with
    /// a default value.
    OverwriteWithDefault,
  }

  impl ExtractionBehavior {
    fn should_try_extract(&self) -> bool {
      !matches!(self, Self::OverwriteWithDefault)
    }

    fn should_propagate_error(&self) -> bool {
      matches!(self, Self::ReadOrError)
    }

    /// Apply the precedence appropriate for this enum case to initialize `P` from a persistent
    /// location at `path` and/or a default constructor `make_default`, then write the result to the
    /// persistent location.
    pub async fn extract<P: Persistent<PathBuf>, F: FnOnce() -> P>(
      &self,
      path: PathBuf,
      make_default: F,
    ) -> Result<P, Error>
    where
      P::Error: Into<Error>,
      Error: From<P::Error>,
    {
      let mut result = if self.should_try_extract() {
        match P::extract(path).await {
          Ok(store) => store,
          Err(e) if self.should_propagate_error() => {
            return Err(e.into());
          }
          _ => make_default(),
        }
      } else {
        make_default()
      };
      result.persist().await?;
      Ok(result)
    }
  }

  /// Specify all the information needed to [`extract()`](Persistent::<PathBuf>::extract) every type
  /// of mutable Signal store from its own individual [PathBuf] location.
  #[derive(Debug, Clone)]
  pub struct FileStoreRequest {
    /// Where [FileSessionStore] will be read from and written to.
    pub session: PathBuf,
    /// Where [FilePreKeyStore] will be read from and written to.
    pub prekey: PathBuf,
    /// Where [FileSignedPreKeyStore] will be read from and written to.
    pub signed_prekey: PathBuf,
    /// Where [FileIdStore] will be read from and written to.
    pub identity: PathBuf,
    /// Where [FileSenderKeyStore] will be read from and written to.
    pub sender_key: PathBuf,
    /// Specify values for [signal::InMemIdentityKeyStore::key_pair] and
    /// [signal::InMemIdentityKeyStore::id].
    pub id: CryptographicIdentity,
    /// How to initialize each store from its persistent location and whether to use a default.
    pub behavior: ExtractionBehavior,
  }

  /// Instantiate every [super::Persistent] store implementation and persist it to the specified
  /// file paths. *See [ExtractionBehavior::extract].*
  pub async fn initialize_file_backed_store_with_default(
    request: FileStoreRequest,
  ) -> Result<FileStore, Error> {
    let FileStoreRequest {
      session,
      prekey,
      signed_prekey,
      identity,
      sender_key,
      id: CryptographicIdentity {
        inner: key_pair,
        seed: id,
      },
      behavior,
    } = request;
    Ok(Store {
      session_store: behavior
        .extract::<FileSessionStore, _>(session.clone(), || FileSessionStore {
          inner: SStore::default(),
          path: session,
        })
        .await?,
      pre_key_store: behavior
        .extract::<FilePreKeyStore, _>(prekey.clone(), || FilePreKeyStore {
          inner: PKStore::default(),
          path: prekey,
        })
        .await?,
      signed_pre_key_store: behavior
        .extract::<FileSignedPreKeyStore, _>(signed_prekey.clone(), || FileSignedPreKeyStore {
          inner: SPKStore::default(),
          path: signed_prekey,
        })
        .await?,
      identity_store: match behavior
        .extract::<FileIdStore, _>(identity.clone(), || FileIdStore {
          inner: IdStore::from(signal::InMemIdentityKeyStore::new(key_pair, id.into())),
          path: identity,
        })
        .await
      {
        Ok(store) => {
          let stored_identity = store.get_identity_key_pair(None).await?;
          if key_pair != stored_identity {
            return Err(Error::Store(StoreError::NonMatchingStoreIdentity(
              stored_identity,
              key_pair,
            )));
          }
          let stored_seed = store.get_local_registration_id(None).await?;
          if id != stored_seed.into() {
            return Err(Error::Store(StoreError::NonMatchingStoreSeed(
              stored_seed.into(),
              id,
            )));
          }
          store
        }
        Err(e) => {
          return Err(e);
        }
      },
      sender_key_store: behavior
        .extract::<FileSenderKeyStore, _>(sender_key.clone(), || FileSenderKeyStore {
          inner: SKStore::default(),
          path: sender_key,
        })
        .await?,
      _record: PhantomData,
    })
  }

  /// Factory for a [FileStoreRequest] which allocates persistent locations for each type of store
  /// within a specified parent directory with [Self::into_layout].
  pub struct DirectoryStoreRequest {
    /// Parent directory location of all [Persistent] file stores. Created by [Self::into_layout] if
    /// it does not already exist.
    pub path: PathBuf,
    /// Seeds [FileStoreRequest::id].
    pub id: CryptographicIdentity,
    /// Seeds [FileStoreRequest::behavior].
    pub behavior: ExtractionBehavior,
  }

  impl DirectoryStoreRequest {
    /// Create the containing directory if [Self::path] does not already exist, then allocate
    /// filenames within that directory for each file-backed store.
    pub fn into_layout(self) -> Result<FileStoreRequest, Error> {
      let DirectoryStoreRequest { path, id, behavior } = self;
      fs::create_dir_all(&path)
        .map_err(|e| Error::ProtobufDecodingError(ProtobufCodingFailure::Io(e)))?;
      let session = path.join(".session");
      let prekey = path.join(".prekey");
      let signed_prekey = path.join(".signed_prekey");
      let identity = path.join(".identity");
      let sender_key = path.join(".sender_key");
      Ok(FileStoreRequest {
        session,
        prekey,
        signed_prekey,
        identity,
        sender_key,
        id,
        behavior,
      })
    }
  }

  /// Helper method around [initialize_file_backed_store_with_default] and
  /// [DirectoryStoreRequest::into_layout].
  pub async fn initialize_file_backed_store(
    req: DirectoryStoreRequest,
  ) -> Result<FileStore, Error> {
    let layout = req.into_layout()?;
    initialize_file_backed_store_with_default(layout).await
  }
}

#[cfg(test)]
pub mod in_memory_store {
  use super::*;
  use crate::identity::CryptographicIdentity;
  use libsignal_protocol as signal;

  #[async_trait]
  impl Persistent<()> for signal::InMemIdentityKeyStore {
    type Error = Error;
    async fn persist(&mut self) -> Result<(), Self::Error> {
      Ok(())
    }
    async fn extract(_record: ()) -> Result<Self, Self::Error>
    where
      Self: Sized,
    {
      unreachable!()
    }
  }

  #[async_trait]
  impl Persistent<()> for signal::InMemSessionStore<signal::StandardSessionStructure> {
    type Error = Error;
    async fn persist(&mut self) -> Result<(), Self::Error> {
      Ok(())
    }
    async fn extract(_record: ()) -> Result<Self, Self::Error>
    where
      Self: Sized,
    {
      Ok(Self::new())
    }
  }

  #[async_trait]
  impl Persistent<()> for signal::InMemPreKeyStore {
    type Error = Error;
    async fn persist(&mut self) -> Result<(), Self::Error> {
      Ok(())
    }
    async fn extract(_record: ()) -> Result<Self, Self::Error>
    where
      Self: Sized,
    {
      Ok(Self::new())
    }
  }

  #[async_trait]
  impl Persistent<()> for signal::InMemSignedPreKeyStore {
    type Error = Error;
    async fn persist(&mut self) -> Result<(), Self::Error> {
      Ok(())
    }
    async fn extract(_record: ()) -> Result<Self, Self::Error>
    where
      Self: Sized,
    {
      Ok(Self::new())
    }
  }

  #[async_trait]
  impl Persistent<()> for signal::InMemSenderKeyStore {
    type Error = Error;
    async fn persist(&mut self) -> Result<(), Self::Error> {
      Ok(())
    }
    async fn extract(_record: ()) -> Result<Self, Self::Error>
    where
      Self: Sized,
    {
      Ok(Self::new())
    }
  }

  pub type InMemStore = super::Store<
    (),
    signal::InMemSessionStore<signal::StandardSessionStructure>,
    signal::InMemPreKeyStore,
    signal::InMemSignedPreKeyStore,
    signal::InMemIdentityKeyStore,
    signal::InMemSenderKeyStore,
  >;

  impl InMemStore {
    pub fn new_from_crypto(crypto: CryptographicIdentity) -> Self {
      let CryptographicIdentity { inner, seed } = crypto;
      let identity_store = signal::InMemIdentityKeyStore::new(inner, seed.into());
      Self {
        session_store: signal::InMemSessionStore::<signal::StandardSessionStructure>::new(),
        pre_key_store: signal::InMemPreKeyStore::new(),
        signed_pre_key_store: signal::InMemSignedPreKeyStore::new(),
        identity_store,
        sender_key_store: signal::InMemSenderKeyStore::new(),
        _record: PhantomData,
      }
    }
  }

  pub type InMemStoreWrapper = StoreWrapper<
    (),
    signal::InMemSessionStore<signal::StandardSessionStructure>,
    signal::InMemPreKeyStore,
    signal::InMemSignedPreKeyStore,
    signal::InMemIdentityKeyStore,
    signal::InMemSenderKeyStore,
  >;
}

#[cfg(test)]
pub mod proptest_strategies {
  pub use super::in_memory_store::*;
  use crate::identity::CryptographicIdentity;

  use parking_lot::RwLock;
  use proptest::prelude::*;
  use tempdir::TempDir;

  use std::path::PathBuf;
  use std::sync::Arc;

  pub fn generate_store(crypto: CryptographicIdentity) -> InMemStore {
    InMemStore::new_from_crypto(crypto)
  }

  pub fn generate_store_wrapper(crypto: CryptographicIdentity) -> InMemStoreWrapper {
    let store = generate_store(crypto);
    Arc::new(RwLock::new(store))
  }

  prop_compose! {
    pub fn generate_temp_dir()(dirname in "tmp-dir-[a-z]{10}") -> TempDir {
      TempDir::new(&dirname).unwrap()
    }
  }

  prop_compose! {
    pub fn generate_filename()(filename in "test-[0-9]+") -> PathBuf {
      PathBuf::from(filename)
    }
  }
}

#[cfg(test)]
pub mod test {
  use super::{file_persistence::*, proptest_strategies::*, *};
  use crate::error::{Error, ProtobufCodingFailure};

  use futures::executor::block_on;
  use proptest::prelude::*;

  use std::fs;
  use std::path::PathBuf;

  #[derive(Debug, Eq, PartialEq)]
  struct BytesPersister(pub PathBuf, pub Vec<u8>);

  #[async_trait]
  impl Persistent<PathBuf> for BytesPersister {
    type Error = Error;
    async fn persist(&mut self) -> Result<(), Self::Error> {
      fs::write(&self.0, &self.1)
        .map_err(|e| Error::ProtobufEncodingError(ProtobufCodingFailure::Io(e)))
    }
    async fn extract(record: PathBuf) -> Result<Self, Self::Error> {
      let bytes = fs::read(&record)
        .map_err(|e| Error::ProtobufDecodingError(ProtobufCodingFailure::Io(e)))?;
      Ok(Self(record, bytes))
    }
  }

  proptest! {
    #[test]
    fn test_extract_persistent(tmp_dir in generate_temp_dir(),
                               filename in generate_filename(),
                               content1 in "[a-z]{40}",
                               content2 in "[a-z]{40}") {
      assert_ne!(&content1, &content2);
      let filename = tmp_dir.path().join(filename);
      prop_assert!(
        block_on(
          ExtractionBehavior::ReadOrError.extract::<BytesPersister, _>(filename.clone(), || panic!())
        ).is_err()
      );
      prop_assert!(
        block_on(ExtractionBehavior::ReadOrDefault.extract::<BytesPersister, _>(
          filename.clone(), || BytesPersister(filename.clone(), content1.as_bytes().to_vec()))
        ).is_ok()
      );
      prop_assert_eq!(
        block_on(
          ExtractionBehavior::ReadOrError.extract::<BytesPersister, _>(filename.clone(), || panic!())
        ).unwrap(),
        BytesPersister(filename.clone(), content1.as_bytes().to_vec())
      );
      prop_assert_eq!(
        block_on(
          ExtractionBehavior::ReadOrDefault.extract::<BytesPersister, _>(
            filename.clone(), || BytesPersister(filename.clone(), content2.as_bytes().to_vec()))
        ).unwrap(),
        BytesPersister(filename.clone(), content1.as_bytes().to_vec())
      );
      prop_assert_eq!(
        block_on(
          ExtractionBehavior::OverwriteWithDefault.extract::<BytesPersister, _>(
            filename.clone(), || BytesPersister(filename.clone(), content2.as_bytes().to_vec()))
        ).unwrap(),
        BytesPersister(filename.clone(), content2.as_bytes().to_vec())
      );
      prop_assert_eq!(
        block_on(
          ExtractionBehavior::ReadOrError.extract::<BytesPersister, _>(filename.clone(), || panic!())
        ).unwrap(),
        BytesPersister(filename.clone(), content2.as_bytes().to_vec())
      );
    }
  }
}

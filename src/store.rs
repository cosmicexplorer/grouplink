/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???

pub mod proto {
  /* Ensure the generated identity.proto outputs are available under [super::identity] within the
   * sub-module also named "proto". */
  pub use crate::identity::proto as identity;
  mod proto {
    include!(concat!(env!("OUT_DIR"), "/grouplink.proto.store.rs"));
  }
  pub use proto::*;
}

use crate::error::Error;

use async_trait::async_trait;
use libsignal_protocol as signal;

use std::marker::PhantomData;

#[async_trait]
pub trait Persistent<Record> {
  async fn persist(&mut self) -> Result<(), Error>;
  async fn extract(record: Record) -> Result<Self, Error>
  where
    Self: Sized;
}

/// ???
#[derive(Debug, Clone)]
pub struct Store<
  Record,
  S: signal::SessionStore + Persistent<Record>,
  PK: signal::PreKeyStore + Persistent<Record>,
  SPK: signal::SignedPreKeyStore + Persistent<Record>,
  ID: signal::IdentityKeyStore + Persistent<Record>,
  Sender: signal::SenderKeyStore + Persistent<Record>,
> {
  pub session_store: S,
  pub pre_key_store: PK,
  pub signed_pre_key_store: SPK,
  pub identity_store: ID,
  pub sender_key_store: Sender,
  pub _record: PhantomData<Record>,
}

#[derive(Debug, Clone)]
pub enum StoreError {
  NonMatchingStoreIdentity(signal::IdentityKeyPair),
  NonMatchingStoreSeed(signal::SessionSeed),
}

impl From<StoreError> for Error {
  fn from(value: StoreError) -> Self {
    Error::Store(value)
  }
}

pub mod conversions {
  use super::proto;
  use crate::error::{Error, ProtobufCodingFailure};
  use crate::identity::ExternalIdentity;
  use crate::util::encode_proto_message;

  use libsignal_protocol as signal;
  use prost::Message;
  use uuid::Uuid;

  use std::borrow::Cow;
  use std::collections::HashMap;
  use std::convert::TryFrom;

  #[derive(Clone, Debug)]
  pub struct IdStore(pub signal::InMemIdentityKeyStore);

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

  impl TryFrom<proto::IdentityKeyStore> for signal::InMemIdentityKeyStore {
    type Error = Error;
    fn try_from(value: proto::IdentityKeyStore) -> Result<Self, Error> {
      let proto::IdentityKeyStore {
        signal_key_pair,
        session_seed,
        known_keys,
      } = value;
      let encoded_signal_key_pair: Vec<u8> = signal_key_pair.ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
          "failed to find `signal_key_pair` field!"
        )))
      })?;
      let decoded_signal_key_pair =
        signal::IdentityKeyPair::try_from(encoded_signal_key_pair.as_ref())?;
      let id: signal::SessionSeed = session_seed
        .ok_or_else(|| {
          Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(format!(
            "failed to find `session_seed` field!"
          )))
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
        id,
        known_keys,
      ))
    }
  }

  impl TryFrom<&[u8]> for IdStore {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Error> {
      let proto_message = proto::IdentityKeyStore::decode(value)?;
      let object = signal::InMemIdentityKeyStore::try_from(proto_message)?;
      Ok(IdStore(object))
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
        session_seed: Some(id.into()),
        known_keys,
      }
    }
  }

  impl From<IdStore> for Box<[u8]> {
    fn from(value: IdStore) -> Self {
      let value: signal::InMemIdentityKeyStore = value.into();
      let proto_message: proto::IdentityKeyStore = value.into();
      encode_proto_message(proto_message)
    }
  }

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

  impl TryFrom<proto::PreKeyStore> for signal::InMemPreKeyStore {
    type Error = Error;
    fn try_from(value: proto::PreKeyStore) -> Result<Self, Error> {
      let proto::PreKeyStore { pre_keys } = value;
      let pre_keys = pre_keys
        .into_iter()
        .map(|(id, record)| {
          let id: signal::PreKeyId = id.into();
          let record = signal::PreKeyRecord::deserialize(&record)?;
          Ok((id, record))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(signal::InMemPreKeyStore { pre_keys })
    }
  }

  impl TryFrom<&[u8]> for PKStore {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Error> {
      let proto_message = proto::PreKeyStore::decode(value)?;
      let object = signal::InMemPreKeyStore::try_from(proto_message)?;
      Ok(PKStore(object))
    }
  }

  impl TryFrom<signal::InMemPreKeyStore> for proto::PreKeyStore {
    type Error = Error;
    fn try_from(value: signal::InMemPreKeyStore) -> Result<Self, Error> {
      let signal::InMemPreKeyStore { pre_keys } = value;
      let pre_keys: HashMap<u32, Vec<u8>> = pre_keys
        .into_iter()
        .map(|(id, record)| Ok((id.into(), record.serialize()?.to_vec())))
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(proto::PreKeyStore { pre_keys })
    }
  }

  impl TryFrom<PKStore> for Box<[u8]> {
    type Error = Error;
    fn try_from(value: PKStore) -> Result<Self, Error> {
      let value: signal::InMemPreKeyStore = value.into();
      let proto_message = proto::PreKeyStore::try_from(value)?;
      Ok(encode_proto_message(proto_message))
    }
  }

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

  impl TryFrom<proto::SignedPreKeyStore> for signal::InMemSignedPreKeyStore {
    type Error = Error;
    fn try_from(value: proto::SignedPreKeyStore) -> Result<Self, Error> {
      let proto::SignedPreKeyStore { signed_pre_keys } = value;
      let signed_pre_keys = signed_pre_keys
        .into_iter()
        .map(|(id, record)| {
          let id: signal::SignedPreKeyId = id.into();
          let record = signal::SignedPreKeyRecord::deserialize(&record)?;
          Ok((id, record))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(signal::InMemSignedPreKeyStore { signed_pre_keys })
    }
  }

  impl TryFrom<&[u8]> for SPKStore {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Error> {
      let proto_message = proto::SignedPreKeyStore::decode(value)?;
      let object = signal::InMemSignedPreKeyStore::try_from(proto_message)?;
      Ok(SPKStore(object))
    }
  }

  impl TryFrom<signal::InMemSignedPreKeyStore> for proto::SignedPreKeyStore {
    type Error = Error;
    fn try_from(value: signal::InMemSignedPreKeyStore) -> Result<Self, Error> {
      let signal::InMemSignedPreKeyStore { signed_pre_keys } = value;
      let signed_pre_keys: HashMap<u32, Vec<u8>> = signed_pre_keys
        .into_iter()
        .map(|(id, record)| Ok((id.into(), record.serialize()?.to_vec())))
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(proto::SignedPreKeyStore { signed_pre_keys })
    }
  }

  impl TryFrom<SPKStore> for Box<[u8]> {
    type Error = Error;
    fn try_from(value: SPKStore) -> Result<Self, Error> {
      let value: signal::InMemSignedPreKeyStore = value.into();
      let proto_message = proto::SignedPreKeyStore::try_from(value)?;
      Ok(encode_proto_message(proto_message))
    }
  }

  #[derive(Debug, Clone, Default)]
  pub struct SStore(pub signal::InMemSessionStore);

  impl From<signal::InMemSessionStore> for SStore {
    fn from(value: signal::InMemSessionStore) -> Self {
      Self(value)
    }
  }

  impl From<SStore> for signal::InMemSessionStore {
    fn from(value: SStore) -> Self {
      value.0
    }
  }

  impl TryFrom<proto::SessionStore> for signal::InMemSessionStore {
    type Error = Error;
    fn try_from(value: proto::SessionStore) -> Result<Self, Error> {
      let proto::SessionStore { sessions } = value;
      let sessions = sessions
        .into_iter()
        .map(|(address, record)| {
          let address: signal::ProtocolAddress =
            ExternalIdentity::from_unambiguous_string(&address)?.into();
          let record = signal::SessionRecord::deserialize(&record)?;
          Ok((address, record))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(signal::InMemSessionStore { sessions })
    }
  }

  impl TryFrom<&[u8]> for SStore {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Error> {
      let proto_message = proto::SessionStore::decode(value)?;
      let object = signal::InMemSessionStore::try_from(proto_message)?;
      Ok(SStore(object))
    }
  }

  impl TryFrom<signal::InMemSessionStore> for proto::SessionStore {
    type Error = Error;
    fn try_from(value: signal::InMemSessionStore) -> Result<Self, Error> {
      let signal::InMemSessionStore { sessions } = value;
      let sessions: HashMap<String, Vec<u8>> = sessions
        .into_iter()
        .map(|(address, record)| {
          let address_str = ExternalIdentity::from(address).as_unambiguous_string();
          Ok((address_str, record.serialize()?.to_vec()))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(proto::SessionStore { sessions })
    }
  }

  impl TryFrom<SStore> for Box<[u8]> {
    type Error = Error;
    fn try_from(value: SStore) -> Result<Self, Error> {
      let value: signal::InMemSessionStore = value.into();
      let proto_message = proto::SessionStore::try_from(value)?;
      Ok(encode_proto_message(proto_message))
    }
  }

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

  impl TryFrom<proto::SenderKeyStore> for signal::InMemSenderKeyStore {
    type Error = Error;
    fn try_from(value: proto::SenderKeyStore) -> Result<Self, Error> {
      let proto::SenderKeyStore { keys } = value;
      let keys = keys
        .into_iter()
        .map(|(merged_address_uuid, record)| {
          let colon_index = merged_address_uuid.find(':').ok_or_else(|| {
            Error::ProtobufDecodingError(ProtobufCodingFailure::MapStringCodingFailed(format!(
              "failed to decode an address and uuid from a string used as a protobuf map key! was: '{}'",
              merged_address_uuid
            )))
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
              )))
            })?;
          let record = signal::SenderKeyRecord::deserialize(&record)?;
          Ok(((Cow::Owned(address), uuid), record))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(signal::InMemSenderKeyStore { keys })
    }
  }

  impl TryFrom<&[u8]> for SKStore {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self, Error> {
      let proto_message = proto::SenderKeyStore::decode(value)?;
      let object = signal::InMemSenderKeyStore::try_from(proto_message)?;
      Ok(SKStore(object))
    }
  }

  impl TryFrom<signal::InMemSenderKeyStore> for proto::SenderKeyStore {
    type Error = Error;
    fn try_from(value: signal::InMemSenderKeyStore) -> Result<Self, Error> {
      let signal::InMemSenderKeyStore { keys } = value;
      let keys: HashMap<String, Vec<u8>> = keys
        .into_iter()
        .map(|((address, uuid), record)| {
          let address_str = ExternalIdentity::from(address.into_owned()).as_unambiguous_string();
          let merged_address_uuid = format!("{}:{}", address_str, uuid.to_hyphenated().to_string());
          Ok((merged_address_uuid, record.serialize()?.to_vec()))
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(proto::SenderKeyStore { keys })
    }
  }

  impl TryFrom<SKStore> for Box<[u8]> {
    type Error = Error;
    fn try_from(value: SKStore) -> Result<Self, Error> {
      let value: signal::InMemSenderKeyStore = value.into();
      let proto_message = proto::SenderKeyStore::try_from(value)?;
      Ok(encode_proto_message(proto_message))
    }
  }
}

pub mod file_persistence {
  use super::conversions::{IdStore, PKStore, SKStore, SPKStore, SStore};
  use super::{Persistent, Store, StoreError};

  use crate::error::{Error, ProtobufCodingFailure};
  use crate::identity::CryptographicIdentity;

  use async_trait::async_trait;
  use libsignal_protocol::{self as signal, IdentityKeyStore};
  use uuid::Uuid;

  use std::convert::{TryFrom, TryInto};
  use std::default::Default;
  use std::fs;
  use std::marker::PhantomData;
  use std::path::PathBuf;

  #[derive(Debug, Clone)]
  pub struct FileIdStore {
    pub inner: IdStore,
    pub path: PathBuf,
  }

  impl FileIdStore {
    pub fn new(inner: IdStore, path: PathBuf) -> Self {
      Self { inner, path }
    }
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
    ) -> Result<signal::SessionSeed, signal::SignalProtocolError> {
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
    async fn persist(&mut self) -> Result<(), Error> {
      let bytes: Box<[u8]> = self.inner.clone().try_into()?;
      fs::write(&self.path, bytes)
        .map_err(|e| Error::ProtobufEncodingError(ProtobufCodingFailure::Io(e)))
    }
    async fn extract(record: PathBuf) -> Result<Self, Error> {
      let bytes: Box<[u8]> = fs::read(&record)
        .map_err(|e| Error::ProtobufDecodingError(ProtobufCodingFailure::Io(e)))?
        .into_boxed_slice();
      let inner = IdStore::try_from(bytes.as_ref())?;
      Ok(Self {
        inner,
        path: record,
      })
    }
  }

  #[derive(Debug, Clone)]
  pub struct FilePreKeyStore {
    pub inner: PKStore,
    pub path: PathBuf,
  }

  impl FilePreKeyStore {
    pub fn new(inner: PKStore, path: PathBuf) -> Self {
      Self { inner, path }
    }
  }

  /* Forwards to inner. */
  #[async_trait(?Send)]
  impl signal::PreKeyStore for FilePreKeyStore {
    async fn get_pre_key(
      &self,
      prekey_id: signal::PreKeyId,
      ctx: signal::Context,
    ) -> Result<signal::PreKeyRecord, signal::SignalProtocolError> {
      self.inner.0.get_pre_key(prekey_id, ctx).await
    }
    async fn save_pre_key(
      &mut self,
      prekey_id: signal::PreKeyId,
      record: &signal::PreKeyRecord,
      ctx: signal::Context,
    ) -> Result<(), signal::SignalProtocolError> {
      self.inner.0.save_pre_key(prekey_id, record, ctx).await
    }
    async fn remove_pre_key(
      &mut self,
      prekey_id: signal::PreKeyId,
      ctx: signal::Context,
    ) -> Result<(), signal::SignalProtocolError> {
      self.inner.0.remove_pre_key(prekey_id, ctx).await
    }
  }

  #[async_trait]
  impl Persistent<PathBuf> for FilePreKeyStore {
    async fn persist(&mut self) -> Result<(), Error> {
      let bytes: Box<[u8]> = self.inner.clone().try_into()?;
      fs::write(&self.path, bytes)
        .map_err(|e| Error::ProtobufEncodingError(ProtobufCodingFailure::Io(e)))
    }
    async fn extract(record: PathBuf) -> Result<Self, Error> {
      let bytes: Box<[u8]> = fs::read(&record)
        .map_err(|e| Error::ProtobufDecodingError(ProtobufCodingFailure::Io(e)))?
        .into_boxed_slice();
      let inner = PKStore::try_from(bytes.as_ref())?;
      Ok(Self {
        inner,
        path: record,
      })
    }
  }

  #[derive(Debug, Clone)]
  pub struct FileSignedPreKeyStore {
    pub inner: SPKStore,
    pub path: PathBuf,
  }

  impl FileSignedPreKeyStore {
    pub fn new(inner: SPKStore, path: PathBuf) -> Self {
      Self { inner, path }
    }
  }

  /* Forwards to inner. */
  #[async_trait(?Send)]
  impl signal::SignedPreKeyStore for FileSignedPreKeyStore {
    async fn get_signed_pre_key(
      &self,
      signed_prekey_id: signal::SignedPreKeyId,
      ctx: signal::Context,
    ) -> Result<signal::SignedPreKeyRecord, signal::SignalProtocolError> {
      self.inner.0.get_signed_pre_key(signed_prekey_id, ctx).await
    }
    async fn save_signed_pre_key(
      &mut self,
      signed_prekey_id: signal::SignedPreKeyId,
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
    async fn persist(&mut self) -> Result<(), Error> {
      let bytes: Box<[u8]> = self.inner.clone().try_into()?;
      fs::write(&self.path, bytes)
        .map_err(|e| Error::ProtobufEncodingError(ProtobufCodingFailure::Io(e)))
    }
    async fn extract(record: PathBuf) -> Result<Self, Error> {
      let bytes: Box<[u8]> = fs::read(&record)
        .map_err(|e| Error::ProtobufDecodingError(ProtobufCodingFailure::Io(e)))?
        .into_boxed_slice();
      let inner = SPKStore::try_from(bytes.as_ref())?;
      Ok(Self {
        inner,
        path: record,
      })
    }
  }

  #[derive(Debug, Clone)]
  pub struct FileSessionStore {
    pub inner: SStore,
    pub path: PathBuf,
  }

  impl FileSessionStore {
    pub fn new(inner: SStore, path: PathBuf) -> Self {
      Self { inner, path }
    }
  }

  /* Forwards to inner. */
  #[async_trait(?Send)]
  impl signal::SessionStore for FileSessionStore {
    async fn load_session(
      &self,
      address: &signal::ProtocolAddress,
      ctx: signal::Context,
    ) -> Result<Option<signal::SessionRecord>, signal::SignalProtocolError> {
      self.inner.0.load_session(address, ctx).await
    }
    async fn store_session(
      &mut self,
      address: &signal::ProtocolAddress,
      record: &signal::SessionRecord,
      ctx: signal::Context,
    ) -> Result<(), signal::SignalProtocolError> {
      self.inner.0.store_session(address, record, ctx).await
    }
  }

  #[async_trait]
  impl Persistent<PathBuf> for FileSessionStore {
    async fn persist(&mut self) -> Result<(), Error> {
      let bytes: Box<[u8]> = self.inner.clone().try_into()?;
      fs::write(&self.path, bytes)
        .map_err(|e| Error::ProtobufEncodingError(ProtobufCodingFailure::Io(e)))
    }
    async fn extract(record: PathBuf) -> Result<Self, Error> {
      let bytes: Box<[u8]> = fs::read(&record)
        .map_err(|e| Error::ProtobufDecodingError(ProtobufCodingFailure::Io(e)))?
        .into_boxed_slice();
      let inner = SStore::try_from(bytes.as_ref())?;
      Ok(Self {
        inner,
        path: record,
      })
    }
  }

  #[derive(Debug, Clone)]
  pub struct FileSenderKeyStore {
    pub inner: SKStore,
    pub path: PathBuf,
  }

  impl FileSenderKeyStore {
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
    async fn persist(&mut self) -> Result<(), Error> {
      let bytes: Box<[u8]> = self.inner.clone().try_into()?;
      fs::write(&self.path, bytes)
        .map_err(|e| Error::ProtobufEncodingError(ProtobufCodingFailure::Io(e)))
    }
    async fn extract(record: PathBuf) -> Result<Self, Error> {
      let bytes: Box<[u8]> = fs::read(&record)
        .map_err(|e| Error::ProtobufDecodingError(ProtobufCodingFailure::Io(e)))?
        .into_boxed_slice();
      let inner = SKStore::try_from(bytes.as_ref())?;
      Ok(Self {
        inner,
        path: record,
      })
    }
  }

  pub type FileStore = super::Store<
    PathBuf,
    FileSessionStore,
    FilePreKeyStore,
    FileSignedPreKeyStore,
    FileIdStore,
    FileSenderKeyStore,
  >;

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum ExtractionBehavior {
    ReadOrError,
    ReadOrDefault,
    OverwriteWithDefault,
  }

  impl ExtractionBehavior {
    pub async fn extract<P: Persistent<PathBuf>, F: FnOnce() -> P>(
      &self,
      path: PathBuf,
      make_default: F,
    ) -> Result<P, Error> {
      let mut result = match self {
        Self::OverwriteWithDefault => make_default(),
        _ => match P::extract(path).await {
          Ok(store) => store,
          Err(e) => match self {
            Self::ReadOrError => {
              return Err(e);
            }
            _ => make_default(),
          },
        },
      };
      result.persist().await?;
      Ok(result)
    }
  }

  #[derive(Debug, Clone)]
  pub struct FileStoreRequest {
    pub session: PathBuf,
    pub prekey: PathBuf,
    pub signed_prekey: PathBuf,
    pub identity: PathBuf,
    pub sender_key: PathBuf,
    pub id: CryptographicIdentity,
    pub behavior: ExtractionBehavior,
  }

  impl FileStore {
    pub async fn initialize_file_backed_store_with_default(
      request: FileStoreRequest,
    ) -> Result<Self, Error> {
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
            inner: IdStore::from(signal::InMemIdentityKeyStore::new(key_pair, id)),
            path: identity,
          })
          .await
        {
          Ok(store) => {
            let stored_identity = store.get_identity_key_pair(None).await?;
            if key_pair != stored_identity {
              return Err(Error::Store(StoreError::NonMatchingStoreIdentity(
                stored_identity,
              )));
            }
            let stored_seed = store.get_local_registration_id(None).await?;
            if id != stored_seed {
              return Err(Error::Store(StoreError::NonMatchingStoreSeed(stored_seed)));
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
  }

  pub struct DirectoryStoreRequest {
    pub path: PathBuf,
    pub id: CryptographicIdentity,
    pub behavior: ExtractionBehavior,
  }

  impl DirectoryStoreRequest {
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
}

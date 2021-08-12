/// [prost] structs for serializing types of identities so they can be revived in a persistent
/// [store](crate::store).
pub mod proto {
  include!(concat!(
    env!("OUT_DIR"),
    "/grouplink.cli.proto.identity_db.rs"
  ));
}

use displaydoc::Display;
use prost;
use thiserror::Error;

#[derive(Debug, Display, Error)]
pub enum Error {
  /// mismatched fingerprint: expected fingerprint {0} should be equal to calculated fingerprint {1}
  MismatchedFingerprint(String, String),
  /// key with fingerprint {0} was already imported into the identity database
  KeyAlreadyImported(String),
  /// key with fingerprint {0} does not exist in the identity database
  KeyDoesNotExist(String),
  /// internal error from grouplink: {0}
  LibraryError(#[from] grouplink::error::Error),
}

impl From<prost::DecodeError> for Error {
  fn from(value: prost::DecodeError) -> Self {
    let e: grouplink::error::Error = value.into();
    e.into()
  }
}

pub use traits::IdentityDbOperation;
pub mod traits {
  use crate::key_info::KeyVariant;

  use async_trait::async_trait;

  #[async_trait(?Send)]
  pub trait IdentityDbOperation<KeyType>
  where
    KeyType: KeyVariant,
  {
    type Error;
    type OutType;
    async fn execute(&self) -> Result<Self::OutType, Self::Error>;
  }
}

pub mod stores {
  use super::{proto, Error};

  use grouplink::{
    identity::{self, proto as id_proto},
    serde::{self, fingerprinting::HexFingerprint, *},
    signal,
  };

  use std::{
    collections::{hash_map::Entry, HashMap},
    convert::{TryFrom, TryInto},
    path::PathBuf,
  };

  pub trait IdentityStoreBase {
    type Key;
    type Value;
  }

  pub trait IdentityLookupStore: IdentityStoreBase {
    fn get(&self, key: &Self::Key) -> Option<&Self::Value>;
  }

  pub trait IdentityWriteStore: IdentityStoreBase {
    fn set(&mut self, key: Self::Key, value: Self::Value) -> Result<&Self::Value, Error>;
  }

  #[derive(Debug, Clone)]
  pub struct PublicIdStore {
    pub known_public_keys: HashMap<HexFingerprint<signal::IdentityKey>, identity::PublicIdentity>,
  }

  impl IdentityStoreBase for PublicIdStore {
    type Key = HexFingerprint<signal::IdentityKey>;
    type Value = identity::PublicIdentity;
  }

  impl IdentityLookupStore for PublicIdStore {
    fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
      self.known_public_keys.get(key)
    }
  }

  impl IdentityWriteStore for PublicIdStore
  where
    Self::Key: Clone,
  {
    fn set(&mut self, key: Self::Key, value: Self::Value) -> Result<&Self::Value, Error> {
      match self.known_public_keys.entry(key.clone()) {
        Entry::Vacant(entry) => Ok(entry.insert(value)),
        Entry::Occupied(entry) => Err(Error::KeyAlreadyImported(key.into())),
      }
    }
  }

  impl serde::Schema for proto::PublicIdentityDb {
    type Source = PublicIdStore;
  }

  impl TryFrom<proto::PublicIdentityDb> for PublicIdStore {
    type Error = Error;
    fn try_from(value: proto::PublicIdentityDb) -> Result<Self, Self::Error> {
      let proto::PublicIdentityDb { known_public_keys } = value;
      let known_public_keys = known_public_keys
        .into_iter()
        .map(|(hex, id_bytes)| {
          let fp: HexFingerprint<signal::IdentityKey> = hex.into();
          let identity =
            serde::Protobuf::<identity::PublicIdentity, id_proto::PublicKey>::deserialize(
              &id_bytes,
            )?;
          let calculated_hex_fp =
            serde::KeyFingerprint::<signal::IdentityKey>::new(identity.public_key.0).serialize();
          if fp == calculated_hex_fp {
            Ok((fp, identity))
          } else {
            Err(Error::MismatchedFingerprint(
              fp.into(),
              calculated_hex_fp.into(),
            ))
          }
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(Self { known_public_keys })
    }
  }

  impl From<PublicIdStore> for proto::PublicIdentityDb {
    fn from(value: PublicIdStore) -> Self {
      let PublicIdStore { known_public_keys } = value;
      Self {
        known_public_keys: known_public_keys
          .into_iter()
          .map(|(hex, id)| {
            (
              hex.into(),
              serde::Protobuf::<identity::PublicIdentity, id_proto::PublicKey>::new(id)
                .serialize()
                .into_vec(),
            )
          })
          .collect(),
      }
    }
  }

  #[derive(Debug, Clone)]
  pub struct PrivateIdStore {
    known_private_keys: HashMap<HexFingerprint<signal::IdentityKeyPair>, identity::Identity>,
  }

  impl IdentityStoreBase for PrivateIdStore {
    type Key = HexFingerprint<signal::IdentityKeyPair>;
    type Value = identity::Identity;
  }

  impl IdentityLookupStore for PrivateIdStore {
    fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
      self.known_private_keys.get(key)
    }
  }

  impl IdentityWriteStore for PrivateIdStore
  where
    Self::Key: Clone,
  {
    fn set(&mut self, key: Self::Key, value: Self::Value) -> Result<&Self::Value, Error> {
      match self.known_private_keys.entry(key.clone()) {
        Entry::Vacant(entry) => Ok(entry.insert(value)),
        Entry::Occupied(entry) => Err(Error::KeyAlreadyImported(key.into())),
      }
    }
  }

  impl serde::Schema for proto::PrivateIdentityDb {
    type Source = PrivateIdStore;
  }

  impl TryFrom<proto::PrivateIdentityDb> for PrivateIdStore {
    type Error = Error;
    fn try_from(value: proto::PrivateIdentityDb) -> Result<Self, Self::Error> {
      let proto::PrivateIdentityDb { known_private_keys } = value;
      let known_private_keys = known_private_keys
        .into_iter()
        .map(|(hex, id_bytes)| {
          let fp: HexFingerprint<signal::IdentityKeyPair> = hex.into();
          let identity =
            serde::Protobuf::<identity::Identity, id_proto::PrivateKey>::deserialize(&id_bytes)?;
          let calculated_hex_fp =
            serde::KeyFingerprint::<signal::IdentityKeyPair>::new(identity.crypto.inner)
              .serialize();
          if fp == calculated_hex_fp {
            Ok((fp, identity))
          } else {
            Err(Error::MismatchedFingerprint(
              fp.into(),
              calculated_hex_fp.into(),
            ))
          }
        })
        .collect::<Result<HashMap<_, _>, Error>>()?;
      Ok(Self { known_private_keys })
    }
  }

  impl From<PrivateIdStore> for proto::PrivateIdentityDb {
    fn from(value: PrivateIdStore) -> Self {
      let PrivateIdStore { known_private_keys } = value;
      Self {
        known_private_keys: known_private_keys
          .into_iter()
          .map(|(hex, id)| {
            (
              hex.into(),
              serde::Protobuf::<identity::Identity, id_proto::PrivateKey>::new(id)
                .serialize()
                .into_vec(),
            )
          })
          .collect(),
      }
    }
  }

  pub mod file_persistence {
    use super::{super::Error, *};

    use grouplink::{self, serde, store::Persistent};

    use async_trait::async_trait;

    use std::fs;

    #[derive(Debug, Clone)]
    pub struct FilePublicIdStore {
      pub inner: PublicIdStore,
      pub path: PathBuf,
    }

    impl IdentityStoreBase for FilePublicIdStore {
      type Key = <PublicIdStore as IdentityStoreBase>::Key;
      type Value = <PublicIdStore as IdentityStoreBase>::Value;
    }

    impl IdentityLookupStore for FilePublicIdStore {
      fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
        self.inner.get(key)
      }
    }

    impl IdentityWriteStore for FilePublicIdStore {
      fn set(&mut self, key: Self::Key, value: Self::Value) -> Result<&Self::Value, Error> {
        self.inner.set(key, value)
      }
    }

    #[async_trait]
    impl Persistent<PathBuf> for FilePublicIdStore {
      type Error = Error;
      async fn persist(&mut self) -> Result<(), Self::Error> {
        let bytes: Box<[u8]> =
          serde::Protobuf::<PublicIdStore, proto::PublicIdentityDb>::new(self.inner.clone())
            .serialize();
        fs::write(&self.path, bytes).map_err(|e| {
          grouplink::error::Error::ProtobufEncodingError(
            grouplink::error::ProtobufCodingFailure::Io(e),
          )
        })?;
        Ok(())
      }
      async fn extract(record: PathBuf) -> Result<Self, Self::Error> {
        let bytes: Box<[u8]> = fs::read(&record)
          .map_err(|e| {
            grouplink::error::Error::ProtobufDecodingError(
              grouplink::error::ProtobufCodingFailure::Io(e),
            )
          })?
          .into_boxed_slice();
        let inner = <serde::Protobuf::<PublicIdStore, proto::PublicIdentityDb> as serde::Deserializer>::deserialize(&bytes)?;
        Ok(Self {
          inner,
          path: record,
        })
      }
    }

    #[derive(Debug, Clone)]
    pub struct FilePrivateIdStore {
      pub inner: PrivateIdStore,
      pub path: PathBuf,
    }

    impl IdentityStoreBase for FilePrivateIdStore {
      type Key = HexFingerprint<signal::IdentityKeyPair>;
      type Value = identity::Identity;
    }

    impl IdentityLookupStore for FilePrivateIdStore {
      fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
        self.inner.get(key)
      }
    }

    impl IdentityWriteStore for FilePrivateIdStore {
      fn set(&mut self, key: Self::Key, value: Self::Value) -> Result<&Self::Value, Error> {
        self.inner.set(key, value)
      }
    }

    #[async_trait]
    impl Persistent<PathBuf> for FilePrivateIdStore {
      type Error = Error;
      async fn persist(&mut self) -> Result<(), Self::Error> {
        let bytes: Box<[u8]> =
          serde::Protobuf::<PrivateIdStore, proto::PrivateIdentityDb>::new(self.inner.clone())
            .serialize();
        fs::write(&self.path, bytes).map_err(|e| {
          grouplink::error::Error::ProtobufEncodingError(
            grouplink::error::ProtobufCodingFailure::Io(e),
          )
        })?;
        Ok(())
      }
      async fn extract(record: PathBuf) -> Result<Self, Self::Error> {
        let bytes: Box<[u8]> = fs::read(&record)
          .map_err(|e| {
            grouplink::error::Error::ProtobufDecodingError(
              grouplink::error::ProtobufCodingFailure::Io(e),
            )
          })?
          .into_boxed_slice();
        let inner =
          serde::Protobuf::<PrivateIdStore, proto::PrivateIdentityDb>::deserialize(&bytes)?;
        Ok(Self {
          inner,
          path: record,
        })
      }
    }
  }
}

pub use operations::{ExportIdentity, ImportIdentity};
pub mod operations {
  use super::{
    stores::{IdentityLookupStore, IdentityStoreBase, IdentityWriteStore},
    traits::IdentityDbOperation,
    Error,
  };

  use crate::key_info::*;

  use grouplink::{
    identity,
    serde::{self, *},
    store::Persistent,
  };

  use async_trait::async_trait;
  use parking_lot::RwLock;

  use std::{marker::PhantomData, sync::Arc};

  pub struct ImportIdentity<Fingerprint, Id, Record, Store> {
    pub fingerprint: Fingerprint,
    pub store: Arc<RwLock<Store>>,
    pub id: Id,
    _record: PhantomData<Record>,
  }

  #[async_trait(?Send)]
  impl<KeyType, Record, Store> IdentityDbOperation<KeyType>
    for ImportIdentity<
        <ExtractFingerprint as KeyInfoOperation<KeyType>>::OutType,
        KeyType,
        Record,
        Store>
  where
    KeyType: KeyVariant+Clone,
    ExtractFingerprint: KeyInfoOperation<KeyType>,
    <ExtractFingerprint as KeyInfoOperation<KeyType>>::OutType: PartialEq + Eq + Serializer + Clone,
    <<<ExtractFingerprint as KeyInfoOperation<KeyType>>::OutType as SerdeViaBase>::Fmt as SerializationFormat>::Written: Into<String>,
    Store: Persistent<Record>+IdentityStoreBase<Key=<<<ExtractFingerprint as KeyInfoOperation<KeyType>>::OutType as SerdeViaBase>::Fmt as SerializationFormat>::Written, Value=KeyType>+IdentityWriteStore,
    Error: From<<Store as Persistent<Record>>::Error>,
  {
    type Error = Error;
    type OutType = ();
    async fn execute(&self) -> Result<Self::OutType, Self::Error> {
      let ImportIdentity { fingerprint: given_fingerprint, store, id, .. } = self;
      let calculated_fingerprint: <ExtractFingerprint as KeyInfoOperation<KeyType>>::OutType =
        ExtractFingerprint.execute(id.clone());
      if given_fingerprint != &calculated_fingerprint {
        return Err(Error::MismatchedFingerprint(
          given_fingerprint.clone().serialize().into(),
          calculated_fingerprint.clone().serialize().into(),
        ));
      }
      let mut store = store.write();
      store.set(given_fingerprint.clone().serialize(), id.clone())?;
      store.persist().await?;
      Ok(())
    }
  }

  pub struct ExportIdentity<Fingerprint, Record, Store> {
    pub fingerprint: Fingerprint,
    pub store: Arc<RwLock<Store>>,
    _record: PhantomData<Record>,
  }

  #[async_trait(?Send)]
  impl<KeyType, Record, Store> IdentityDbOperation<KeyType>
  for ExportIdentity<<ExtractFingerprint as KeyInfoOperation<KeyType>>::OutType, Record, Store>
  where
    KeyType: KeyVariant+Clone,
    ExtractFingerprint: KeyInfoOperation<KeyType>,
    <ExtractFingerprint as KeyInfoOperation<KeyType>>::OutType: PartialEq + Eq + Serializer + Clone,
    <<<ExtractFingerprint as KeyInfoOperation<KeyType>>::OutType as SerdeViaBase>::Fmt as SerializationFormat>::Written: Into<String>,
    Store: Persistent<Record>+IdentityStoreBase<Key=<<<ExtractFingerprint as KeyInfoOperation<KeyType>>::OutType as SerdeViaBase>::Fmt as SerializationFormat>::Written, Value=KeyType>+IdentityLookupStore,
  {
    type Error = Error;
    type OutType = KeyType;
    async fn execute(&self) -> Result<Self::OutType, Self::Error> {
      let ExportIdentity { fingerprint: given_fingerprint, store, .. } = self;
      let store = store.read();
      let given_hex_fingerprint = given_fingerprint.clone().serialize();
      match store.get(&given_hex_fingerprint) {
        None => Err(Error::KeyDoesNotExist(given_hex_fingerprint.into())),
        Some(id) => Ok(id.clone()),
      }
    }
  }
}

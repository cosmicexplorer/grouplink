use displaydoc::Display;
use thiserror::Error;

#[derive(Debug, Display, Error)]
pub enum Error {
  /// an i/o error was received: {0}
  Io(#[from] std::io::Error),
  /// the store with id {0:?} already exists
  StoreAlreadyExists(operations::StoreId),
  /// the store with id {0:?} does not exist
  StoreDoesNotExist(operations::StoreId),
  /// a grouplink error was received: {0}
  LibraryError(#[from] grouplink::error::Error),
}

impl From<grouplink::signal::SignalProtocolError> for Error {
  fn from(value: grouplink::signal::SignalProtocolError) -> Self {
    Self::LibraryError(value.into())
  }
}

pub use traits::SignalSessionOperation;
pub mod traits {
  use async_trait::async_trait;

  #[async_trait(?Send)]
  pub trait SignalSessionOperation {
    type OutType;
    type Error;
    async fn execute(&self) -> Result<Self::OutType, Self::Error>;
  }
}

pub mod operations {
  use super::{traits::SignalSessionOperation, Error};

  use grouplink::{
    identity,
    signal::{self, IdentityKeyStore},
    store::{
      self,
      file_persistence::{initialize_file_backed_store, DirectoryStoreRequest, ExtractionBehavior},
      Persistent,
    },
  };

  use async_trait::async_trait;

  use std::{fs, io, path::PathBuf};

  #[derive(Debug, Clone)]
  pub struct StoreRoot(PathBuf);

  impl From<PathBuf> for StoreRoot {
    fn from(value: PathBuf) -> Self {
      Self(value)
    }
  }

  impl From<StoreRoot> for PathBuf {
    fn from(value: StoreRoot) -> Self {
      value.0
    }
  }

  #[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
  pub struct StoreId(String);

  impl From<String> for StoreId {
    fn from(value: String) -> Self {
      Self(value)
    }
  }

  impl From<StoreId> for String {
    fn from(value: StoreId) -> Self {
      value.0
    }
  }

  #[derive(Debug, Clone)]
  pub struct GenerateNewStore {
    pub id: identity::Identity,
    pub store_id: StoreId,
    pub store_root: StoreRoot,
  }

  #[async_trait(?Send)]
  impl SignalSessionOperation for GenerateNewStore {
    type OutType = store::file_persistence::FileStore;
    type Error = Error;
    async fn execute(&self) -> Result<Self::OutType, Self::Error> {
      let GenerateNewStore {
        id,
        store_id,
        store_root,
      } = self;
      let store_root: PathBuf = store_root.clone().into();
      let store_id: String = store_id.clone().into();
      let path_segment = PathBuf::from(store_id.clone());
      let new_store_path = store_root.join(path_segment);
      fs::create_dir(&new_store_path).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => Error::StoreAlreadyExists(store_id.into()),
        _ => Error::Io(e),
      })?;
      let store_request = DirectoryStoreRequest {
        path: new_store_path,
        id: id.crypto,
        behavior: ExtractionBehavior::OverwriteWithDefault,
      };
      Ok(initialize_file_backed_store(store_request).await?)
    }
  }

  #[derive(Debug, Clone)]
  pub struct ListAllStores {
    pub id: identity::Identity,
    pub store_root: StoreRoot,
  }

  #[async_trait(?Send)]
  impl SignalSessionOperation for ListAllStores {
    type OutType = Vec<store::file_persistence::FileStore>;
    type Error = Error;
    async fn execute(&self) -> Result<Self::OutType, Self::Error> {
      let ListAllStores { id, store_root } = self;
      let mut stores: Self::OutType = Vec::new();
      let store_root: PathBuf = store_root.clone().into();
      for dir_entry in fs::read_dir(store_root)? {
        let subdir = dir_entry?.path();
        let req = DirectoryStoreRequest {
          path: subdir,
          id: id.crypto,
          behavior: ExtractionBehavior::ReadOrError,
        };
        match initialize_file_backed_store(req).await {
          Ok(store) => stores.push(store),
          Err(grouplink::error::Error::Store(store::StoreError::NonMatchingStoreIdentity(
            _,
            _,
          ))) => (),
          Err(e) => {
            let e: grouplink::error::Error = e.into();
            return Err(Error::LibraryError(e));
          }
        }
      }
      Ok(stores)
    }
  }

  #[derive(Debug, Clone)]
  pub struct RetrieveStore {
    pub id: identity::Identity,
    pub store_id: StoreId,
    pub store_root: StoreRoot,
  }

  #[async_trait(?Send)]
  impl SignalSessionOperation for RetrieveStore {
    type OutType = store::file_persistence::FileStore;
    type Error = Error;
    async fn execute(&self) -> Result<Self::OutType, Self::Error> {
      let RetrieveStore {
        id,
        store_id,
        store_root,
      } = self;
      let store_root: PathBuf = store_root.clone().into();
      let store_id: String = store_id.clone().into();
      let path_segment = PathBuf::from(store_id.clone());
      let new_store_path = store_root.join(path_segment);
      match fs::read_dir(&new_store_path) {
        Ok(_) => (),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
          return Err(Error::StoreDoesNotExist(store_id.into()));
        }
        Err(e) => {
          return Err(Error::Io(e));
        }
      }
      let store_request = DirectoryStoreRequest {
        path: new_store_path,
        id: id.crypto,
        behavior: ExtractionBehavior::ReadOrError,
      };
      Ok(initialize_file_backed_store(store_request).await?)
    }
  }

  #[derive(Debug, Clone)]
  pub struct ForgetStore {
    pub store_id: StoreId,
    pub store_root: StoreRoot,
  }

  #[async_trait(?Send)]
  impl SignalSessionOperation for ForgetStore {
    type OutType = ();
    type Error = Error;
    async fn execute(&self) -> Result<Self::OutType, Self::Error> {
      let ForgetStore {
        store_id,
        store_root,
      } = self;
      let store_root: PathBuf = store_root.clone().into();
      let store_id: String = store_id.clone().into();
      let path_segment = PathBuf::from(store_id.clone());
      let store_path_to_forget = store_root.join(path_segment);
      match fs::read_dir(&store_path_to_forget) {
        Ok(_) => (),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
          return Err(Error::StoreDoesNotExist(store_id.into()));
        }
        Err(e) => {
          return Err(Error::Io(e));
        }
      }
      fs::remove_dir_all(&store_path_to_forget)?;
      Ok(())
    }
  }

  #[derive(Debug, Clone)]
  pub struct ImportPublicIdentity {
    pub base_id: identity::Identity,
    pub store_id: StoreId,
    pub store_root: StoreRoot,
    pub id_to_import: identity::PublicIdentity,
  }

  #[derive(Debug, Copy, Clone)]
  pub enum IdentityImportResult {
    WasModified,
    NewOrNotReplaced,
  }

  #[async_trait(?Send)]
  impl SignalSessionOperation for ImportPublicIdentity {
    type OutType = IdentityImportResult;
    type Error = Error;
    async fn execute(&self) -> Result<Self::OutType, Self::Error> {
      let Self {
        base_id,
        store_id,
        store_root,
        id_to_import:
          identity::PublicIdentity {
            public_key: identity::PublicCryptoIdentity(public_key),
            external,
          },
      } = self;
      let retrieve_request = RetrieveStore {
        id: base_id.clone(),
        store_id: store_id.clone(),
        store_root: store_root.clone(),
      };
      let mut file_store = retrieve_request.execute().await?;
      let address: signal::ProtocolAddress = external.clone().into();
      let result = file_store
        .identity_store
        .save_identity(&address, public_key, None)
        .await?;
      file_store.identity_store.persist().await?;
      Ok(match result {
        true => IdentityImportResult::WasModified,
        false => IdentityImportResult::NewOrNotReplaced,
      })
    }
  }
}

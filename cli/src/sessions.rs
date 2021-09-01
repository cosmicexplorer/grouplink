use displaydoc::Display;
use thiserror::Error;

#[derive(Debug, Display, Error)]
pub enum Error {
  /// an i/o error was received: {0}
  Io(#[from] std::io::Error),
  /// the store with id {0:?} already exists
  StoreAlreadyExists(operations::stores::StoreId),
  /// the store with id {0:?} does not exist
  StoreDoesNotExist(operations::stores::StoreId),
  /// the sealed sender client with id {0:?} already exists
  SealedSenderClientAlreadyExists(operations::stores::SealedSenderId),
  /// the sealed sender client with id {0:?} does not exist
  SealedSenderClientDoesNotExist(operations::stores::SealedSenderId),
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
    identity, session,
    signal::{self, IdentityKeyStore},
    store::{
      self,
      file_persistence::{initialize_file_backed_store, DirectoryStoreRequest, ExtractionBehavior},
      Persistent,
    },
  };

  use async_trait::async_trait;
  use parking_lot::RwLock;

  use std::sync::Arc;

  pub mod stores {
    use super::*;

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
        fs::read_dir(&new_store_path).map_err(|e| match e.kind() {
          io::ErrorKind::NotFound => Error::StoreDoesNotExist(store_id.into()),
          _ => Error::Io(e),
        })?;
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

    #[derive(Debug, Clone)]
    pub struct SealedSenderIdRoot(PathBuf);

    impl From<PathBuf> for SealedSenderIdRoot {
      fn from(value: PathBuf) -> Self {
        Self(value)
      }
    }

    impl From<SealedSenderIdRoot> for PathBuf {
      fn from(value: SealedSenderIdRoot) -> Self {
        value.0
      }
    }

    #[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
    pub struct SealedSenderId(String);

    impl From<String> for SealedSenderId {
      fn from(value: String) -> Self {
        Self(value)
      }
    }

    impl From<SealedSenderId> for String {
      fn from(value: SealedSenderId) -> Self {
        value.0
      }
    }

    #[derive(Debug, Clone)]
    pub struct GenerateSealedSenderIdentity {
      pub id: identity::Identity,
      pub sealed_sender_id: SealedSenderId,
      pub sealed_sender_id_root: SealedSenderIdRoot,
    }

    #[async_trait(?Send)]
    impl SignalSessionOperation for GenerateSealedSenderIdentity {
      type OutType = identity::SealedSenderIdentity;
      type Error = Error;
      async fn execute(&self) -> Result<Self::OutType, Self::Error> {
        use grouplink::serde::{Protobuf, Serializer};
        use identity::{proto as id_proto, *};
        use io::Write;

        let GenerateSealedSenderIdentity {
          id,
          sealed_sender_id,
          sealed_sender_id_root,
        } = self;
        let sealed_sender_id_root: PathBuf = sealed_sender_id_root.clone().into();
        let sealed_sender_id: String = sealed_sender_id.clone().into();
        let path_segment = PathBuf::from(sealed_sender_id.clone());
        let new_sealed_sender_id_path = sealed_sender_id_root.join(path_segment);
        let mut file = fs::OpenOptions::new()
          .write(true)
          .create_new(true)
          .open(&new_sealed_sender_id_path)
          .map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => {
              Error::SealedSenderClientAlreadyExists(sealed_sender_id.into())
            }
            _ => Error::Io(e),
          })?;
        let sealed_sender_client = identity::generate_sealed_sender_identity(id.external.clone());
        let serialized_client: Box<[u8]> = Protobuf::<
          identity::SealedSenderIdentity,
          id_proto::SealedSenderIdentity,
        >::new(sealed_sender_client.clone())
        .serialize();
        file.write_all(&serialized_client)?;
        file.sync_all()?;
        Ok(sealed_sender_client)
      }
    }

    #[derive(Debug, Clone)]
    pub struct ListAllSealedSenderIds {
      pub id: identity::Identity,
      pub sealed_sender_id_root: SealedSenderIdRoot,
    }

    #[async_trait(?Send)]
    impl SignalSessionOperation for ListAllSealedSenderIds {
      type OutType = Vec<identity::SealedSenderIdentity>;
      type Error = Error;
      async fn execute(&self) -> Result<Self::OutType, Self::Error> {
        use grouplink::serde::{Deserializer, Protobuf};
        use identity::{proto as id_proto, *};
        use io::Read;

        let Self {
          id,
          sealed_sender_id_root,
        } = self;
        let mut ids: Self::OutType = Vec::new();
        let sealed_sender_id_root: PathBuf = sealed_sender_id_root.clone().into();
        for dir_entry in fs::read_dir(sealed_sender_id_root)? {
          let serialized_file_path = dir_entry?.path();
          let mut file = fs::File::open(&serialized_file_path)?;
          let mut buf: Vec<u8> = Vec::new();
          file.read_to_end(&mut buf)?;
          let deserialized_client = Protobuf::<
            identity::SealedSenderIdentity,
            id_proto::SealedSenderIdentity,
          >::deserialize(&buf)?;
          ids.push(deserialized_client);
        }
        Ok(ids)
      }
    }

    #[derive(Debug, Clone)]
    pub struct RetrieveSealedSenderId {
      pub id: identity::Identity,
      pub sealed_sender_id: SealedSenderId,
      pub sealed_sender_id_root: SealedSenderIdRoot,
    }

    #[async_trait(?Send)]
    impl SignalSessionOperation for RetrieveSealedSenderId {
      type OutType = identity::SealedSenderIdentity;
      type Error = Error;
      async fn execute(&self) -> Result<Self::OutType, Self::Error> {
        use grouplink::serde::{Deserializer, Protobuf};
        use identity::{proto as id_proto, *};
        use io::Read;

        let Self {
          id,
          sealed_sender_id,
          sealed_sender_id_root,
        } = self;
        let sealed_sender_id_root: PathBuf = sealed_sender_id_root.clone().into();
        let sealed_sender_id: String = sealed_sender_id.clone().into();
        let path_segment = PathBuf::from(sealed_sender_id.clone());
        let sealed_sender_id_path = sealed_sender_id_root.join(path_segment);
        let mut file = fs::File::open(&sealed_sender_id_path).map_err(|e| match e.kind() {
          io::ErrorKind::NotFound => Error::SealedSenderClientDoesNotExist(sealed_sender_id.into()),
          _ => Error::Io(e),
        })?;
        let mut buf: Vec<u8> = Vec::new();
        file.read_to_end(&mut buf)?;
        let deserialized_client = Protobuf::<
          identity::SealedSenderIdentity,
          id_proto::SealedSenderIdentity,
        >::deserialize(&buf)?;
        Ok(deserialized_client)
      }
    }

    #[derive(Debug, Clone)]
    pub struct ForgetSealedSenderId {
      pub sealed_sender_id: SealedSenderId,
      pub sealed_sender_id_root: SealedSenderIdRoot,
    }

    #[async_trait(?Send)]
    impl SignalSessionOperation for ForgetSealedSenderId {
      type OutType = ();
      type Error = Error;
      async fn execute(&self) -> Result<Self::OutType, Self::Error> {
        let Self {
          sealed_sender_id,
          sealed_sender_id_root,
        } = self;
        let sealed_sender_id_root: PathBuf = sealed_sender_id_root.clone().into();
        let sealed_sender_id: String = sealed_sender_id.clone().into();
        let path_segment = PathBuf::from(sealed_sender_id.clone());
        let sealed_sender_id_path = sealed_sender_id_root.join(path_segment);
        fs::remove_file(&sealed_sender_id_path).map_err(|e| match e.kind() {
          io::ErrorKind::NotFound => Error::SealedSenderClientDoesNotExist(sealed_sender_id.into()),
          _ => Error::Io(e),
        })?;
        Ok(())
      }
    }
  }

  pub mod pre_keys {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct GenerateSignedPreKey {
      pub store: Arc<RwLock<store::file_persistence::FileStore>>,
    }

    #[async_trait(?Send)]
    impl SignalSessionOperation for GenerateSignedPreKey {
      type OutType = session::SignedPreKey;
      type Error = Error;
      async fn execute(&self) -> Result<Self::OutType, Self::Error> {
        let Self { store } = self;
        let mut store = store.write();
        Ok(session::generate_signed_pre_key(&mut store).await?)
      }
    }

    #[derive(Debug, Clone)]
    pub struct GenerateOneTimePreKey {
      pub store: Arc<RwLock<store::file_persistence::FileStore>>,
    }

    #[async_trait(?Send)]
    impl SignalSessionOperation for GenerateOneTimePreKey {
      type OutType = session::OneTimePreKey;
      type Error = Error;
      async fn execute(&self) -> Result<Self::OutType, Self::Error> {
        let Self { store } = self;
        let mut store = store.write();
        Ok(session::generate_one_time_pre_key(&mut store).await?)
      }
    }

    #[derive(Debug, Clone)]
    pub struct GeneratePreKeyBundle {
      pub base_id: identity::Identity,
      pub store: Arc<RwLock<store::file_persistence::FileStore>>,
      pub signed_pre_key: session::SignedPreKey,
      pub one_time_pre_key: session::OneTimePreKey,
    }

    #[async_trait(?Send)]
    impl SignalSessionOperation for GeneratePreKeyBundle {
      type OutType = session::PreKeyBundle;
      type Error = Error;
      async fn execute(&self) -> Result<Self::OutType, Self::Error> {
        let Self {
          base_id,
          store,
          signed_pre_key,
          one_time_pre_key,
        } = self;
        let store = store.read();
        Ok(
          session::generate_pre_key_bundle(
            base_id.external.clone(),
            signed_pre_key.clone(),
            one_time_pre_key.clone(),
            &store,
          )
          .await?,
        )
      }
    }
  }

  pub mod initiate {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct SendSessionInitiatingMessage {
      pub base_id: identity::Identity,
      pub sealed_sender_identity: identity::SealedSenderIdentity,
      pub target: identity::ExternalIdentity,
      pub pre_key_bundle: session::PreKeyBundle,
      pub store: Arc<RwLock<store::file_persistence::FileStore>>,
    }

    #[async_trait(?Send)]
    impl SignalSessionOperation for SendSessionInitiatingMessage {
      type OutType = session::SealedSenderMessage;
      type Error = Error;
      async fn execute(&self) -> Result<Self::OutType, Self::Error> {
        let Self {
          base_id,
          sealed_sender_identity,
          target,
          pre_key_bundle,
          store,
        } = self;
        let mut store = store.write();
        let sender_cert = identity::generate_sender_cert(
          /* FIXME: i think we can remove the .stripped_e164() here? or at least make it
           * optional? */
          sealed_sender_identity.stripped_e164(),
          base_id.crypto,
          identity::SenderCertTTL::default(),
        )?;
        let request = session::SealedSenderPreKeyBundleRequest {
          bundle: pre_key_bundle.clone(),
          sender_cert,
          destination: target.clone(),
        };
        let message = session::encrypt_pre_key_bundle_message(request, &mut store).await?;
        Ok(message)
      }
    }

    #[derive(Debug, Clone)]
    pub struct ReceiveSessionInitiatingMessage {
      pub sealed_sender_identity: identity::SealedSenderIdentity,
      pub message: session::SealedSenderMessage,
      pub store: Arc<RwLock<store::file_persistence::FileStore>>,
    }

    #[async_trait(?Send)]
    impl SignalSessionOperation for ReceiveSessionInitiatingMessage {
      type OutType = session::PreKeyBundle;
      type Error = Error;
      async fn execute(&self) -> Result<Self::OutType, Self::Error> {
        use grouplink::serde::{Deserializer, Protobuf};

        let Self {
          sealed_sender_identity,
          message,
          store,
        } = self;
        let mut store = store.write();
        let request = session::SealedSenderDecryptionRequest {
          inner: message.clone(),
          local_identity: sealed_sender_identity.clone(),
        };
        let bundle_decrypted = session::decrypt_pre_key_message(request, &mut store).await?;
        let bundle = Protobuf::<session::PreKeyBundle, session::proto::PreKeyBundle>::deserialize(
          &bundle_decrypted.plaintext,
        )?;
        Ok(bundle)
      }
    }
  }
}

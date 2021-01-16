pub mod generic {
  use crate::address::Address;
  use crate::buffer::Buffer;

  #[derive(Debug)]
  pub enum Error {}

  #[derive(Debug)]
  pub struct IdentityKeyPair {
    pub public: Buffer,
    /* FIXME: should this be validated against Sensitivity at all? */
    pub private: Buffer,
  }

  pub struct RegistrationId(u32);

  pub struct RemoteIdentityKey(Vec<u8>);

  pub enum RemoteIdTrustResult {
    Trusted,
    Untrusted,
  }

  pub trait IdentityKeyStore {
    ///
    /// Get the local client's identity key pair.
    ///
    /// @param public_data pointer to a newly allocated buffer containing the
    ///     public key, if found. Unset if no record was found.
    ///     The Signal Protocol library is responsible for freeing this buffer.
    /// @param private_data pointer to a newly allocated buffer containing the
    ///     private key, if found. Unset if no record was found.
    ///     The Signal Protocol library is responsible for freeing this buffer.
    /// @return 0 on success, negative on failure
    ///
    fn get_identity_key_pair(&mut self) -> Result<IdentityKeyPair, Error>;
    /* TODO: This is a *persistent secret* -- mark this somehow and integrate it with liveness.rs! */

    ///
    /// Return the local client's registration ID.
    ///
    /// Clients should maintain a registration ID, a random number
    /// between 1 and 16380 that's generated once at install time.
    ///
    /// @param registration_id pointer to be set to the local client's
    ///     registration ID, if it was successfully retrieved.
    /// @return 0 on success, negative on failure
    ///
    fn get_local_registration_id(&mut self) -> Result<RegistrationId, Error>;
    /* TODO: This is a *persistent secret* -- mark this somehow and integrate it with liveness.rs! */

    ///
    /// Save a remote client's identity key
    /// <p>
    /// Store a remote client's identity key as trusted.
    /// The value of key_data may be null. In this case remove the key data
    /// from the identity store, but retain any metadata that may be kept
    /// alongside it.
    ///
    /// @param address the address of the remote client
    /// @param key_data Pointer to the remote client's identity key, may be null
    /// @param key_len Length of the remote client's identity key
    /// @return 0 on success, negative on failure
    ///
    fn save_identity(
      &mut self,
      address: Address,
      remote_id_key: RemoteIdentityKey,
    ) -> Result<(), Error>;

    ///
    /// Verify a remote client's identity key.
    ///
    /// Determine whether a remote client's identity is trusted.  Convention is
    /// that the TextSecure protocol is 'trust on first use.'  This means that
    /// an identity key is considered 'trusted' if there is no entry for the recipient
    /// in the local store, or if it matches the saved key for a recipient in the local
    /// store.  Only if it mismatches an entry in the local store is it considered
    /// 'untrusted.'
    ///
    /// @param address the address of the remote client
    /// @param identityKey The identity key to verify.
    /// @param key_data Pointer to the identity key to verify
    /// @param key_len Length of the identity key to verify
    /// @return 1 if trusted, 0 if untrusted, negative on failure
    ///
    fn is_trusted_identity(
      &mut self,
      address: Address,
      remote_id_key: RemoteIdentityKey,
    ) -> Result<RemoteIdTrustResult, Error>;

    ///
    /// Function called to perform cleanup when the data store context is being
    /// destroyed.
    ///
    fn destroy(&mut self);
  }
}

pub mod store_impl {
  use super::generic::IdentityKeyStore;

  use crate::handle::{DataStore, WithDataStore};

  #[derive(Clone, Debug)]
  pub struct DefaultIdKeyStore {
    data_store: DataStore,
  }

  impl WithDataStore for DefaultIdKeyStore {
    fn get_signal_data_store(&mut self) -> &mut DataStore {
      &mut self.data_store
    }
  }

  impl IdentityKeyStore for DefaultIdKeyStore {}
}

pub mod c_abi_impl {
  use super::generic::*;
  use super::store_impl::DefaultIdKeyStore;

  use crate::error::{ErrorCodeable, SUCCESS};
  use crate::gen::signal_buffer;
  use crate::handle::Handle;
  use crate::internal_error::InternalError;
  use crate::liveness::{Sensitive, Sensitivity};
  use crate::stores::StoreError;
  use crate::util::get_mut_ctx;

  use std::os::raw::{c_int, c_void};

  #[no_mangle]
  pub extern "C" fn IDKEY_get_identity_key_pair_func(
    public_data: *mut *mut signal_buffer,
    private_data: *mut *mut signal_buffer,
    user_data: *mut c_void,
  ) -> c_int {
    let id_key_store: &mut DefaultIdKeyStore = unsafe { get_mut_ctx(user_data) };
    match id_key_store.get_identity_key_pair() {
      Ok(pair) => {
        let IdentityKeyPair { public, private } = pair;
        /* NB: this is our first attempt to validate this against Sensitivity conditions!
         * FIXME: Expand this! */
        assert_eq!(private.as_sensitivity(), Sensitivity::Sensitive);
        unsafe {
          let public: &mut Handle<_> = public.as_mut();
          *public_data = public.get_mut_ptr();
          let private: &mut Handle<_> = private.as_mut();
          *private_data = private.get_mut_ptr();
        }
      }
      Err(e) => {
        let store_err: StoreError = e.into();
        let internal_err: InternalError = store_err.into();
        internal_err.into_rc()
      }
    }
  }

  #[no_mangle]
  pub extern "C" fn IDKEY_get_local_registration_id(
    user_data: *mut c_void,
    registration_id: *mut u32,
  ) -> c_int {
    let id_key_store: &mut DefaultIdKeyStore = unsafe { get_mut_ctx(user_data) };
    match id_key_store.get_local_registration_id() {
      Ok(reg_id) => unsafe {
        *registration_id = reg_id;
        SUCCESS
      },
      Err(e) => {
        let store_err: StoreError = e.into();
        let internal_err: InternalError = store_err.into();
        internal_err.into_rc()
      }
    }
  }
}

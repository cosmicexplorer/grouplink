// Copyright 2021, Danny McClanahan
// Licensed under the GNU GPL, Version 3.0 or any later version (see COPYING).

#![feature(get_mut_unchecked)]
#![deny(warnings)]
// Enable all clippy lints except for many of the pedantic ones. It's a shame this needs to be copied and pasted across crates, but there doesn't appear to be a way to include inner attributes from a common source.
#![deny(
  clippy::all,
  clippy::default_trait_access,
  clippy::expl_impl_clone_on_copy,
  clippy::if_not_else,
  clippy::needless_continue,
  clippy::unseparated_literal_suffix,
  // TODO: Falsely triggers for async/await:
  //   see https://github.com/rust-lang/rust-clippy/issues/5360
  // clippy::used_underscore_binding
)]
// It is often more clear to show that nothing is being moved.
#![allow(clippy::match_ref_pats)]
// Subjective style.
#![allow(
  clippy::len_without_is_empty,
  clippy::redundant_field_names,
  clippy::too_many_arguments
)]
// Default isn't as big a deal as people seem to think it is.
#![allow(clippy::new_without_default, clippy::new_ret_no_self)]
// Arc<Mutex> can be more clear than needing to grok Orderings:
#![allow(clippy::mutex_atomic)]
// Avoid docstrings on every unsafe method.
#![allow(clippy::missing_safety_doc)]

pub mod buffer;
pub mod error;
pub mod handles;

mod native_bindings;
use native_bindings::generated_bindings as gen;

pub mod handle {
  use parking_lot::Mutex;

  use std::ops::{Deref, DerefMut};
  use std::sync::Arc;

  pub type ConstPointer<T> = *const T;
  pub type Pointer<T> = *mut T;
  pub struct Handle<T> {
    inner: Arc<Mutex<Pointer<T>>>,
  }
  unsafe impl<T> Send for Handle<T> {}
  unsafe impl<T> Sync for Handle<T> {}

  impl<T> Deref for Handle<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
      unsafe { &**self.inner.lock() }
    }
  }

  impl<T> DerefMut for Handle<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
      unsafe { &mut **self.inner.lock() }
    }
  }

  impl<T> Handle<T> {
    pub unsafe fn new(p: Pointer<T>) -> Self {
      Self {
        inner: Arc::new(Mutex::new(p)),
      }
    }

    pub unsafe fn get_ptr(&self) -> ConstPointer<T> {
      let inner: &T = &*self;
      let inner_ptr: *const T = inner;
      inner_ptr
    }

    pub unsafe fn get_mut_ptr(&mut self) -> Pointer<T> {
      let inner: &mut T = &mut *self;
      let inner_ptr: *mut T = inner;
      inner_ptr
    }
  }
}

mod internal_error {
  #[derive(Debug)]
  pub enum InternalError {
    InvalidLogLevel(crate::log_level::LogCode),
    Unknown,
  }
}

pub mod log_level {
  use super::gen::{SG_LOG_DEBUG, SG_LOG_ERROR, SG_LOG_INFO, SG_LOG_NOTICE, SG_LOG_WARNING};
  use super::internal_error::InternalError;

  pub type LogCode = u32;

  #[derive(Debug)]
  pub enum Error {
    InvalidLogLevel(LogCode),
  }

  pub enum LogLevel {
    Error,
    Warning,
    Notice,
    Info,
    Debug,
  }

  impl LogLevel {
    pub fn from_log_code(value: LogCode) -> Result<Self, InternalError> {
      match value {
        SG_LOG_ERROR => Ok(Self::Error),
        SG_LOG_WARNING => Ok(Self::Warning),
        SG_LOG_NOTICE => Ok(Self::Notice),
        SG_LOG_INFO => Ok(Self::Info),
        SG_LOG_DEBUG => Ok(Self::Debug),
        x => Err(InternalError::InvalidLogLevel(x)),
      }
    }

    pub fn into_log_code(self) -> LogCode {
      match self {
        Self::Error => SG_LOG_ERROR,
        Self::Warning => SG_LOG_WARNING,
        Self::Notice => SG_LOG_NOTICE,
        Self::Info => SG_LOG_INFO,
        Self::Debug => SG_LOG_DEBUG,
      }
    }
  }
}

pub mod providers {
  pub mod crypto_provider {
    use crate::error::SignalError;

    pub trait CryptoProvider<HMACContext> {
      /// Callback for a secure random number generator.
      /// This function shall fill the provided buffer with random bytes.
      ///
      /// @param data pointer to the output buffer
      /// @param len size of the output buffer
      /// @return 0 on success, negative on failure
      fn random(data: &mut [u8]) -> Result<(), SignalError>;

      ///
      /// Callback for an HMAC-SHA256 implementation.
      /// This function shall initialize an HMAC context with the provided key.
      ///
      /// @param hmac_context private HMAC context pointer
      /// @param key pointer to the key
      /// @param key_len length of the key
      /// @return 0 on success, negative on failure
      fn hmac_sha256_init(key: &[u8]) -> Result<HMACContext, SignalError>;

      ///
      /// Callback for an HMAC-SHA256 implementation.
      /// This function shall update the HMAC context with the provided data
      ///
      /// @param hmac_context private HMAC context pointer
      /// @param data pointer to the data
      /// @param data_len length of the data
      /// @return 0 on success, negative on failure
      fn hmac_sha256_update(hmac_context: *mut HMACContext, data: &[u8])
        -> Result<(), SignalError>;

      ///
      /// Callback for an HMAC-SHA256 implementation.
      /// This function shall finalize an HMAC calculation and populate the output
      /// buffer with the result.
      ///
      /// @param hmac_context private HMAC context pointer
      /// @param output buffer to be allocated and populated with the result
      /// @return 0 on success, negative on failure
      /* fn hmac_sha256_final(hmac_context: HMACContext, signal_buffer **output, void *user_data) -> Result<(), SignalError>; */

      ///
      /// Callback for an HMAC-SHA256 implementation.
      /// This function shall free the private context allocated in
      /// hmac_sha256_init.
      ///
      /// @param hmac_context private HMAC context pointer
      /* void (*hmac_sha256_cleanup)(void *hmac_context, void *user_data); */

      ///
      /// Callback for a SHA512 message digest implementation.
      /// This function shall initialize a digest context.
      ///
      /// @param digest_context private digest context pointer
      /// @return 0 on success, negative on failure
      /* int (*sha512_digest_init)(void **digest_context, void *user_data); */

      ///
      /// Callback for a SHA512 message digest implementation.
      /// This function shall update the digest context with the provided data.
      ///
      /// @param digest_context private digest context pointer
      /// @param data pointer to the data
      /// @param data_len length of the data
      /// @return 0 on success, negative on failure
      /* int (*sha512_digest_update)(void *digest_context, const uint8_t *data, size_t data_len, void *user_data); */

      ///
      /// Callback for a SHA512 message digest implementation.
      /// This function shall finalize the digest calculation, populate the
      /// output buffer with the result, and prepare the context for reuse.
      ///
      /// @param digest_context private digest context pointer
      /// @param output buffer to be allocated and populated with the result
      /// @return 0 on success, negative on failure
      /* int (*sha512_digest_final)(void *digest_context, signal_buffer **output, void *user_data); */

      ///
      /// Callback for a SHA512 message digest implementation.
      /// This function shall free the private context allocated in
      /// sha512_digest_init.
      ///
      /// @param digest_context private digest context pointer
      /* void (*sha512_digest_cleanup)(void *digest_context, void *user_data); */

      ///
      /// Callback for an AES encryption implementation.
      ///
      /// @param output buffer to be allocated and populated with the ciphertext
      /// @param cipher specific cipher variant to use, either SG_CIPHER_AES_CTR_NOPADDING or SG_CIPHER_AES_CBC_PKCS5
      /// @param key the encryption key
      /// @param key_len length of the encryption key
      /// @param iv the initialization vector
      /// @param iv_len length of the initialization vector
      /// @param plaintext the plaintext to encrypt
      /// @param plaintext_len length of the plaintext
      /// @return 0 on success, negative on failure
      /* int (*encrypt)(signal_buffer **output, */
      /*         int cipher, */
      /*         const uint8_t *key, size_t key_len, */
      /*         const uint8_t *iv, size_t iv_len, */
      /*         const uint8_t *plaintext, size_t plaintext_len, */
      /*         void *user_data); */

      ///
      /// Callback for an AES decryption implementation.
      ///
      /// @param output buffer to be allocated and populated with the plaintext
      /// @param cipher specific cipher variant to use, either SG_CIPHER_AES_CTR_NOPADDING or SG_CIPHER_AES_CBC_PKCS5
      /// @param key the encryption key
      /// @param key_len length of the encryption key
      /// @param iv the initialization vector
      /// @param iv_len length of the initialization vector
      /// @param ciphertext the ciphertext to decrypt
      /// @param ciphertext_len length of the ciphertext
      /// @return 0 on success, negative on failure
      /* int (*decrypt)(signal_buffer **output, */
      /*         int cipher, */
      /*         const uint8_t *key, size_t key_len, */
      /*         const uint8_t *iv, size_t iv_len, */
      /*         const uint8_t *ciphertext, size_t ciphertext_len, */
      /*         void *user_data); */
      fn a() {}
    }
  }
  pub mod locking_functions {}

  pub mod log_function {}
}

pub mod stores {
  pub mod session_store {
    pub trait SessionStore {}
  }

  pub mod pre_key_store {
    pub trait PreKeyStore {}
  }

  pub mod signed_pre_key_store {
    pub trait SignedPreKeyStore {}
  }

  pub mod identity_key_store {
    pub trait IdentityKyeStore {}
  }

  pub mod sender_key_store {
    pub trait SenderKeyStore {}
  }
}

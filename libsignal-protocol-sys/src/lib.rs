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

pub mod buffer;
pub mod error;

mod native_bindings;
use native_bindings::generated_bindings as gen;

/* mod log_level { */
/*   use super::error::SignalError; */
/*   use super::gen::{SG_LOG_DEBUG, SG_LOG_ERROR, SG_LOG_INFO, SG_LOG_NOTICE, SG_LOG_WARNING}; */

/*   type LogCode = u32; */

/*   #[derive(Debug)] */
/*   pub enum Error { */
/*     InvalidLogLevel(LogCode), */
/*   } */

/*   pub enum LogLevel { */
/*     Error, */
/*     Warning, */
/*     Notice, */
/*     Info, */
/*     Debug, */
/*   } */

/*   impl LogLevel { */
/*     pub fn from_log_code(value: LogCode) -> Result<Self, SignalError> { */
/*       match value { */
/*         SG_LOG_ERROR => Ok(Self::Error), */
/*         SG_LOG_WARNING => Ok(Self::Warning), */
/*         SG_LOG_NOTICE => Ok(Self::Notice), */
/*         SG_LOG_INFO => Ok(Self::Info), */
/*         SG_LOG_DEBUG => Ok(Self::Debug), */
/*         x => Err(SignalError::InvalidLogLevel(x)), */
/*       } */
/*     } */

/*     pub fn into_log_code(self) -> LogCode { */
/*       match self { */
/*         Self::Error => SG_LOG_ERROR, */
/*         Self::Warning => SG_LOG_WARNING, */
/*         Self::Notice => SG_LOG_NOTICE, */
/*         Self::Info => SG_LOG_INFO, */
/*         Self::Debug => SG_LOG_DEBUG, */
/*       } */
/*     } */
/*   } */
/* } */

mod handle {
  use parking_lot::Mutex;

  use std::ops::{Deref, DerefMut};
  use std::sync::Arc;

  type ConstPointer<T> = *const T;
  type Pointer<T> = *mut T;
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

  pub trait Destroyed<T, E> {
    unsafe fn destroy_raw(t: Pointer<T>) -> Result<(), E>;
  }

  pub trait Managed<T, I, E>: Destroyed<T, E> {
    unsafe fn create_raw(i: I) -> Result<Pointer<T>, E>;

    unsafe fn create_new_handle(i: I) -> Result<Handle<T>, E> {
      let p = Self::create_raw(i)?;
      Ok(Handle::new(p))
    }
  }

  pub trait ViaHandle<T> {
    fn from_handle(handle: Handle<T>) -> Self;
    fn as_handle(&mut self) -> &mut Handle<T>;
  }

  pub unsafe trait Handled<T, I, E>: Managed<T, I, E> + ViaHandle<T> {
    unsafe fn handled_instance(i: I) -> Result<Self, E>
    where
      Self: Sized,
    {
      Ok(Self::from_handle(Self::create_new_handle(i)?))
    }

    unsafe fn handled_drop(&mut self) -> Result<(), E>
    where
      Self: Sized,
    {
      Self::destroy_raw(self.as_handle().get_mut_ptr())
    }
  }
}

mod global_context {
  use lazy_static::lazy_static;

  use std::ffi::c_void;
  use std::ptr;
  use std::sync::Arc;

  use super::error::{SignalError, SignalNativeResult};
  use super::gen::{signal_context, signal_context_create, signal_context_destroy};
  use super::handle::{Destroyed, Handle, Handled, Managed, ViaHandle};

  pub(crate) struct Context {
    handle: Handle<signal_context>,
  }

  impl Destroyed<signal_context, SignalError> for Context {
    unsafe fn destroy_raw(t: *mut signal_context) -> Result<(), SignalError> {
      signal_context_destroy(t);
      Ok(())
    }
  }

  impl Managed<signal_context, (), SignalError> for Context {
    unsafe fn create_raw(_i: ()) -> Result<*mut signal_context, SignalError> {
      let inner: *mut *mut signal_context = ptr::null_mut();
      let user_data: *mut c_void = ptr::null_mut();
      let result: Result<*mut *mut signal_context, SignalError> =
        SignalNativeResult::call_method(inner, |inner| signal_context_create(inner, user_data))
          .into();
      Ok(*result?)
    }
  }

  impl ViaHandle<signal_context> for Context {
    fn from_handle(handle: Handle<signal_context>) -> Self {
      Self { handle }
    }
    fn as_handle(&mut self) -> &mut Handle<signal_context> {
      &mut self.handle
    }
  }

  unsafe impl Handled<signal_context, (), SignalError> for Context {}

  impl Drop for Context {
    fn drop(&mut self) {
      unsafe {
        self.handled_drop().expect("failed to drop Context");
      };
    }
  }

  lazy_static! {
    pub(crate) static ref GLOBAL_CONTEXT: Arc<Context> = unsafe {
      Arc::new(Context::handled_instance(()).expect("creating global signal Context failed!"))
    };
  }
}

pub mod data_store {
  use std::ptr;
  use std::sync::Arc;

  use super::error::{SignalError, SignalNativeResult};
  use super::gen::{
    signal_protocol_store_context, signal_protocol_store_context_create,
    signal_protocol_store_context_destroy,
  };
  use super::global_context::{Context, GLOBAL_CONTEXT};
  use super::handle::{Destroyed, Handle, Handled, Managed, ViaHandle};

  pub struct DataStore {
    handle: Handle<signal_protocol_store_context>,
  }

  impl DataStore {
    pub fn new() -> Self {
      let mut ctx = GLOBAL_CONTEXT.clone();
      let context: &mut Context = unsafe { Arc::get_mut_unchecked(&mut ctx) };
      unsafe { Self::handled_instance(context).expect("creating signal DataStore context failed!") }
    }
  }

  impl Destroyed<signal_protocol_store_context, SignalError> for DataStore {
    unsafe fn destroy_raw(t: *mut signal_protocol_store_context) -> Result<(), SignalError> {
      signal_protocol_store_context_destroy(t);
      Ok(())
    }
  }

  impl Managed<signal_protocol_store_context, &mut Context, SignalError> for DataStore {
    unsafe fn create_raw(
      i: &mut Context,
    ) -> Result<*mut signal_protocol_store_context, SignalError> {
      let inner: *mut *mut signal_protocol_store_context = ptr::null_mut();
      let ctx = i.as_handle().get_mut_ptr();
      let result: Result<*mut *mut signal_protocol_store_context, SignalError> =
        SignalNativeResult::call_method(inner, |inner| {
          signal_protocol_store_context_create(inner, ctx)
        })
        .into();
      Ok(*result?)
    }
  }

  impl ViaHandle<signal_protocol_store_context> for DataStore {
    fn from_handle(handle: Handle<signal_protocol_store_context>) -> Self {
      Self { handle }
    }
    fn as_handle(&mut self) -> &mut Handle<signal_protocol_store_context> {
      &mut self.handle
    }
  }

  unsafe impl Handled<signal_protocol_store_context, &mut Context, SignalError> for DataStore {}

  impl Drop for DataStore {
    fn drop(&mut self) {
      unsafe {
        self.handled_drop().expect("failed to drop DataStore");
      };
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

// Copyright 2021, Danny McClanahan
// Licensed under the GNU GPL, Version 3.0 or any later version (see COPYING).

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

mod native_bindings;
use native_bindings::generated_bindings as gen;

pub mod error {
  use super::gen::{
    SG_ERR_DUPLICATE_MESSAGE, SG_ERR_FP_IDENT_MISMATCH, SG_ERR_FP_VERSION_MISMATCH, SG_ERR_INVAL,
    SG_ERR_INVALID_KEY, SG_ERR_INVALID_KEY_ID, SG_ERR_INVALID_MAC, SG_ERR_INVALID_MESSAGE,
    SG_ERR_INVALID_PROTO_BUF, SG_ERR_INVALID_VERSION, SG_ERR_LEGACY_MESSAGE, SG_ERR_MINIMUM,
    SG_ERR_NOMEM, SG_ERR_NO_SESSION, SG_ERR_STALE_KEY_EXCHANGE, SG_ERR_UNKNOWN,
    SG_ERR_UNTRUSTED_IDENTITY, SG_ERR_VRF_SIG_VERIF_FAILED, SG_SUCCESS,
  };

  use std::convert::Into;

  #[derive(Debug)]
  pub struct UnknownError<E> {
    more_specific_value: Option<E>,
  }

  impl<E> UnknownError<E> {
    pub fn generic() -> Self {
      Self {
        more_specific_value: None,
      }
    }

    pub fn specific(value: E) -> Self {
      Self {
        more_specific_value: Some(value),
      }
    }
  }

  #[derive(Debug)]
  pub enum SignalError {
    NoMemory,
    InvalidArgument,
    UnknownSignalProtocolError(UnknownError<i32>),
    DuplicateMessage,
    InvalidKey,
    InvalidKeyId,
    InvalidMAC,
    InvalidMessage,
    InvalidVersion,
    LegacyMessage,
    NoSession,
    StaleKeyExchange,
    UntrustedIdentity,
    VRFSignatureVerificationFailed,
    InvalidProtobuf,
    FPVersionMismatch,
    FPIdentMismatch,
    UnknownClientApplicationError(UnknownError<i32>),
  }

  pub(crate) enum SignalNativeResult<T> {
    Success(T),
    Failure(SignalError),
  }

  type ReturnCode = i32;
  const SUCCESS: ReturnCode = SG_SUCCESS as ReturnCode;

  impl<T> SignalNativeResult<T> {
    pub fn success(arg: T) -> Self {
      Self::Success(arg)
    }

    pub fn fail(error: SignalError) -> Self {
      Self::Failure(error)
    }

    pub fn invalid_argument() -> Self {
      Self::fail(SignalError::InvalidArgument)
    }

    pub fn from_rc(rc: ReturnCode, arg: T) -> Self {
      match rc {
        SUCCESS => Self::success(arg),
        SG_ERR_NOMEM => Self::fail(SignalError::NoMemory),
        SG_ERR_INVAL => Self::invalid_argument(),
        SG_ERR_UNKNOWN => Self::fail(SignalError::UnknownSignalProtocolError(
          UnknownError::generic(),
        )),
        SG_ERR_DUPLICATE_MESSAGE => Self::fail(SignalError::DuplicateMessage),
        SG_ERR_INVALID_KEY => Self::fail(SignalError::InvalidKey),
        SG_ERR_INVALID_KEY_ID => Self::fail(SignalError::InvalidKeyId),
        SG_ERR_INVALID_MAC => Self::fail(SignalError::InvalidMAC),
        SG_ERR_INVALID_MESSAGE => Self::fail(SignalError::InvalidMessage),
        SG_ERR_INVALID_VERSION => Self::fail(SignalError::InvalidVersion),
        SG_ERR_LEGACY_MESSAGE => Self::fail(SignalError::LegacyMessage),
        SG_ERR_NO_SESSION => Self::fail(SignalError::NoSession),
        SG_ERR_STALE_KEY_EXCHANGE => Self::fail(SignalError::StaleKeyExchange),
        SG_ERR_UNTRUSTED_IDENTITY => Self::fail(SignalError::UntrustedIdentity),
        SG_ERR_VRF_SIG_VERIF_FAILED => Self::fail(SignalError::VRFSignatureVerificationFailed),
        SG_ERR_INVALID_PROTO_BUF => Self::fail(SignalError::InvalidProtobuf),
        SG_ERR_FP_VERSION_MISMATCH => Self::fail(SignalError::FPVersionMismatch),
        SG_ERR_FP_IDENT_MISMATCH => Self::fail(SignalError::FPIdentMismatch),
        x if x >= SG_ERR_MINIMUM => Self::fail(SignalError::UnknownSignalProtocolError(
          UnknownError::specific(x),
        )),
        x => Self::fail(SignalError::UnknownClientApplicationError(
          UnknownError::specific(x),
        )),
      }
    }
  }

  impl<T> Into<Result<T, SignalError>> for SignalNativeResult<T> {
    fn into(self: Self) -> Result<T, SignalError> {
      match self {
        Self::Success(x) => Ok(x),
        Self::Failure(e) => Err(e),
      }
    }
  }

  impl<T: Copy> SignalNativeResult<T> {
    pub fn call_method<F: FnOnce(T) -> ReturnCode>(t: T, f: F) -> Self {
      let rc = f(t);
      Self::from_rc(rc, t)
    }
  }
}

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

  use super::error::{SignalError, SignalNativeResult};
  use super::gen::{signal_context, signal_context_create, signal_context_destroy};
  use super::handle::{Destroyed, Handle, Handled, Managed, ViaHandle};

  pub(crate) struct Context {
    handle: Handle<signal_context>,
  }

  impl Destroyed<signal_context, SignalError> for Context {
    unsafe fn destroy_raw(t: *mut signal_context) -> Result<(), SignalError> {
      Ok(signal_context_destroy(t))
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
    pub(crate) static ref GLOBAL_CONTEXT: Context =
      unsafe { Context::handled_instance(()).expect("creating global signal Context failed!") };
  }
}

pub mod data_store {
  use std::ptr;

  use super::error::{SignalError, SignalNativeResult};
  use super::gen::{
    signal_protocol_store_context, signal_protocol_store_context_create,
    signal_protocol_store_context_destroy,
  };
  use super::global_context::Context;
  use super::handle::{Destroyed, Handle, Handled, Managed, ViaHandle};

  pub struct DataStore {
    handle: Handle<signal_protocol_store_context>,
  }

  impl Destroyed<signal_protocol_store_context, SignalError> for DataStore {
    unsafe fn destroy_raw(t: *mut signal_protocol_store_context) -> Result<(), SignalError> {
      Ok(signal_protocol_store_context_destroy(t))
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

pub mod buffer {
  mod protocol {
    use std::convert::{AsMut, AsRef, From};

    pub struct BufferRequest {
      pub size: usize,
    }

    pub trait BufferRequestable<'a>: Clone + From<&'a [u8]> + From<BufferRequest> {}

    pub trait BufferReferrable: AsRef<[u8]> + AsMut<[u8]> {
      fn len(&self) -> usize;
    }

    pub trait BufferOps<'a>: BufferRequestable<'a> + BufferReferrable {}
  }

  mod signal_native {
    use std::convert::{AsMut, AsRef, From};
    use std::slice;

    use super::protocol::*;

    use crate::gen::{
      signal_buffer, signal_buffer_alloc, signal_buffer_bzero_free, signal_buffer_const_data,
      signal_buffer_copy, signal_buffer_create, signal_buffer_data, signal_buffer_free,
      signal_buffer_len, size_t,
    };

    use crate::error::SignalError;
    use crate::handle::Handle;

    type SizeType = size_t;

    pub trait BufferWrapper<Buf> {
      unsafe fn from_ptr(buf: *mut Buf) -> Self;
      fn receive_buffer(buf: *mut Buf) -> Result<*mut Buf, SignalError> {
        if buf.is_null() {
          Err(SignalError::NoMemory)
        } else {
          Ok(buf)
        }
      }
      fn inner_handle(&self) -> *const Buf;
      fn inner_handle_mut(&mut self) -> *mut Buf;
      fn buffer_free(&mut self);
      fn buffer_bzero_free(&mut self);
    }

    pub struct Buffer {
      handle: Handle<signal_buffer>,
    }

    impl BufferWrapper<signal_buffer> for Buffer {
      unsafe fn from_ptr(buf: *mut signal_buffer) -> Self {
        Self {
          handle: Handle::new(buf),
        }
      }
      fn inner_handle(&self) -> *const signal_buffer {
        unsafe { self.handle.get_ptr() }
      }
      fn inner_handle_mut(&mut self) -> *mut signal_buffer {
        unsafe { self.handle.get_mut_ptr() }
      }
      fn buffer_free(&mut self) {
        unsafe { signal_buffer_free(self.inner_handle_mut()) }
      }
      fn buffer_bzero_free(&mut self) {
        unsafe { signal_buffer_bzero_free(self.inner_handle_mut()) }
      }
    }

    /* impl<'a> BufferRequestable<'a> */
    impl Clone for Buffer {
      fn clone(&self) -> Self {
        let ptr = Self::receive_buffer(unsafe { signal_buffer_copy(self.inner_handle()) })
          .expect("did not expect failure to clone signal buffer");
        unsafe { Buffer::from_ptr(ptr) }
      }
    }

    impl<'a> From<&'a [u8]> for Buffer {
      fn from(other: &'a [u8]) -> Self {
        let ptr = Self::receive_buffer(unsafe {
          signal_buffer_create(other.as_ptr(), other.len() as SizeType)
        })
        .expect("did not expect failure to create signal buffer from data");
        unsafe { Buffer::from_ptr(ptr) }
      }
    }

    impl From<BufferRequest> for Buffer {
      fn from(other: BufferRequest) -> Self {
        let ptr = Self::receive_buffer(unsafe { signal_buffer_alloc(other.size as SizeType) })
          .expect("did not expect failure to allocate blank signal buffer");
        unsafe { Buffer::from_ptr(ptr) }
      }
    }

    impl<'a> BufferRequestable<'a> for Buffer {}

    /* impl BufferReferrable */
    impl AsRef<[u8]> for Buffer {
      fn as_ref(&self) -> &[u8] {
        let ptr: *const u8 = unsafe { signal_buffer_const_data(self.inner_handle()) };
        let len = self.len();
        unsafe { slice::from_raw_parts(ptr, len) }
      }
    }

    impl AsMut<[u8]> for Buffer {
      fn as_mut(&mut self) -> &mut [u8] {
        let ptr: *mut u8 = unsafe { signal_buffer_data(self.inner_handle_mut()) };
        let len = self.len();
        unsafe { slice::from_raw_parts_mut(ptr, len) }
      }
    }

    impl BufferReferrable for Buffer {
      fn len(&self) -> usize {
        unsafe { signal_buffer_len(self.inner_handle()) as usize }
      }
    }

    /* TODO: rustc doesn't like it when the `X` in `for X` is itself a generic bound. */
    impl<'a> BufferOps<'a> for Buffer {}
  }

  mod sensitivity {
    use std::convert::{AsMut, AsRef};
    use std::marker::PhantomData;

    use super::protocol::*;
    use super::signal_native::BufferWrapper;

    pub enum Buffer<'a, Inner, Buf: BufferWrapper<Inner> + BufferOps<'a>> {
      Sensitive(Buf, PhantomData<&'a Buf>, PhantomData<Inner>),
      Idk(Buf),
    }

    impl<'a, Inner, Buf: BufferWrapper<Inner> + BufferOps<'a>> Buffer<'a, Inner, Buf> {
      pub fn sensitive(buf: Buf) -> Self {
        Self::Sensitive(buf, PhantomData, PhantomData)
      }
      pub fn idk(buf: Buf) -> Self {
        Self::Idk(buf)
      }
    }

    /* TODO: make this "composition" boilerplate into a macro! */
    /* impl BufferReferrable */
    impl<'a, Inner, Buf: BufferWrapper<Inner> + BufferOps<'a>> AsRef<Buf> for Buffer<'a, Inner, Buf> {
      fn as_ref(&self) -> &Buf {
        match self {
          Self::Sensitive(ref x, _, _) => x,
          Self::Idk(ref x) => x,
        }
      }
    }

    impl<'a, Inner, Buf: BufferWrapper<Inner> + BufferOps<'a>> AsMut<Buf> for Buffer<'a, Inner, Buf> {
      fn as_mut(&mut self) -> &mut Buf {
        match self {
          Self::Sensitive(ref mut x, _, _) => x,
          Self::Idk(ref mut x) => x,
        }
      }
    }

    /* impl Drop */
    impl<'a, Inner, Buf: BufferWrapper<Inner> + BufferOps<'a>> Drop for Buffer<'a, Inner, Buf> {
      fn drop(&mut self) {
        match self {
          Self::Sensitive(ref mut x, _, _) => x.buffer_bzero_free(),
          Self::Idk(ref mut x) => x.buffer_free(),
        }
      }
    }
  }

  pub use protocol::BufferRequest;
  pub use signal_native::Buffer as InnerBuffer;

  pub type BufferFactory<'a> = sensitivity::Buffer<'a, super::gen::signal_buffer, InnerBuffer>;
  pub type Buffer = BufferFactory<'static>;
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

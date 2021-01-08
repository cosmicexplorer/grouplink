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

mod log {
  use super::gen::{SG_LOG_DEBUG, SG_LOG_ERROR, SG_LOG_INFO, SG_LOG_NOTICE, SG_LOG_WARNING};

  type LogCode = u32;

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
    pub fn from_log_code(value: LogCode) -> Result<Self, Error> {
      match value {
        SG_LOG_ERROR => Ok(Self::Error),
        SG_LOG_WARNING => Ok(Self::Warning),
        SG_LOG_NOTICE => Ok(Self::Notice),
        SG_LOG_INFO => Ok(Self::Info),
        SG_LOG_DEBUG => Ok(Self::Debug),
        x => Err(Error::InvalidLogLevel(x)),
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

mod handle {
  use parking_lot::Mutex;

  use std::ops::{Deref, DerefMut};
  use std::sync::Arc;

  type Pointer<T> = *mut *mut T;
  pub struct Handle<T> {
    inner: Arc<Mutex<Pointer<T>>>,
  }
  unsafe impl<T> Send for Handle<T> {}
  unsafe impl<T> Sync for Handle<T> {}

  impl<T> Deref for Handle<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
      unsafe { &***self.inner.lock() }
    }
  }

  impl<T> DerefMut for Handle<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
      unsafe { &mut ***self.inner.lock() }
    }
  }

  impl<T> Handle<T> {
    pub unsafe fn new(p: Pointer<T>) -> Self {
      Self {
        inner: Arc::new(Mutex::new(p)),
      }
    }

    pub unsafe fn get_ptr(&self) -> *const T {
      let inner: &T = &*self;
      let inner_ptr: *const T = inner;
      inner_ptr
    }

    pub unsafe fn get_mut_ptr(&mut self) -> *mut T {
      let inner: &mut T = &mut *self;
      let inner_ptr: *mut T = inner;
      inner_ptr
    }
  }

  pub trait Managed<T, I, E> {
    unsafe fn create_raw(i: I) -> Result<*mut *mut T, E>;
    unsafe fn destroy_raw(t: *mut T) -> Result<(), E>;

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

pub mod global_context {
  use lazy_static::lazy_static;

  use std::ffi::c_void;
  use std::ptr::null_mut;

  use super::error::{SignalError, SignalNativeResult};
  use super::gen::{signal_context, signal_context_create, signal_context_destroy};
  use super::handle::{Handle, Handled, Managed, ViaHandle};

  pub(crate) struct Context {
    handle: Handle<signal_context>,
  }

  impl Managed<signal_context, (), SignalError> for Context {
    unsafe fn create_raw(_i: ()) -> Result<*mut *mut signal_context, SignalError> {
      let inner: *mut *mut signal_context = null_mut();
      let user_data: *mut c_void = null_mut();
      let result: Result<*mut *mut signal_context, SignalError> =
        SignalNativeResult::call_method(inner, |inner| signal_context_create(inner, user_data))
          .into();
      result
    }

    unsafe fn destroy_raw(t: *mut signal_context) -> Result<(), SignalError> {
      Ok(signal_context_destroy(t))
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
    static ref GLOBAL_CONTEXT: Context =
      unsafe { Context::handled_instance(()).expect("creating global signal Context failed!") };
  }
}

pub mod data_store {
  use std::ptr::null_mut;

  use super::error::{SignalError, SignalNativeResult};
  use super::gen::{
    signal_protocol_store_context, signal_protocol_store_context_create,
    signal_protocol_store_context_destroy,
  };
  use super::global_context::Context;
  use super::handle::{Handle, Handled, Managed, ViaHandle};

  pub struct DataStore {
    handle: Handle<signal_protocol_store_context>,
  }

  impl Managed<signal_protocol_store_context, &mut Context, SignalError> for DataStore {
    unsafe fn create_raw(
      i: &mut Context,
    ) -> Result<*mut *mut signal_protocol_store_context, SignalError> {
      let inner: *mut *mut signal_protocol_store_context = null_mut();
      let ctx = i.as_handle().get_mut_ptr();
      let result: Result<*mut *mut signal_protocol_store_context, SignalError> =
        SignalNativeResult::call_method(inner, |inner| {
          signal_protocol_store_context_create(inner, ctx)
        })
        .into();
      result
    }

    unsafe fn destroy_raw(t: *mut signal_protocol_store_context) -> Result<(), SignalError> {
      Ok(signal_protocol_store_context_destroy(t))
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

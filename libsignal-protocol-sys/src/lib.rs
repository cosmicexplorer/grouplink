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

mod error {
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

  pub enum SignalNativeResult<T> {
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

mod global_context {
  use lazy_static::lazy_static;

  use parking_lot::Mutex;

  use std::ffi::c_void;
  use std::ptr::null_mut;
  use std::sync::Arc;

  use super::gen::{signal_context, signal_context_create, signal_context_destroy};

  use super::error::{SignalError, SignalNativeResult};

  pub struct Context {
    inner: Arc<Mutex<*mut *mut signal_context>>,
  }
  unsafe impl Send for Context {}
  unsafe impl Sync for Context {}

  impl Context {
    unsafe fn new() -> Result<Self, SignalError> {
      let inner: *mut *mut signal_context = null_mut();
      let user_data: *mut c_void = null_mut();
      let result: Result<_, _> =
        SignalNativeResult::call_method(inner, |inner| signal_context_create(inner, user_data))
          .into();
      Ok(Self {
        inner: Arc::new(Mutex::new(result?)),
      })
    }
  }

  impl Drop for Context {
    fn drop(&mut self) {
      let inner_ptr = self.inner.lock();
      let ctx: *mut signal_context = unsafe { **inner_ptr };
      unsafe { signal_context_destroy(ctx) };
    }
  }

  lazy_static! {
    static ref GLOBAL_CONTEXT: Context =
      unsafe { Context::new().expect("creating global signal context failed!") };
  }
}

// Copyright 2021, Danny McClanahan
// Licensed under the GNU GPL, Version 3.0 or any later version (see COPYING).

// Nightly features.
#![feature(associated_type_defaults)]
// Fail on warnings.
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
// We *only* use unsafe pointer dereferences when we implement the libsignal callbacks, so it is
// nicer to list internal minor calls as unsafe, than to mark the whole function as unsafe which may
// hide other unsafeness.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod buffer;
pub mod crypto_provider;
pub mod error;
pub mod global_context_manipulation;
pub mod handles;

mod native_bindings;
use native_bindings::generated_bindings as gen;

pub mod cell {
  use std::cell::UnsafeCell;

  pub unsafe trait UnsafeAPI<T> {
    unsafe fn get_ptr(&self) -> *mut T;
    unsafe fn get(&self) -> &mut T {
      &mut *self.get_ptr()
    }
  }

  pub struct EvenMoreUnsafeCell<T> {
    inner: UnsafeCell<T>,
  }

  unsafe impl<T> UnsafeAPI<T> for EvenMoreUnsafeCell<T> {
    unsafe fn get_ptr(&self) -> *mut T {
      self.inner.get()
    }
  }

  impl<T> From<T> for EvenMoreUnsafeCell<T> {
    fn from(val: T) -> Self {
      Self { inner: val.into() }
    }
  }

  unsafe impl<T> Send for EvenMoreUnsafeCell<T> {}
  unsafe impl<T> Sync for EvenMoreUnsafeCell<T> {}
}

pub mod handle {
  use parking_lot::RwLock;

  use std::mem;
  use std::ops::{Deref, DerefMut};
  use std::os::raw::c_void;
  use std::sync::Arc;

  pub type ConstPointer<T> = *const T;
  pub type Pointer<T> = *mut T;
  pub struct Handle<T> {
    inner: Arc<RwLock<Pointer<T>>>,
  }
  unsafe impl<T> Send for Handle<T> {}
  unsafe impl<T> Sync for Handle<T> {}

  impl<T> Deref for Handle<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
      unsafe { &**self.inner.read() }
    }
  }

  impl<T> DerefMut for Handle<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
      unsafe { &mut **self.inner.write() }
    }
  }

  impl<T> Handle<T> {
    pub fn new(p: Pointer<T>) -> Self {
      Self {
        inner: Arc::new(RwLock::new(p)),
      }
    }

    pub fn get_ptr(&self) -> ConstPointer<T> {
      let inner: &T = self.deref();
      let inner_ptr: *const T = inner;
      inner_ptr
    }

    pub fn get_mut_ptr(&mut self) -> Pointer<T> {
      let inner: &mut T = self.deref_mut();
      let inner_ptr: *mut T = inner;
      inner_ptr
    }
  }

  ///
  /// This method is intended for implementors of #[no_mangle] extern "C" fn APIs which are made to
  /// store `user_data` information in a buffer provided again to other callback methods.
  pub unsafe fn get_mut_ctx<'a, T>(user_data: *mut c_void) -> &'a mut T {
    let user_data: *mut T = mem::transmute::<*mut c_void, *mut T>(user_data);
    assert!(!user_data.is_null());
    &mut *user_data
  }
}

mod internal_error {
  use crate::cipher::CipherCode;
  use crate::error::{
    extensions::ShiftedErrorCodeable,
    foundations::{ReturnCode, MINIMUM},
  };
  use crate::log_level::LogCode;

  use std::convert::From;
  use std::str;

  #[derive(Debug)]
  pub enum InternalError {
    InvalidLogLevel(LogCode),
    InvalidCipherType(CipherCode),
    InvalidUtf8(str::Utf8Error),
    Unknown,
  }

  impl From<str::Utf8Error> for InternalError {
    fn from(err: str::Utf8Error) -> Self {
      Self::InvalidUtf8(err)
    }
  }

  impl ShiftedErrorCodeable for InternalError {
    fn shift(&self) -> ReturnCode {
      MINIMUM
    }
    fn into_relative_rc(self) -> ReturnCode {
      match self {
        Self::InvalidLogLevel(_) => -1,
        Self::InvalidCipherType(_) => -2,
        Self::InvalidUtf8(_) => -3,
        Self::Unknown => -4,
      }
    }
  }
}

pub mod cipher {
  use super::gen::{SG_CIPHER_AES_CBC_PKCS5, SG_CIPHER_AES_CTR_NOPADDING};
  use super::internal_error::InternalError;

  pub type CipherCode = u32;

  pub enum CipherType {
    AesCtrNoPadding,
    AesCbcPkcS5,
  }

  impl CipherType {
    pub fn from_cipher_code(value: CipherCode) -> Result<Self, InternalError> {
      match value {
        SG_CIPHER_AES_CTR_NOPADDING => Ok(Self::AesCtrNoPadding),
        SG_CIPHER_AES_CBC_PKCS5 => Ok(Self::AesCbcPkcS5),
        x => Err(InternalError::InvalidCipherType(x)),
      }
    }

    pub fn into_cipher_code(self) -> CipherCode {
      match self {
        Self::AesCtrNoPadding => SG_CIPHER_AES_CTR_NOPADDING,
        Self::AesCbcPkcS5 => SG_CIPHER_AES_CBC_PKCS5,
      }
    }
  }
}

pub mod log_level {
  use crate::gen::{SG_LOG_DEBUG, SG_LOG_ERROR, SG_LOG_INFO, SG_LOG_NOTICE, SG_LOG_WARNING};
  use crate::internal_error::InternalError;

  pub type LogCode = u32;

  #[derive(Debug)]
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

#[cfg(test)]
mod test {
  use std::io;

  #[test]
  fn test_something() -> io::Result<()> {
    Ok(())
  }
}

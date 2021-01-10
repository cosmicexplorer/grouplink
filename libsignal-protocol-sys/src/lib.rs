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
pub mod handle;
pub mod list;
pub mod liveness;

pub mod stores;

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

mod internal_error {
  use crate::cipher::CipherCode;
  use crate::error::{ReturnCode, ShiftedErrorCodeable, MINIMUM};
  use crate::log_level::LogCode;
  use crate::stores::StoreError;

  use std::convert::From;
  use std::str;

  #[derive(Debug)]
  pub enum InternalError {
    InvalidLogLevel(LogCode),
    InvalidCipherType(CipherCode),
    InvalidUtf8(str::Utf8Error),
    Store(StoreError),
    Unknown,
  }

  impl From<str::Utf8Error> for InternalError {
    fn from(err: str::Utf8Error) -> Self {
      Self::InvalidUtf8(err)
    }
  }

  impl From<StoreError> for InternalError {
    fn from(err: StoreError) -> Self {
      Self::Store(err)
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
        Self::Store(_) => -4,
        Self::Unknown => -5,
      }
    }
  }
}

pub mod util {
  use std::mem;
  use std::os::raw::c_void;

  ///
  /// This method is intended for implementors of #[no_mangle] extern "C" fn APIs which are made to
  /// store `user_data` information in a buffer provided again to other callback methods.
  pub unsafe fn get_mut_ctx<'a, T>(user_data: *mut c_void) -> &'a mut T {
    let user_data: *mut T = mem::transmute::<*mut c_void, *mut T>(user_data);
    assert!(!user_data.is_null());
    &mut *user_data
  }

  pub trait BidirectionalConstruction {
    type Native;
    fn into_native(self) -> Self::Native;
    fn from_native(native: Self::Native) -> Self;
  }

  pub mod signed_data {
    use crate::gen::size_t as SizeType;

    use std::mem;
    use std::slice;

    pub fn i_slice<'a>(src: *const i8, len: SizeType) -> &'a [i8] {
      unsafe { slice::from_raw_parts(src, len as usize) }
    }
    pub fn i_slice_mut<'a>(src: *mut i8, len: SizeType) -> &'a mut [i8] {
      unsafe { slice::from_raw_parts_mut(src, len as usize) }
    }
    pub fn u_slice<'a>(src: *const u8, len: SizeType) -> &'a [u8] {
      unsafe { slice::from_raw_parts(src, len as usize) }
    }
    pub fn u_slice_mut<'a>(src: *mut u8, len: SizeType) -> &'a mut [u8] {
      unsafe { slice::from_raw_parts_mut(src, len as usize) }
    }

    pub fn i2u(signed_data: &[i8]) -> &[u8] {
      unsafe { mem::transmute::<&[i8], &[u8]>(signed_data) }
    }
    pub fn i2u_mut(signed_data: &mut [i8]) -> &mut [u8] {
      unsafe { mem::transmute::<&mut [i8], &mut [u8]>(signed_data) }
    }
    pub fn u2i(unsigned_data: &[u8]) -> &[i8] {
      unsafe { mem::transmute::<&[u8], &[i8]>(unsigned_data) }
    }
    pub fn u2i_mut(unsigned_data: &mut [u8]) -> &mut [i8] {
      unsafe { mem::transmute::<&mut [u8], &mut [i8]>(unsigned_data) }
    }
  }
}

pub mod address {
  use crate::gen::{signal_protocol_address, size_t as SizeType};
  use crate::util::BidirectionalConstruction;

  use std::mem;
  use std::slice;

  #[derive(Copy, Clone, Debug)]
  pub struct DeviceId {
    id: i32,
  }

  impl BidirectionalConstruction for DeviceId {
    type Native = i32;
    fn into_native(self) -> i32 {
      self.id
    }
    fn from_native(native: i32) -> Self {
      Self { id: native }
    }
  }

  #[derive(Clone, Debug)]
  pub struct Address<'a> {
    name: &'a [u8],
    device_id: DeviceId,
  }

  impl<'a> BidirectionalConstruction for Address<'a> {
    type Native = signal_protocol_address;
    fn into_native(self) -> signal_protocol_address {
      let len = self.name.len();
      let id = self.device_id.into_native();
      signal_protocol_address {
        name: self.name.as_ptr() as *const i8,
        name_len: len as SizeType,
        device_id: id,
      }
    }
    fn from_native(native: signal_protocol_address) -> Self {
      assert_eq!(mem::size_of::<i8>(), mem::size_of::<u8>());
      let modified_name = unsafe { mem::transmute::<*const i8, *const u8>(native.name) };
      Self {
        name: unsafe { slice::from_raw_parts(modified_name, native.name_len as usize) },
        device_id: DeviceId::from_native(native.device_id),
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

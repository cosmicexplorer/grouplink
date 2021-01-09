// Copyright 2021, Danny McClanahan
// Licensed under the GNU GPL, Version 3.0 or any later version (see COPYING).

// Nightly features.
#![feature(get_mut_unchecked)]
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

pub mod buffer;

// We *only* use unsafe pointer dereferences when we implement the libsignal callbacks, so it is
// nicer to list internal minor calls as unsafe, than to mark the whole function as unsafe which may
// hide other unsafeness.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub mod crypto_provider;

pub mod error;
pub mod handles;

mod native_bindings;
use native_bindings::generated_bindings as gen;

pub mod handle {
  use parking_lot::RwLock;

  use std::ops::{Deref, DerefMut};
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
}

mod internal_error {
  use crate::error::{
    extensions::ShiftedErrorCodeable,
    foundations::{ReturnCode, MINIMUM},
  };

  #[derive(Debug)]
  pub enum InternalError {
    InvalidLogLevel(crate::log_level::LogCode),
    InvalidCipherType(crate::cipher::CipherCode),
    Unknown,
  }

  impl ShiftedErrorCodeable for InternalError {
    fn shift(&self) -> ReturnCode {
      MINIMUM
    }
    fn into_relative_rc(self) -> ReturnCode {
      match self {
        Self::InvalidLogLevel(_) => -1,
        Self::InvalidCipherType(_) => -2,
        Self::Unknown => -3,
      }
    }
  }
}

pub mod log_level {
  use super::gen::{SG_LOG_DEBUG, SG_LOG_ERROR, SG_LOG_INFO, SG_LOG_NOTICE, SG_LOG_WARNING};
  use super::internal_error::InternalError;

  pub type LogCode = u32;

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

///
/// FIXME: ???
pub mod buffers {
  use crate::buffer::{Buffer, BufferCopy, BufferOps, BufferSource, Sensitivity};

  pub trait WrappedBufferable<Buf: BufferOps> {
    fn wrapped_buffer(&mut self) -> Buf;
  }
  pub trait WrappedBufferBase<Buf: BufferOps>: WrappedBufferable<Buf> {
    fn from_buf(buf: Buf) -> Self;
  }
  pub trait SensitiveWrappedBuffer: WrappedBufferBase<Buffer> {
    fn from_bytes(data: &[u8]) -> Self
    where
      Self: Sized,
    {
      let wrapped_buffer: Buffer = BufferCopy {
        source: BufferSource::from_data(&data),
        sensitivity: Sensitivity::Sensitive,
      }
      .into();
      Self::from_buf(wrapped_buffer)
    }
  }

  pub mod keys {
    use super::{SensitiveWrappedBuffer, WrappedBufferBase, WrappedBufferable};
    use crate::buffer::Buffer;

    pub trait Key: SensitiveWrappedBuffer {}

    pub struct EncryptionKey {
      buf: Buffer,
    }
    impl WrappedBufferable<Buffer> for EncryptionKey {
      fn wrapped_buffer(&mut self) -> Buffer {
        self.buf.clone()
      }
    }
    impl WrappedBufferBase<Buffer> for EncryptionKey {
      fn from_buf(buf: Buffer) -> Self {
        Self { buf }
      }
    }
    impl SensitiveWrappedBuffer for EncryptionKey {}
    impl Key for EncryptionKey {}

    pub struct DecryptionKey {
      buf: Buffer,
    }
    impl WrappedBufferable<Buffer> for DecryptionKey {
      fn wrapped_buffer(&mut self) -> Buffer {
        self.buf.clone()
      }
    }
    impl WrappedBufferBase<Buffer> for DecryptionKey {
      fn from_buf(buf: Buffer) -> Self {
        Self { buf }
      }
    }
    impl SensitiveWrappedBuffer for DecryptionKey {}
    impl Key for DecryptionKey {}
  }

  pub mod per_message {
    use super::{SensitiveWrappedBuffer, WrappedBufferBase, WrappedBufferable};
    use crate::buffer::Buffer;

    pub trait PerMessage: SensitiveWrappedBuffer {}

    pub struct InitializationVector {
      buf: Buffer,
    }
    impl WrappedBufferable<Buffer> for InitializationVector {
      fn wrapped_buffer(&mut self) -> Buffer {
        self.buf.clone()
      }
    }
    impl WrappedBufferBase<Buffer> for InitializationVector {
      fn from_buf(buf: Buffer) -> Self {
        Self { buf }
      }
    }
    impl SensitiveWrappedBuffer for InitializationVector {}
    impl PerMessage for InitializationVector {}

    pub struct Plaintext {
      buf: Buffer,
    }
    impl WrappedBufferable<Buffer> for Plaintext {
      fn wrapped_buffer(&mut self) -> Buffer {
        self.buf.clone()
      }
    }
    impl WrappedBufferBase<Buffer> for Plaintext {
      fn from_buf(buf: Buffer) -> Self {
        Self { buf }
      }
    }
    impl SensitiveWrappedBuffer for Plaintext {}
    impl PerMessage for Plaintext {}

    pub struct Ciphertext {
      buf: Buffer,
    }
    impl WrappedBufferable<Buffer> for Ciphertext {
      fn wrapped_buffer(&mut self) -> Buffer {
        self.buf.clone()
      }
    }
    impl WrappedBufferBase<Buffer> for Ciphertext {
      fn from_buf(buf: Buffer) -> Self {
        Self { buf }
      }
    }
    impl SensitiveWrappedBuffer for Ciphertext {}
    impl PerMessage for Ciphertext {}
  }

  pub mod digest {
    use super::WrappedBufferable;
    use crate::buffer::*;

    pub trait Digester<Buf: BufferOps>: WrappedBufferable<Buf> {
      type Args;
      fn initialize(args: Self::Args) -> Self;
      fn update(&mut self, data: &[u8]);
    }

    pub trait HMACSHA256Digester: Digester<Buffer> {
      type Args = BufferSource;
    }

    #[derive(Default)]
    pub struct HMACSHA256 {
      buf: Buffer,
    }
    impl WrappedBufferable<Buffer> for HMACSHA256 {
      fn wrapped_buffer(&mut self) -> Buffer {
        self.buf.clone()
      }
    }
    impl Digester<Buffer> for HMACSHA256 {
      type Args = <Self as HMACSHA256Digester>::Args;
      fn initialize(args: BufferSource) -> Self {
        Self {
          /* FIXME: IS THIS CORRECT????? */
          buf: Buffer::from(BufferCopy {
            source: args,
            sensitivity: Sensitivity::Sensitive,
          }),
        }
      }
      fn update(&mut self, _data: &[u8]) {
        unimplemented!("!!!!");
      }
    }
    impl HMACSHA256Digester for HMACSHA256 {}

    pub trait SHA512Digester: Digester<Buffer> {
      type Args = ();
    }

    #[derive(Default)]
    pub struct SHA512 {
      buf: Buffer,
    }
    impl WrappedBufferable<Buffer> for SHA512 {
      fn wrapped_buffer(&mut self) -> Buffer {
        self.buf.clone()
      }
    }
    impl Digester<Buffer> for SHA512 {
      type Args = <Self as SHA512Digester>::Args;
      fn initialize(_args: ()) -> Self {
        Self {
          buf: Buffer::from(BufferAllocate {
            /* FIXME: we know what the size of the written data is going to be here, right? */
            size: 0,
            sensitivity: Sensitivity::Sensitive,
          }),
        }
      }
      fn update(&mut self, _data: &[u8]) {
        unimplemented!("xxxxxx");
      }
    }
    impl SHA512Digester for SHA512 {}
  }
}

pub mod providers {
  pub use crate::crypto_provider as crypto;

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

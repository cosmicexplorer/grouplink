pub mod generic {
  use crate::buffer::buffers::{
    digest::{HMACSHA256, SHA512},
    keys::{DecryptionKey, EncryptionKey},
    per_message::{Ciphertext, InitializationVector, Plaintext},
  };
  use crate::buffer::Buffer;
  use crate::cipher::CipherType;
  use crate::error::SignalError;

  pub trait CryptoProvider {
    ///
    /// Callback for a secure random number generator.
    /// This function shall fill the provided buffer with random bytes.
    ///
    /// @param data pointer to the output buffer
    /// @param len size of the output buffer
    /// @return 0 on success, negative on failure
    ///
    fn random(&mut self, data: &mut [u8]) -> Result<(), SignalError>;

    ///
    /// Callback for an HMAC-SHA256 implementation.
    /// This function shall initialize an HMAC context with the provided key.
    ///
    /// @param hmac_context private HMAC context pointer
    /// @param key pointer to the key
    /// @param key_len length of the key
    /// @return 0 on success, negative on failure
    ///
    fn hmac_sha256_init(&mut self, key: &[u8]) -> Result<HMACSHA256, SignalError>;

    ///
    /// Callback for an HMAC-SHA256 implementation.
    /// This function shall update the HMAC context with the provided data
    ///
    /// @param hmac_context private HMAC context pointer
    /// @param data pointer to the data
    /// @param data_len length of the data
    /// @return 0 on success, negative on failure
    ///
    fn hmac_sha256_update(
      &mut self,
      hmac_context: &mut HMACSHA256,
      data: &[u8],
    ) -> Result<(), SignalError>;

    ///
    /// Callback for an HMAC-SHA256 implementation.
    /// This function shall finalize an HMAC calculation and populate the output
    /// buffer with the result.
    ///
    /// @param hmac_context private HMAC context pointer
    /// @param output buffer to be allocated and populated with the result
    /// @return 0 on success, negative on failure
    ///
    fn hmac_sha256_final(&mut self, hmac_context: &mut HMACSHA256) -> Result<Buffer, SignalError>;

    ///
    /// Callback for an HMAC-SHA256 implementation.
    /// This function shall free the private context allocated in
    /// hmac_sha256_init.
    ///
    /// @param hmac_context private HMAC context pointer
    ///
    fn hmac_sha256_cleanup(&mut self, hmac_context: &mut HMACSHA256);

    ///
    /// Callback for a SHA512 message digest implementation.
    /// This function shall initialize a digest context.
    ///
    /// @param digest_context private digest context pointer
    /// @return 0 on success, negative on failure
    ///
    fn sha512_digest_init(&mut self) -> Result<SHA512, SignalError>;

    ///
    /// Callback for a SHA512 message digest implementation.
    /// This function shall update the digest context with the provided data.
    ///
    /// @param digest_context private digest context pointer
    /// @param data pointer to the data
    /// @param data_len length of the data
    /// @return 0 on success, negative on failure
    ///
    fn sha512_digest_update(
      &mut self,
      digest_context: &mut SHA512,
      data: &[u8],
    ) -> Result<(), SignalError>;

    ///
    /// Callback for a SHA512 message digest implementation.
    /// This function shall finalize the digest calculation, populate the
    /// output buffer with the result, and prepare the context for reuse.
    ///
    /// @param digest_context private digest context pointer
    /// @param output buffer to be allocated and populated with the result
    /// @return 0 on success, negative on failure
    ///
    fn sha512_digest_final(&mut self, digest_context: &mut SHA512) -> Result<Buffer, SignalError>;

    ///
    /// Callback for a SHA512 message digest implementation.
    /// This function shall free the private context allocated in
    /// sha512_digest_init.
    ///
    /// @param digest_context private digest context pointer
    ///
    fn sha512_digest_cleanup(&mut self, digest_context: &mut SHA512);

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
    ///
    fn encrypt(
      &mut self,
      cipher: CipherType,
      key: EncryptionKey,
      iv: InitializationVector,
      plaintext: Plaintext,
    ) -> Result<Ciphertext, SignalError>;

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
    ///
    fn decrypt(
      &mut self,
      cipher: CipherType,
      key: DecryptionKey,
      iv: InitializationVector,
      ciphertext: Ciphertext,
    ) -> Result<Plaintext, SignalError>;
  }
}

pub mod crypto_impl {
  use super::generic::CryptoProvider;

  use crate::buffer::buffers::{
    digest::{Digester, HMACSHA256, SHA512},
    keys::{DecryptionKey, EncryptionKey},
    per_message::{Ciphertext, InitializationVector, Plaintext},
    WrappedBufferable,
  };
  use crate::buffer::*;
  use crate::cipher::CipherType;
  use crate::error::SignalError;
  use crate::handle::{Context, WithContext};

  use std::mem;

  #[derive(Clone, Debug)]
  pub struct DefaultCrypto {
    context: Context,
  }

  impl WithContext for DefaultCrypto {
    fn get_signal_context(&mut self) -> &mut Context {
      &mut self.context
    }
  }

  impl CryptoProvider for DefaultCrypto {
    fn random(&mut self, _data: &mut [u8]) -> Result<(), SignalError> {
      unimplemented!("random!");
    }

    fn hmac_sha256_init(&mut self, key: &[u8]) -> Result<HMACSHA256, SignalError> {
      /* TODO: share memory between these keys somehow? does keeping them as an Arc affect security
       * (of course it does)? */
      Ok(HMACSHA256::initialize(BufferSource::from_data(&key)))
    }
    fn hmac_sha256_update(
      &mut self,
      hmac_context: &mut HMACSHA256,
      data: &[u8],
    ) -> Result<(), SignalError> {
      hmac_context.update(data);
      Ok(())
    }
    fn hmac_sha256_final(&mut self, hmac_context: &mut HMACSHA256) -> Result<Buffer, SignalError> {
      Ok(hmac_context.wrapped_buffer())
    }
    fn hmac_sha256_cleanup(&mut self, hmac_context: &mut HMACSHA256) {
      mem::drop(hmac_context);
    }

    fn sha512_digest_init(&mut self) -> Result<SHA512, SignalError> {
      Ok(SHA512::initialize(()))
    }
    fn sha512_digest_update(
      &mut self,
      digest_context: &mut SHA512,
      data: &[u8],
    ) -> Result<(), SignalError> {
      digest_context.update(data);
      Ok(())
    }
    fn sha512_digest_final(&mut self, digest_context: &mut SHA512) -> Result<Buffer, SignalError> {
      Ok(digest_context.wrapped_buffer())
    }
    fn sha512_digest_cleanup(&mut self, digest_context: &mut SHA512) {
      mem::drop(digest_context);
    }

    fn encrypt(
      &mut self,
      _cipher: CipherType,
      _key: EncryptionKey,
      _iv: InitializationVector,
      _plaintext: Plaintext,
    ) -> Result<Ciphertext, SignalError> {
      unimplemented!("encrypt!");
    }

    fn decrypt(
      &mut self,
      _cipher: CipherType,
      _key: DecryptionKey,
      _iv: InitializationVector,
      _ciphertext: Ciphertext,
    ) -> Result<Plaintext, SignalError> {
      unimplemented!("decrypt!");
    }
  }
}

pub mod c_abi_impl {
  use super::crypto_impl::DefaultCrypto;
  use super::generic::CryptoProvider;

  use crate::buffer::buffers::{
    digest::{HMACSHA256, SHA512},
    keys::{DecryptionKey, EncryptionKey},
    per_message::{Ciphertext, InitializationVector, Plaintext},
    SensitiveWrappedBuffer, WrappedBufferable,
  };
  use crate::buffer::*;
  use crate::cipher::{CipherCode, CipherType};
  use crate::error::{ErrorCodeable, SUCCESS};
  use crate::gen::{signal_buffer, size_t};
  use crate::handle::Handle;
  use crate::util::get_mut_ctx;

  use std::ops::DerefMut;
  use std::os::raw::{c_int, c_void};
  use std::slice;

  ///
  /// Implement the Signal API callbacks.
  ///
  /// NB: We manually prepend a common prefix to each method (here, `CRYPTO_`) in order to avoid any
  /// symbol overlaps in the binary executable with all of them together!
  /// TODO: rustc may already do this check though?
  #[no_mangle]
  pub extern "C" fn CRYPTO_random_func(
    data: *mut u8,
    len: size_t,
    user_data: *mut c_void,
  ) -> c_int {
    let crypto: &mut DefaultCrypto = unsafe { get_mut_ctx(user_data) };
    let data = unsafe { slice::from_raw_parts_mut(data, len as usize) };
    match crypto.random(data) {
      Ok(()) => SUCCESS,
      Err(e) => e.into_rc(),
    }
  }

  #[no_mangle]
  pub extern "C" fn CRYPTO_hmac_sha256_init_func(
    hmac_context: *mut *mut c_void,
    key: *const u8,
    key_len: size_t,
    user_data: *mut c_void,
  ) -> c_int {
    let crypto: &mut DefaultCrypto = unsafe { get_mut_ctx(user_data) };
    let key = unsafe { slice::from_raw_parts(key, key_len as usize) };
    match crypto.hmac_sha256_init(key) {
      Ok(ctx) => unsafe {
        *hmac_context = Box::into_raw(Box::new(ctx)) as *mut c_void;
        SUCCESS
      },
      Err(e) => e.into_rc(),
    }
  }

  #[no_mangle]
  pub extern "C" fn CRYPTO_hmac_sha256_update_func(
    hmac_context: *mut c_void,
    data: *const u8,
    data_len: size_t,
    user_data: *mut c_void,
  ) -> c_int {
    let crypto: &mut DefaultCrypto = unsafe { get_mut_ctx(user_data) };
    let hmac: &mut HMACSHA256 = unsafe { get_mut_ctx(hmac_context) };
    let data = unsafe { slice::from_raw_parts(data, data_len as usize) };
    match crypto.hmac_sha256_update(hmac, data) {
      Ok(()) => SUCCESS,
      Err(e) => e.into_rc(),
    }
  }

  fn leak_signal_buffer(mut buf: Buffer) -> *mut Inner {
    let handle: &mut Handle<Inner> = buf.as_mut();
    let signal_buf: &mut Inner = handle.deref_mut();
    &mut *signal_buf
  }

  #[no_mangle]
  pub extern "C" fn CRYPTO_hmac_sha256_final_func(
    hmac_context: *mut c_void,
    output: *mut *mut signal_buffer,
    user_data: *mut c_void,
  ) -> c_int {
    let crypto: &mut DefaultCrypto = unsafe { get_mut_ctx(user_data) };
    let hmac: &mut HMACSHA256 = unsafe { get_mut_ctx(hmac_context) };
    match crypto.hmac_sha256_final(hmac) {
      Ok(digest) => unsafe {
        *output = leak_signal_buffer(digest);
        SUCCESS
      },
      Err(e) => e.into_rc(),
    }
  }

  #[no_mangle]
  pub extern "C" fn CRYPTO_hmac_sha256_cleanup_func(
    hmac_context: *mut c_void,
    user_data: *mut c_void,
  ) {
    let crypto: &mut DefaultCrypto = unsafe { get_mut_ctx(user_data) };
    let hmac: &mut HMACSHA256 = unsafe { get_mut_ctx(hmac_context) };
    crypto.hmac_sha256_cleanup(hmac);
  }

  #[no_mangle]
  pub extern "C" fn CRYPTO_sha512_digest_init_func(
    digest_context: *mut *mut c_void,
    user_data: *mut c_void,
  ) -> c_int {
    let crypto: &mut DefaultCrypto = unsafe { get_mut_ctx(user_data) };
    match crypto.sha512_digest_init() {
      Ok(sha512) => unsafe {
        *digest_context = Box::into_raw(Box::new(sha512)) as *mut c_void;
        SUCCESS
      },
      Err(e) => e.into_rc(),
    }
  }

  #[no_mangle]
  pub extern "C" fn CRYPTO_sha512_digest_update_func(
    digest_context: *mut c_void,
    data: *const u8,
    data_len: size_t,
    user_data: *mut c_void,
  ) -> c_int {
    let crypto: &mut DefaultCrypto = unsafe { get_mut_ctx(user_data) };
    let sha512: &mut SHA512 = unsafe { get_mut_ctx(digest_context) };
    let data = unsafe { slice::from_raw_parts(data, data_len as usize) };
    match crypto.sha512_digest_update(sha512, data) {
      Ok(()) => SUCCESS,
      Err(e) => e.into_rc(),
    }
  }

  #[no_mangle]
  pub extern "C" fn CRYPTO_sha512_digest_final_func(
    digest_context: *mut c_void,
    output: *mut *mut signal_buffer,
    user_data: *mut c_void,
  ) -> c_int {
    let crypto: &mut DefaultCrypto = unsafe { get_mut_ctx(user_data) };
    let sha512: &mut SHA512 = unsafe { get_mut_ctx(digest_context) };
    match crypto.sha512_digest_final(sha512) {
      Ok(digest) => unsafe {
        *output = leak_signal_buffer(digest);
        SUCCESS
      },
      Err(e) => e.into_rc(),
    }
  }

  #[no_mangle]
  pub extern "C" fn CRYPTO_sha512_digest_cleanup_func(
    digest_context: *mut c_void,
    user_data: *mut c_void,
  ) {
    let crypto: &mut DefaultCrypto = unsafe { get_mut_ctx(user_data) };
    let sha512: &mut SHA512 = unsafe { get_mut_ctx(digest_context) };
    crypto.sha512_digest_cleanup(sha512);
  }

  #[no_mangle]
  pub extern "C" fn CRYPTO_encrypt_func(
    output: *mut *mut signal_buffer,
    cipher: c_int,
    key: *const u8,
    key_len: size_t,
    iv: *const u8,
    iv_len: size_t,
    plaintext: *const u8,
    plaintext_len: size_t,
    user_data: *mut c_void,
  ) -> c_int {
    let crypto: &mut DefaultCrypto = unsafe { get_mut_ctx(user_data) };
    let cipher = match CipherType::from_cipher_code(cipher as CipherCode) {
      Ok(x) => x,
      Err(e) => {
        return e.into_rc();
      }
    };
    let key = EncryptionKey::from_bytes(unsafe { slice::from_raw_parts(key, key_len as usize) });
    let iv =
      InitializationVector::from_bytes(unsafe { slice::from_raw_parts(iv, iv_len as usize) });
    let plaintext =
      Plaintext::from_bytes(unsafe { slice::from_raw_parts(plaintext, plaintext_len as usize) });

    match crypto.encrypt(cipher, key, iv, plaintext) {
      Ok(mut ciphertext) => unsafe {
        *output = leak_signal_buffer(ciphertext.wrapped_buffer());
        SUCCESS
      },
      Err(e) => e.into_rc(),
    }
  }

  #[no_mangle]
  pub extern "C" fn CRYPTO_decrypt_func(
    output: *mut *mut signal_buffer,
    cipher: c_int,
    key: *const u8,
    key_len: size_t,
    iv: *const u8,
    iv_len: size_t,
    ciphertext: *const u8,
    ciphertext_len: size_t,
    user_data: *mut c_void,
  ) -> c_int {
    let crypto: &mut DefaultCrypto = unsafe { get_mut_ctx(user_data) };
    let cipher = match CipherType::from_cipher_code(cipher as CipherCode) {
      Ok(x) => x,
      Err(e) => {
        return e.into_rc();
      }
    };
    let key = DecryptionKey::from_bytes(unsafe { slice::from_raw_parts(key, key_len as usize) });
    let iv =
      InitializationVector::from_bytes(unsafe { slice::from_raw_parts(iv, iv_len as usize) });
    let ciphertext =
      Ciphertext::from_bytes(unsafe { slice::from_raw_parts(ciphertext, ciphertext_len as usize) });

    match crypto.decrypt(cipher, key, iv, ciphertext) {
      Ok(mut plaintext) => unsafe {
        *output = leak_signal_buffer(plaintext.wrapped_buffer());
        SUCCESS
      },
      Err(e) => e.into_rc(),
    }
  }
}

pub mod via_native {
  use super::c_abi_impl::{
    CRYPTO_decrypt_func, CRYPTO_encrypt_func, CRYPTO_hmac_sha256_cleanup_func,
    CRYPTO_hmac_sha256_final_func, CRYPTO_hmac_sha256_init_func, CRYPTO_hmac_sha256_update_func,
    CRYPTO_random_func, CRYPTO_sha512_digest_cleanup_func, CRYPTO_sha512_digest_final_func,
    CRYPTO_sha512_digest_init_func, CRYPTO_sha512_digest_update_func,
  };
  use super::crypto_impl::DefaultCrypto;
  use super::generic::CryptoProvider;

  use crate::error::{SignalError, SignalNativeResult};
  use crate::gen::{signal_context_set_crypto_provider, signal_crypto_provider};
  use crate::handle::{Context, WithContext};
  use crate::stores::generics::{ContextRegisterable, SeparateFromContextRegisterable};

  use std::convert::AsMut;
  use std::os::raw::c_void;

  impl<P: CryptoProvider> From<P> for signal_crypto_provider {
    fn from(provider: P) -> Self {
      signal_crypto_provider {
        random_func: Some(CRYPTO_random_func),
        hmac_sha256_init_func: Some(CRYPTO_hmac_sha256_init_func),
        hmac_sha256_update_func: Some(CRYPTO_hmac_sha256_update_func),
        hmac_sha256_final_func: Some(CRYPTO_hmac_sha256_final_func),
        hmac_sha256_cleanup_func: Some(CRYPTO_hmac_sha256_cleanup_func),
        sha512_digest_init_func: Some(CRYPTO_sha512_digest_init_func),
        sha512_digest_update_func: Some(CRYPTO_sha512_digest_update_func),
        sha512_digest_final_func: Some(CRYPTO_sha512_digest_final_func),
        sha512_digest_cleanup_func: Some(CRYPTO_sha512_digest_cleanup_func),
        encrypt_func: Some(CRYPTO_encrypt_func),
        decrypt_func: Some(CRYPTO_decrypt_func),
        user_data: Box::into_raw(Box::new(provider)) as *mut c_void,
      }
    }
  }

  impl SeparateFromContextRegisterable<signal_crypto_provider, SignalError> for DefaultCrypto {
    type Ctx = Context;
    fn get_context(&mut self) -> &mut Self::Ctx {
      self.get_signal_context()
    }

    fn modify_context(
      ctx: &mut Context,
      native: signal_crypto_provider,
    ) -> Result<(), SignalError> {
      let result: Result<(), SignalError> = SignalNativeResult::call_method((), |()| {
        let ctx = ctx.as_mut().get_mut_ptr();
        unsafe { signal_context_set_crypto_provider(ctx, &*&native) }
      })
      .into();
      result
    }
  }

  /* FIXME: make this impl automatic? rustc yells :( */
  impl ContextRegisterable<SignalError> for DefaultCrypto {
    fn register(self) -> Result<(), SignalError> {
      <Self as SeparateFromContextRegisterable<signal_crypto_provider, _>>::register(self)
    }
  }
}

pub use crypto_impl::DefaultCrypto;
pub use generic::CryptoProvider;

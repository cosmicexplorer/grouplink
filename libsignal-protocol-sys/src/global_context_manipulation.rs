pub mod generics {
  use crate::error::SignalError;
  use crate::handles::{Context, GlobalContext};

  use std::convert::Into;

  pub trait ContextRegisterable {
    fn register(self) -> Result<(), SignalError>;
  }

  /* NB: The other "registerable" items don't have any pointers to distinguish between them except
   * function pointers, so we have to stick them with the Context itself. */
  pub(crate) trait SeparateFromContextRegisterable<NativeStruct>:
    Into<NativeStruct> + GlobalContext
  {
    fn register(self) -> Result<(), SignalError> {
      let ctx: &'static mut Context = Self::get_global_writeable_context();
      let native: NativeStruct = self.into();
      Self::modify_context(ctx, native)
    }

    fn modify_context(ctx: &'static mut Context, native: NativeStruct) -> Result<(), SignalError>;
  }
}

pub mod crypto {
  pub use crate::crypto_provider::{
    CryptoProvider as CryptoInterface, DefaultCrypto as CryptoImplementor,
  };
}

pub mod recursive_locking_functions {
  pub mod generic {
    pub trait Locker {
      fn lock(&self);
      fn unlock(&self);
    }
  }

  pub mod mutex_impl {
    use super::generic::Locker;

    use parking_lot::{lock_api::RawMutex, ReentrantMutex};

    use std::marker::PhantomData;

    pub struct DefaultLocker {
      /* NB: The reentrancy is REQUIRED, as noted in a comment in signal_protocol.h */
      lock: ReentrantMutex<PhantomData<()>>,
    }

    impl DefaultLocker {
      pub fn new() -> Self {
        Self {
          lock: ReentrantMutex::new(PhantomData),
        }
      }
    }

    impl Locker for DefaultLocker {
      fn lock(&self) {
        let () = RawMutex::lock(unsafe { self.lock.raw() });
      }

      fn unlock(&self) {
        let () = unsafe { RawMutex::unlock(self.lock.raw()) };
      }
    }
  }

  pub mod c_abi_impl {
    use crate::handle::get_mut_ctx;
    use crate::handles::{Context, GetAux};

    use std::os::raw::c_void;

    #[no_mangle]
    pub extern "C" fn lock_func(user_data: *mut c_void) {
      let context: &mut Context = unsafe { get_mut_ctx(user_data) };
      context.get_aux().locker.lock();
    }

    #[no_mangle]
    pub extern "C" fn unlock_func(user_data: *mut c_void) {
      let context: &mut Context = unsafe { get_mut_ctx(user_data) };
      context.get_aux().locker.unlock();
    }
  }
}

pub mod log_function {
  pub mod generic {
    use crate::log_level::LogLevel;

    pub trait Logger {
      fn log(&self, level: LogLevel, msg: &str);
    }
  }

  pub mod log_impl {
    use super::generic::Logger;

    use crate::log_level::LogLevel;

    pub struct DefaultLogger();

    impl Logger for DefaultLogger {
      fn log(&self, level: LogLevel, msg: &str) {
        eprintln!("[{:?}] {}", level, msg);
      }
    }
  }

  pub mod c_abi_impl {
    use crate::gen::size_t as SizeType;
    use crate::handle::get_mut_ctx;
    use crate::handles::{Context, GetAux};
    use crate::internal_error::InternalError;
    use crate::log_level::LogLevel;

    use std::mem;
    use std::os::raw::{c_char, c_int, c_void};
    use std::slice;
    use std::str;

    #[no_mangle]
    pub extern "C" fn log_func(
      level: c_int,
      message: *const c_char,
      len: SizeType,
      user_data: *mut c_void,
    ) {
      let bytes: &[i8] = unsafe { slice::from_raw_parts(message, len as usize) };
      let bytes: &[u8] = unsafe { mem::transmute::<&[i8], &[u8]>(bytes) };
      match str::from_utf8(bytes)
        .map_err(InternalError::from)
        .and_then(|msg| {
          let context: &mut Context = unsafe { get_mut_ctx(user_data) };
          let level = LogLevel::from_log_code(level as u32)?;
          context.get_aux().logger.log(level, msg);
          Ok(())
        }) {
        Ok(()) => (),
        Err(e) => {
          panic!(
            "unhandled error when logging (due to lack of bidi comms with logger) {:?}",
            e
          );
        }
      }
    }
  }
}

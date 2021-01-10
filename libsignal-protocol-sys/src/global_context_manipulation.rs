pub mod generics {
  use crate::error::SignalError;

  use std::convert::Into;

  pub trait ContextRegisterable {
    fn register(self) -> Result<(), SignalError>;
  }

  /* NB: The other "registerable" items don't have any pointers to distinguish between them except
   * function pointers, so we have to stick them with the Context itself. */
  pub(crate) trait SeparateFromContextRegisterable<NativeStruct>:
    Into<NativeStruct>
  {
    type Ctx;
    fn get_context(&mut self) -> &mut Self::Ctx;

    fn register(mut self) -> Result<(), SignalError> {
      /* <Self as SeparateFromContextRegisterable<NativeStruct>>::Ctx: 'static; */
      let ctx: &mut Self::Ctx = self.get_context();
      let native: NativeStruct = self.into();
      Self::modify_context(ctx, native)
    }

    fn modify_context(ctx: &mut Self::Ctx, native: NativeStruct) -> Result<(), SignalError>;
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
    use crate::handles::{Context, GetAux};
    use crate::util::get_mut_ctx;

    use std::os::raw::c_void;

    #[no_mangle]
    pub extern "C" fn LOCK_lock_func(user_data: *mut c_void) {
      let context: &mut Context = unsafe { get_mut_ctx(user_data) };
      context.get_aux().locker.lock();
    }

    #[no_mangle]
    pub extern "C" fn LOCK_unlock_func(user_data: *mut c_void) {
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
    use crate::handles::{Context, GetAux};
    use crate::internal_error::InternalError;
    use crate::log_level::LogLevel;
    use crate::util::{get_mut_ctx, signed_data::*};

    use std::os::raw::{c_char, c_int, c_void};
    use std::str;

    #[no_mangle]
    pub extern "C" fn LOG_log_func(
      level: c_int,
      message: *const c_char,
      len: SizeType,
      user_data: *mut c_void,
    ) {
      let bytes: &[u8] = unsafe { i2u(i_slice(message, len)) };
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

pub mod stores {
  pub use session_store::generic::Error as SessionError;

  #[derive(Debug)]
  pub enum StoreError {
    Session(SessionError),
  }

  impl From<SessionError> for StoreError {
    fn from(err: SessionError) -> Self {
      Self::Session(err)
    }
  }

  pub mod session_store {
    pub mod generic {
      use crate::address::Address;
      use crate::buffer::Buffer;

      pub(crate) struct LoadSessionReturnValue {
        pub record: Buffer,
        pub user_record: Buffer,
      }

      #[derive(Debug)]
      pub enum Error {
        LoadSessionFailed,
      }

      pub trait SessionStore {
        fn load_session(&self, address: Address) -> Result<LoadSessionReturnValue, Error> {
          unimplemented!("load_session()")
        }
        fn get_sub_device_sessions();
        fn store_session(&self, address: Address, record: &mut [u8], user_record: &mut [u8]) {
          unimplemented!("store_session()")
        }
        fn contains_session();
        fn delete_session();
        fn delete_all_sessions();
        fn destroy();
      }
    }

    pub mod store_impl {
      use super::generic::SessionStore;

      use crate::handles::{DataStore, WithDataStore};

      pub struct DefaultSessionStore {
        data_store: DataStore,
      }

      impl WithDataStore for DefaultSessionStore {
        fn get_signal_data_store(&mut self) -> &mut DataStore {
          &mut self.data_store
        }
      }

      impl SessionStore for DefaultSessionStore {}
    }

    pub mod c_abi_impl {
      use super::generic::*;
      use super::store_impl::DefaultSessionStore;

      use crate::address::Address;
      use crate::error::{ErrorCodeable, SUCCESS};
      use crate::gen::{signal_buffer, signal_protocol_address, size_t as SizeType};
      use crate::global_context_manipulation::stores::StoreError;
      use crate::handle::Handle;
      use crate::internal_error::InternalError;
      use crate::util::{get_mut_ctx, BidirectionalConstruction};

      use std::os::raw::{c_char, c_int, c_void};

      #[no_mangle]
      pub extern "C" fn SESSION_load_session_func(
        record: *mut *mut signal_buffer,
        user_record: *mut *mut signal_buffer,
        address: *const signal_protocol_address,
        user_data: *mut c_void,
      ) -> c_int {
        let sessions: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
        let address = Address::from_native(*address);
        match sessions.load_session(address) {
          Ok(LoadSessionReturnValue {
            record: mut r,
            user_record: mut u,
          }) => unsafe {
            let r: &mut Handle<_> = r.as_mut();
            *record = r.get_mut_ptr();
            let u: &mut Handle<_> = u.as_mut();
            *user_record = u.get_mut_ptr();
            SUCCESS
          },
          Err(e) => {
            let store_err: StoreError = e.into();
            let internal_err: InternalError = store_err.into();
            internal_err.into_rc()
          }
        }
      }

      #[no_mangle]
      pub extern "C" fn SESSION_get_sub_device_sessions_func(
        sessions: *mut *mut signal_int_list,
        name: *const c_char,
        name_len: SizeType,
        user_data: *mut c_void,
      ) -> c_int {
        let sessions: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
        unimplemented!("TODO: OMG THE SESSION STORE!!!");
      }

      #[no_mangle]
      pub extern "C" fn SESSION_store_session_func(
        address: *const signal_protocol_address,
        record: *mut u8,
        record_len: SizeType,
        user_record: *mut u8,
        user_record_len: SizeType,
        user_data: *mut c_void,
      ) -> c_int {
        let sessions: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
        unimplemented!("TODO: OMG THE SESSION STORE!!!");
      }

      #[no_mangle]
      pub extern "C" fn SESSION_contains_session_func(
        address: *const signal_protocol_address,
        user_data: *mut c_void,
      ) -> c_int {
        let sessions: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
        unimplemented!("TODO: OMG THE SESSION STORE!!!");
      }

      #[no_mangle]
      pub extern "C" fn SESSION_delete_session_func(
        address: *const signal_protocol_address,
        user_data: *mut c_void,
      ) -> c_int {
        let sessions: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
        unimplemented!("TODO: OMG THE SESSION STORE!!!");
      }

      #[no_mangle]
      pub extern "C" fn SESSION_delete_all_sessions_func(
        name: *const c_char,
        name_len: SizeType,
        user_data: *mut c_void,
      ) -> c_int {
        let sessions: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
        unimplemented!("TODO: OMG THE SESSION STORE!!!");
      }

      #[no_mangle]
      pub extern "C" fn SESSION_destroy_func(user_data: *mut c_void) {
        let sessions: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
        unimplemented!("TODO: OMG THE SESSION STORE!!!");
      }
    }

    pub mod via_native {
      use super::c_abi_impl::{
        SESSION_contains_session_func, SESSION_delete_all_sessions_func,
        SESSION_delete_session_func, SESSION_destroy_func, SESSION_get_sub_device_sessions_func,
        SESSION_load_session_func, SESSION_store_session_func,
      };
      use super::generic::SessionStore;
      use super::store_impl::DefaultSessionStore;

      use crate::error::{SignalError, SignalNativeResult};
      use crate::gen::{
        signal_protocol_session_store, signal_protocol_store_context_set_session_store,
      };
      use crate::global_context_manipulation::generics::{
        ContextRegisterable, SeparateFromContextRegisterable,
      };
      use crate::handles::{DataStore, WithDataStore};

      use std::os::raw::c_void;

      impl<S: SessionStore> From<S> for signal_protocol_session_store {
        fn from(store: S) -> Self {
          signal_protocol_session_store {
            load_session_func: Some(SESSION_load_session_func),
            get_sub_device_sessions_func: Some(SESSION_get_sub_device_sessions_func),
            store_session_func: Some(SESSION_store_session_func),
            contains_session_func: Some(SESSION_contains_session_func),
            delete_session_func: Some(SESSION_delete_session_func),
            delete_all_sessions_func: Some(SESSION_delete_all_sessions_func),
            destroy_func: Some(SESSION_destroy_func),
            user_data: Box::into_raw(Box::new(store)) as *mut c_void,
          }
        }
      }

      impl SeparateFromContextRegisterable<signal_protocol_session_store> for DefaultSessionStore {
        type Ctx = DataStore;
        fn get_context(&mut self) -> &mut Self::Ctx {
          self.get_signal_data_store()
        }

        fn modify_context(
          ctx: &mut DataStore,
          native: signal_protocol_session_store,
        ) -> Result<(), SignalError> {
          let result: Result<(), SignalError> = SignalNativeResult::call_method((), |()| {
            let ctx = ctx.as_mut().get_mut_ptr();
            unsafe { signal_protocol_store_context_set_session_store(ctx, &*&native) }
          })
          .into();
          result
        }
      }

      impl ContextRegisterable for DefaultSessionStore {
        fn register(self) -> Result<(), SignalError> {
          <Self as SeparateFromContextRegisterable<signal_protocol_session_store>>::register(self)
        }
      }
    }
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

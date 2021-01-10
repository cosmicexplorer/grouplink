/* TODO: These are handles in LIVE contexts, aka data that is gone (?) after a process execution.
 * Persistent identities will require a *tad* more effort. */

pub mod generic {
  use parking_lot::RwLock;

  use std::ops::{Deref, DerefMut};
  use std::sync::Arc;

  pub type ConstPointer<T> = *const T;
  pub type Pointer<T> = *mut T;

  #[derive(Clone, Debug)]
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

pub mod handled {
  use super::generic::*;

  use std::convert::{AsMut, AsRef};

  pub trait GetAux<Aux> {
    fn get_aux(&self) -> &Aux;
  }

  pub trait Destroyed<StructType, Aux> {
    unsafe fn destroy_raw(t: Pointer<StructType>, aux: &Aux);
  }

  pub trait Managed<StructType, Aux, I, E> {
    unsafe fn create_raw(i: I, aux: &Aux) -> Result<Pointer<StructType>, E>;

    unsafe fn create_new_handle(i: I, aux: Aux) -> Result<(Handle<StructType>, Aux), E> {
      let p = Self::create_raw(i, &aux)?;
      Ok((Handle::new(p), aux))
    }
  }

  pub trait ViaHandle<StructType, Aux>:
    AsRef<Handle<StructType>> + AsMut<Handle<StructType>>
  {
    fn from_handle(handle: Handle<StructType>, aux: Aux) -> Self;
  }

  pub trait Handled<StructType, Aux: Clone, I, E>:
    GetAux<Aux>
    + Managed<StructType, Aux, I, E>
    + Destroyed<StructType, Aux>
    + ViaHandle<StructType, Aux>
  {
    fn handled_instance(i: I, aux: Aux) -> Result<Self, E>
    where
      Self: Sized,
    {
      let (p, s) = unsafe { Self::create_new_handle(i, aux)? };
      Ok(Self::from_handle(p, s))
    }

    fn handled_drop(&mut self)
    where
      Self: Sized,
    {
      let aux = self.get_aux().clone();
      let handle: &mut Handle<StructType> = self.as_mut();
      unsafe { Self::destroy_raw(handle.get_mut_ptr(), &aux) };
    }
  }
}

mod global_context {
  use lazy_static::lazy_static;

  use std::convert::{AsMut, AsRef};
  use std::ffi::c_void;
  use std::ptr;
  use std::sync::Arc;

  use super::handled::{Destroyed, GetAux, Handled, Managed, ViaHandle};

  use crate::cell::{EvenMoreUnsafeCell, UnsafeAPI};
  use crate::error::{SignalError, SignalNativeResult};
  use crate::gen::{signal_context, signal_context_create, signal_context_destroy};
  use crate::handle::Handle;

  /* NB: We would like to be able to rely on a separate pointer carrying this information as in
   * crypto_provider.rs, but since we can't (TODO: is this intentional???), we have to rely on
   * deeply interworked imports. */
  use conjoined_config::{
    log_function::{generic::Logger, log_impl::DefaultLogger},
    recursive_locking_functions::{generic::Locker, mutex_impl::DefaultLocker},
  };

  #[derive(Clone, Debug)]
  pub struct ContextAux {
    pub locker: Arc<dyn Locker>,
    pub logger: Arc<dyn Logger>,
  }
  unsafe impl Send for ContextAux {}
  unsafe impl Sync for ContextAux {}

  #[derive(Clone, Debug)]
  pub struct Context {
    handle: Handle<signal_context>,
    aux: ContextAux,
  }

  impl GetAux<ContextAux> for Context {
    fn get_aux(&self) -> &ContextAux {
      &self.aux
    }
  }

  impl Destroyed<signal_context, ContextAux> for Context {
    unsafe fn destroy_raw(t: *mut signal_context, _aux: &ContextAux) {
      signal_context_destroy(t);
    }
  }

  impl Managed<signal_context, ContextAux, (), SignalError> for Context {
    unsafe fn create_raw(_i: (), _aux: &ContextAux) -> Result<*mut signal_context, SignalError> {
      let inner: *mut *mut signal_context = ptr::null_mut();
      let user_data: *mut c_void = ptr::null_mut();
      let result: Result<*mut *mut signal_context, SignalError> =
        SignalNativeResult::call_method(inner, |inner| signal_context_create(inner, user_data))
          .into();
      Ok(*result?)
    }
  }

  impl AsRef<Handle<signal_context>> for Context {
    fn as_ref(&self) -> &Handle<signal_context> {
      &self.handle
    }
  }
  impl AsMut<Handle<signal_context>> for Context {
    fn as_mut(&mut self) -> &mut Handle<signal_context> {
      &mut self.handle
    }
  }
  impl ViaHandle<signal_context, ContextAux> for Context {
    fn from_handle(handle: Handle<signal_context>, aux: ContextAux) -> Self {
      Self { handle, aux }
    }
  }

  impl Handled<signal_context, ContextAux, (), SignalError> for Context {}

  impl Drop for Context {
    fn drop(&mut self) {
      self.handled_drop();
    }
  }

  ///
  /// NB: The other "registerable" items don't have any pointers to distinguish between them except
  /// function pointers, so we have to stick them with the Context itself.
  pub mod conjoined_config {
    pub mod recursive_locking_functions {
      pub mod generic {
        use std::fmt::Debug;

        pub trait Locker: Debug {
          fn lock(&self);
          fn unlock(&self);
        }
      }

      pub mod mutex_impl {
        use super::generic::Locker;

        use parking_lot::{lock_api::RawMutex, ReentrantMutex};

        use std::marker::PhantomData;

        #[derive(Debug)]
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
        use crate::handle::{Context, GetAux};
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

        use std::fmt::Debug;

        pub trait Logger: Debug {
          fn log(&self, level: LogLevel, msg: &str);
        }
      }

      pub mod log_impl {
        use super::generic::Logger;

        use crate::log_level::LogLevel;

        #[derive(Clone, Debug)]
        pub struct DefaultLogger();

        impl Logger for DefaultLogger {
          fn log(&self, level: LogLevel, msg: &str) {
            eprintln!("[{:?}] {}", level, msg);
          }
        }
      }

      pub mod c_abi_impl {
        use crate::gen::size_t as SizeType;
        use crate::handle::{Context, GetAux};
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
          let bytes: &[u8] = i2u(i_slice(message, len));
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

    use crate::error::{SignalError, SignalNativeResult};

    pub fn register_bundled_config(ctx: &mut super::Context) -> Result<(), SignalError> {
      let ctx = ctx.as_mut().get_mut_ptr();

      /* Locker */
      use crate::gen::signal_context_set_locking_functions;
      use crate::handle::global_context::conjoined_config::recursive_locking_functions::c_abi_impl::{LOCK_lock_func, LOCK_unlock_func};
      let result: Result<(), SignalError> = SignalNativeResult::call_method((), |()| unsafe {
        signal_context_set_locking_functions(ctx, Some(LOCK_lock_func), Some(LOCK_unlock_func))
      })
      .into();
      result?;

      /* Logger */
      use crate::gen::signal_context_set_log_function;
      use crate::handle::global_context::conjoined_config::log_function::c_abi_impl::LOG_log_func;
      let result: Result<(), SignalError> = SignalNativeResult::call_method((), |()| unsafe {
        signal_context_set_log_function(ctx, Some(LOG_log_func))
      })
      .into();
      result?;

      Ok(())
    }
  }

  impl Context {
    pub fn new() -> Result<Self, SignalError> {
      let locker: Arc<dyn Locker> = Arc::new(DefaultLocker::new());
      let logger: Arc<dyn Logger> = Arc::new(DefaultLogger());
      let aux = ContextAux { locker, logger };
      let mut ret: Context = Self::handled_instance((), aux)?;
      conjoined_config::register_bundled_config(&mut ret)?;
      Ok(ret)
    }
  }

  lazy_static! {
    pub static ref GLOBAL_CONTEXT: EvenMoreUnsafeCell<Context> = {
      let ctx = Context::new().expect("creating global signal Context failed!");
      ctx.into()
    };
  }

  pub trait WithContext {
    fn global() -> &'static mut Context {
      unsafe { (*GLOBAL_CONTEXT).get() }
    }
    fn get_signal_context(&mut self) -> &mut Context {
      Self::global()
    }
  }
}

pub mod data_store {
  use std::convert::{AsMut, AsRef};
  use std::ptr;

  use super::global_context::Context;
  use super::handled::{Destroyed, GetAux, Handled, Managed, ViaHandle};
  use crate::error::{SignalError, SignalNativeResult};
  use crate::gen::{
    signal_protocol_store_context, signal_protocol_store_context_create,
    signal_protocol_store_context_destroy,
  };
  use crate::handle::Handle;

  #[derive(Clone, Debug)]
  pub struct DataStore {
    handle: Handle<signal_protocol_store_context>,
  }

  pub trait WithDataStore {
    fn get_signal_data_store(&mut self) -> &mut DataStore;
  }

  impl GetAux<()> for DataStore {
    fn get_aux(&self) -> &() {
      &()
    }
  }

  impl Destroyed<signal_protocol_store_context, ()> for DataStore {
    unsafe fn destroy_raw(t: *mut signal_protocol_store_context, _aux: &()) {
      signal_protocol_store_context_destroy(t);
    }
  }

  impl Managed<signal_protocol_store_context, (), &mut Context, SignalError> for DataStore {
    unsafe fn create_raw(
      i: &mut Context,
      _aux: &(),
    ) -> Result<*mut signal_protocol_store_context, SignalError> {
      let inner: *mut *mut signal_protocol_store_context = ptr::null_mut();
      let ctx = i.as_mut().get_mut_ptr();
      let result: Result<*mut *mut signal_protocol_store_context, SignalError> =
        SignalNativeResult::call_method(inner, |inner| {
          signal_protocol_store_context_create(inner, ctx)
        })
        .into();
      Ok(*result?)
    }
  }

  impl AsRef<Handle<signal_protocol_store_context>> for DataStore {
    fn as_ref(&self) -> &Handle<signal_protocol_store_context> {
      &self.handle
    }
  }
  impl AsMut<Handle<signal_protocol_store_context>> for DataStore {
    fn as_mut(&mut self) -> &mut Handle<signal_protocol_store_context> {
      &mut self.handle
    }
  }
  impl ViaHandle<signal_protocol_store_context, ()> for DataStore {
    fn from_handle(handle: Handle<signal_protocol_store_context>, _i: ()) -> Self {
      Self { handle }
    }
  }

  impl Handled<signal_protocol_store_context, (), &mut Context, SignalError> for DataStore {}

  pub trait HasWriteableStoreContext<'a> {
    fn writeable_context(self) -> &'a mut Context;
  }

  impl Drop for DataStore {
    fn drop(&mut self) {
      self.handled_drop();
    }
  }
}

pub use generic::*;
pub use handled::*;

pub use data_store::{DataStore, WithDataStore};
pub use global_context::{Context, WithContext};

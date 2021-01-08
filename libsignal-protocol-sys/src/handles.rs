mod handled {
  use crate::handle::*;

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
  use std::sync::Arc;

  use super::handled::{Destroyed, Handled, Managed, ViaHandle};
  use crate::error::{SignalError, SignalNativeResult};
  use crate::gen::{signal_context, signal_context_create, signal_context_destroy};
  use crate::handle::Handle;

  pub(crate) struct Context {
    handle: Handle<signal_context>,
  }

  impl Destroyed<signal_context, SignalError> for Context {
    unsafe fn destroy_raw(t: *mut signal_context) -> Result<(), SignalError> {
      signal_context_destroy(t);
      Ok(())
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
    pub(crate) static ref GLOBAL_CONTEXT: Arc<Context> = unsafe {
      Arc::new(Context::handled_instance(()).expect("creating global signal Context failed!"))
    };
  }
}

pub mod data_store {
  use std::ptr;
  use std::sync::Arc;

  use super::global_context::{Context, GLOBAL_CONTEXT};
  use super::handled::{Destroyed, Handled, Managed, ViaHandle};
  use crate::error::{SignalError, SignalNativeResult};
  use crate::gen::{
    signal_protocol_store_context, signal_protocol_store_context_create,
    signal_protocol_store_context_destroy,
  };
  use crate::handle::Handle;

  pub struct DataStore {
    handle: Handle<signal_protocol_store_context>,
  }

  impl DataStore {
    pub fn new() -> Self {
      let mut ctx = GLOBAL_CONTEXT.clone();
      let context: &mut Context = unsafe { Arc::get_mut_unchecked(&mut ctx) };
      unsafe { Self::handled_instance(context).expect("creating signal DataStore context failed!") }
    }
  }

  impl Destroyed<signal_protocol_store_context, SignalError> for DataStore {
    unsafe fn destroy_raw(t: *mut signal_protocol_store_context) -> Result<(), SignalError> {
      signal_protocol_store_context_destroy(t);
      Ok(())
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

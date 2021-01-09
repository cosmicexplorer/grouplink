pub mod handled {
  use crate::handle::*;

  use std::convert::{AsMut, AsRef};

  pub trait GetAux<Aux> {
    fn get_aux(&self) -> Aux;
  }

  pub trait Destroyed<StructType, Aux> {
    unsafe fn destroy_raw(t: Pointer<StructType>, aux: Aux);
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

  pub trait Handled<StructType, Aux, I, E>:
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
      let aux = self.get_aux();
      let handle: &mut Handle<StructType> = self.as_mut();
      unsafe { Self::destroy_raw(handle.get_mut_ptr(), aux) };
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
  use crate::error::{SignalError, SignalNativeResult};
  use crate::gen::{signal_context, signal_context_create, signal_context_destroy};
  use crate::handle::Handle;

  pub(crate) struct Context {
    handle: Handle<signal_context>,
  }

  impl GetAux<()> for Context {
    fn get_aux(&self) {}
  }

  impl Destroyed<signal_context, ()> for Context {
    unsafe fn destroy_raw(t: *mut signal_context, _aux: ()) {
      signal_context_destroy(t);
    }
  }

  impl Managed<signal_context, (), (), SignalError> for Context {
    unsafe fn create_raw(_i: (), _aux: &()) -> Result<*mut signal_context, SignalError> {
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
  impl ViaHandle<signal_context, ()> for Context {
    fn from_handle(handle: Handle<signal_context>, _i: ()) -> Self {
      Self { handle }
    }
  }

  impl Handled<signal_context, (), (), SignalError> for Context {}

  impl Drop for Context {
    fn drop(&mut self) {
      self.handled_drop();
    }
  }

  lazy_static! {
    pub(crate) static ref GLOBAL_CONTEXT: Arc<Context> =
      Arc::new(Context::handled_instance((), ()).expect("creating global signal Context failed!"));
  }
}

pub mod data_store {
  use std::convert::{AsMut, AsRef};
  use std::ptr;
  use std::sync::Arc;

  use super::global_context::{Context, GLOBAL_CONTEXT};
  use super::handled::{Destroyed, GetAux, Handled, Managed, ViaHandle};
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
      Self::handled_instance(context, ()).expect("creating signal DataStore context failed!")
    }
  }

  impl GetAux<()> for DataStore {
    fn get_aux(&self) {}
  }

  impl Destroyed<signal_protocol_store_context, ()> for DataStore {
    unsafe fn destroy_raw(t: *mut signal_protocol_store_context, _aux: ()) {
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

  impl Drop for DataStore {
    fn drop(&mut self) {
      self.handled_drop();
    }
  }
}

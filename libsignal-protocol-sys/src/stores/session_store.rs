pub mod generic {
  use crate::address::Address;
  use crate::buffer::Buffer;
  use crate::list::IntList;

  pub struct LoadSessionReturnValue {
    pub record: Buffer,
    pub user_record: Buffer,
  }

  #[derive(Debug)]
  pub enum Error {
    LoadSessionFailed,
  }

  #[derive(Debug)]
  pub enum SessionFound {
    SessionExists,
    NoSuchSessionExists,
  }

  #[allow(unused_variables)]
  pub trait SessionStore {
    fn load_session(&mut self, address: Address) -> Result<LoadSessionReturnValue, Error> {
      unimplemented!("load_session()")
    }
    fn get_sub_device_sessions(&mut self, name: &[u8]) -> Result<IntList, Error> {
      unimplemented!("get_sub_device_sessions()")
    }
    fn store_session(
      &mut self,
      address: Address,
      record: &mut [u8],
      user_record: &mut [u8],
    ) -> Result<(), Error> {
      unimplemented!("store_session()")
    }
    fn contains_session(&mut self, address: Address) -> Result<SessionFound, Error> {
      unimplemented!("contains_session()")
    }
    fn delete_session(&mut self, address: Address) -> Result<(), Error> {
      unimplemented!("delete_session()")
    }
    fn delete_all_sessions(&mut self, name: &[u8]) -> Result<(), Error> {
      unimplemented!("delete_all_sessions()")
    }
    fn destroy(&mut self) {
      /* TODO: ??? */
      eprintln!("DESTRUCTION DOES NOTHING YOU FOOL!!! but this function can probably be deleted if we have nothing to clean up (???)");
    }
  }
}

pub mod store_impl {
  use super::generic::SessionStore;

  use crate::handle::{DataStore, WithDataStore};

  #[derive(Clone, Debug)]
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
  use crate::gen::{signal_buffer, signal_int_list, signal_protocol_address, size_t as SizeType};
  use crate::handle::Handle;
  use crate::internal_error::InternalError;
  use crate::stores::StoreError;
  use crate::util::{get_mut_ctx, signed_data::*, BidirectionalConstruction};

  use std::os::raw::{c_char, c_int, c_void};

  #[no_mangle]
  pub extern "C" fn SESSION_load_session_func(
    record: *mut *mut signal_buffer,
    user_record: *mut *mut signal_buffer,
    address: *const signal_protocol_address,
    user_data: *mut c_void,
  ) -> c_int {
    let session_store: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
    let address = Address::from_native(unsafe { *address });
    match session_store.load_session(address) {
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
    let session_store: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
    let name = i2u(i_slice(name, name_len));
    match session_store.get_sub_device_sessions(name) {
      Ok(mut int_list) => {
        let handle: &mut Handle<_> = int_list.as_mut();
        unsafe {
          *sessions = handle.get_mut_ptr();
        }
        SUCCESS
      }
      Err(e) => {
        let store_err: StoreError = e.into();
        let internal_err: InternalError = store_err.into();
        internal_err.into_rc()
      }
    }
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
    let session_store: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
    let address = Address::from_native(unsafe { *address });
    let record = u_slice_mut(record, record_len);
    let user_record = u_slice_mut(user_record, user_record_len);
    match session_store.store_session(address, record, user_record) {
      Ok(()) => SUCCESS,
      Err(e) => {
        let store_err: StoreError = e.into();
        let internal_err: InternalError = store_err.into();
        internal_err.into_rc()
      }
    }
  }

  #[no_mangle]
  pub extern "C" fn SESSION_contains_session_func(
    address: *const signal_protocol_address,
    user_data: *mut c_void,
  ) -> c_int {
    let session_store: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
    let address = Address::from_native(unsafe { *address });
    match session_store.contains_session(address) {
      /* Return a "C boolean", aka a 1 or 0 int. */
      Ok(found) => match found {
        SessionFound::SessionExists => 1,
        SessionFound::NoSuchSessionExists => 0,
      },
      /* Raise an error upon other errors. */
      Err(e) => {
        let store_err: StoreError = e.into();
        let internal_err: InternalError = store_err.into();
        internal_err.into_rc()
      }
    }
  }

  #[no_mangle]
  pub extern "C" fn SESSION_delete_session_func(
    address: *const signal_protocol_address,
    user_data: *mut c_void,
  ) -> c_int {
    let session_store: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
    let address = Address::from_native(unsafe { *address });
    match session_store.delete_session(address) {
      Ok(()) => SUCCESS,
      Err(e) => {
        let store_err: StoreError = e.into();
        let internal_err: InternalError = store_err.into();
        internal_err.into_rc()
      }
    }
  }

  #[no_mangle]
  pub extern "C" fn SESSION_delete_all_sessions_func(
    name: *const c_char,
    name_len: SizeType,
    user_data: *mut c_void,
  ) -> c_int {
    let session_store: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
    let name = i2u(i_slice(name, name_len));
    match session_store.delete_all_sessions(name) {
      Ok(()) => SUCCESS,
      Err(e) => {
        let store_err: StoreError = e.into();
        let internal_err: InternalError = store_err.into();
        internal_err.into_rc()
      }
    }
  }

  #[no_mangle]
  pub extern "C" fn SESSION_destroy_func(user_data: *mut c_void) {
    let session_store: &mut DefaultSessionStore = unsafe { get_mut_ctx(user_data) };
    session_store.destroy();
  }
}

pub mod via_native {
  use super::c_abi_impl::{
    SESSION_contains_session_func, SESSION_delete_all_sessions_func, SESSION_delete_session_func,
    SESSION_destroy_func, SESSION_get_sub_device_sessions_func, SESSION_load_session_func,
    SESSION_store_session_func,
  };
  use super::generic::SessionStore;
  use super::store_impl::DefaultSessionStore;

  use crate::error::{SignalError, SignalNativeResult};
  use crate::gen::{
    signal_protocol_session_store, signal_protocol_store_context_set_session_store,
  };
  use crate::handle::{DataStore, WithDataStore};
  use crate::stores::generics::{SeparateFromContextRegisterable, ContextRegisterable};

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

  impl SeparateFromContextRegisterable<signal_protocol_session_store, SignalError>
    for DefaultSessionStore
  {
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

  impl ContextRegisterable<SignalError> for DefaultSessionStore {
    fn register(self) -> Result<(), SignalError> {
      <Self as SeparateFromContextRegisterable<signal_protocol_session_store, _>>::register(self)
    }
  }
}

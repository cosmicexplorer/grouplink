pub mod generic {
  use crate::error::SignalError;

  /* TODO: IntList doesn't have any *_copy() methods like BufferList, so Clone is only defined on
   * one of the two! */
  pub trait SignalList {
    type Aux;
    type Element;

    fn push_back(&mut self, value: Self::Element) -> Result<(), SignalError>;
    /* TODO: size() and at() should be able to use &, not &mut self! */
    fn size(&mut self) -> usize;
    fn at(&mut self, index: usize) -> Result<Self::Element, SignalError>;
    fn new(aux: Self::Aux) -> Result<Self, SignalError>
    where
      Self: Sized;
  }
}

pub mod lists {
  pub mod buffer {
    use super::super::generic::SignalList;

    use crate::buffer::Buffer;
    use crate::error::{SignalError, SignalNativeResult, ValidateBufferHasMem};
    use crate::gen::{
      signal_buffer, signal_buffer_list, signal_buffer_list_alloc, signal_buffer_list_at,
      signal_buffer_list_bzero_free, signal_buffer_list_copy, signal_buffer_list_free,
      signal_buffer_list_push_back, signal_buffer_list_size, size_t as SizeType,
    };
    use crate::handle::{Destructible, GetAux, Handle, Handled, Managed, ViaHandle};
    use crate::liveness::{Sensitive, Sensitivity};

    use std::convert::TryInto;

    pub type Element = signal_buffer;
    pub type Inner = signal_buffer_list;

    pub struct BufferList {
      handle: Handle<Inner>,
      sensitivity: Sensitivity,
    }

    /* START: impl ViaHandle */
    impl AsRef<Handle<Inner>> for BufferList {
      fn as_ref(&self) -> &Handle<Inner> {
        &self.handle
      }
    }
    impl AsMut<Handle<Inner>> for BufferList {
      fn as_mut(&mut self) -> &mut Handle<Inner> {
        &mut self.handle
      }
    }
    impl ViaHandle<Inner, Sensitivity> for BufferList {
      fn from_handle(handle: Handle<Inner>, aux: Sensitivity) -> Self {
        Self {
          handle,
          sensitivity: aux,
        }
      }
    }
    /* END: impl ViaHandle */

    /* START: from_*() methods */
    unsafe fn from_other(buf: *const Inner) -> Result<*mut Inner, SignalError> {
      SignalError::validate_has_mem(signal_buffer_list_copy(buf))
    }
    /* END: from_*() methods */

    /* START: impl Handled */
    impl Sensitive for BufferList {
      fn as_sensitivity(&self) -> Sensitivity {
        self.sensitivity
      }
    }
    impl GetAux<Sensitivity> for BufferList {
      fn get_aux(&self) -> &Sensitivity {
        &self.sensitivity
      }
    }
    impl Destructible<Inner, Sensitivity> for BufferList {
      unsafe fn destroy_raw(t: *mut Inner, aux: &Sensitivity) {
        match aux {
          Sensitivity::Sensitive => signal_buffer_list_bzero_free(t),
          Sensitivity::Idk => signal_buffer_list_free(t),
        }
      }
    }
    impl Managed<Inner, Sensitivity, (), SignalError> for BufferList {
      unsafe fn create_raw(_i: (), _aux: &Sensitivity) -> Result<*mut Inner, SignalError> {
        SignalError::validate_has_mem(signal_buffer_list_alloc())
      }
    }
    impl Handled<Inner, Sensitivity, (), SignalError> for BufferList {}
    /* END: impl Handled */

    impl Drop for BufferList {
      fn drop(&mut self) {
        self.handled_drop();
      }
    }

    /* START: impl SignalList */
    impl Clone for BufferList {
      fn clone(&self) -> Self {
        let ptr = unsafe {
          from_other(self.handle.get_ptr())
            .expect("did not expect failure to clone signal buffer list")
        };
        let handle = Handle::new(ptr);
        BufferList::from_handle(handle, self.as_sensitivity())
      }
    }
    impl SignalList for BufferList {
      type Aux = Sensitivity;
      type Element = Buffer;

      fn push_back(&mut self, mut value: Buffer) -> Result<(), SignalError> {
        let result: Result<(), SignalError> = SignalNativeResult::call_method((), |()| {
          let list: &mut Handle<_> = self.as_mut();
          let value: &mut Handle<_> = value.as_mut();
          unsafe { signal_buffer_list_push_back(list.get_mut_ptr(), value.get_mut_ptr()) }
        })
        .into();
        result
      }
      fn size(&mut self) -> usize {
        let list: &mut Handle<_> = self.as_mut();
        unsafe { signal_buffer_list_size(list.get_mut_ptr()) as usize }
      }
      fn at(&mut self, index: usize) -> Result<Buffer, SignalError> {
        let list: &mut Handle<_> = self.as_mut();
        let ptr = unsafe {
          signal_buffer_list_at(list.get_mut_ptr(), (index as SizeType).try_into().unwrap())
        };
        SignalError::validate_has_mem(ptr).map(|ptr| {
          let handle = Handle::new(ptr);
          Buffer::from_handle(handle, self.as_sensitivity())
        })
      }
      fn new(aux: Sensitivity) -> Result<Self, SignalError> {
        Self::handled_instance((), aux)
      }
    }
    /* END: impl SignalList */
  }

  pub mod int {
    use super::super::generic::SignalList;

    use crate::error::{SignalError, SignalNativeResult, ValidateBufferHasMem};
    use crate::gen::{
      signal_int_list, signal_int_list_alloc, signal_int_list_at, signal_int_list_free,
      signal_int_list_push_back, signal_int_list_size, size_t as SizeType,
    };
    use crate::handle::{Destructible, GetAux, Handle, Handled, Managed, ViaHandle};

    use std::convert::TryInto;

    pub type Element = i32;
    pub type Inner = signal_int_list;

    pub struct IntList {
      handle: Handle<Inner>,
    }

    /* START: impl ViaHandle */
    impl AsRef<Handle<Inner>> for IntList {
      fn as_ref(&self) -> &Handle<Inner> {
        &self.handle
      }
    }
    impl AsMut<Handle<Inner>> for IntList {
      fn as_mut(&mut self) -> &mut Handle<Inner> {
        &mut self.handle
      }
    }
    impl ViaHandle<Inner, ()> for IntList {
      fn from_handle(handle: Handle<Inner>, _aux: ()) -> Self {
        Self { handle }
      }
    }
    /* END: impl ViaHandle */

    /* START: impl Handled */
    impl GetAux<()> for IntList {
      fn get_aux(&self) -> &() {
        &()
      }
    }
    impl Destructible<Inner, ()> for IntList {
      unsafe fn destroy_raw(t: *mut Inner, _aux: &()) {
        signal_int_list_free(t);
      }
    }
    impl Managed<Inner, (), (), SignalError> for IntList {
      unsafe fn create_raw(_i: (), _aux: &()) -> Result<*mut Inner, SignalError> {
        SignalError::validate_has_mem(signal_int_list_alloc())
      }
    }
    impl Handled<Inner, (), (), SignalError> for IntList {}
    /* END: impl Handled */

    impl Drop for IntList {
      fn drop(&mut self) {
        self.handled_drop();
      }
    }

    /* START: impl SignalList */
    /* NB: weirdly, there's no *_copy() method for int lists. */
    impl SignalList for IntList {
      type Aux = ();
      type Element = i32;

      fn push_back(&mut self, value: i32) -> Result<(), SignalError> {
        let result: Result<(), SignalError> = SignalNativeResult::call_method((), |()| {
          let list: &mut Handle<_> = self.as_mut();
          unsafe { signal_int_list_push_back(list.get_mut_ptr(), value) }
        })
        .into();
        result
      }
      fn size(&mut self) -> usize {
        let list: &mut Handle<_> = self.as_mut();
        unsafe { signal_int_list_size(list.get_mut_ptr()) as usize }
      }
      fn at(&mut self, index: usize) -> Result<i32, SignalError> {
        let list: &mut Handle<_> = self.as_mut();
        Ok(unsafe {
          signal_int_list_at(list.get_mut_ptr(), (index as SizeType).try_into().unwrap())
        })
      }
      fn new(aux: ()) -> Result<Self, SignalError> {
        Self::handled_instance((), aux)
      }
    }
    /* END: impl SignalList */
  }
}

pub use generic::*;
pub use lists::{buffer::*, int::*};

mod protocol {
  use crate::handles::handled::Handled;

  use std::convert::{AsMut, AsRef, From};
  use std::default::Default;
  use std::sync::Arc;

  #[derive(Default, Debug, Clone)]
  pub struct BufferAllocate {
    pub size: usize,
    pub sensitivity: Sensitivity,
  }

  #[derive(Debug, Clone)]
  pub struct BufferSource {
    pub data: Arc<Vec<u8>>,
  }

  impl BufferSource {
    pub fn from_data<V: AsRef<[u8]>>(data: V) -> Self {
      Self {
        data: Arc::new(data.as_ref().to_vec()),
      }
    }
    /* TODO: try to match raw pointer values to allocated Handle. Possibly also match raw
     * pointers by a hash of their contents (see upc/). */
    pub fn from_arc(other: Arc<Vec<u8>>) -> Self {
      Self {
        data: Arc::clone(&other),
      }
    }
  }

  impl AsRef<[u8]> for BufferSource {
    fn as_ref(&self) -> &[u8] {
      self.data.as_ref()
    }
  }

  impl Default for BufferSource {
    fn default() -> Self {
      Self::from_data(&[])
    }
  }

  #[derive(Default, Debug, Clone)]
  pub struct BufferCopy {
    pub source: BufferSource,
    pub sensitivity: Sensitivity,
  }

  pub trait BufferAllocateable: Clone + From<BufferAllocate> + From<BufferCopy> + Default {}

  pub trait BufferReferrable: AsRef<[u8]> + AsMut<[u8]> {
    fn len(&self) -> usize;
  }

  pub trait BufferOps: BufferAllocateable + BufferReferrable {}

  #[derive(Clone, Debug, Copy)]
  pub enum Sensitivity {
    Sensitive,
    Idk,
  }

  impl Default for Sensitivity {
    fn default() -> Self {
      /* FIXME: default to bzeroing buffers? */
      Self::Sensitive
    }
  }

  pub trait Sensitive {
    fn as_sensitivity(&self) -> Sensitivity;
  }

  pub trait BufferWrapper<StructType, Aux, I, E>:
    Handled<StructType, Aux, I, E> + BufferOps + Sensitive
  {
  }
}

mod signal_native_impl {
  use std::convert::{AsMut, AsRef, From};
  use std::default::Default;
  use std::slice;

  use super::protocol::*;

  use crate::error::SignalError;
  use crate::gen::{
    signal_buffer, signal_buffer_alloc, signal_buffer_bzero_free, signal_buffer_const_data,
    signal_buffer_copy, signal_buffer_create, signal_buffer_data, signal_buffer_free,
    signal_buffer_len, size_t,
  };
  use crate::handle::Handle;
  use crate::handles::handled::{Destroyed, GetAux, Handled, Managed, ViaHandle};

  pub type Inner = signal_buffer;

  type SizeType = size_t;

  fn receive_buffer_mut(buf: *mut Inner) -> Result<*mut Inner, SignalError> {
    if buf.is_null() {
      Err(SignalError::NoMemory)
    } else {
      Ok(buf)
    }
  }

  unsafe fn from_other(buf: *const Inner) -> Result<*mut Inner, SignalError> {
    receive_buffer_mut(signal_buffer_copy(buf))
  }

  unsafe fn from_bytes(data: &[u8]) -> Result<*mut Inner, SignalError> {
    receive_buffer_mut(signal_buffer_create(data.as_ptr(), data.len() as SizeType))
  }

  pub struct Buffer {
    handle: Handle<Inner>,
    sensitivity: Sensitivity,
  }

  /* START: impl ViaHandle */
  impl AsRef<Handle<Inner>> for Buffer {
    fn as_ref(&self) -> &Handle<Inner> {
      &self.handle
    }
  }
  impl AsMut<Handle<Inner>> for Buffer {
    fn as_mut(&mut self) -> &mut Handle<Inner> {
      &mut self.handle
    }
  }
  impl ViaHandle<Inner, Sensitivity> for Buffer {
    fn from_handle(handle: Handle<Inner>, aux: Sensitivity) -> Self {
      Self {
        handle,
        sensitivity: aux,
      }
    }
  }
  /* END: impl ViaHandle */

  /* START: impl BufferWrapper */
  impl Sensitive for Buffer {
    fn as_sensitivity(&self) -> Sensitivity {
      self.sensitivity
    }
  }
  impl GetAux<Sensitivity> for Buffer {
    fn get_aux(&self) -> Sensitivity {
      self.as_sensitivity()
    }
  }
  impl Destroyed<Inner, Sensitivity> for Buffer {
    unsafe fn destroy_raw(t: *mut Inner, aux: Sensitivity) {
      match aux {
        Sensitivity::Sensitive => signal_buffer_bzero_free(t),
        Sensitivity::Idk => signal_buffer_free(t),
      }
    }
  }
  impl Managed<Inner, Sensitivity, BufferSource, SignalError> for Buffer {
    unsafe fn create_raw(i: BufferSource, _aux: &Sensitivity) -> Result<*mut Inner, SignalError> {
      from_bytes(i.as_ref())
    }
  }
  impl Handled<Inner, Sensitivity, BufferSource, SignalError> for Buffer {}
  /* END: impl BufferWrapper */

  impl Drop for Buffer {
    fn drop(&mut self) {
      self.handled_drop();
    }
  }

  /* START: impl BufferAllocateable */
  impl Clone for Buffer {
    fn clone(&self) -> Self {
      let ptr = unsafe {
        from_other(self.handle.get_ptr()).expect("did not expect failure to clone signal buffer")
      };
      let handle = Handle::new(ptr);
      Buffer::from_handle(handle, self.as_sensitivity())
    }
  }
  impl From<BufferCopy> for Buffer {
    fn from(other: BufferCopy) -> Self {
      let BufferCopy {
        source,
        sensitivity,
      } = other;
      let ptr = unsafe {
        from_bytes(source.as_ref())
          .expect("did not expect failure to create signal buffer from data")
      };
      let handle = Handle::new(ptr);
      Buffer::from_handle(handle, sensitivity)
    }
  }
  impl From<BufferAllocate> for Buffer {
    fn from(other: BufferAllocate) -> Self {
      let BufferAllocate { size, sensitivity } = other;
      let ptr = unsafe {
        from_other(signal_buffer_alloc(size as SizeType))
          .expect("did not expect failure to allocate blank signal buffer")
      };
      let handle = Handle::new(ptr);
      Buffer::from_handle(handle, sensitivity)
    }
  }
  impl Default for Buffer {
    fn default() -> Self {
      Self::from(BufferAllocate::default())
    }
  }
  impl BufferAllocateable for Buffer {}
  /* END: impl BufferAllocateable */

  /* START: impl BufferReferrable */
  impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
      let ptr: *const u8 = unsafe { signal_buffer_const_data(self.handle.get_ptr()) };
      let len = self.len();
      unsafe { slice::from_raw_parts(ptr, len) }
    }
  }
  impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
      let ptr: *mut u8 = unsafe { signal_buffer_data(self.handle.get_mut_ptr()) };
      let len = self.len();
      unsafe { slice::from_raw_parts_mut(ptr, len) }
    }
  }
  impl BufferReferrable for Buffer {
    fn len(&self) -> usize {
      unsafe { signal_buffer_len(self.handle.get_ptr()) as usize }
    }
  }
  /* END: impl BufferReferrable */

  /* TODO: rustc doesn't like it when the `X` in `for X` is itself a generic bound. */
  impl BufferOps for Buffer {}

  impl BufferWrapper<Inner, Sensitivity, BufferSource, SignalError> for Buffer {}
}

/* exposed interface */
pub use protocol::*;
pub use signal_native_impl::{Buffer, Inner};

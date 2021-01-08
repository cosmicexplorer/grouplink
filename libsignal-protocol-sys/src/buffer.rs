mod protocol {
  use std::convert::{AsMut, AsRef, From};

  pub struct BufferRequest {
    pub size: usize,
  }

  pub trait BufferRequestable<'a>: Clone + From<&'a [u8]> + From<BufferRequest> {}

  pub trait BufferReferrable: AsRef<[u8]> + AsMut<[u8]> {
    fn len(&self) -> usize;
  }

  pub trait BufferOps<'a>: BufferRequestable<'a> + BufferReferrable {}
}

mod signal_native {
  use std::convert::{AsMut, AsRef, From};
  use std::slice;

  use super::protocol::*;

  use crate::gen::{
    signal_buffer, signal_buffer_alloc, signal_buffer_bzero_free, signal_buffer_const_data,
    signal_buffer_copy, signal_buffer_create, signal_buffer_data, signal_buffer_free,
    signal_buffer_len, size_t,
  };

  use crate::error::SignalError;
  use crate::handle::Handle;

  type SizeType = size_t;

  pub trait BufferWrapper<Buf> {
    unsafe fn from_ptr(buf: *mut Buf) -> Self;
    fn receive_buffer(buf: *mut Buf) -> Result<*mut Buf, SignalError> {
      if buf.is_null() {
        Err(SignalError::NoMemory)
      } else {
        Ok(buf)
      }
    }
    fn inner_handle(&self) -> *const Buf;
    fn inner_handle_mut(&mut self) -> *mut Buf;
    fn buffer_free(&mut self);
    fn buffer_bzero_free(&mut self);
  }

  pub struct Buffer {
    handle: Handle<signal_buffer>,
  }

  impl BufferWrapper<signal_buffer> for Buffer {
    unsafe fn from_ptr(buf: *mut signal_buffer) -> Self {
      Self {
        handle: Handle::new(buf),
      }
    }
    fn inner_handle(&self) -> *const signal_buffer {
      unsafe { self.handle.get_ptr() }
    }
    fn inner_handle_mut(&mut self) -> *mut signal_buffer {
      unsafe { self.handle.get_mut_ptr() }
    }
    fn buffer_free(&mut self) {
      unsafe { signal_buffer_free(self.inner_handle_mut()) }
    }
    fn buffer_bzero_free(&mut self) {
      unsafe { signal_buffer_bzero_free(self.inner_handle_mut()) }
    }
  }

  /* impl<'a> BufferRequestable<'a> */
  impl Clone for Buffer {
    fn clone(&self) -> Self {
      let ptr = Self::receive_buffer(unsafe { signal_buffer_copy(self.inner_handle()) })
        .expect("did not expect failure to clone signal buffer");
      unsafe { Buffer::from_ptr(ptr) }
    }
  }

  impl<'a> From<&'a [u8]> for Buffer {
    fn from(other: &'a [u8]) -> Self {
      let ptr = Self::receive_buffer(unsafe {
        signal_buffer_create(other.as_ptr(), other.len() as SizeType)
      })
      .expect("did not expect failure to create signal buffer from data");
      unsafe { Buffer::from_ptr(ptr) }
    }
  }

  impl From<BufferRequest> for Buffer {
    fn from(other: BufferRequest) -> Self {
      let ptr = Self::receive_buffer(unsafe { signal_buffer_alloc(other.size as SizeType) })
        .expect("did not expect failure to allocate blank signal buffer");
      unsafe { Buffer::from_ptr(ptr) }
    }
  }

  impl<'a> BufferRequestable<'a> for Buffer {}

  /* impl BufferReferrable */
  impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
      let ptr: *const u8 = unsafe { signal_buffer_const_data(self.inner_handle()) };
      let len = self.len();
      unsafe { slice::from_raw_parts(ptr, len) }
    }
  }

  impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
      let ptr: *mut u8 = unsafe { signal_buffer_data(self.inner_handle_mut()) };
      let len = self.len();
      unsafe { slice::from_raw_parts_mut(ptr, len) }
    }
  }

  impl BufferReferrable for Buffer {
    fn len(&self) -> usize {
      unsafe { signal_buffer_len(self.inner_handle()) as usize }
    }
  }

  /* TODO: rustc doesn't like it when the `X` in `for X` is itself a generic bound. */
  impl<'a> BufferOps<'a> for Buffer {}
}

mod sensitivity {
  use std::convert::{AsMut, AsRef};
  use std::marker::PhantomData;

  use super::protocol::*;
  use super::signal_native::BufferWrapper;

  pub enum Buffer<'a, Inner, Buf: BufferWrapper<Inner> + BufferOps<'a>> {
    Sensitive(Buf, PhantomData<&'a Buf>, PhantomData<Inner>),
    Idk(Buf),
  }

  impl<'a, Inner, Buf: BufferWrapper<Inner> + BufferOps<'a>> Buffer<'a, Inner, Buf> {
    pub fn sensitive(buf: Buf) -> Self {
      Self::Sensitive(buf, PhantomData, PhantomData)
    }
    pub fn idk(buf: Buf) -> Self {
      Self::Idk(buf)
    }
  }

  /* TODO: make this "composition" boilerplate into a macro! */
  impl<'a, Inner, Buf: BufferWrapper<Inner> + BufferOps<'a>> AsRef<Buf> for Buffer<'a, Inner, Buf> {
    fn as_ref(&self) -> &Buf {
      match self {
        Self::Sensitive(ref x, _, _) => x,
        Self::Idk(ref x) => x,
      }
    }
  }

  impl<'a, Inner, Buf: BufferWrapper<Inner> + BufferOps<'a>> AsMut<Buf> for Buffer<'a, Inner, Buf> {
    fn as_mut(&mut self) -> &mut Buf {
      match self {
        Self::Sensitive(ref mut x, _, _) => x,
        Self::Idk(ref mut x) => x,
      }
    }
  }

  impl<'a, Inner, Buf: BufferWrapper<Inner> + BufferOps<'a>> Drop for Buffer<'a, Inner, Buf> {
    fn drop(&mut self) {
      match self {
        Self::Sensitive(ref mut x, _, _) => x.buffer_bzero_free(),
        Self::Idk(ref mut x) => x.buffer_free(),
      }
    }
  }
}

/* exposed interface */
pub use protocol::BufferRequest;
pub use signal_native::Buffer as InnerBuffer;

pub type BufferFactory<'a> = sensitivity::Buffer<'a, super::gen::signal_buffer, InnerBuffer>;
pub type Buffer = BufferFactory<'static>;

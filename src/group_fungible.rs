use libsignal_protocol_sys::buffer::{Buffer, BufferCopy, BufferSource, Sensitivity};

use std::convert::From;

pub struct GroupFungible {
  pub buf: Buffer,
}

impl GroupFungible {
  pub fn new() -> Self {
    Self {
      /* buf: Buffer::idk(InnerBuffer::from(BufferAllocate { size: 0 })), */
      /* buf: Buffer::idk(InnerBuffer::from("xxxxx".as_ref())), */
      buf: Buffer::from(BufferCopy {
        source: BufferSource::from_data("xxx123".as_ref() as &[u8]),
        sensitivity: Sensitivity::Idk,
      }),
    }
  }
}

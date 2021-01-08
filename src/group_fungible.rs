use libsignal_protocol_sys::buffer::{Buffer, InnerBuffer};

pub struct GroupFungible {
  pub buf: Buffer,
}

impl GroupFungible {
  pub fn new() -> Self {
    Self {
      /* buf: Buffer::idk(InnerBuffer::from(BufferRequest { size: 0 })), */
      buf: Buffer::idk(InnerBuffer::from("xxxxx".as_ref())),
    }
  }
}

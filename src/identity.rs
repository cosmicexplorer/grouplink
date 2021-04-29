/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

/* use libsignal_protocol; */

#[allow(dead_code)]
pub struct DurableSafeIdentity {
  id_key_pair: (),
}

pub trait GroupFungible {}

/* pub struct GroupFungible { */
/*   pub buf: Buffer, */
/* } */

/* impl GroupFungible { */
/*   pub fn new() -> Self { */
/*     Self { */
/*       /\* buf: Buffer::idk(InnerBuffer::from(BufferAllocate { size: 0 })), *\/ */
/*       /\* buf: Buffer::idk(InnerBuffer::from("xxxxx".as_ref())), *\/ */
/*       buf: Buffer::from(BufferCopy { */
/*         source: BufferSource::from_data("xxx123".as_ref() as &[u8]), */
/*         sensitivity: Sensitivity::Idk, */
/*       }), */
/*     } */
/*   } */
/* } */

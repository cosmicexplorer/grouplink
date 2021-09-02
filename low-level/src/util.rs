/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

use prost::{self, Message};

pub fn no_encoding_error(r: Result<(), prost::EncodeError>) {
  r.expect("expect encoding into a vec to never fail")
}

pub fn encode_proto_message<M: Message>(m: M) -> Box<[u8]> {
  let mut serialized = Vec::<u8>::with_capacity(m.encoded_len());
  no_encoding_error(m.encode(&mut &mut serialized));
  serialized.into_boxed_slice()
}

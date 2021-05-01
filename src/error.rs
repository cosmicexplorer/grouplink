/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???

use libsignal_protocol::SignalProtocolError;
use prost;

/// ???
#[derive(Debug)]
pub enum Error {
  ProtobufEncodingError(String),
  ProtobufDecodingError(String),
  Signal(SignalProtocolError),
}

impl From<prost::EncodeError> for Error {
  fn from(err: prost::EncodeError) -> Error {
    Error::ProtobufEncodingError(format!("{:?}", err))
  }
}

impl From<prost::DecodeError> for Error {
  fn from(err: prost::DecodeError) -> Error {
    Error::ProtobufDecodingError(format!("{:?}", err))
  }
}

impl From<SignalProtocolError> for Error {
  fn from(err: SignalProtocolError) -> Error {
    Error::Signal(err)
  }
}

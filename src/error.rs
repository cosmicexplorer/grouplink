/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???

use libsignal_protocol::SignalProtocolError;
use prost;

use std::error;
use std::fmt;

#[derive(Debug)]
pub enum ProtobufCodingFailure {
  OptionalFieldAbsent(String),
  FieldCompositionWasIncorrect(String),
  Encode(prost::EncodeError),
  Decode(prost::DecodeError),
}

impl fmt::Display for ProtobufCodingFailure {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    /* TODO: what to put here? this impl is needed for [error::Error]. */
    write!(f, "{:?}", self)
  }
}

impl error::Error for ProtobufCodingFailure {
  fn source(&self) -> Option<&(dyn error::Error + 'static)> {
    match self {
      Self::OptionalFieldAbsent(_) => None,
      Self::FieldCompositionWasIncorrect(_) => None,
      Self::Encode(e) => Some(e),
      Self::Decode(e) => Some(e),
    }
  }
}

/// ???
#[derive(Debug)]
pub enum Error {
  ProtobufEncodingError(ProtobufCodingFailure),
  ProtobufDecodingError(ProtobufCodingFailure),
  Signal(SignalProtocolError),
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    /* TODO: what to put here? this impl is needed for [error::Error]. */
    write!(f, "{:?}", self)
  }
}

impl error::Error for Error {
  fn source(&self) -> Option<&(dyn error::Error + 'static)> {
    match self {
      Self::ProtobufEncodingError(e) | Self::ProtobufDecodingError(e) => Some(e),
      Self::Signal(e) => Some(e),
    }
  }
}

impl From<prost::EncodeError> for Error {
  fn from(err: prost::EncodeError) -> Error {
    Error::ProtobufEncodingError(ProtobufCodingFailure::Encode(err))
  }
}

impl From<prost::DecodeError> for Error {
  fn from(err: prost::DecodeError) -> Error {
    Error::ProtobufDecodingError(ProtobufCodingFailure::Decode(err))
  }
}

impl From<SignalProtocolError> for Error {
  fn from(err: SignalProtocolError) -> Error {
    Error::Signal(err)
  }
}

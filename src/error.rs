/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???

use crate::store::StoreError;

use displaydoc::Display;
use libsignal_protocol::SignalProtocolError;
use prost;
use thiserror::Error;

use std::convert::Infallible;
use std::io;

/// ???
#[derive(Debug, Display, Error)]
pub enum ProtobufCodingFailure {
  /// an optional field '{0}' was absent when en/decoding protobuf {1}
  OptionalFieldAbsent(String, String),
  /// an invalid state {0} was detected when en/decoding protobuf {1}
  FieldCompositionWasIncorrect(String, String),
  /// an error {0} occurred when en/decoding a protobuf map for the type {1}
  MapStringCodingFailed(String, String),
  /// an io error {0} was raised internally
  Io(#[from] io::Error),
  /// a prost encoding error {0} was raised internally
  Encode(#[from] prost::EncodeError),
  /// a prost decoding error {0} was raised internally
  Decode(#[from] prost::DecodeError),
}

/// ???
#[derive(Debug, Display, Error)]
pub enum Error {
  /// an error {0} occurred when encoding a protobuf
  ProtobufEncodingError(#[source] ProtobufCodingFailure),
  /// an error {0} occurred when decoding a protobuf
  ProtobufDecodingError(#[source] ProtobufCodingFailure),
  /// an error {0} was raised internally
  Store(#[from] StoreError),
  /// an error {0} was raised internally
  Signal(#[from] SignalProtocolError),
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

impl From<Infallible> for Error {
  fn from(_err: Infallible) -> Error {
    unreachable!()
  }
}

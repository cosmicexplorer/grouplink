/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! Contains [enum@Error].

use crate::identity::IdentityError;
use crate::message::MessageError;
use crate::store::StoreError;

use displaydoc::Display;
use libsignal_protocol::SignalProtocolError;
use prost;
use thiserror::Error;

use std::convert::Infallible;
use std::io;

/// Error type for specifics on failures to serialize or deserialize a protobuf-backed object.
///
/// This crate takes a different approach than [libsignal_protocol] to serializable structs, since
/// we expect more than just the Signal app client and backend server to be consuming these
/// serializations--in fact, they are intended to serve as a standard, future-proof file format.
///
/// To that end, we require every protobuf field to be marked `optional`, and encode map keys as
/// bytes for polymorphism within the limited representative power of the protobuf version
/// 2 schema. We also then shift the complexity of protobuf validation into this error type, where
/// we can standardize the types of encoding failures and how clients should respond to them as the
/// underlying data model changes.
///
/// **TODO: Switch to Apache Thrift!** See thrift-generated rust code at
/// <https://github.com/cosmicexplorer/learning-progress-bar/blob/1ada17c77cf14a948430161f5c648ae3375aa4ba/terminal/thrift/streaming_interface.rs>
/// for example.
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

/// Parent error type for this crate.
#[derive(Debug, Display, Error)]
pub enum Error {
  /// an error {0} occurred when encoding a protobuf
  ProtobufEncodingError(#[source] ProtobufCodingFailure),
  /// an error {0} occurred when decoding a protobuf
  ProtobufDecodingError(#[source] ProtobufCodingFailure),
  /// an identity error {0} was raised internally
  Identity(#[from] IdentityError),
  /// a message error {0} was raised internally
  Message(#[from] MessageError),
  /// a store error {0} was raised internally
  Store(#[from] StoreError),
  /// a signal protocol error {0} was raised internally
  Signal(#[from] SignalProtocolError),
}

impl From<prost::EncodeError> for Error {
  fn from(err: prost::EncodeError) -> Error {
    Error::ProtobufEncodingError(ProtobufCodingFailure::from(err))
  }
}

impl From<prost::DecodeError> for Error {
  fn from(err: prost::DecodeError) -> Error {
    Error::ProtobufDecodingError(ProtobufCodingFailure::from(err))
  }
}

impl From<Infallible> for Error {
  fn from(_err: Infallible) -> Error {
    unreachable!()
  }
}

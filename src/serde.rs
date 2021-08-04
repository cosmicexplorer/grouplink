/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! Serialization and deserialization (ser/de) mechanisms for this crate's objects.

use displaydoc::Display;
use prost;

use std::marker::PhantomData;

/// Plaintext (UTF-8) ser/de formats.
#[derive(Debug, Display)]
pub enum TextFormat {
  /// ASCII armor
  AsciiArmor,
}

/// Binary ser/de formats.
#[derive(Debug, Display)]
pub enum BinaryFormat<Proto: prost::Message> {
  /// according to a protobuf
  Protobuf(PhantomData<Proto>),
}

/// All ser/de formats.
#[derive(Debug, Display)]
pub enum SerdeFormat<Proto: prost::Message> {
  /// text format: {0}
  Text(TextFormat),
  /// binary format: {0}
  Binary(BinaryFormat<Proto>),
}

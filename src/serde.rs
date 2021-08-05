/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! Serialization and deserialization (ser/de) mechanisms for this crate's objects.

use crate::error::Error;
use crate::util::encode_proto_message;

use displaydoc::Display;
use prost;

use std::{
  convert::{AsRef, Infallible, TryFrom, TryInto},
  default::Default,
  /* iter::IntoIterator, */
  marker::PhantomData,
  str,
};

/// An implementor of this trait provides a *schema* for [Self::Source].
///
/// **TODO: what is a schema?**
pub trait Schema {
  type Source;
}

pub trait SerializationFormat {
  type Read: ?Sized;
  type Written: Sized;
}

#[derive(Debug, Copy, Clone)]
pub struct AsciiArmorFormat;

impl SerializationFormat for AsciiArmorFormat {
  type Read = str;
  type Written = String;
}

#[derive(Debug, Copy, Clone)]
pub struct ProtobufFormat;

impl SerializationFormat for ProtobufFormat {
  type Read = [u8];
  type Written = Box<[u8]>;
}

pub trait SerdeViaBase {
  type Fmt: SerializationFormat;
  type Medium: Schema;
}

pub trait Serializer: SerdeViaBase {
  fn serialize(self) -> <Self::Fmt as SerializationFormat>::Written;
}

pub trait Deserializer: SerdeViaBase {
  fn deserialize(
    data: &<Self::Fmt as SerializationFormat>::Read,
  ) -> Result<<Self::Medium as Schema>::Source, Error>
  where
    Self: Sized;
}

pub trait SerdeVia: Serializer + Deserializer {}

#[derive(Debug, Copy, Clone)]
pub struct AsciiArmor<T, Proto>(pub T, PhantomData<Proto>);

impl<T, Proto> From<T> for AsciiArmor<T, Proto> {
  fn from(value: T) -> Self {
    Self(value, PhantomData)
  }
}

#[derive(Debug, Copy, Clone)]
pub struct Protobuf<Source, Proto>(pub Source, PhantomData<Proto>);

impl<Source, Proto> Protobuf<Source, Proto> {
  pub fn new(source: Source) -> Self {
    Self(source, PhantomData)
  }
}

pub trait FromConverter<T> {
  fn converted_from(value: T) -> Self;
}

pub trait TryIntoConverter<T> {
  type ErrorType;
  fn try_convert_into(self) -> Result<T, Self::ErrorType>
  where
    Self: Sized;
}

impl<Proto> SerdeViaBase for Protobuf<Proto::Source, Proto>
where
  Proto: Schema,
{
  type Fmt = ProtobufFormat;
  type Medium = Proto;
}

impl<Proto> Serializer for Protobuf<Proto::Source, Proto>
where
  Proto: Schema + prost::Message + From<Proto::Source>,
{
  fn serialize(self) -> Box<[u8]> {
    let proto_message: Proto = self.0.into();
    encode_proto_message(proto_message)
  }
}

impl<Proto> Deserializer for Protobuf<Proto::Source, Proto>
where
  Proto: Schema + prost::Message + TryInto<Proto::Source, Error = Error> + Default,
{
  fn deserialize(data: &[u8]) -> Result<Proto::Source, Error>
  where
    Self: Sized,
  {
    let proto_message = Proto::decode(data)?;
    proto_message.try_into()
  }
}

impl<Proto> SerdeVia for Protobuf<Proto::Source, Proto> where
  Proto:
    Schema + prost::Message + From<Proto::Source> + TryInto<Proto::Source, Error = Error> + Default
{
}

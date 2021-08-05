/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! Serialization and deserialization (ser/de) mechanisms for this crate's objects.

pub use traits::*;
pub mod traits {
  use crate::error::Error;

  pub trait Schema {
    type Source;
  }

  pub trait SerializationFormat {
    type Read: ?Sized;
    type Written: Sized;
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
    ) -> Result<<Self::Medium as Schema>::Source, Error>;
  }

  pub trait SerdeVia: Serializer + Deserializer {}
}

pub mod fingerprinting {
  use super::traits::Schema;

  use hex;

  use std::{convert::AsRef, marker::PhantomData};

  #[derive(Debug, Clone)]
  pub struct FingerprintableBytes<Source>(Box<[u8]>, PhantomData<Source>);

  #[derive(Debug, Clone)]
  pub struct HexFingerprint<Source>(String, PhantomData<Source>);

  impl<Source> From<String> for HexFingerprint<Source> {
    fn from(value: String) -> Self {
      Self(value, PhantomData)
    }
  }
  impl<Source> From<HexFingerprint<Source>> for String {
    fn from(value: HexFingerprint<Source>) -> Self {
      value.0
    }
  }
  impl<Source> AsRef<str> for HexFingerprint<Source> {
    fn as_ref(&self) -> &str {
      self.0.as_ref()
    }
  }

  impl<Source> FingerprintableBytes<Source> {
    pub fn new(bytes: Box<[u8]>) -> Self {
      Self(bytes, PhantomData)
    }
    pub fn from_hex_string(hex_string: &str) -> Result<Self, hex::FromHexError> {
      let decoded: Vec<u8> = hex::decode(hex_string)?;
      Ok(Self::new(decoded.into_boxed_slice()))
    }
    pub fn into_hex_string(self) -> HexFingerprint<Source> {
      HexFingerprint::from(hex::encode(&self.0))
    }
  }

  impl<Source> Schema for FingerprintableBytes<Source> {
    type Source = Source;
  }

  pub trait Fingerprintable: Into<FingerprintableBytes<Self>> {}
}

pub use formats::protobuf::Protobuf;
pub mod formats {
  use super::traits::*;

  use std::marker::PhantomData;

  pub mod key_fingerprint {
    use super::{super::fingerprinting::*, *};

    #[derive(Debug, Copy, Clone)]
    pub struct KeyFingerprintFormat<Source>(PhantomData<Source>);

    impl<Source> SerializationFormat for KeyFingerprintFormat<Source> {
      type Read = str;
      type Written = HexFingerprint<Source>;
    }

    #[derive(Debug, Copy, Clone)]
    pub struct KeyFingerprint<Source>(Source);

    impl<Source> KeyFingerprint<Source> {
      pub fn new(source: Source) -> Self {
        Self(source)
      }
    }

    impl<Source> SerdeViaBase for KeyFingerprint<Source>
    where
      Source: Fingerprintable,
    {
      type Fmt = KeyFingerprintFormat<Source>;
      type Medium = FingerprintableBytes<Source>;
    }

    impl<Source> Serializer for KeyFingerprint<Source>
    where
      Source: Fingerprintable,
    {
      fn serialize(self) -> HexFingerprint<Source> {
        let proto_message: FingerprintableBytes<_> = self.0.into();
        proto_message.into_hex_string()
      }
    }
  }

  pub mod protobuf {
    use super::*;
    use crate::error::Error;
    use crate::util::encode_proto_message;

    use std::{convert::TryInto, default::Default};

    #[derive(Debug, Copy, Clone)]
    pub struct ProtobufFormat;

    impl SerializationFormat for ProtobufFormat {
      type Read = [u8];
      type Written = Box<[u8]>;
    }

    #[derive(Debug, Copy, Clone)]
    pub struct Protobuf<Source, Proto>(pub Source, PhantomData<Proto>);

    impl<Source, Proto> Protobuf<Source, Proto> {
      pub fn new(source: Source) -> Self {
        Self(source, PhantomData)
      }
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
      fn deserialize(data: &[u8]) -> Result<Proto::Source, Error> {
        let proto_message = Proto::decode(data)?;
        proto_message.try_into()
      }
    }

    impl<Proto> SerdeVia for Protobuf<Proto::Source, Proto> where
      Proto: Schema
        + prost::Message
        + From<Proto::Source>
        + TryInto<Proto::Source, Error = Error>
        + Default
    {
    }
  }
}

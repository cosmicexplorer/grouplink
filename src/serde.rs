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
    ) -> Result<<Self::Medium as Schema>::Source, Error>
    where
      Self: Sized;
  }

  pub trait SerdeVia: Serializer + Deserializer {}
}

pub use formats::protobuf::Protobuf;
pub mod formats {
  use super::traits::*;

  use std::marker::PhantomData;

  pub mod key_fingerprint {
    use super::*;

    #[derive(Debug, Copy, Clone)]
    pub struct KeyFingerprintFormat;

    impl SerializationFormat for KeyFingerprintFormat {
      type Read = str;
      type Written = String;
    }

    #[derive(Debug, Copy, Clone)]
    pub struct KeyFingerprint<Source, Proto>(pub Source, PhantomData<Proto>);

    impl<Source, Proto> KeyFingerprint<Source, Proto> {
      pub fn new(source: Source) -> Self {
        Self(source, PhantomData)
      }
    }

    impl<Proto> SerdeViaBase for KeyFingerprint<Proto::Source, Proto>
    where
      Proto: Schema,
    {
      type Fmt = KeyFingerprintFormat;
      type Medium = Proto;
    }

    /* impl<Proto> Serializer for KeyFingerprint<Proto::Source, Proto> */
    /* where */
    /*   Proto: Schema, */
    /* { */
    /*   fn serialize(self) -> String { */
    /*     let proto_message: Proto = self.0.into(); */
    /*   } */
    /* } */
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
      fn deserialize(data: &[u8]) -> Result<Proto::Source, Error>
      where
        Self: Sized,
      {
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

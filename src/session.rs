/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

//! ???

pub mod proto {
  /* Ensure the generated identity.proto outputs are available under [super::identity] within the
   * sub-module also named "proto". */
  pub use crate::identity::proto as identity;
  mod proto {
    include!(concat!(env!("OUT_DIR"), "/grouplink.proto.session.rs"));
  }
  pub use proto::*;
}

use crate::error::{Error, ProtobufCodingFailure};
use crate::identity::{
  CryptographicIdentity, ExternalIdentity, SealedSenderIdentity, SenderCert, Spontaneous,
};
use crate::store::Persistent;
use crate::util::encode_proto_message;

use libsignal_protocol as signal;
use prost::Message;
use rand::{self, CryptoRng, Rng};

use std::convert::{TryFrom, TryInto};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy)]
pub struct SignedPreKeyRequest {
  pub id: signal::SignedPreKeyId,
  pub pair: signal::IdentityKeyPair,
}

impl Spontaneous<()> for SignedPreKeyRequest {
  fn generate<R: CryptoRng + Rng>(_params: (), r: &mut R) -> Self {
    let pair = signal::IdentityKeyPair::generate(r);
    let id: signal::SignedPreKeyId = Box::new(r).gen::<u32>().into();
    Self { id, pair }
  }
}

#[derive(Debug, Clone)]
pub struct SignedPreKey {
  pub id: signal::SignedPreKeyId,
  pub pair: signal::IdentityKeyPair,
  pub signature: Box<[u8]>,
}

fn get_timestamp() -> u64 {
  SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .expect("timestamp calculation will never fail")
    .as_secs()
}

impl SignedPreKey {
  pub async fn intern<
    Record,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    SPK: signal::SignedPreKeyStore + Persistent<Record>,
    R: CryptoRng + Rng,
  >(
    params: SignedPreKeyRequest,
    id_store: &mut ID,
    signed_prekey_store: &mut SPK,
    csprng: &mut R,
  ) -> Result<Self, Error> {
    let SignedPreKeyRequest { id, pair } = params;

    let pub_signed_prekey: Box<[u8]> = pair.public_key().serialize();

    let pub_sign = id_store
      .get_identity_key_pair(None)
      .await?
      .private_key()
      .calculate_signature(&pub_signed_prekey, csprng)?;
    id_store.persist().await?;

    let inner =
      signal::SignedPreKeyRecord::new(id.into(), get_timestamp(), &pair.into(), &pub_sign);
    signed_prekey_store
      .save_signed_pre_key(id.into(), &inner, None)
      .await?;
    signed_prekey_store.persist().await?;

    Ok(Self {
      id,
      pair,
      signature: pub_sign,
    })
  }
}

#[derive(Debug, Clone, Copy)]
pub struct OneTimePreKeyRequest {
  pub id: signal::PreKeyId,
  pub pair: signal::IdentityKeyPair,
}

impl Spontaneous<()> for OneTimePreKeyRequest {
  fn generate<R: CryptoRng + Rng>(_params: (), r: &mut R) -> Self {
    let pair = signal::IdentityKeyPair::generate(r);
    let id: signal::PreKeyId = Box::new(r).gen::<u32>().into();
    Self { id, pair }
  }
}

#[derive(Debug, Clone, Copy)]
pub struct OneTimePreKey {
  pub id: signal::PreKeyId,
  pub pair: signal::IdentityKeyPair,
}

impl OneTimePreKey {
  pub async fn intern<Record, PK: signal::PreKeyStore + Persistent<Record>>(
    params: OneTimePreKeyRequest,
    store: &mut PK,
  ) -> Result<Self, Error> {
    let OneTimePreKeyRequest { id, pair } = params;
    let inner = signal::PreKeyRecord::new(id.into(), &pair.into());
    store.save_pre_key(id.into(), &inner, None).await?;
    store.persist().await?;
    Ok(Self { id, pair })
  }
}

#[derive(Debug, Clone)]
pub struct PreKeyBundleRequest {
  pub destination: ExternalIdentity,
  pub signed: SignedPreKey,
  pub one_time: OneTimePreKey,
  pub identity: CryptographicIdentity,
}

impl PreKeyBundleRequest {
  pub async fn create<Record, ID: signal::IdentityKeyStore + Persistent<Record>>(
    destination: ExternalIdentity,
    signed: SignedPreKey,
    one_time: OneTimePreKey,
    store: &ID,
  ) -> Result<Self, Error> {
    let seed = store.get_local_registration_id(None).await?;
    let inner = store.get_identity_key_pair(None).await?;
    let identity = CryptographicIdentity { inner, seed };
    Ok(Self {
      destination,
      signed,
      one_time,
      identity,
    })
  }
}

#[derive(Debug, Clone)]
pub struct PreKeyBundle {
  pub destination: ExternalIdentity,
  pub inner: signal::PreKeyBundle,
}

impl PreKeyBundle {
  pub fn new(request: PreKeyBundleRequest) -> Result<Self, Error> {
    let PreKeyBundleRequest {
      destination,
      signed,
      one_time,
      identity: CryptographicIdentity { inner, seed },
    } = request;
    let inner = signal::PreKeyBundle::new(
      seed.into(),
      destination.device_id.into(),
      Some((one_time.id.into(), *one_time.pair.public_key())),
      signed.id.into(),
      *signed.pair.public_key(),
      signed.signature.to_vec(),
      *inner.identity_key(),
    )?;
    Ok(Self { destination, inner })
  }

  pub async fn process<
    Record,
    S: signal::SessionStore + Persistent<Record>,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    R: CryptoRng + Rng,
  >(
    self,
    session_store: &mut S,
    id_store: &mut ID,
    csprng: &mut R,
  ) -> Result<(), Error> {
    signal::process_prekey_bundle(
      &self.destination.into(),
      session_store,
      id_store,
      &self.inner,
      csprng,
      None,
    )
    .await?;
    session_store.persist().await?;
    id_store.persist().await?;
    Ok(())
  }
}

impl TryFrom<PreKeyBundle> for proto::PreKeyBundle {
  type Error = Error;
  fn try_from(value: PreKeyBundle) -> Result<Self, Error> {
    let PreKeyBundle { destination, inner } = value;
    Ok(proto::PreKeyBundle {
      destination: Some(destination.into()),
      registration_id: Some(inner.registration_id()?),
      device_id: Some(inner.device_id()?),
      pre_key_id: inner.pre_key_id()?.map(|id| id.into()),
      pre_key_public: inner
        .pre_key_public()?
        .map(|key| key.serialize().into_vec()),
      signed_pre_key_id: Some(inner.signed_pre_key_id()?.into()),
      signed_pre_key_public: Some(inner.signed_pre_key_public()?.serialize().into_vec()),
      signed_pre_key_signature: Some(inner.signed_pre_key_signature()?.to_vec()),
      identity_key: Some(inner.identity_key()?.serialize().into_vec()),
    })
  }
}

impl TryFrom<PreKeyBundle> for Box<[u8]> {
  type Error = Error;
  fn try_from(value: PreKeyBundle) -> Result<Self, Error> {
    let proto_message: proto::PreKeyBundle = value.try_into()?;
    Ok(encode_proto_message(proto_message))
  }
}

impl TryFrom<proto::PreKeyBundle> for PreKeyBundle {
  type Error = Error;
  fn try_from(value: proto::PreKeyBundle) -> Result<Self, Error> {
    let proto::PreKeyBundle {
      destination,
      registration_id,
      device_id,
      pre_key_id,
      pre_key_public,
      signed_pre_key_id,
      signed_pre_key_public,
      signed_pre_key_signature,
      identity_key,
    } = value.clone();
    let destination: ExternalIdentity = destination
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
          format!("failed to find `destination` field!"),
          format!("{:?}", value),
        ))
      })?
      .try_into()?;
    let registration_id: u32 = registration_id.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
        format!("failed to find `registration_id` field!"),
        format!("{:?}", value),
      ))
    })?;
    let device_id: u32 = device_id.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
        format!("failed to find `device_id` field!"),
        format!("{:?}", value),
      ))
    })?;
    let pre_key_id: Option<signal::PreKeyId> = pre_key_id.map(|key| key.into());
    let pre_key_public: Option<signal::PublicKey> = match pre_key_public {
      Some(key) => Some(signal::PublicKey::try_from(key.as_ref())?),
      None => None,
    };
    let pre_key: Option<(signal::PreKeyId, signal::PublicKey)> = match (pre_key_id, pre_key_public)
    {
      (Some(id), Some(key)) => Some((id, key)),
      (None, None) => None,
      _ => {
        return Err(Error::ProtobufDecodingError(ProtobufCodingFailure::FieldCompositionWasIncorrect(
          format!("if either the fields `pre_key_id` or `pre_key_public` are provided, then *BOTH* must be provided!"),
          format!("{:?}", value)
        )))
      }
    };
    let signed_pre_key_id: signal::SignedPreKeyId = signed_pre_key_id
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
          format!("failed to find `signed_pre_key_id` field!"),
          format!("{:?}", value),
        ))
      })?
      .into();
    let signed_pre_key_public: signal::PublicKey = signed_pre_key_public.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
        format!("failed to find `signed_pre_key_public` field!"),
        format!("{:?}", value),
      ))
    })?[..]
      .try_into()?;
    let signed_pre_key_signature: Vec<u8> = signed_pre_key_signature
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
          format!("failed to find `signed_pre_key_signature` field!"),
          format!("{:?}", value),
        ))
      })?
      .to_vec();
    let identity_key: signal::IdentityKey = identity_key.ok_or_else(|| {
      Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
        format!("failed to find `identity_key` field!"),
        format!("{:?}", value),
      ))
    })?[..]
      .try_into()?;
    Ok(Self {
      destination,
      inner: signal::PreKeyBundle::new(
        registration_id,
        device_id,
        pre_key,
        signed_pre_key_id,
        signed_pre_key_public,
        signed_pre_key_signature,
        identity_key,
      )?,
    })
  }
}

impl TryFrom<&[u8]> for PreKeyBundle {
  type Error = Error;
  fn try_from(value: &[u8]) -> Result<Self, Error> {
    let proto_message = proto::PreKeyBundle::decode(value)?;
    Self::try_from(proto_message)
  }
}

#[derive(Debug, Clone)]
pub struct SealedSenderMessageRequest<'a> {
  pub bundle: PreKeyBundle,
  pub sender_cert: SenderCert,
  pub ptext: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct SealedSenderFollowupMessageRequest<'a> {
  pub target: ExternalIdentity,
  pub sender_cert: SenderCert,
  pub ptext: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct SealedSenderMessage {
  pub trust_root: signal::PublicKey,
  pub encrypted_message: Box<[u8]>,
}

impl SealedSenderMessage {
  pub async fn intern<
    'a,
    Record,
    S: signal::SessionStore + Persistent<Record>,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    R: CryptoRng + Rng,
  >(
    request: SealedSenderMessageRequest<'a>,
    session_store: &mut S,
    id_store: &mut ID,
    csprng: &mut R,
  ) -> Result<Self, Error> {
    let SealedSenderMessageRequest {
      bundle,
      sender_cert,
      ptext,
    } = request;

    let target = bundle.destination.clone();
    bundle.process(session_store, id_store, csprng).await?;

    Self::intern_followup(
      SealedSenderFollowupMessageRequest {
        target,
        sender_cert,
        ptext,
      },
      session_store,
      id_store,
      csprng,
    )
    .await
  }

  pub async fn intern_followup<
    'a,
    Record,
    S: signal::SessionStore + Persistent<Record>,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    R: CryptoRng + Rng,
  >(
    request: SealedSenderFollowupMessageRequest<'a>,
    session_store: &mut S,
    id_store: &mut ID,
    csprng: &mut R,
  ) -> Result<Self, Error> {
    let SealedSenderFollowupMessageRequest {
      target: destination,
      sender_cert: SenderCert {
        inner: sender_cert,
        trust_root,
      },
      ptext,
    } = request;

    let encrypted_message = signal::sealed_sender_encrypt(
      &destination.into(),
      &sender_cert,
      ptext,
      session_store,
      id_store,
      None,
      csprng,
    )
    .await?
    .into_boxed_slice();
    session_store.persist().await?;
    id_store.persist().await?;

    Ok(Self {
      trust_root,
      encrypted_message,
    })
  }
}

impl From<SealedSenderMessage> for proto::SealedSenderMessage {
  fn from(value: SealedSenderMessage) -> Self {
    let SealedSenderMessage {
      trust_root,
      encrypted_message,
    } = value;
    proto::SealedSenderMessage {
      trust_root_public_key: Some(trust_root.serialize().into_vec()),
      encrypted_sealed_sender_message: Some(encrypted_message.into_vec()),
    }
  }
}

impl From<SealedSenderMessage> for Box<[u8]> {
  fn from(value: SealedSenderMessage) -> Self {
    let proto_message: proto::SealedSenderMessage = value.into();
    encode_proto_message(proto_message)
  }
}

impl TryFrom<proto::SealedSenderMessage> for SealedSenderMessage {
  type Error = Error;
  fn try_from(value: proto::SealedSenderMessage) -> Result<Self, Error> {
    let proto::SealedSenderMessage {
      trust_root_public_key,
      encrypted_sealed_sender_message,
    } = value.clone();
    let trust_root_public_key = signal::PublicKey::try_from(
      trust_root_public_key
        .ok_or_else(|| {
          Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
            format!("failed to find `trust_root_public_key` field!"),
            format!("{:?}", value),
          ))
        })?
        .as_ref(),
    )?;
    let encrypted_sealed_sender_message: Box<[u8]> = encrypted_sealed_sender_message
      .ok_or_else(|| {
        Error::ProtobufDecodingError(ProtobufCodingFailure::OptionalFieldAbsent(
          format!("failed to find `encrypted_sealed_sender_message` field!"),
          format!("{:?}", value),
        ))
      })?
      .into_boxed_slice();
    Ok(Self {
      trust_root: trust_root_public_key,
      encrypted_message: encrypted_sealed_sender_message,
    })
  }
}

impl TryFrom<&[u8]> for SealedSenderMessage {
  type Error = Error;
  fn try_from(value: &[u8]) -> Result<Self, Error> {
    let proto_message = proto::SealedSenderMessage::decode(value)?;
    Self::try_from(proto_message)
  }
}

#[derive(Debug, Clone)]
pub struct SealedSenderDecryptionRequest {
  pub inner: SealedSenderMessage,
  pub local_identity: SealedSenderIdentity,
}

#[derive(Debug, Clone)]
pub struct SealedSenderMessageResult {
  pub sender: SealedSenderIdentity,
  pub plaintext: Box<[u8]>,
}

impl SealedSenderMessageResult {
  pub async fn intern<
    Record,
    ID: signal::IdentityKeyStore + Persistent<Record>,
    S: signal::SessionStore + Persistent<Record>,
    PK: signal::PreKeyStore + Persistent<Record>,
    SPK: signal::SignedPreKeyStore + Persistent<Record>,
  >(
    message: SealedSenderDecryptionRequest,
    id_store: &mut ID,
    session_store: &mut S,
    pre_key_store: &mut PK,
    signed_pre_key_store: &mut SPK,
  ) -> Result<Self, Error> {
    let SealedSenderDecryptionRequest {
      inner: SealedSenderMessage {
        trust_root,
        encrypted_message,
      },
      local_identity:
        SealedSenderIdentity {
          inner:
            ExternalIdentity {
              name: local_uuid,
              device_id: local_device_id,
            },
          e164: local_e164,
        },
    } = message;

    let signal::SealedSenderDecryptionResult {
      sender_uuid,
      sender_e164,
      device_id: sender_device_id,
      message: plaintext,
    } = signal::sealed_sender_decrypt(
      encrypted_message.as_ref(),
      &trust_root,
      get_timestamp(),
      local_e164,
      local_uuid,
      local_device_id,
      id_store,
      session_store,
      pre_key_store,
      signed_pre_key_store,
      None,
    )
    .await?;
    id_store.persist().await?;
    session_store.persist().await?;
    pre_key_store.persist().await?;
    signed_pre_key_store.persist().await?;

    let sender = SealedSenderIdentity {
      inner: ExternalIdentity {
        name: sender_uuid,
        device_id: sender_device_id,
      },
      e164: sender_e164,
    };
    Ok(Self {
      sender,
      plaintext: plaintext.into_boxed_slice(),
    })
  }
}

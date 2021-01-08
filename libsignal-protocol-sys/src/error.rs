use super::gen::{
  SG_ERR_DUPLICATE_MESSAGE, SG_ERR_FP_IDENT_MISMATCH, SG_ERR_FP_VERSION_MISMATCH, SG_ERR_INVAL,
  SG_ERR_INVALID_KEY, SG_ERR_INVALID_KEY_ID, SG_ERR_INVALID_MAC, SG_ERR_INVALID_MESSAGE,
  SG_ERR_INVALID_PROTO_BUF, SG_ERR_INVALID_VERSION, SG_ERR_LEGACY_MESSAGE, SG_ERR_MINIMUM,
  SG_ERR_NOMEM, SG_ERR_NO_SESSION, SG_ERR_STALE_KEY_EXCHANGE, SG_ERR_UNKNOWN,
  SG_ERR_UNTRUSTED_IDENTITY, SG_ERR_VRF_SIG_VERIF_FAILED, SG_SUCCESS,
};

use std::convert::From;

#[derive(Debug)]
pub struct UnknownError<E> {
  more_specific_value: Option<E>,
}

impl<E> UnknownError<E> {
  pub fn generic() -> Self {
    Self {
      more_specific_value: None,
    }
  }

  pub fn specific(value: E) -> Self {
    Self {
      more_specific_value: Some(value),
    }
  }
}

#[derive(Debug)]
pub enum SignalError {
  NoMemory,
  InvalidArgument,
  UnknownSignalProtocolError(UnknownError<i32>),
  DuplicateMessage,
  InvalidKey,
  InvalidKeyId,
  InvalidMAC,
  InvalidMessage,
  InvalidVersion,
  LegacyMessage,
  NoSession,
  StaleKeyExchange,
  UntrustedIdentity,
  VRFSignatureVerificationFailed,
  InvalidProtobuf,
  FPVersionMismatch,
  FPIdentMismatch,
  UnknownClientApplicationError(UnknownError<i32>),
}

pub(crate) enum SignalNativeResult<T> {
  Success(T),
  Failure(SignalError),
}

type ReturnCode = i32;
const SUCCESS: ReturnCode = SG_SUCCESS as ReturnCode;

impl<T> SignalNativeResult<T> {
  pub fn success(arg: T) -> Self {
    Self::Success(arg)
  }

  pub fn fail(error: SignalError) -> Self {
    Self::Failure(error)
  }

  pub fn invalid_argument() -> Self {
    Self::fail(SignalError::InvalidArgument)
  }

  pub fn from_rc(rc: ReturnCode, arg: T) -> Self {
    match rc {
      SUCCESS => Self::success(arg),
      SG_ERR_NOMEM => Self::fail(SignalError::NoMemory),
      SG_ERR_INVAL => Self::invalid_argument(),
      SG_ERR_UNKNOWN => Self::fail(SignalError::UnknownSignalProtocolError(
        UnknownError::generic(),
      )),
      SG_ERR_DUPLICATE_MESSAGE => Self::fail(SignalError::DuplicateMessage),
      SG_ERR_INVALID_KEY => Self::fail(SignalError::InvalidKey),
      SG_ERR_INVALID_KEY_ID => Self::fail(SignalError::InvalidKeyId),
      SG_ERR_INVALID_MAC => Self::fail(SignalError::InvalidMAC),
      SG_ERR_INVALID_MESSAGE => Self::fail(SignalError::InvalidMessage),
      SG_ERR_INVALID_VERSION => Self::fail(SignalError::InvalidVersion),
      SG_ERR_LEGACY_MESSAGE => Self::fail(SignalError::LegacyMessage),
      SG_ERR_NO_SESSION => Self::fail(SignalError::NoSession),
      SG_ERR_STALE_KEY_EXCHANGE => Self::fail(SignalError::StaleKeyExchange),
      SG_ERR_UNTRUSTED_IDENTITY => Self::fail(SignalError::UntrustedIdentity),
      SG_ERR_VRF_SIG_VERIF_FAILED => Self::fail(SignalError::VRFSignatureVerificationFailed),
      SG_ERR_INVALID_PROTO_BUF => Self::fail(SignalError::InvalidProtobuf),
      SG_ERR_FP_VERSION_MISMATCH => Self::fail(SignalError::FPVersionMismatch),
      SG_ERR_FP_IDENT_MISMATCH => Self::fail(SignalError::FPIdentMismatch),
      x if x >= SG_ERR_MINIMUM => Self::fail(SignalError::UnknownSignalProtocolError(
        UnknownError::specific(x),
      )),
      x => Self::fail(SignalError::UnknownClientApplicationError(
        UnknownError::specific(x),
      )),
    }
  }
}

impl<T> From<SignalNativeResult<T>> for Result<T, SignalError> {
  fn from(other: SignalNativeResult<T>) -> Self {
    match other {
      SignalNativeResult::Success(x) => Ok(x),
      SignalNativeResult::Failure(e) => Err(e),
    }
  }
}

impl<T: Copy> SignalNativeResult<T> {
  pub fn call_method<F: FnOnce(T) -> ReturnCode>(t: T, f: F) -> Self {
    let rc = f(t);
    Self::from_rc(rc, t)
  }
}

pub mod generic {
  pub type ReturnCode = i32;

  #[derive(Debug)]
  pub struct UnknownError<E> {
    pub more_specific_value: Option<E>,
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

  pub trait ErrorCodeable {
    fn into_rc(self) -> ReturnCode;
  }

  impl ErrorCodeable for T
  where
    T: Into<E>,
    E: ErrorCodeable,
  {
    fn into_rc(self) -> ReturnCode {
      let e: E = self.into();
      e.into_rc()
    }
  }
}

pub mod constants {
  use super::generic::*;

  use crate::gen::{SG_ERR_MINIMUM, SG_SUCCESS};

  pub const SUCCESS: ReturnCode = SG_SUCCESS as ReturnCode;
  pub const MINIMUM: ReturnCode = SG_ERR_MINIMUM;
}

pub mod errored {
  use super::constants::*;
  use super::generic::*;

  pub trait ShiftedErrorCodeable {
    fn shift(&self) -> ReturnCode;
    fn into_relative_rc(self) -> ReturnCode;
  }

  impl<T> ErrorCodeable for T
  where
    T: ShiftedErrorCodeable,
  {
    fn into_rc(self) -> ReturnCode {
      assert_eq!(SUCCESS, 0);
      let basis = self.shift();
      assert!(basis < SUCCESS);
      let relative_rc = self.into_relative_rc();
      assert!(relative_rc < SUCCESS);
      assert!((-1 * relative_rc) < (-1 * basis));
      basis + relative_rc
    }
  }

  ///
  /// The Signal Protocol follows a common pattern when allocating anything -- return 0 on failure.
  /// This trait verifies that behavior and raises the appropriate error if needed.
  pub trait ValidateBufferHasMem<T> {
    fn enomem() -> Self;

    fn validate_has_mem(buf: *mut T) -> Result<*mut T, Self>
    where
      Self: Sized,
    {
      if buf.is_null() {
        Err(Self::enomem())
      } else {
        Ok(buf)
      }
    }
  }
}

pub mod errors {
  use super::constants::*;
  use super::errored::*;
  use super::generic::*;

  use crate::gen::{
    SG_ERR_DUPLICATE_MESSAGE, SG_ERR_FP_IDENT_MISMATCH, SG_ERR_FP_VERSION_MISMATCH, SG_ERR_INVAL,
    SG_ERR_INVALID_KEY, SG_ERR_INVALID_KEY_ID, SG_ERR_INVALID_MAC, SG_ERR_INVALID_MESSAGE,
    SG_ERR_INVALID_PROTO_BUF, SG_ERR_INVALID_VERSION, SG_ERR_LEGACY_MESSAGE, SG_ERR_NOMEM,
    SG_ERR_NO_SESSION, SG_ERR_STALE_KEY_EXCHANGE, SG_ERR_UNKNOWN, SG_ERR_UNTRUSTED_IDENTITY,
    SG_ERR_VRF_SIG_VERIF_FAILED,
  };

  #[derive(Debug)]
  pub enum SignalError {
    NoMemory,
    InvalidArgument,
    UnknownSignalProtocolError(UnknownError<ReturnCode>),
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
    /* All of our own errors! */
    ClientApplicationError(UnknownError<ReturnCode>),
  }

  impl ErrorCodeable for SignalError {
    fn into_rc(self) -> ReturnCode {
      match self {
        Self::NoMemory => SG_ERR_NOMEM,
        Self::InvalidArgument => SG_ERR_INVAL,
        Self::UnknownSignalProtocolError(err) => err.more_specific_value.unwrap_or(SG_ERR_UNKNOWN),
        Self::DuplicateMessage => SG_ERR_DUPLICATE_MESSAGE,
        Self::InvalidKey => SG_ERR_INVALID_KEY,
        Self::InvalidKeyId => SG_ERR_INVALID_KEY_ID,
        Self::InvalidMAC => SG_ERR_INVALID_MAC,
        Self::InvalidMessage => SG_ERR_INVALID_MESSAGE,
        Self::InvalidVersion => SG_ERR_INVALID_VERSION,
        Self::LegacyMessage => SG_ERR_LEGACY_MESSAGE,
        Self::NoSession => SG_ERR_NO_SESSION,
        Self::StaleKeyExchange => SG_ERR_STALE_KEY_EXCHANGE,
        Self::UntrustedIdentity => SG_ERR_UNTRUSTED_IDENTITY,
        Self::VRFSignatureVerificationFailed => SG_ERR_VRF_SIG_VERIF_FAILED,
        Self::InvalidProtobuf => SG_ERR_INVALID_PROTO_BUF,
        Self::FPVersionMismatch => SG_ERR_FP_VERSION_MISMATCH,
        Self::FPIdentMismatch => SG_ERR_FP_IDENT_MISMATCH,
        Self::ClientApplicationError(err) => err.more_specific_value.unwrap_or(MINIMUM - 1),
      }
    }
  }

  impl<T> ValidateBufferHasMem<T> for SignalError {
    fn enomem() -> Self {
      Self::NoMemory
    }
  }
}

pub mod util {
  use super::constants::*;
  use super::errors::*;
  use super::generic::*;

  use crate::gen::{
    SG_ERR_DUPLICATE_MESSAGE, SG_ERR_FP_IDENT_MISMATCH, SG_ERR_FP_VERSION_MISMATCH, SG_ERR_INVAL,
    SG_ERR_INVALID_KEY, SG_ERR_INVALID_KEY_ID, SG_ERR_INVALID_MAC, SG_ERR_INVALID_MESSAGE,
    SG_ERR_INVALID_PROTO_BUF, SG_ERR_INVALID_VERSION, SG_ERR_LEGACY_MESSAGE, SG_ERR_MINIMUM,
    SG_ERR_NOMEM, SG_ERR_NO_SESSION, SG_ERR_STALE_KEY_EXCHANGE, SG_ERR_UNKNOWN,
    SG_ERR_UNTRUSTED_IDENTITY, SG_ERR_VRF_SIG_VERIF_FAILED,
  };

  pub enum SignalNativeResult<T> {
    Success(T),
    Failure(SignalError),
  }

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
        x => Self::fail(SignalError::ClientApplicationError(UnknownError::specific(
          x,
        ))),
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
}

pub use constants::*;
pub use errored::*;
pub use errors::*;
pub use generic::*;
pub use util::*;

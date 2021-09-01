use displaydoc::Display;
use thiserror::Error;

#[derive(Debug, Display, Error)]
pub enum Error {
  /// key info error: {0}
  KeyInfo(#[from] crate::key_info::Error),
  /// identity db error: {0}
  IdentityDb(#[from] crate::identity_db::Error),
}

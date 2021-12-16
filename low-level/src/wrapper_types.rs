/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct SessionSeed(u32);

impl From<u32> for SessionSeed {
  fn from(value: u32) -> Self {
    Self(value)
  }
}

impl From<SessionSeed> for u32 {
  fn from(value: SessionSeed) -> Self {
    value.0
  }
}

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct SignedPreKeyId(u32);

impl From<u32> for SignedPreKeyId {
  fn from(value: u32) -> Self {
    Self(value)
  }
}

impl From<SignedPreKeyId> for u32 {
  fn from(value: SignedPreKeyId) -> Self {
    value.0
  }
}

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct PreKeyId(u32);

impl From<u32> for PreKeyId {
  fn from(value: u32) -> Self {
    Self(value)
  }
}

impl From<PreKeyId> for u32 {
  fn from(value: PreKeyId) -> Self {
    value.0
  }
}

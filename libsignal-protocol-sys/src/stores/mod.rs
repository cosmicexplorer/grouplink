// Fail on warnings.
#![deny(warnings)]
// Enable all clippy lints except for many of the pedantic ones. It's a shame this needs to be copied and pasted across crates, but there doesn't appear to be a way to include inner attributes from a common source.
#![deny(
  clippy::all,
  clippy::default_trait_access,
  clippy::expl_impl_clone_on_copy,
  clippy::if_not_else,
  clippy::needless_continue,
  clippy::unseparated_literal_suffix,
  // TODO: Falsely triggers for async/await:
  //   see https://github.com/rust-lang/rust-clippy/issues/5360
  // clippy::used_underscore_binding
)]
// It is often more clear to show that nothing is being moved.
#![allow(clippy::match_ref_pats)]
// Subjective style.
#![allow(
  clippy::len_without_is_empty,
  clippy::redundant_field_names,
  clippy::too_many_arguments
)]
// Default isn't as big a deal as people seem to think it is.
#![allow(clippy::new_without_default, clippy::new_ret_no_self)]
// Arc<Mutex> can be more clear than needing to grok Orderings:
#![allow(clippy::mutex_atomic)]
// Avoid docstrings on every unsafe method.
#![allow(clippy::missing_safety_doc)]
// We *only* use unsafe pointer dereferences when we implement the libsignal callbacks, so it is
// nicer to list internal minor calls as unsafe, than to mark the whole function as unsafe which may
// hide other unsafeness.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod generics {
  pub trait ContextRegisterable<E> {
    fn register(self) -> Result<(), E>;
  }

  pub trait SeparateFromContextRegisterable<NativeStruct, E>: Into<NativeStruct> + Clone {
    type Ctx;
    fn get_context(&mut self) -> &mut Self::Ctx;

    fn register(mut self) -> Result<(), E> {
      let other = self.clone();
      let ctx: &mut Self::Ctx = self.get_context();
      let native: NativeStruct = other.into();
      Self::modify_context(ctx, native)
    }

    fn modify_context(ctx: &mut Self::Ctx, native: NativeStruct) -> Result<(), E>;
  }
}

pub mod crypto_provider;

pub mod identity_key_store;
pub mod pre_key_store;
pub mod sender_key_store;
pub mod session_store;
pub mod signed_pre_key_store;

use crate::error::SignalError as CryptoError;
use identity_key_store::generic::Error as IdentityKeyError;
use pre_key_store::generic::Error as PreKeyError;
use sender_key_store::generic::Error as SenderKeyError;
use session_store::generic::Error as SessionError;
use signed_pre_key_store::generic::Error as SignedPreKeyError;

#[derive(Debug)]
pub enum StoreError {
  IdentityKey(IdentityKeyError),
  PreKey(PreKeyError),
  SenderKey(SenderKeyError),
  Session(SessionError),
  SignedPreKey(SignedPreKeyError),
  Crypto(CryptoError),
}

impl From<IdentityKeyError> for StoreError {
  fn from(err: IdentityKeyError) -> Self {
    Self::IdentityKey(err)
  }
}
impl From<PreKeyError> for StoreError {
  fn from(err: PreKeyError) -> Self {
    Self::PreKey(err)
  }
}
impl From<SenderKeyError> for StoreError {
  fn from(err: SenderKeyError) -> Self {
    Self::SenderKey(err)
  }
}
impl From<SessionError> for StoreError {
  fn from(err: SessionError) -> Self {
    Self::Session(err)
  }
}
impl From<SignedPreKeyError> for StoreError {
  fn from(err: SignedPreKeyError) -> Self {
    Self::SignedPreKey(err)
  }
}
impl From<CryptoError> for StoreError {
  fn from(err: CryptoError) -> Self {
    Self::Crypto(err)
  }
}

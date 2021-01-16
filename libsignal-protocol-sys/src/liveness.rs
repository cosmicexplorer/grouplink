/* TODO: formalize the concepts of "information liveness" that make asynchronous messaging more
 * difficult (but also much more useful in the 21st century) than a single static asymmetric GPG
 * keypair.
 *
 * This approach is intended to ensure security via a more formal analysis of information flow. It
 * is also intended to help expose hidden data dependencies between operations, along with other
 * side channel venues.
 *
 * TODO: see what guarantees we can get on this "easily" via several upcoming modifications and what
 * utility each modification *intends* to provide vs *actually* provides compared to the
 * Signal Protocol.
 */

#[derive(Clone, Debug, Copy)]
pub enum Sensitivity {
  Sensitive,
  Idk,
}

impl Default for Sensitivity {
  fn default() -> Self {
    /* FIXME: default to bzeroing buffers? */
    Self::Sensitive
  }
}

pub trait AssuredSensitive {
  fn as_sensitivity() -> Sensitivity;
}

pub trait Sensitive {
  fn as_sensitivity(&self) -> Sensitivity;
}

impl Sensitive for T
where
  T: AssuredSensitive,
{
  fn as_sensitivity(&self) -> Sensitivity {
    <Self as AssuredSensitive>::as_sensitivity()
  }
}

/* pub trait SensitivityValidated { */
/*   fn validate(&self) */
/* } */

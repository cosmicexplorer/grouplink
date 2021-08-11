use grouplink::Identity;

pub enum Command {
  PrivateKeyGeneration(PrivateKeyGeneration),
  KeyInfoExtraction,
  IdentityDatabaseOperation,
  SignalSessionOperation,
}

pub struct PrivateKeyGeneration;

pub enum KeyInfoExtraction {
  Fingerprint(),
}

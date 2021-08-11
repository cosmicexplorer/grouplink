use grouplink::{
  identity::{self, *},
  rand,
};

pub struct KeyGenerationOptions;

pub fn generate_private_key(_options: KeyGenerationOptions) -> identity::Identity {
  identity::Identity::generate((), &mut rand::thread_rng())
}

use grouplink::{
  identity::{self, *},
  rand,
};

pub struct KeyGenerationOptions;

pub fn generate_private_key<R>(_options: KeyGenerationOptions, rng: &mut R) -> identity::Identity
where
  R: rand::Rng + rand::CryptoRng,
{
  identity::Identity::generate((), rng)
}

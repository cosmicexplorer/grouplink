/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

use prost_build;

fn main() {
  let protos = ["src/identity.proto"];
  prost_build::compile_protos(&protos, &["src"]).expect("protobufs were somehow invalid?");
  for proto in &protos {
    println!("cargo:rerun-if-changed={}", proto);
  }
}

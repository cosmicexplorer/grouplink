/* Copyright 2021-2022 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

fn main() {
  let protos = [
    "src/anonymity.proto",
    "src/identity.proto",
    "src/message.proto",
    "src/session.proto",
    "src/store.proto",
  ];
  prost_build::compile_protos(&protos, &["src"]).expect("protobufs were somehow invalid?");
  for proto in &protos {
    println!("cargo:rerun-if-changed={}", proto);
  }
}

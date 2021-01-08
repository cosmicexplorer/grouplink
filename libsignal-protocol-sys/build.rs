// Copyright 2021, Danny McClanahan
// Licensed under the GNU GPL, Version 3.0 or any later version (see COPYING).

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

use bindgen;

fn main() {
  // Tell cargo to tell rustc to link against the spack-provided libraries.
  println!("cargo:rustc-link-lib=signal-protocol-c");

  // Tell cargo to invalidate the built crate whenever the wrapper changes.
  println!("cargo:rerun-if-changed=src/bindgen-wrapper.h");

  // The bindgen::Builder is the main entry point
  // to bindgen, and lets you build up options for
  // the resulting bindings.
  bindgen::Builder::default()
    // The input header we would like to generate
    // bindings for.
    .header("src/bindgen-wrapper.h")
    // Tell cargo to invalidate the built crate whenever any of the
    // included header files changed.
    .parse_callbacks(Box::new(bindgen::CargoCallbacks))
    // Only include signal methods, types, and variables.
    .whitelist_function(".*_?signal_.*")
    .whitelist_type(".*_?signal_.*")
    .whitelist_var(".*_?signal_.*")
    .whitelist_var("SG_.*")
    // Finish the builder and generate the bindings.
    .generate()
    // Unwrap the Result and panic on failure.
    .expect("Unable to generate bindings")
    // Write the bindings to src/native_bindings/generated_bindings.rs.
    .write_to_file("src/native_bindings/generated_bindings.rs")
    // Unwrap the Result and panic on failure.
    .expect("Couldn't write bindings!");
}

// Local Variables:
// mode: rust
// End:

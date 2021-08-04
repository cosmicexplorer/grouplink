/* Copyright 2021 Danny McClanahan */
/* SPDX-License-Identifier: AGPL-3.0-only */

/* Turn all warnings into errors! */
/* #![deny(warnings)] */
/* Warn for missing docs in general, and hard require crate-level docs. */
#![warn(missing_docs)]
#![warn(missing_crate_level_docs)]
/* Taken from the `libsignal_protocol` crate. */
#![deny(unsafe_code)]
/* Make all doctests fail if they produce any warnings. */
#![doc(test(attr(deny(warnings))))]
/* Enable all clippy lints except for many of the pedantic ones. It's a shame this needs to be
 * copied and pasted across crates, but there doesn't appear to be a way to include inner attributes
 * from a common source. */
#![deny(
  clippy::all,
  clippy::default_trait_access,
  clippy::expl_impl_clone_on_copy,
  clippy::if_not_else,
  clippy::needless_continue,
  clippy::unseparated_literal_suffix,
  clippy::used_underscore_binding
)]
/* It is often more clear to show that nothing is being moved. */
#![allow(clippy::match_ref_pats)]
/* Subjective style. */
#![allow(
  clippy::len_without_is_empty,
  clippy::redundant_field_names,
  clippy::too_many_arguments
)]
/* Default isn't as big a deal as people seem to think it is. */
#![allow(clippy::new_without_default, clippy::new_ret_no_self)]
/* Arc<Mutex> can be more clear than needing to grok Orderings: */
#![allow(clippy::mutex_atomic)]

use clap::{App, Arg, ArgGroup, SubCommand};

fn main() {
  let matches = App::new("grouplink")
    .version("0.1.0")
    .author("Danny McClanahan <dmcC2@hypnicjerk.ai>")
    .about("A replacement for `gpg` using the Signal Protocol.")
    .subcommand(

      /* key */
      SubCommand::with_name("key")
        .about("Create, modify, or query key files.")
        .arg(
          Arg::with_name("key-input")
            .short("f")
            .long("key-input")
            .value_name("KEY-INPUT")
            .help("If not provided, or if the value is the string '-', read from stdin.")
            .takes_value(true),
        )
        .arg(
          Arg::with_name("output")
            .short("o")
            .long("output")
            .value_name("OUTPUT")
            .help("If not provided, or if the value is the string '-', write to stdout.")
            .takes_value(true),
        )
        .subcommand(
          SubCommand::with_name("fingerprint").about("Extract a fingerprint from a private key."),
        )
        .subcommand(
          SubCommand::with_name("public").about("Extract a public key from a private key.")
            .subcommand(
              SubCommand::with_name("fingerprint").about("Extract a fingerprint from a public key.")
            ),
        )
        .subcommand(
          SubCommand::with_name("create").about("Create a new private key.")
            .arg(Arg::with_name("interactive").long("interactive")
                 .help("If this argument is provided, or if `--key-file` is not provided, an interactive prompt is displayed.")),
        )
    )
    .subcommand(

      /* identity */
      SubCommand::with_name("identity")
        .about("Import or export identities from key files to the identity database.")
        .arg(
          Arg::with_name("public-key-fingerprint").short("k").long("public-key-fingerprint")
            .value_name("PUBLIC-KEY-FINGERPRINT")
            .help("Operate on the public key specified by PUBLIC-KEY-FINGERPRINT.")
            .takes_value(true),
        )
        .arg(
          Arg::with_name("private-key-fingerprint").short("K").long("private-key-fingerprint")
            .value_name("PRIVATE-KEY-FINGERPRINT")
            .help("Operate on the private key specified by PRIVATE-KEY-FINGERPRINT.")
            .takes_value(true),
        )
        .group(
          ArgGroup::with_name("fingerprint")
            .args(&["public-key-fingerprint", "private-key-fingerprint"])
            .required(true)
        )
        .subcommand(
          SubCommand::with_name("import").about("Import a key from a file.")
            .arg(Arg::with_name("overwrite").long("overwrite")
                 .help("Error out if the key does not match an existing identity. If not provided, the key must be a new identity."))
            .arg(Arg::with_name("key-input").short("f").long("key-input")
                 .value_name("KEY-INPUT")
                 .help("Read an identity from a key file. If not provided, or if the value is the string '-', read from stdin.")
                 .takes_value(true)))
        .subcommand(
          SubCommand::with_name("export").about("Export a key to a file.")
            .arg(Arg::with_name("output").short("o").long("output")
                 .value_name("OUTPUT")
                 .help("If not provided, or if the value is the string '-', write to stdout.")
                 .takes_value(true))
        )
        .subcommand(
          SubCommand::with_name("forget").about("Remove a key from the identity database.")
        )
    )
    .subcommand(

      /* session */
      SubCommand::with_name("session")
        .about("Operations consuming the mutable Signal stores.")
        .subcommand(

          /* session/store */
          SubCommand::with_name("store").about("Process a store.")
            .subcommand(
              SubCommand::with_name("identity").about("Process a store for some identity")
                .arg(
                  Arg::with_name("private-key-fingerprint").short("K").long("private-key-fingerprint")
                    .value_name("PRIVATE-KEY-FINGERPRINT")
                    .help("Operate on the private key specified by PRIVATE-KEY-FINGERPRINT.")
                    .takes_value(true)
                    .required(true),
                )
                .subcommand(SubCommand::with_name("generate").about("Generate a new store for the given identity."))
                .subcommand(SubCommand::with_name("list").about("List all stores for a given identity."))
            )
            .subcommand(
              SubCommand::with_name("info").about("Process a store with a given id.")
                .arg(
                  Arg::with_name("store-id").short("S").long("store-id")
                    .value_name("STORE-ID")
                    .help("Operate on the store specified by STORE-ID.")
                    .takes_value(true)
                    .required(true),
                )
                .subcommand(SubCommand::with_name("path").about("Print the path to the store with the given id."))
                .subcommand(SubCommand::with_name("forget").about("Remove a store."))
                .subcommand(
                  SubCommand::with_name("identity").about("Process an identity.")
                    .arg(
                      Arg::with_name("public-key-fingerprint").short("k").long("public-key-fingerprint")
                        .value_name("PUBLIC-KEY-FINGERPRINT")
                        .help("Import the public key specified by PUBLIC-KEY-FINGERPRINT.")
                        .takes_value(true)
                        .required(true),
                    )
                    .subcommand(SubCommand::with_name("import").about("Import a public key from the identity database."))
                    .subcommand(SubCommand::with_name("forget").about("Forget a public key from this store."))
                )
            )
        )

        /* session/initiate */
        .subcommand(
          SubCommand::with_name("initiate")
            .about("Perform the multi-step handoff to create a forward-secret messaging session.")
            .arg(
              Arg::with_name("store-id").short("S").long("store-id")
                .value_name("STORE-ID")
                .help("Operate on the store specified by STORE-ID.")
                .takes_value(true)
                .required(true),
            )
            .arg(Arg::with_name("send").long("send")
                 .help("Generate a message to send."))
            .arg(Arg::with_name("recv").long("recv")
                 .help("Process a message that was received."))
            .group(
              ArgGroup::with_name("direction").args(&["send", "recv"]).required(true)
            )
            .arg(
              Arg::with_name("public-key-fingerprint").short("k").long("public-key-fingerprint")
                .value_name("PUBLIC-KEY-FINGERPRINT")
                .help("Operate on a session with the public key specified by PUBLIC-KEY-FINGERPRINT.")
                .takes_value(true),
            )
            .group(
              ArgGroup::with_name("session-target").args(&["public-key-fingerprint"]).required(true)
            )
            .subcommand(
              SubCommand::with_name("pre-key-bundle").about("Process a pre-key bundle message."))
            .subcommand(
              SubCommand::with_name("initial-message").about("Process an initial session message."))
      )

      /* session/ratchet */
      .subcommand(
        SubCommand::with_name("ratchet")
          .about("Perform a stateful messaging operation.")
          .arg(
            Arg::with_name("store-id").short("S").long("store-id")
              .value_name("STORE-ID")
              .help("Operate on the store specified by STORE-ID.")
              .takes_value(true)
              .required(true),
          )
          .arg(
            Arg::with_name("session-id").short("s").long("session-id")
              .value_name("SESSION-ID")
              .help("Operate on the session specified by SESSION-ID.")
              .takes_value(true)
              .required(true),
          )
          .arg(
            Arg::with_name("input")
              .short("i")
              .long("input")
              .value_name("INPUT")
              .help("If not provided, or if the value is the string '-', read from stdin.")
              .takes_value(true),
          )
          .arg(
            Arg::with_name("output")
              .short("o")
              .long("output")
              .value_name("OUTPUT")
              .help("If not provided, or if the value is the string '-', write to stdout.")
              .takes_value(true),
          )
          .subcommand(SubCommand::with_name("send").about("Serialize a message to send."))
          .subcommand(SubCommand::with_name("recv").about("Deserialize a received message."))
      )
    )
    .get_matches();

  println!("Hello, world!");
}

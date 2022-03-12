anonymity
=========

Signal's Double Ratchet message conversation model introduces a separation between the phase of *initiating* a conversation and then *responding* to it. This contrasts to e.g. PGP-signed email relying upon Web of Trust, which requires that each participant provide a cryptographic guarantee that they possess the private key to a specific well-known public key that they widely associate with their name. Web of Trust not only takes massive time and effort to maintain, but it precludes the possibility of anonymity while using encryption. **Unfortunately, Signal itself also produces a form of this failure, by requiring that you identify yourself with a single working phone number.**

Web of Trust/PGP may be thought of as "stateless" in a way that Signal is not--in this case, Signal's ratcheting state improves security, introducing forward secrecy. We would like to extend this advantage by using the ratcheting KDF state to generate secret *header keys* which are used to anonymize the metadata of each message. While **tor does this through a network of relays** to stimy the tracking of individual packets in and out, we can **use the pre-negotiated stateful message chain to deterministically ensure the anonymity of our messages!**

# Header Encryption

Signal's Double Ratchet Spec contains a [section describing *header encryption*](https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption), which can be used to implement the above. One of the subsequent requirements noted to apply this method is **associating messages to sessions.** The Pond protocol is suggested as a way to perform this.

## Pond Protocol

The [Pond protocol](https://crypto.stanford.edu/~dabo/papers/groupsigs.pdf) is a group signature scheme, which affords anonymity to signers while enabling the association of messages to sessions as specified above. There is an [unmaintained implementation of the Pond protocol in go](https://github.com/agl/pond) as prior art to refer to here. We should be able to adapt this code to rust (along with their test suite!) to produce header-encrypted Signal message chains.

# Architecture

This subcrate should extend the API of `../low-level` to cover the Pond protocol's use case: to send and receive anonymized messages. `low-level` refers to concrete identities which need to be encrypted for anonymity, implemented in this crate.

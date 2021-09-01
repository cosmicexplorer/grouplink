A "Decentralized" Extension of the Signal Protocol
==================================================

This codebase is intended to implement an extension of the [Signal Protocol](#definition-of-the-signal-protocol) which can be used to encrypt messages without reference to a central server. Our aim is to replace the flawed GPG tool, as well as the restrictive Web of Trust (WoT) security model [^wot].

# Retaining Signal's Proven Security Guarantees

The Signal developers have stated clearly in the past that they do not believe this is likely to be a good idea [^no-signal-federation]. This appears largely due to the (very, very reasonable) desire to avoid maintaining a generic protocol for message encryption, along with all the bells and whistles that typically implies. This concern is especially reasonable when considering that Signal's main goal is to provide secure messaging, and extensible protocols such as JWT can often tend to produce security holes while trying to satisfy greater and greater requirements than the protocol was originally built to handle.

## Goals

Our goal in this document is to describe our plan to **extend the Signal Protocol to arbitrary message encryption scenarios, without reference to a central server**. We believe this can be done while remaining close enough to the original model of the Signal Protocol so that we can continue to rely on the security hardening work done by the Signal developers.

# Definition of the Signal Protocol

The "Signal Protocol" is an umbrella term referring to the collection of cryptographic mechanisms used to implement the Signal app [^signal]. Signal has created succinct formal specifications of their generic cryptographic mechanisms to aid others in reproducing their functionality in separate applications:
- the X3DH asynchronous key agreement protocol [^x3dh]
- the Double Ratchet forward-secret message encryption protocol [^double-ratchet]
- the Sesame session agreement protocol [^sesame]

## Official Rust Implementation

These specifications are however also implemented in readable, auditable Rust code in a public github repo [^libsignal-client]. That codebase is licensed under the AGPL v3 [^agpl-v3], which is compatible with the codebase containing this document.

Since the official Rust implementation [^libsignal-client] is directly used to implement the Signal app, we can be reasonably confident that it is secure. If we can avoid diverging from the main Signal client repo very much (or at all), then we can expect to continue to pull in any documentation, performance, or security fixes released by the Signal developers in the future.

## Relevant Subset

Of Signal's [specification documents listed above](#definition-of-the-signal-protocol), the X3DH [^x3dh] and Double Ratchet [^double-ratchet] algorithms seem applicable to our use case. The Sesame protocol [^sesame] is *not* implemented in the Signal client repo [^libsignal-client], and appears to be relatively specific to Signal's model with a central server.

It is possible that the Sesame protocol may be extensible to our case, but we will discard it for the time being.

## Basic Messaging Model

We attempt to define an abstract description of the independent actors and operations currently required to initiate and continue a conversation in the Signal app. We will later [describe our modifications to this model](#decentralized-messaging-model).

There exist some descriptions online which seem to correspond to the one below:
- *high-level analysis* [^signal-analysis-medium]
- *formal analysis* [^signal-analysis-formal]

### Actors
1. **Device A:** a user of the Signal app, whom we name "Alice", is assumed to possess a device which contains the Signal client application.
2. **Device B:** another user of the Signal app, whom we name "Bob", is assumed to have a separate device with the Signal client application.
3. **Signal Server:** a server program, assumed to be running a version of the open-source Signal server application [^signal-server].

### Assumptions
1. Communication from a device to the Signal server is secured via HTTPS.
    - **TODO: is this actually relied on?**
2. All messages are sent using Signal's *sealed-sender encryption* [^sealed-sender], so that the sender's identity is not revealed.
    - However, the identity of the *recipient* is currently exposed with this method.

### Operations
Operations are labelled with numeric indices to indicate which operations occur before another in time.

#### Setup
Before a conversation begins, the following occurs:

0. Alice and Bob independently set up the Signal application on their device, producing a unique **Identity**, with a public/private key pair.
1. Bob generates a nonzero number of **Signed Pre-Keys**.
    - Bob uploads these to the Signal server.
2. Bob generates a **One-Time Pre-Key** on Device B, and matches this with a *signed pre-key* to produce a **Pre-Key Bundle**.
    - Bob uploads this to the Signal server.

#### Initiate a Conversation
To initiate a conversation, the following occurs:

3. Alice sends a request to the Signal server for a *pre-key bundle*. The Signal server returns one of Bob's uploaded *pre-key bundles*, then deletes the bundle so it cannot be used again.
4. Alice generates a **PreKeySignalMessage** from the *pre-key bundle* and the encrypted contents of an initial message to send to Bob.
    - Alice then uploads this message to the Signal server.
5. Bob pings the Signal server periodically to check for any incoming messages. After the server receives Alice's *PreKeySignalMessage*, Bob's next request will download the message to Device B.
    - Bob decrypts the message.

At this point, both Alice and Bob will have a copy of the Double Ratchet KDF [^double-ratchet-kdf], and either can send a message to the other using that KDF.

# Extensions to the Base Protocol

As described in the [goals](#goals) section, we want to build off of the existing Signal Protocol as much as possible, while making it suitable for message encryption using purely local operations, without reference to a central server. A brief description of our approach is given in the [module-level documentation for the `grouplink` crate](./lib.rs) in this repo:

``` rust
//! This crate wraps [libsignal_protocol] and offers asynchronous message encryption and signature
//! operations over arbitrary input files. It is intended to serve as a replacement for `gpg`.
//!
//! An end-to-end example of a secure bidirectional conversation between two individuals
//! *`alice`* and *`bob`*:
```

## Decentralized Messaging Model

We modify the [basic messaging model](#basic-messaging-model) from the Signal app to remove the *Signal server*. This requires us to replace operations performed through the Signal server with operations directly between Alice and Bob. **We italicize every operation which is unchanged.**

### Actors
1. *Device A: as before.*
2. *Device B: as before.*

### Assumptions
1. **Communication between devices is *not* performed over an encrypted channel.**
2. *All messages use Signal's sealed-sender encryption, as before [^sealed-sender]. This exposes the identity of the recipient, but not the sender.*

### Operations

#### Setup
The first few setup operations are the same, but without sending any information to any other location: all information is retained on the local device.

0. *Alice and Bob independently set up the Signal application on their device, producing a unique identity, with a public/private key pair.*
1. *Bob generates a nonzero number of signed pre-keys.*
2. *Bob generates a one-time pre-key on Device B, and matches this with a signed pre-key to produce a pre-key bundle.*

#### Initiate a Conversation
Since we don't assume a secure communication channel, we need to reproduce the way Bob transfers a *pre-key bundle* to Alice. We add an additional message type to do this:

3. Bob creates a **PreKeyBundleMessage** addressed to Alice, containing the encrypted contents of his *pre-key bundle*.
    - Bob sends the encrypted *PreKeyBundleMessage* to Alice, which exposes that it is intended for Alice, but not that it came from Bob.
    - Alice receives the message and decrypts it to obtain Bob's *pre-key bundle*.

After this is performed, the operations are the same as in Signal:

4. *Alice generates a PreKeySignalMessage from the pre-key bundle and the encrypted contents of an initial message to send to Bob.*
    - *Bob receives and decrypts the PreKeySignalMessage*.

Note that this involves **one less message sent than in Signal**, by virtue of sending messages directly between Alice and Bob instead of the Signal server intermediary.

*At this point, both Alice and Bob will have a copy of the Double Ratchet KDF [^double-ratchet-kdf], and either can send a message to the other using that KDF.*

[^signal]: https://signal.org
[^x3dh]: https://signal.org/docs/specifications/x3dh/
[^double-ratchet]: https://signal.org/docs/specifications/doubleratchet/
[^sesame]: https://signal.org/docs/specifications/sesame/
[^libsignal-client]: https://github.com/signalapp/libsignal-client/
[^agpl-v3]: https://www.gnu.org/licenses/agpl-3.0.en.html
[^no-signal-federation]: https://signal.org/blog/the-ecosystem-is-moving/
[^signal-server]: https://github.com/signalapp/Signal-Server/
[^double-ratchet-kdf]: https://signal.org/docs/specifications/doubleratchet/#kdf-chains
[^sealed-sender]: https://signal.org/blog/sealed-sender/
[^wot]: https://en.wikipedia.org/wiki/Web_of_trust
[^signal-analysis-medium]: https://medium.com/@justinomora/demystifying-the-signal-protocol-for-end-to-end-encryption-e2ee-ad6a567e6cb4
[^signal-analysis-formal]: https://eprint.iacr.org/2016/1013.pdf

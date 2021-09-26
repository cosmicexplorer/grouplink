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

# Signal Extensions

*Updated 2021-09-25.*

There is a vague implementation of a `gpg`-*like* tool based on Signal in the repo currently (as the top-level [`grouplink` crate](../../README.md)). That work is perhaps 50% done. However, we now face a choice: we would like to be able to resist metadata analysis as well, something that Signal itself considers out of scope (as the Signal app requires the recipient to be specified unencrypted to know where to route a message to [^sealed-sender]). Our approach to solving this conundrum may require rethinking our (and Signal's) model of identity a bit.

So below we describe what we might want to add on top of the Signal protocol, *separate* from our current achievement of separating the Signal protocol form the Signal server. We hope that this will lead to a result that can still be used in a format similar to `gpg` as the `grouplink` CLI currently provides, but we hope that by doing this work now we can also achieve anonymity and plausible deniability for our users without special setup.

## Review of Sealed-Sender

A brief understanding of the current Signal implementation of  "sealed sender"[^sealed-sender] has been summarized and converted into a module docstring in our upstream signal fork [here](https://github.com/cosmicexplorer/libsignal-client/commit/4b25d1a9774a6d3026b14af2b64594639ee1b8e5):

> This is a single-key multi-recipient KEM, defined in Manuel Barbosa's ["Randomness Reuse:
> Extensions and Improvements"](https://haslab.uminho.pt/mbb/files/reuse.pdf). It uses the "Generic Construction" in `4.1` of that paper,
> instantiated with ElGamal encryption.
>
> 1. generate a random [sealed_sender_v2::DerivedKeys].
> 2. encrypt the keypair using a shared secret derived from the sender's private key and
>    recipient's public key (this secret never changes for that pair of identity keys) with
>    [sealed_sender_v2::apply_agreement_xor].
> 3. sign the encrypted keypair using the sender's private key with
>    [sealed_sender_v2::compute_authentication_tag].
> 4. use the keypair from (1) to symmetrically encrypt the underlying
>    [UnidentifiedSenderMessageContent].

This background becomes useful for the following analysis.

## Signal's Simplifying Assumptions

**We would like to enable rotation of static identity keys.**

The above sealed-sender mechanism relies on a shared secret calculated by a DH key agreement using the sender's private key and the recipient's public key. This makes the secret static, since Signal currently makes the implicit assumption that identity keys do not change and therefore key compromise is catastrophic (this corresponds with Signal's stated intent to _not_ try to solve the case of device compromise *(TODO: add citation!)*). Note that the sealed-sender key for _individual_ messages uses randomness generated once per message (see paper linked above), but if a user's device is compromised, the compromise of the identity key means that all sealed-sender messages can then be read. This is especially a concern in our case because we want to be able to send these messages over insecure channels, and Signal retains some control over that by controlling the Signal server, while we want to remove that dependency as an explicit goal (and have been reasonably successful at this so far).

### Towards Identity Key Rotation

One salient feature of the double ratchet[^double-ratchet] mechanism, just as an architectural feature, is how it demarcates the ratcheting keys used for individual messages from long-term identity keys. It is also convenient how Signal separates a `ProtocolAddress` (with a recipient's UUID) from any specific identity key (which then gets looked up according to that UUID in the `IdentityKeyStore`). In particular, while the Signal app seems to apply TOFU when mapping a `ProtocolAddress`'s UUID to an identity key, the elements seem to already be in place to remove that assumption and enable rotation of the identity key corresponding to a user's UUID. This provides a solid foundation for experimenting with key rotation.

### Wrinkle: UUID Rotation <=> Proposed "Sealed-Recipient" Extension

We would like to extend the sealed-sender mechanism to cover encryption of the message *recipient* in a similar way. This was motivated by Moxie explicitly stating that "sealed recipient" would be unsuitable for specifically the Signal service[^sealed-sender]:
> While the service always needs to know where a message should be delivered, ideally it shouldn’t need to know who the sender is.

However, our goal is to separate Signal's message encryption from the Signal service, which lets us relax some assumptions (it also makes our job a little more difficult). In discussion with `@elidupree` and reading up on onion routing[^onion-routing], we realized that communication graph anonymity should probably be considered a necessary goal for `grouplink`, and it seems pretty clear that leaking static global identifiers like the recipient's UUID in a Signal `ProtocolAddress` defeats that (as that can simply be inspected by a passive adversary to remove half of the careful anonymization we would get via e.g. onion routing).

## Analysis of Research Areas

A few things vaguely come together here:
1. **We want to be able to rotate identity keys.** The Signal codebase would make it relatively straightforward to add the ability to rotate the identity key used within a specific Double Ratchet[^double-ratchet] chain, or to modify the mapping of UUID => identity key via `IdentityKeyStoer` (which would allow someone to initiate a new double ratchet chain with that identity).
2. **We want to be able to correctly route messages to a desired sender via some metadata within the message.** Signal currently uses a static UUID for the target of a Signal message for this purpose.
3. **We do not want to leak information from a message that can be correlated to a sender's or recipient's identity** across any earlier or later message within a double ratchet chain.
4. **We want to enable a user to retain multiple disparate identities**, and to share identities across devices.

### Proposed TODO

*Updated 2021-09-25.*

A proposed set of milestones to incrementally achieve the above goals:
1. **Add the ability to send a message which tells `grouplink` clients to start referring to a particular user with a totally new UUID**, which itself should probably be encrypted as part of a double ratchet message chain (as per (3)).
2. **Add the ability to send a message which tells `grouplink` clients to map a particular UUID to a new public key (as per (1)).**
3. **Add the ability to reset the identity key for a user within a particular double ratchet message chain (also as per (1)).**

With the above, we hope to define a protocol that enables sending messages over arbitrary insecure streams, without any particular source of truth except by using a double ratchet message chain which was already securely established. It's not yet clear if this solves the problem of catastrophic private key compromise after the fact, but it *could* enable key rotation to _avoid_ such compromise (and in particular, to enable plausible deniability upon device compromise, if keys and UUIDs are rotated after sending the message that needs to be plausibly denied).

#### Cwtch Research

The *Cwtch* tool is a metadata-resistant secure messaging application which uses the tor network[^cwtch]. In implementing this, OpenPrivacy has *likely* had to figure out some way to **represent users' identities in a way that can be cryptographically authenticated by the intended recipient, but remains meaningless to a passive or active adversary.** We should look very closely at how they achieve this and whether we can rely on their richochet library[^libricochet], either as a direct code dependency, or as a model for how we'd like to structure our approach.

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
[^onion-routing]: https://svn-archive.torproject.org/svn/projects/design-paper/tor-design.pdf
[^cwtch]: https://openprivacy.ca/work/cwtch/
[^libricochet]: https://openprivacy.ca/work/libricochet

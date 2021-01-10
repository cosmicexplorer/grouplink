grouplink
=========

We want to build two prototypes of a cryptosystem to support **anonymous, group-fungible identities**. *Eventually,* our goal is to additionally support **forward-secret verification** and **legacy GPG interop**. We propose to build this on top of the Signal double ratchet [^double-ratchet] and X3DH algorithms [^x3dh] as follows:
1. [*minimal:*](#minimal) use the Signal Protocol (and its constituent algorithms) unchanged, but add endpoints for creating a special new class of *group-fungible* identities.
2. [*full:*](#full) replace a Signal *UserID* with an anonymous identity, and allow all operations to be group-fungible.

The above will be implemented via a CLI tool in Rust, without any concept of a central server yet. We then would like to add:

3. [*gpg:*](#gpg) expose a group message type which creates ephemeral gpg keys for signing, encryption, and/or decryption.

We finally reconstitute this cryptosystem into a messaging system:

4. [*live:*](#live) make a server which supports our modified "grouplink" protocol.

# Minimal

- [x] **Confirmed** that the Signal Protocol itself has no dependency on a phone number, just the app.
- [ ] **TODO: WE ARE HERE** Perform a minimal enc/dec test for a buffer.
    - [ ] Remaining stores to implement:
        - [x] **`crypto_provider`**
        - [x] **`session_store`**
        - [ ] `identity_key_store`
        - [ ] `pre_key_store`
        - [ ] `sender_key_store`
        - [ ] `signed_pre_key_store`
    - [ ] Discuss memory motion through the stores a bit with `@ireneista` and co.
        - Try to agree on which actions/entities each corresponds to in the double-ratchet [^double-ratchet] or sesame [^sesame-paper] protocols.


Then, see if the following still makes sense:
- [ ] Add an "endpoint" to the Signal Protocol to create a new *group-fungible* identity, which doesn't do anything yet.
- [ ] Add corresponding endpoints for:
    - [ ] Adding another such identity to the group.
    - [ ] Sending a message *to* the group.
    - [ ] Sending a message *as* the group (hence making it "group-fungible").

## Completion Criteria
Encrypted messages can be sent between group-fungible identities in a test case.

# Full

- [ ] Modify the Signal Protocol library [^libsignal-protocol-c] to use *group-fungible* identities instead of *UserID*s.
- [ ] Make it work in a CLI tool.
    - i.e. externalize the identities and message keys into concrete files.

## Config Options
Then consider this discussion:
- [ ] Consider the **configuration options** we want to present to the user:
> @turingtarpit
> "think about whether there’s any room for letting the user configure to have degraded service in some situations for increased privacy"
> @ireneista
> there's a trade-off in terms of actually implementing it
> any time you add something the user can configure, if the setting they chose can be detected by an attacker, the attacker can use it to fingerprint them
> so we'll want to provide a minimal number of settings so as not to leak too many bits
>
> yep! 33 bits of entropy identifies anyone (because log base 2 of 8 billion is 33); we can document how much each setting leaks
> though in reality the bits leaked in theory are just an approximation, because users don't choose all possible values uniformly
> but it's still good to document so we can ballpark things

Then consider (more) our approach to elliptic curve encryption:
### Elliptic Curves
- [ ] Consider introducing elliptic curve encryption methods via libgcrypt:
> @vintroxx:
> main benefit of ECC is smaller key lengths but a lot of the curves aren't necessarily trustworthy.
> would recommend curve25519 though
>
> good resource: [^safe-curves]

## Completion Criteria
A Rust CLI tool can create and send group-fungible messages with a modified version of the Signal Protocol library.

# GPG

- [ ] Create a group message type which produces a public/private GPG key pair.
    - This should be very similar to the result of a "DH ratchet" step in the double ratchet protocol [^double-ratchet].
    - This should use `libgcrypt` [^libgcrypt].
- [ ] This should be parameterizable by sign/encrypt/decrypt.
- [ ] This should produce all necessary keys to send an encrypted message from one group to another.
- [ ] This should upload all generated public keys to a keyserver.
- [ ] This should interop with static GPG identities.

## Completion Criteria
Ephemeral GPG identities can be created and used for:
1. [ ] **forward-secret signatures**
2. [ ] **legacy GPG interop**

# Live

- [ ] Create a server implementing the above "grouplink" protocol with GPG support, either by:
    - modifying the Signal Server [^todo-signal-server-security-guarantees] to invoke the rust CLI tool.
    - *(preferred)* creating a rust server which extends the code from the CLI tool.

## Validation/Verification
- [ ] Consider whether the *Cryptol* [^cryptol] tool can validate any properties we want to validate.
- [ ] See whether eBPF could do anything like this as well.

## Completion Criteria
An arbitrary device can perform the operations of the grouplink protocol with GPG support by sending encrypted requests to an external server process.

# Footnotes

[^double-ratchet]: https://signal.org/docs/specifications/doubleratchet/

[^x3dh]: https://signal.org/docs/specifications/x3dh/

[^todo-verify-UUID-uniqueness]: TODO: when is this ever a problem?

[^todo-ssl-sufficient]: TODO: is https/SSL sufficient?

[^todo-threat-model-ratchet]: TODO: threat model this! How does this interact with the ratcheting $SecretIdentity$?

[^signal-docs]: https://signal.org/docs

[^todo-keyserver-redundant]: TODO: does this need to use the keyserver?

[^todo-thread-model-fake-keyserver]: TODO: threat model this! Do we need to worry about fake keyserver data?

[^fake-signal-break]: https://web.archive.org/web/20201210210721/https://www.cellebrite.com/en/blog/cellebrites-new-solution-for-decrypting-the-signal-app/

[^shamirs-secret-sharing]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing

[^paperkey]: https://www.jabberwocky.com/software/paperkey/

[^libgcrypt]: https://en.wikipedia.org/wiki/Libgcrypt

[^w3-did-core]: https://www.w3.org/TR/did-core/

[^w3-creds-data-model]: https://www.w3.org/TR/vc-data-model/

[^libsignal-tips]: https://github.com/signalapp/libsignal-protocol-c#using-libsignal-protocol-c

[^asynchronous-perfect-forward-secrecy-signal]: https://signal.org/blog/asynchronous-security/

[^double-ratchet-wiki]: https://en.wikipedia.org/wiki/Double_Ratchet_Algorithm

[^todo-canonically-describe-anon-identities]: TODO: find/write a good canonical description of anonymous identities!

[^todo-gc-entries-avoid-plaintext]: TODO: this should probably try to gc entries referring to the deleted identity, but we really want to avoid retaining any plaintext data which can link entries across the database in general. This is probably a difficult topic and has some prior art we can refer to.

[^todo-evaluate-whether-pure-stateful-still-matter]: TODO: evaluate whether local <=> pure and remote <=> stateful still makes sense later!

[^multi-armed-bandit]: https://en.wikipedia.org/wiki/Multi-armed_bandit

[^todo-signal-server-security-guarantees]: TODO: dive through the signal server and determine how they describe their own security guarantees: https://github.com/cosmicexplorer/Signal-Server

[^upc]: https://github.com/cosmicexplorer/upc

[^effects-formalization]: file:./effects-appendix.md

[^duality]: https://en.wikipedia.org/wiki/Duality_(mathematics)

[^multi-actor-protocol]: file:./effects-appendix.md#actor-effect-duality

[^signal-groups-paper]: https://eprint.iacr.org/2019/1416.pdf

[^some-graph-anonymization-paper]: ./literature/liu2008-k-anonymity-on-graphs.pdf

[^tofu-wiki]: https://en.wikipedia.org/wiki/Trust_on_first_use

[^web-of-trust-wiki]: https://en.wikipedia.org/wiki/Web_of_trust

[^verified-safety-number-signal]: https://signal.org/blog/verified-safety-number-updates/

[^key-revocation-gpg-blog-post]: https://www.hackdiary.com/2004/01/18/revoking-a-gpg-key/

[^key-revocation-gpg-docs]: https://www.gnupg.org/gph/en/manual/c14.html

[^private-groups-overview-signal]: https://signal.org/blog/private-groups/

[^otr-deniability-signal]: https://signal.org/blog/simplifying-otr-deniability/

[^sealed-sender-signal]: https://signal.org/blog/sealed-sender/

[^asynchronous-perfect-forward-secrecy-signal]: https://signal.org/blog/asynchronous-security/

[^secure-value-recovery-signal]: https://signal.org/blog/secure-value-recovery/

[^private-contact-discovery-signal]: https://signal.org/blog/private-contact-discovery/

[^view-once-messages-signal]: https://signal.org/blog/view-once/

[^federated-systems-are-bad-signal]: https://signal.org/blog/the-ecosystem-is-moving/

[^private-groups-technical-signal]: https://signal.org/blog/signal-private-group-system/

[^safety-number-updates-signal]: https://signal.org/blog/safety-number-updates/

[^castle-continuous-anonymization]: ./literature/jiannengcao2011-castle-continuously-anonymizing-data-streams.pdf

[^magic-wormhole-twitter]: https://twitter.com/patio11/status/1317656122937856003?s=20

[^magic-wormhole-motivation]: https://magic-wormhole.readthedocs.io/en/latest/welcome.html#motivation

[^signal-ratcheting-protocol-wiki]: https://en.wikipedia.org/wiki/Double_Ratchet_Algorithm

[^google-sharing-extension]: https://github.com/DisruptiveStudies/GoogleSharing

[^some-graph-anonymization-paper]: ./literature/liu2008-k-anonymity-on-graphs.pdf

[^tofu-wiki]: https://en.wikipedia.org/wiki/Trust_on_first_use

[^web-of-trust-wiki]: https://en.wikipedia.org/wiki/Web_of_trust

[^verified-safety-number-signal]: https://signal.org/blog/verified-safety-number-updates/

[^key-revocation-gpg-blog-post]: https://www.hackdiary.com/2004/01/18/revoking-a-gpg-key/

[^key-revocation-gpg-docs]: https://www.gnupg.org/gph/en/manual/c14.html

[^private-groups-overview-signal]: https://signal.org/blog/private-groups/

[^otr-deniability-signal]: https://signal.org/blog/simplifying-otr-deniability/

[^sealed-sender-signal]: https://signal.org/blog/sealed-sender/

[^encrypted-profiles-beta-signal]: https://signal.org/blog/signal-profiles-beta/

[^asynchronous-perfect-forward-secrecy-signal]: https://signal.org/blog/asynchronous-security/

[^secure-value-recovery-signal]: https://signal.org/blog/secure-value-recovery/

[^private-contact-discovery-signal]: https://signal.org/blog/private-contact-discovery/

[^view-once-messages-signal]: https://signal.org/blog/view-once/

[^federated-systems-are-bad-signal]: https://signal.org/blog/the-ecosystem-is-moving/

[^private-groups-technical-signal]: https://signal.org/blog/signal-private-group-system/

[^safety-number-updates-signal]: https://signal.org/blog/safety-number-updates/

[^castle-continuous-anonymization]: ./literature/jiannengcao2011-castle-continuously-anonymizing-data-streams.pdf

[^magic-wormhole-twitter]: https://twitter.com/patio11/status/1317656122937856003?s=20

[^magic-wormhole-motivation]: https://magic-wormhole.readthedocs.io/en/latest/welcome.html#motivation

[^signal-ratcheting-protocol-wiki]: https://en.wikipedia.org/wiki/Double_Ratchet_Algorithm

[^google-sharing-extension]: https://github.com/DisruptiveStudies/GoogleSharing

[^sesame-paper]: https://signal.org/docs/specifications/sesame/sesame.pdf

[^giving-up-on-pgp]: https://blog.filippo.io/giving-up-on-long-term-pgp/

[^zk-proof]: https://en.wikipedia.org/wiki/Zero-knowledge_proof

[^safe-curves]: https://safecurves.cr.yp.to/

[^cryptol]: https://cryptol.net/

<!-- Local Variables: -->
<!-- markdown-list-indent-width: 4 -->
<!-- End: -->

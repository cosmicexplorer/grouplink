Constant Rotation of Identity Keys and Using Clients as Keyservers
==================================================================

*TODO: improve the title!*

# A: enabling rotation of long-term identity keys
oh and yes! i have shifted my focus to merely making a long-term key less of a liability (in particular, to be able to migrate existing conversations to use a new public key for me instead, allowing me to destroy the old key). however, that doesn't address the issue (that exists in gpg as well), where i also want someone new to be able to *initiate* a conversation with me who hasn't before. keyservers exist for this in gpg, and `libsignal_protocol` enables updating the public key attached to a `ProtocolAddress` UUID on a particular client, so the foundation is there.

*note*: ideally we would ratchet the conversation-specific asymmetric keypair upon every message in a double ratchet chain, but we can start by just explicitly being able to tell someone to update the keypair globally, before implementing conversation-specific keypairs.

# B: decoupling long-term identity keys from conversation-specific keys
i think my annoyance is that posting a key publicly at all can become a liability if the private part of that key is compromised. i think what i want is to be able to separate the public key posted to a keyserver from the `IdentityKey` public key which is used e.g. to authenticate signed pre-keys (used to initiate a message chain) and to authenticate sealed-sender messages i send to others. this would mean that posting a key publicly would be a liability only until that key is rotated by sending an encrypted update to a keyserver. however, this still would mean i would need to retain a private key on my device corresponding to my posted public key at all times, which retains the liability, although less of a problem.

# C: delegation of conversation-initiating keys
*this begins to look a lot more like signal's server, and i think that's a good sign!*
this is the fun part. we can require the keyserver to act as a delegate to hand out keys to people wishing to contact me. so this requires A and B to work:
1. i initiate a message chain with a keyserver somehow, using a keypair i've created for the occasion. i then use B to immediately tell the keyserver to use a new keypair for me in this conversation, and throw away the initial keypair. i then provide some number of randomly-generated public keys to the keyserver (to be replenished as frequently as necessary).
2. when someone wishes to contact me whom i've never spoken to before, they initiate (or continue) a message chain with the keyserver, send a request to the keyserver, and provide a public key they've created just for this occasion. the keyserver returns one of my public keys Y, then leaves a message in my "mailbox" saying that public key X is going to contact me using my randomly-generated public key Y. the keyserver then deletes Y and doesn't use it again.
3. i periodically check my mailbox from the keyserver, and if i see that external public key X maps to my public key Y, i will calculate a string of bytes Z from the "agreement" of public X and my private Y (signal's sealed sender v2 does this--essentially a DH exchange using two keypairs to provide the inputs), store the mapping X->Z on my client, then delete the private Y. i generate *both* a keypair Z and a symmetric key Z' from the bytes for Z.
4. i receive a message from some messaging channel one day which states that it is sent using public key Z, and provides an authentication tag for the ciphertext which authenticates that the holder owns the private key of Z. i then use Z' (the holder of X can calculate Z and Z' from public Y and private X) to symmetrically decrypt the message. the message contains a new keypair to use for the other conversation participant (as per B). i send a message back with a new keypair to use for me, and we can now initiate a normal signal message chain.

## results
- a crooked keyserver *cannot* calculate Z, so it cannot correlate the later message to X's initial keyserver contact
- if a crooked keyserver modifies the value of public X, the later message will be meaningless to me and still cannot be correlated with the keyserver contact
- the holder of X can immediately destroy X after sending the initial message to me
- the private keys for Y will have to be stored for some time, but it is possible to place the private keys for Y in a *separate storage location* than the device used for communication. this part is an extension of the greatest power of the signal protocol, which is to separate message chains from identity keys. it is *expected* that most encrypted messaging is an extension of an existing message chain.

# D: we are all keyservers
i guess finally, it would be very good to cut out the keyserver altogether if someone i haven't messaged with before has a "mutual friend" with me. in that case the mutual friend could perform the job of the keyserver (i.e. the keyserver operations could be performed by any client). this tidies up C quite a lot by making any client at all be able to act as a keyserver, which means a keyserver could just be a normal client instance.

# epilogue

these thoughts came about from diving into the sealed sender logic quite deeply over the week in https://github.com/signalapp/libsignal-client/pull/366 and i think C and D together actually finally cracks the thing i've been trying to figure out for a while, which is how to make use of existing trust mechanisms from existing conversations to bootstrap a new conversation. i'll have to put these thoughts into a doc and then think about it in the morning, but the bit about using a key agreement to calculate Z and Z' to avoid trusting the keyserver is pretty exciting.

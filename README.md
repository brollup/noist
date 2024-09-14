# NOIST
NOIST is a non-interactive, single-round t-of-n threshold signing scheme.

NOIST allows multiple untrusted entities to come together and jointly produce a group key and generate signatures in constant time, where a disruptive signer cannot force a re-do of the entire round. The resulting signature is a single 64-byte  [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)  compatible Schnorr signature.
#![allow(dead_code)]

use sha2::Digest as _;
use sha2::Sha256;

type Bytes = Vec<u8>;

pub fn sha_256(data: impl AsRef<[u8]>) -> [u8; 32] {
    let hash: [u8; 32] = Sha256::new().chain_update(&data).finalize().into();
    hash
}

pub fn hash_256(data: impl AsRef<[u8]>) -> [u8; 32] {
    let hash: [u8; 32] = sha_256(sha_256(data));
    hash
}

pub enum HashTag {
    BindingValue,
    DeterministicNonce,
    BIP0340Challenge,
    ProtocolMessageChallenge,
    CustomMessageChallenge,
    CustomTag(String),
}

pub fn tagged_hash(data: impl AsRef<[u8]>, tag: HashTag) -> [u8; 32] {
    let mut preimage = Vec::<u8>::new();

    let tag_digest = match tag {
        HashTag::BindingValue => Sha256::digest("Spine/bindingvalue"),
        HashTag::DeterministicNonce => Sha256::digest("Spine/deterministicnonce"),
        HashTag::BIP0340Challenge => Sha256::digest("BIP0340/challenge"),
        HashTag::ProtocolMessageChallenge => Sha256::digest("Spine/protocolmessage/challenge"),
        HashTag::CustomMessageChallenge => Sha256::digest("Spine/custommessage/challenge"),
        HashTag::CustomTag(tag) => Sha256::digest(tag),
    };

    preimage.extend(tag_digest);
    preimage.extend(tag_digest);
    preimage.extend(data.as_ref());

    sha_256(preimage)
}
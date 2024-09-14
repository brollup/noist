use crate::into::SecpError;
use secp::{MaybePoint, MaybeScalar, Point, Scalar};

pub fn vse_encrypting_key_secret(self_secret: Scalar, to_public: Point) -> Scalar {
    let secret_point = self_secret * to_public;

    let secret_point_xbytes = secret_point.serialize_xonly();

    let shared_secret = Scalar::reduce_from(&secret_point_xbytes);

    shared_secret
}

pub fn vse_encrypting_key_public(self_secret: Scalar, to_public: Point) -> Point {
    vse_encrypting_key_secret(self_secret, to_public).base_point_mul()
}

pub fn vse_encrypt(
    secret_to_encrypt: Scalar,
    encrypting_key_secret: Scalar,
) -> Result<Scalar, SecpError> {
    match secret_to_encrypt + encrypting_key_secret {
        MaybeScalar::Valid(scalar) => Ok(scalar),
        MaybeScalar::Zero => Err(SecpError::InvalidScalar),
    }
}

pub fn vse_decrypt(
    secret_to_decrypt: Scalar,
    encrypting_key_secret: Scalar,
) -> Result<Scalar, SecpError> {
    match secret_to_decrypt - encrypting_key_secret {
        MaybeScalar::Valid(scalar) => Ok(scalar),
        MaybeScalar::Zero => Err(SecpError::InvalidScalar),
    }
}

pub fn vse_verify(
    encrypted_share_scalar: Scalar,
    public_share_point: Point,
    encrypting_key_public: Point,
) -> bool {
    let combined_point = encrypted_share_scalar.base_point_mul();

    combined_point
        == match public_share_point + encrypting_key_public {
            MaybePoint::Valid(point) => point,
            MaybePoint::Infinity => return false,
        }
}

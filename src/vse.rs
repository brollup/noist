use crate::into::SecpError;
use secp::{MaybePoint, MaybeScalar, Point, Scalar};

pub fn vse_encryption_secret(self_secret: Scalar, to_public: Point) -> Scalar {
    let secret_point = self_secret * to_public;

    let secret_point_xbytes = secret_point.serialize_xonly();

    let shared_secret = Scalar::reduce_from(&secret_point_xbytes);

    shared_secret
}

pub fn vse_encryption_public(self_secret: Scalar, to_public: Point) -> Point {
    let secret_point = self_secret * to_public;

    let secret_point_xbytes = secret_point.serialize_xonly();

    let shared_secret = Scalar::reduce_from(&secret_point_xbytes);

    let shared_public = shared_secret.base_point_mul();

    shared_public
}

pub fn vse_encrypt(
    secret_to_encrypt: Scalar,
    encryption_secret: Scalar,
) -> Result<Scalar, SecpError> {
    match secret_to_encrypt + encryption_secret {
        MaybeScalar::Valid(scalar) => Ok(scalar),
        MaybeScalar::Zero => Err(SecpError::InvalidScalar),
    }
}

pub fn vse_decrypt(
    secret_to_decrypt: Scalar,
    encryption_secret: Scalar,
) -> Result<Scalar, SecpError> {
    match secret_to_decrypt - encryption_secret {
        MaybeScalar::Valid(scalar) => Ok(scalar),
        MaybeScalar::Zero => Err(SecpError::InvalidScalar),
    }
}

pub fn vse_verify(
    encrypted_share_scalar: Scalar,
    public_share_point: Point,
    encryption_point: Point,
) -> bool {
    let combined_point = encrypted_share_scalar.base_point_mul();

    combined_point
        == match public_share_point + encryption_point {
            MaybePoint::Valid(point) => point,
            MaybePoint::Infinity => return false,
        }
}

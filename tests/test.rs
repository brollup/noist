mod core_tests {
    use secp::Scalar;
    use noist::{
        secret::{secret_share_combine, secret_share_gen},
        vss::vss_verify_secret,
    };

    #[test]
    fn test_main() {
        let hex = "781650e9b6e646b581cff8ddb57017177d832a7f3d8086aa32117c1a91b8b5cf";
        let secret = hex.parse::<Scalar>().unwrap();

        let (secrets, group_key, vss_commitments) = secret_share_gen(secret, 5, 3).unwrap();

        println!(
            "group key is : {}",
            hex::encode(group_key.serialize().to_vec())
        );

        for (index, secret) in secrets.iter().enumerate() {
            println!(
                "secret share {} is : {}, {}",
                index,
                hex::encode(secret.0.serialize().to_vec()),
                hex::encode(secret.1.serialize().to_vec())
            );

            println!(
                "vss verify: {}",
                vss_verify_secret((secret.0, secret.1), &vss_commitments)
            );
        }

        let x1_bytes = "0000000000000000000000000000000000000000000000000000000000000001";
        let x1: Scalar = x1_bytes.parse::<Scalar>().unwrap();

        let y1_bytes = "d7b484b748281b20095bbbd967a4c3f62af09b37e422b2b0556455f04fe77202";
        let y1: Scalar = y1_bytes.parse::<Scalar>().unwrap();

        let x2_bytes = "0000000000000000000000000000000000000000000000000000000000000002";
        let x2: Scalar = x2_bytes.parse::<Scalar>().unwrap();

        let y2_bytes = "d665f2ffaf1546a693ee6b0dc24bfaa187939119ea23991c5106b34506889286";
        let y2: Scalar = y2_bytes.parse::<Scalar>().unwrap();

        let x3_bytes = "0000000000000000000000000000000000000000000000000000000000000003";
        let x3: Scalar = x3_bytes.parse::<Scalar>().unwrap();

        let y3_bytes = "c1a24473318c1e402fcf425258af63f41996e83df7aa8b6af37b6fe9cc8c929c";
        let y3: Scalar = y3_bytes.parse::<Scalar>().unwrap();

        let mut shares = Vec::<(Scalar, Scalar)>::new();

        shares.push((x1, y1));
        shares.push((x2, y2));
        shares.push((x3, y3));

        let s = secret_share_combine(&shares, 3).unwrap();

        println!("laooo {}", hex::encode(s.serialize().to_vec()));
    }
}

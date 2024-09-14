mod single_tests {
    use noist::{
        into::{IntoByteArray, SecpError},
        schnorr::{sign_schnorr, verify_schnorr, SignFlag},
    };

    #[test]
    fn test_sign_schnorr_single() -> Result<(), SecpError> {
        let message =
            hex::decode("e97f06fabc231539119048bd3c55d0aa6015ed157532e6a5e6fb15aae331791d")
                .unwrap();
        let private_key =
            hex::decode("09f5dde60c19101b671a5e3f4e6f0c0aaa92814170edf7f6bc19b5a21e358a51")
                .unwrap();
        // corresponding public key: 02dee61ab0f4cb3a993cb13c552e44f5abfbf1b377c08b0380da14de41234ea8bd

        let sig_expected = hex::decode("47698380a92278684fe8a8f744f270fed68da78ea882a673d98c519e4e512c39065f34b452aeebf5ed276eb1100cd229bf10dadd78e4dd5b568eea12a3f7bc67").unwrap();

        let sig: [u8; 64] = sign_schnorr(
            private_key
                .into_byte_array_32()
                .map_err(|_| SecpError::SignatureParseError)?,
            message
                .into_byte_array_32()
                .map_err(|_| SecpError::SignatureParseError)?,
            SignFlag::BIP0340Sign,
        )?;

        assert_eq!(sig.to_vec(), sig_expected);

        Ok(())
    }

    #[test]
    fn test_verify_schnorr_single() -> Result<(), SecpError> {
        let message =
            hex::decode("e97f06fabc231539119048bd3c55d0aa6015ed157532e6a5e6fb15aae331791d")
                .unwrap();

        let public_key =
            hex::decode("dee61ab0f4cb3a993cb13c552e44f5abfbf1b377c08b0380da14de41234ea8bd")
                .unwrap();

        // corresponding secret key: 09f5dde60c19101b671a5e3f4e6f0c0aaa92814170edf7f6bc19b5a21e358a51

        let signature = hex::decode("47698380a92278684fe8a8f744f270fed68da78ea882a673d98c519e4e512c39065f34b452aeebf5ed276eb1100cd229bf10dadd78e4dd5b568eea12a3f7bc67").unwrap();

        verify_schnorr(
            public_key
                .into_byte_array_32()
                .map_err(|_| SecpError::SignatureParseError)?,
            message
                .into_byte_array_32()
                .map_err(|_| SecpError::SignatureParseError)?,
            signature
                .into_byte_array_64()
                .map_err(|_| SecpError::SignatureParseError)?,
            SignFlag::BIP0340Sign,
        )
    }
}

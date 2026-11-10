use crate::error::EpicAuthError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn verify_signature(
    public_key_hex: &str,
    signature_hex: &str,
    message: &[u8],
) -> Result<bool, EpicAuthError> {
    let pub_bytes = hex::decode(public_key_hex)
        .map_err(|e| EpicAuthError::CryptoError(format!("Failed to decode public key hex: {e}")))?;

    let pub_array: [u8; 32] = pub_bytes.as_slice().try_into().map_err(|_| {
        EpicAuthError::CryptoError("Invalid public key length (expected 32 bytes)".into())
    })?;

    let verifying_key = VerifyingKey::from_bytes(&pub_array)
        .map_err(|e| EpicAuthError::CryptoError(format!("Invalid verifying key: {e}")))?;

    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| EpicAuthError::CryptoError(format!("Failed to decode signature hex: {e}")))?;

    let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        EpicAuthError::CryptoError("Invalid signature length (expected 64 bytes)".into())
    })?;

    let signature = Signature::from_bytes(&sig_array);

    Ok(verifying_key.verify(message, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_signature_verify() {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let message = b"1234567890{\"success\":true}";
        let sig = signing_key.sign(message);

        let pub_hex = hex::encode(verifying_key.to_bytes());
        let sig_hex = hex::encode(sig.to_bytes());

        let res = verify_signature(&pub_hex, &sig_hex, message).unwrap();
        assert!(res);
    }

    #[test]
    fn test_sha256() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}

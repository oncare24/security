use std::time::SystemTime;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};

use crypto_core::crypto::backends::{
    AeadBackend, AeadBackendError, AeadEncrypted, DATA_KEY_SIZE, NONCE_SIZE, SecureRandom,
    TAG_SIZE,
};
use crypto_core::domain::encrypted_log::EncryptedLogData;

use crate::os_secure_random::OsSecureRandom;

#[derive(Debug, Default, Clone, Copy)]
pub struct AESGCMCrypto;

pub type AESGCMCryptoError = AeadBackendError;

impl AESGCMCrypto {
    // 평문과 32바이트 key를 받아 암호화
    pub fn encrypt(
        plaintext: &[u8],
        key: &[u8; 32],
    ) -> Result<EncryptedLogData, AESGCMCryptoError> {
        Self::encrypt_with_metadata(0, 0, "", plaintext, key)
    }

    //난수를 랜덤 생성하고 aes-gcm 암호화를 수행하고 결과 객체 생성
    pub fn encrypt_with_metadata(
        encrypted_log_id: u64,
        user_id: u64,
        key_id: impl Into<String>,
        plaintext: &[u8],
        key: &[u8; 32],
    ) -> Result<EncryptedLogData, AESGCMCryptoError> {
        let mut iv = [0u8; NONCE_SIZE];
        OsSecureRandom
            .fill_bytes(&mut iv)
            .map_err(|_| AESGCMCryptoError::EncryptionFailed)?;
        let encrypted = AeadBackend::encrypt_detached(&AESGCMCrypto, key, &iv, plaintext, b"")?;

        Ok(EncryptedLogData::new(
            encrypted_log_id,
            user_id,
            encrypted.ciphertext,
            iv,
            encrypted.tag,
            key_id,
            SystemTime::now(),
        ))
    }

    //복호화
    pub fn decrypt(
        encrypted: EncryptedLogData,
        key: &[u8; 32],
    ) -> Result<Vec<u8>, AESGCMCryptoError> {
        Self::decrypt_ref(&encrypted, key)
    }

    // decrypt_ref 함수는 암호문과 키 정보를 사용해 원문을 복원
    pub fn decrypt_ref(
        encrypted: &EncryptedLogData,
        key: &[u8; 32],
    ) -> Result<Vec<u8>, AESGCMCryptoError> {
        AeadBackend::decrypt_detached(
            &AESGCMCrypto,
            key,
            &encrypted.iv,
            &encrypted.ciphertext,
            &encrypted.tag,
            b"",
        )
    }
}

impl AeadBackend for AESGCMCrypto {
    //복호화 하는 과정
    fn encrypt_detached(
        &self,
        key: &[u8; DATA_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<AeadEncrypted, AeadBackendError> {
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| AeadBackendError::EncryptionFailed)?;
        let nonce = Nonce::from_slice(nonce);
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, aad, &mut ciphertext)
            .map_err(|_| AeadBackendError::EncryptionFailed)?;

        let mut tag_bytes = [0u8; TAG_SIZE];
        tag_bytes.copy_from_slice(tag.as_slice());

        Ok(AeadEncrypted::new(ciphertext, tag_bytes))
    }

    // decrypt_detached 함수는 암호문과 키 정보를 사용해 원문을 복원
    fn decrypt_detached(
        &self,
        key: &[u8; DATA_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
        tag: &[u8; TAG_SIZE],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadBackendError> {
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| AeadBackendError::DecryptionFailed)?;
        let nonce = Nonce::from_slice(nonce);
        let tag = Tag::from_slice(tag);
        let mut plaintext = ciphertext.to_vec();

        cipher
            .decrypt_in_place_detached(nonce, aad, &mut plaintext, tag)
            .map_err(|_| AeadBackendError::DecryptionFailed)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::AESGCMCrypto;

    // encrypt_and_decrypt_round_trip 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
    #[test]
    fn encrypt_and_decrypt_round_trip() {
        let key = [7u8; 32];
        let plaintext = b"security log payload";

        let encrypted = AESGCMCrypto::encrypt(plaintext, &key).expect("encryption should work");
        let decrypted = AESGCMCrypto::decrypt_ref(&encrypted, &key).expect("decryption should work");

        assert_eq!(decrypted, plaintext);
    }

    // tampered_tag_fails_validation 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
    #[test]
    fn tampered_tag_fails_validation() {
        let key = [9u8; 32];
        let plaintext = b"tamper check";

        let mut encrypted = AESGCMCrypto::encrypt(plaintext, &key).expect("encryption should work");
        encrypted.tag[0] ^= 0xFF;

        let result = AESGCMCrypto::decrypt_ref(&encrypted, &key);

        assert!(result.is_err());
    }
}

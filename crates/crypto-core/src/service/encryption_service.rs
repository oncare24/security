use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use crate::crypto::backends::{
    AeadBackend, AeadBackendError, NONCE_SIZE, SecureRandom, SecureRandomError,
};
use crate::domain::Timestamp;
use crate::domain::crypto_package::CryptoPackage;
use crate::domain::data_key::DataKey;
use crate::domain::encrypted_log::EncryptedLogData;
use crate::service::key_management_service::{
    KeyManagementService, KeyManagementServiceError,
};

static NEXT_ENCRYPTED_LOG_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct EncryptionRequest {
    pub log_data: Vec<u8>,
    pub user_id: u64,
    pub user_public_key: Vec<u8>,
    pub guardian_id: u64,
    pub guardian_public_key: Vec<u8>,
}

impl EncryptionRequest {
    pub fn new(
        log_data: impl Into<Vec<u8>>,
        user_id: u64,
        user_public_key: impl Into<Vec<u8>>,
        guardian_id: u64,
        guardian_public_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            log_data: log_data.into(),
            user_id,
            user_public_key: user_public_key.into(),
            guardian_id,
            guardian_public_key: guardian_public_key.into(),
        }
    }
}

#[derive(Debug)]
pub enum EncryptionServiceError {
    Aead(AeadBackendError),
    Random(SecureRandomError),
    KeyManagement(KeyManagementServiceError),
}

impl fmt::Display for EncryptionServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead(error) => write!(f, "{error}"),
            Self::Random(error) => write!(f, "{error}"),
            Self::KeyManagement(error) => write!(f, "{error}"),
        }
    }
}

impl Error for EncryptionServiceError {}

impl From<AeadBackendError> for EncryptionServiceError {
    fn from(value: AeadBackendError) -> Self {
        Self::Aead(value)
    }
}

impl From<SecureRandomError> for EncryptionServiceError {
    fn from(value: SecureRandomError) -> Self {
        Self::Random(value)
    }
}

impl From<KeyManagementServiceError> for EncryptionServiceError {
    fn from(value: KeyManagementServiceError) -> Self {
        Self::KeyManagement(value)
    }
}

pub struct EncryptionService {
    key_management_service: KeyManagementService,
    aead_backend: Arc<dyn AeadBackend>,
    secure_random: Arc<dyn SecureRandom>,
}

impl EncryptionService {
    // AeadBackend, SecureRandom, KeyManagementService를 받아 EncryptionService를 만듦
    pub fn with_dependencies(
        aead_backend: Arc<dyn AeadBackend>,
        secure_random: Arc<dyn SecureRandom>,
        key_management_service: KeyManagementService,
    ) -> Self {
        Self {
            key_management_service,
            aead_backend,
            secure_random,
        }
    }

    // encryptionReuest와 datakey를 받고 현재 시각을 기입함
    pub fn encrypt_log_with_data_key(
        &self,
        request: EncryptionRequest,
        data_key: &DataKey,
    ) -> Result<CryptoPackage, EncryptionServiceError> {
        self.encrypt_log_with_data_key_at(request, data_key, SystemTime::now())
    }


    pub fn encrypt_log_with_data_key_at(
        &self,
        request: EncryptionRequest,
        data_key: &DataKey,
        timestamp: Timestamp,
    ) -> Result<CryptoPackage, EncryptionServiceError> {
        // 평문을 aes-gcm으로 암호화
        let encrypted_data = self.encrypt_payload(
            &request.log_data,
            request.user_id,
            &data_key.key_id,
            &data_key.key_value,
            timestamp,
        )?;
        // 사용자 공개키로 user envelope 생성
        let user_envelope = self.key_management_service.create_user_key_envelope(
            data_key,
            request.user_id,
            &request.user_public_key,
        )?;
        // 보호자 공개키로 guardian evelope 생성
        let guardian_envelope = self.key_management_service.create_guardian_key_envelope(
            data_key,
            request.guardian_id,
            &request.guardian_public_key,
        )?;
        //셋을 묶어서 암호화패키지로 반환
        Ok(CryptoPackage::new(
            encrypted_data,
            user_envelope,
            guardian_envelope,
        ))
    }

    // 본문 암호화를 담당하는 내부 함수
    fn encrypt_payload(
        &self,
        plaintext: &[u8],
        user_id: u64,
        key_id: &str,
        key_value: &[u8; 32],
        created_at: Timestamp,
    ) -> Result<EncryptedLogData, EncryptionServiceError> {
        let encrypted_log_id = NEXT_ENCRYPTED_LOG_ID.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; NONCE_SIZE];
        self.secure_random.fill_bytes(&mut nonce)?;
        let encrypted = self
            .aead_backend
            .encrypt_detached(key_value, &nonce, plaintext, b"")?;

        Ok(EncryptedLogData::new(
            encrypted_log_id,
            user_id,
            encrypted.ciphertext,
            nonce,
            encrypted.tag,
            key_id.to_string(),
            created_at,
        ))
    }
}

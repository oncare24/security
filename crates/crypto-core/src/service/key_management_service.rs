use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::crypto::backends::{KemBackend, KemBackendError};
use crate::crypto::key_wrap::{KeyWrapError, unwrap_data_key, wrap_data_key};
use crate::domain::data_key::DataKey;
use crate::domain::key_envelope::{KeyEnvelope, OwnerType};

static NEXT_ENVELOPE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
// 키 관리 과정에서 생길 수 있는 에러를 묶음
pub enum KeyManagementServiceError {
    Kem(KemBackendError),
    KeyWrap(KeyWrapError),
}

// ml-kem 처리 실패나 data key를 감싸고 푸는 과정 실패 에러
impl fmt::Display for KeyManagementServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kem(error) => write!(f, "{error}"),
            Self::KeyWrap(error) => write!(f, "{error}"),
        }
    }
}

impl Error for KeyManagementServiceError {}

impl From<KemBackendError> for KeyManagementServiceError {
    fn from(value: KemBackendError) -> Self {
        Self::Kem(value)
    }
}

impl From<KeyWrapError> for KeyManagementServiceError {
    fn from(value: KeyWrapError) -> Self {
        Self::KeyWrap(value)
    }
}

pub struct KeyManagementService {
    kem_backend: Arc<dyn KemBackend>,
}

impl KeyManagementService {
    //어떤 kem backend를 사용할지 넣어서 keymanagementservice 생성
    pub fn with_kem_backend(kem_backend: Arc<dyn KemBackend>) -> Self {
        Self { kem_backend }
    }

    pub fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), KeyManagementServiceError> {
        Ok(self.kem_backend.generate_keypair()?)
    }

    //사용자용 envelope를 생성
    pub fn create_user_key_envelope(
        &self,
        data_key: &DataKey,
        user_id: u64,
        user_public_key: &[u8],
    ) -> Result<KeyEnvelope, KeyManagementServiceError> {
        self.create_key_envelope(data_key, user_id, OwnerType::User, user_public_key)
    }

    //보호자용 envelope를 생성
    pub fn create_guardian_key_envelope(
        &self,
        data_key: &DataKey,
        guardian_id: u64,
        guardian_public_key: &[u8],
    ) -> Result<KeyEnvelope, KeyManagementServiceError> {
        self.create_key_envelope(
            data_key,
            guardian_id,
            OwnerType::Guardian,
            guardian_public_key,
        )
    }

    pub fn create_key_envelope(
        &self,
        data_key: &DataKey,
        owner_id: u64,
        owner_type: OwnerType,
        public_key: &[u8],
    ) -> Result<KeyEnvelope, KeyManagementServiceError> {
        // envelope id 생성
        let envelope_id = NEXT_ENVELOPE_ID.fetch_add(1, Ordering::Relaxed);
        // public key로 kem 캡슐화 수행
        let encapsulation = self.kem_backend.encapsulate(public_key)?;
        // shared secret로 데이터 키 감쌈
        let encapsulated_key = wrap_data_key(&data_key.key_value, &encapsulation.shared_secret)?;

        Ok(KeyEnvelope::new(
            envelope_id,
            data_key.key_id.clone(),
            owner_id,
            owner_type,
            encapsulation.ciphertext,
            encapsulated_key,
        ))
    }

    //envelope 안에 들어 있는 data key를 푸는 과정
    pub fn open_key_envelope(
        &self,
        envelope: &KeyEnvelope,
        private_key: &[u8],
    ) -> Result<[u8; 32], KeyManagementServiceError> {
        let shared_secret = self
            .kem_backend
            .decapsulate(&envelope.kem_ciphertext, private_key)?;

        Ok(unwrap_data_key(&envelope.encapsulated_key, &shared_secret)?)
    }
}

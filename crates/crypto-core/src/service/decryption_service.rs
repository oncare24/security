use std::error::Error;
use std::fmt;
use std::sync::Arc;

use crate::crypto::backends::{AeadBackend, AeadBackendError, KemBackend, KemBackendError};
use crate::crypto::key_wrap::{KeyWrapError, unwrap_data_key};
use crate::domain::crypto_package::CryptoPackage;
use crate::domain::key_envelope::{KeyEnvelope, OwnerType};

// 복호화를 요청한 사람이 누구인지 나타냄
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptionCaller {
    pub owner_id: u64,
    pub owner_type: OwnerType,
}

impl DecryptionCaller {
    // new 함수는 필요한 값을 받아 새 인스턴스를 생성
    pub fn new(owner_id: u64, owner_type: OwnerType) -> Self {
        Self {
            owner_id,
            owner_type,
        }
    }
}

//복호화 과정에서 발생할 수 있는 에러들을 모아둔 enum
#[derive(Debug)]
pub enum DecryptionServiceError {
    Kem(KemBackendError),
    Aead(AeadBackendError),
    KeyWrap(KeyWrapError),
    EnvelopeNotFound { owner_id: u64, owner_type: OwnerType },
    KeyIdMismatch,
}

impl fmt::Display for DecryptionServiceError {
    // fmt 함수는 값이나 에러를 사람이 읽기 쉬운 문자열로 포맷
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kem(error) => write!(f, "{error}"),
            Self::Aead(error) => write!(f, "{error}"),
            Self::KeyWrap(error) => write!(f, "{error}"),
            Self::EnvelopeNotFound {
                owner_id,
                owner_type,
            } => write!(
                f,
                "no key envelope found for owner_id={owner_id} and owner_type={owner_type:?}"
            ),
            Self::KeyIdMismatch => write!(f, "key envelope does not match encrypted log key id"),
        }
    }
}

//다른 파일의 세부 에러를 자동 변환해주는 부분
impl Error for DecryptionServiceError {}

impl From<KemBackendError> for DecryptionServiceError {
    // from 함수는 외부 타입과 내부 타입 사이의 값을 변환
    fn from(value: KemBackendError) -> Self {
        Self::Kem(value)
    }
}

impl From<AeadBackendError> for DecryptionServiceError {
    // from 함수는 외부 타입과 내부 타입 사이의 값을 변환
    fn from(value: AeadBackendError) -> Self {
        Self::Aead(value)
    }
}

impl From<KeyWrapError> for DecryptionServiceError {
    // from 함수는 외부 타입과 내부 타입 사이의 값을 변환
    fn from(value: KeyWrapError) -> Self {
        Self::KeyWrap(value)
    }
}

pub struct DecryptionService {
    kem_backend: Arc<dyn KemBackend>,
    aead_backend: Arc<dyn AeadBackend>,
}

impl DecryptionService {
    // 복호화 서비스가 사용할 backend를 주입받는 부분
    pub fn with_backends(
        aead_backend: Arc<dyn AeadBackend>,
        kem_backend: Arc<dyn KemBackend>,
    ) -> Self {
        Self {
            kem_backend,
            aead_backend,
        }
    }

    // decrypt_log 함수는 암호문과 키 정보를 사용해 원문을 복원
    pub fn decrypt_log(
        &self,
        crypto_package: &CryptoPackage,
        caller: DecryptionCaller,
        private_key: &[u8],
    ) -> Result<Vec<u8>, DecryptionServiceError> {
        //caller에 맞는 envelope 선택
        let envelope = self.select_envelope(crypto_package, caller)?;

        //envelope가 encrypted log와 같은 key를 가리키는지 확인
        if envelope.key_id != crypto_package.encrypted_data.key_id {
            return Err(DecryptionServiceError::KeyIdMismatch);
        }

        //shared secret 복원
        let shared_secret = self
            .kem_backend
            .decapsulate(&envelope.kem_ciphertext, private_key)?;
        //data key 복원
        let data_key = unwrap_data_key(&envelope.encapsulated_key, &shared_secret)?;
        //aes-gcm으로 평문 복원
        let plaintext = self.aead_backend.decrypt_detached(
            &data_key,
            &crypto_package.encrypted_data.iv,
            &crypto_package.encrypted_data.ciphertext,
            &crypto_package.encrypted_data.tag,
            b"",
        )?;
        
        Ok(plaintext)
    }

    // 사용자인지 보호자인지 고르는 보조 함수
    fn select_envelope<'a>(
        &self,
        crypto_package: &'a CryptoPackage,
        caller: DecryptionCaller,
    ) -> Result<&'a KeyEnvelope, DecryptionServiceError> {
        let candidates = [
            &crypto_package.user_envelope,
            &crypto_package.guardian_envelope,
        ];

        candidates
            .into_iter()
            .find(|envelope| {
                envelope.owner_id == caller.owner_id && envelope.owner_type == caller.owner_type
            })
            .ok_or(DecryptionServiceError::EnvelopeNotFound {
                owner_id: caller.owner_id,
                owner_type: caller.owner_type,
            })
    }
}

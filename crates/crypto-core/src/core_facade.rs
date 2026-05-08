use std::error::Error;
use std::fmt;
use std::sync::Arc;

use crate::crypto::backends::{
    AeadBackend, KemBackend, KemBackendError, SecureRandom, SecureRandomError,
};
use crate::domain::Timestamp;
use crate::domain::crypto_package::CryptoPackage;
use crate::domain::data_key::DataKey;
use crate::domain::key_envelope::{KeyEnvelope, OwnerType};
use crate::service::decryption_service::{
    DecryptionCaller, DecryptionService, DecryptionServiceError,
};
use crate::service::encryption_service::{
    EncryptionRequest, EncryptionService, EncryptionServiceError,
};
use crate::service::key_management_service::{KeyManagementService, KeyManagementServiceError};
use crate::service::sharing_service::{SharingService, SharingServiceError};

//퍼사드 레벨의 상위 에러 enum
#[derive(Debug)]
pub enum CoreFacadeError {
    Random(SecureRandomError),
    Kem(KemBackendError),
    Encryption(EncryptionServiceError),
    Decryption(DecryptionServiceError),
    KeyManagement(KeyManagementServiceError),
    Sharing(SharingServiceError),
}

//에러 출력을 위한 부분
impl fmt::Display for CoreFacadeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random(error) => write!(f, "{error}"),
            Self::Kem(error) => write!(f, "{error}"),
            Self::Encryption(error) => write!(f, "{error}"),
            Self::Decryption(error) => write!(f, "{error}"),
            Self::KeyManagement(error) => write!(f, "{error}"),
            Self::Sharing(error) => write!(f, "{error}"),
        }
    }
}

//표준 에러처럼 다루기 위한 구현
impl Error for CoreFacadeError {}

impl From<SecureRandomError> for CoreFacadeError {
    fn from(value: SecureRandomError) -> Self {
        Self::Random(value)
    }
}

impl From<KemBackendError> for CoreFacadeError {
    fn from(value: KemBackendError) -> Self {
        Self::Kem(value)
    }
}

impl From<EncryptionServiceError> for CoreFacadeError {
    fn from(value: EncryptionServiceError) -> Self {
        Self::Encryption(value)
    }
}

impl From<DecryptionServiceError> for CoreFacadeError {
    fn from(value: DecryptionServiceError) -> Self {
        Self::Decryption(value)
    }
}

impl From<KeyManagementServiceError> for CoreFacadeError {
    fn from(value: KeyManagementServiceError) -> Self {
        Self::KeyManagement(value)
    }
}

impl From<SharingServiceError> for CoreFacadeError {
    fn from(value: SharingServiceError) -> Self {
        Self::Sharing(value)
    }
}

pub struct CoreFacade {
    encryption_service: EncryptionService,
    decryption_service: DecryptionService,
    key_management_service: KeyManagementService,
    sharing_service: SharingService,
    secure_random: Arc<dyn SecureRandom>,
}
//외부에서는 개별 service를 다 알 필요 없이 이 함수들만 써도 되게 만듦
impl CoreFacade {
    //backend를 받아 facade 구성
    pub fn from_backends(
        aead_backend: Arc<dyn AeadBackend>,
        kem_backend: Arc<dyn KemBackend>,
        secure_random: Arc<dyn SecureRandom>,
    ) -> Self {
        let encryption_key_management_service =
            KeyManagementService::with_kem_backend(Arc::clone(&kem_backend));
        let facade_key_management_service =
            KeyManagementService::with_kem_backend(Arc::clone(&kem_backend));
        let sharing_key_management_service =
            KeyManagementService::with_kem_backend(Arc::clone(&kem_backend));

        //각 서비스를 직접 주입해 facade 구성
        Self::with_components(
            EncryptionService::with_dependencies(
                Arc::clone(&aead_backend),
                Arc::clone(&secure_random),
                encryption_key_management_service,
            ),
            DecryptionService::with_backends(aead_backend, kem_backend),
            facade_key_management_service,
            SharingService::with_key_management_service(sharing_key_management_service),
            secure_random,
        )
    }

    pub fn with_components(
        encryption_service: EncryptionService,
        decryption_service: DecryptionService,
        key_management_service: KeyManagementService,
        sharing_service: SharingService,
        secure_random: Arc<dyn SecureRandom>,
    ) -> Self {
        Self {
            encryption_service,
            decryption_service,
            key_management_service,
            sharing_service,
            secure_random,
        }
    }

    //32바이트 랜덤 date key를 생성
    pub fn generate_data_key(
        &self,
        key_id: impl Into<String>,
        created_at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<DataKey, CoreFacadeError> {
        let mut key_value = [0u8; 32];
        self.secure_random.fill_bytes(&mut key_value)?;

        Ok(DataKey::new(key_id, key_value, created_at, expires_at))
    }

    pub fn generate_mlkem_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), CoreFacadeError> {
        Ok(self.key_management_service.generate_keypair()?)
    }

    //주어진 EncryptionRequest와 DateKey로 암호화
    pub fn encrypt_package(
        &self,
        request: EncryptionRequest,
        data_key: &DataKey,
    ) -> Result<CryptoPackage, CoreFacadeError> {
        Ok(self
            .encryption_service
            .encrypt_log_with_data_key(request, data_key)?)
    }

    //암호화 시각을 외부에서 직접 지정
    pub fn encrypt_package_at(
        &self,
        request: EncryptionRequest,
        data_key: &DataKey,
        timestamp: Timestamp,
    ) -> Result<CryptoPackage, CoreFacadeError> {
        Ok(self
            .encryption_service
            .encrypt_log_with_data_key_at(request, data_key, timestamp)?)
    }

    // 복호화 요청자 정보(DecryptionCaller), private key를 받아 plaintext를 복원
    pub fn decrypt_package(
        &self,
        crypto_package: &CryptoPackage,
        caller: DecryptionCaller,
        private_key: &[u8],
    ) -> Result<Vec<u8>, CoreFacadeError> {
        Ok(self
            .decryption_service
            .decrypt_log(crypto_package, caller, private_key)?)
    }

    //특정 DataKey를 특정 owner용으로 감싼 KeyEnvelope를 생성
    pub fn create_key_envelope(
        &self,
        data_key: &DataKey,
        owner_id: u64,
        owner_type: OwnerType,
        public_key: &[u8],
    ) -> Result<KeyEnvelope, CoreFacadeError> {
        Ok(self
            .key_management_service
            .create_key_envelope(data_key, owner_id, owner_type, public_key)?)
    }

    //KeyEnvelope와 private key를 받아 원래 data key를 복원
    pub fn open_key_envelope(
        &self,
        envelope: &KeyEnvelope,
        private_key: &[u8],
    ) -> Result<[u8; 32], CoreFacadeError> {
        Ok(self
            .key_management_service
            .open_key_envelope(envelope, private_key)?)
    }

    //이미 존재하는 DataKey를 다른 recipient도 사용할 수 있게 새 KeyEnvelope를 만듦
    // 공유 기능
    pub fn create_additional_recipient_envelope(
        &self,
        data_key: &DataKey,
        owner_id: u64,
        owner_type: OwnerType,
        public_key: &[u8],
    ) -> Result<KeyEnvelope, CoreFacadeError> {
        Ok(self
            .sharing_service
            .create_additional_recipient_envelope(data_key, owner_id, owner_type, public_key)?)
    }
}

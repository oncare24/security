use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use crypto_core::domain::Timestamp;
use crypto_core::domain::crypto_package::CryptoPackage;
use crypto_core::service::encryption_service::{
    EncryptionRequest, EncryptionService, EncryptionServiceError,
};

use crate::data_key_provider::DataKeyProvider;
use crate::data_key_service::DataKeyServiceError;

#[derive(Debug)]
//에러 관련
pub enum ProviderBackedEncryptionServiceError {
    DataKey(DataKeyServiceError),
    Encryption(EncryptionServiceError),
}

impl fmt::Display for ProviderBackedEncryptionServiceError {
    // fmt 함수는 값이나 에러를 사람이 읽기 쉬운 문자열로 포맷
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataKey(error) => write!(f, "{error}"),
            Self::Encryption(error) => write!(f, "{error}"),
        }
    }
}

impl Error for ProviderBackedEncryptionServiceError {}

//자동으로 변환 해줌
impl From<DataKeyServiceError> for ProviderBackedEncryptionServiceError {
    // from 함수는 외부 타입과 내부 타입 사이의 값을 변환
    fn from(value: DataKeyServiceError) -> Self {
        Self::DataKey(value)
    }
}

impl From<EncryptionServiceError> for ProviderBackedEncryptionServiceError {
    // from 함수는 외부 타입과 내부 타입 사이의 값을 변환
    fn from(value: EncryptionServiceError) -> Self {
        Self::Encryption(value)
    }
}

pub struct ProviderBackedEncryptionService {
    core_encryption_service: EncryptionService,
    data_key_provider: Arc<dyn DataKeyProvider>,
}

impl ProviderBackedEncryptionService {
    //구현체를 받아서 내부적으로 Arc로 감싼 후 호출
    pub fn new<P>(
        core_encryption_service: EncryptionService,
        data_key_provider: P,
    ) -> Self
    where
        P: DataKeyProvider + 'static,
    {
        Self::with_provider(core_encryption_service, Arc::new(data_key_provider))
    }

    //Arc 형태로 가지고 있을 때 생성하는 함수
    pub fn with_provider(
        core_encryption_service: EncryptionService,
        data_key_provider: Arc<dyn DataKeyProvider>,
    ) -> Self {
        Self {
            core_encryption_service,
            data_key_provider,
        }
    }

    //현재 시각을 기준으로 encrypt_log_at을 호출
    pub fn encrypt_log(
        &self,
        request: EncryptionRequest,
    ) -> Result<CryptoPackage, ProviderBackedEncryptionServiceError> {
        self.encrypt_log_at(request, SystemTime::now())
    }

    //해당 시점의 data key를 가져오거나 생성, 그 키를 가지고 실제 암호화 수행
    pub fn encrypt_log_at(
        &self,
        request: EncryptionRequest,
        timestamp: Timestamp,
    ) -> Result<CryptoPackage, ProviderBackedEncryptionServiceError> {
        let data_key = self.data_key_provider.get_or_create_key_for(timestamp)?;
        Ok(self
            .core_encryption_service
            .encrypt_log_with_data_key_at(request, &data_key, timestamp)?)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use crypto_adapters::factory::build_encryption_service;
    use crypto_adapters::mlkem_service::MLKEMService;

    use crate::data_key_service::DataKeyService;
    use crate::repository::key_repository::InMemoryDataKeyRepository;

    use super::*;

    // build_service 함수는 필요한 의존성을 조립해 사용할 객체를 만듦
    fn build_service() -> ProviderBackedEncryptionService {
        let repository = InMemoryDataKeyRepository::default();
        let data_key_service = DataKeyService::new(repository);
        let encryption_service =
            build_encryption_service().expect("core encryption service should initialize");

        ProviderBackedEncryptionService::new(encryption_service, data_key_service)
    }

    // build_request 함수는 필요한 의존성을 조립해 사용할 객체를 만듦
    fn build_request() -> EncryptionRequest {
        let ml_kem_service = MLKEMService::new().expect("ml-kem service should initialize");
        let (user_public_key, _) = ml_kem_service
            .generate_keypair()
            .expect("user keypair should be created");
        let (guardian_public_key, _) = ml_kem_service
            .generate_keypair()
            .expect("guardian keypair should be created");

        EncryptionRequest::new(
            b"log payload".to_vec(),
            100,
            user_public_key,
            200,
            guardian_public_key,
        )
    }

    // reuses_daily_key_for_same_day_encryptions 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
    #[test]
    fn reuses_daily_key_for_same_day_encryptions() {
        let service = build_service();
        let first_timestamp = UNIX_EPOCH + Duration::from_secs(86_400 * 40 + 10);
        let second_timestamp = UNIX_EPOCH + Duration::from_secs(86_400 * 40 + 300);

        let first_package = service
            .encrypt_log_at(build_request(), first_timestamp)
            .expect("first encryption should succeed");
        let second_package = service
            .encrypt_log_at(build_request(), second_timestamp)
            .expect("same-day encryption should reuse key");

        assert_eq!(
            first_package.encrypted_data.key_id,
            second_package.encrypted_data.key_id
        );
        assert_eq!(
            first_package.user_envelope.key_id,
            second_package.user_envelope.key_id
        );
        assert_eq!(
            first_package.guardian_envelope.key_id,
            second_package.guardian_envelope.key_id
        );
    }
}

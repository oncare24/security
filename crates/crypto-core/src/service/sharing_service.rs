use std::error::Error;
use std::fmt;

use crate::domain::data_key::DataKey;
use crate::domain::key_envelope::{KeyEnvelope, OwnerType};
use crate::service::key_management_service::{
    KeyManagementService, KeyManagementServiceError,
};

#[derive(Debug)]
//공유 과정에서 발생하는 에러
pub enum SharingServiceError {
    KeyManagement(KeyManagementServiceError),
}

impl fmt::Display for SharingServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyManagement(error) => write!(f, "{error}"),
        }
    }
}

impl Error for SharingServiceError {}

impl From<KeyManagementServiceError> for SharingServiceError {
    fn from(value: KeyManagementServiceError) -> Self {
        Self::KeyManagement(value)
    }
}

pub struct SharingService {
    key_management_service: KeyManagementService,
}

impl SharingService {
    // 공유 서비스를 만들 때 키 관리 서비스를 주입하는 함수
    pub fn with_key_management_service(key_management_service: KeyManagementService) -> Self {
        Self {
            key_management_service,
        }
    }

    //기존 data key를 가지고 새로운 수신자용 envelope를 하나 더 만드는 역할
    pub fn create_additional_recipient_envelope(
        &self,
        data_key: &DataKey,
        owner_id: u64,
        owner_type: OwnerType,
        public_key: &[u8],
    ) -> Result<KeyEnvelope, SharingServiceError> {
        Ok(self
            .key_management_service
            .create_key_envelope(data_key, owner_id, owner_type, public_key)?)
    }
}

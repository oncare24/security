//암호화된 본문 1개, 사용자용 key, 보호자용 key를 하나로 묶는 패키지
//각자 data key를 복원할 수 있게 만든 envelope를 들고 있음

use super::encrypted_log::EncryptedLogData;
use super::key_envelope::KeyEnvelope;

#[derive(Debug, Clone)]
pub struct CryptoPackage {
    pub encrypted_data: EncryptedLogData,
    pub user_envelope: KeyEnvelope,
    pub guardian_envelope: KeyEnvelope,
}

impl CryptoPackage {
    pub fn new(
        encrypted_data: EncryptedLogData,
        user_envelope: KeyEnvelope,
        guardian_envelope: KeyEnvelope,
    ) -> Self {
        Self {
            encrypted_data,
            user_envelope,
            guardian_envelope,
        }
    }
}

//data key를 표현하는 도메인 객체

use super::Timestamp;

#[derive(Debug, Clone)]
pub struct DataKey {
    pub key_id: String,
    pub key_value: [u8; 32],
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

impl DataKey {
    // new 함수는 필요한 값을 받아 새 인스턴스를 생성
    pub fn new(
        key_id: impl Into<String>,
        key_value: [u8; 32],
        created_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            key_value,
            created_at,
            expires_at,
        }
    }
}

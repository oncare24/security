//로그 본문을 대칭키로 암호화한 결과물을 담음
//aes-gcm쪽에서 사용

use super::Timestamp;

#[derive(Debug, Clone)]
pub struct EncryptedLogData {
    pub encrypted_log_id: u64,
    pub user_id: u64,
    pub ciphertext: Vec<u8>,
    pub iv: [u8; 12],
    pub tag: [u8; 16],
    pub key_id: String,
    pub created_at: Timestamp,
}

impl EncryptedLogData {
    // new 함수는 필요한 값을 받아 새 인스턴스를 생성
    pub fn new(
        encrypted_log_id: u64,
        user_id: u64,
        ciphertext: Vec<u8>,
        iv: [u8; 12],
        tag: [u8; 16],
        key_id: impl Into<String>,
        created_at: Timestamp,
    ) -> Self {
        Self {
            encrypted_log_id,
            user_id,
            ciphertext,
            iv,
            tag,
            key_id: key_id.into(),
            created_at,
        }
    }
}

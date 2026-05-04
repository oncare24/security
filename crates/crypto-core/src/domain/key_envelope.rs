//사용자나 보호자가 data key를 복원할 수 있도록 만드는 전달체

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnerType {
    User,
    Guardian,
}

#[derive(Debug, Clone)]
pub struct KeyEnvelope {
    pub envelope_id: u64, 
    pub key_id: String, // 어떤 data key에 대한 envelope인지 식별
    pub owner_id: u64, // 받는 사람의 id
    pub owner_type: OwnerType, 
    pub kem_ciphertext: Vec<u8>, // ml-kem 결과물
    pub encapsulated_key: Vec<u8>, // shared secret를 이용해 감싼 data key
}

impl KeyEnvelope {
    pub fn new(
        envelope_id: u64,
        key_id: impl Into<String>,
        owner_id: u64,
        owner_type: OwnerType,
        kem_ciphertext: Vec<u8>,
        encapsulated_key: Vec<u8>,
    ) -> Self {
        Self {
            envelope_id,
            key_id: key_id.into(),
            owner_id,
            owner_type,
            kem_ciphertext,
            encapsulated_key,
        }
    }
}

use std::fmt;
use std::sync::Once;

use oqs::kem;

use crypto_core::crypto::backends::{KemBackend, KemBackendError, KemEncapsulation};
use crypto_core::crypto::key_wrap::{KeyWrapError, unwrap_data_key, wrap_data_key};
use crypto_core::domain::key_envelope::{KeyEnvelope, OwnerType};

pub struct MLKEMService {
    kem: kem::Kem,
    algorithm: kem::Algorithm,
}

pub type MLKEMServiceError = KemBackendError;

impl fmt::Debug for MLKEMService {
    // fmt 함수는 값이나 에러를 사람이 읽기 쉬운 문자열로 포맷
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MLKEMService")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl MLKEMService {
    //MLKEMService를 생성하는 함수
    pub fn new() -> Result<Self, MLKEMServiceError> {
        initialize_oqs();

        let algorithm = kem::Algorithm::MlKem1024;
        let kem = kem::Kem::new(algorithm)
            .map_err(|error| MLKEMServiceError::OperationFailed(error.to_string()))?;

        Ok(Self { kem, algorithm })
    }

    //어떤 ml-kem 알고리즘을 쓰는지 반환
    pub fn algorithm(&self) -> kem::Algorithm {
        self.algorithm
    }

    //공개키와 개인키를 생성
    pub fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), MLKEMServiceError> {
        KemBackend::generate_keypair(self)
    }

    //data_key와 상대방 public_key를 받아 KeyEnvelope를 생성
    pub fn encapsulate(
        &self,
        data_key: &[u8; 32],
        public_key: &[u8],
    ) -> Result<KeyEnvelope, MLKEMServiceError> {
        self.encapsulate_for_owner(data_key, public_key, "", 0, OwnerType::User, 0)
    }

    //공개키로 KEM 암호화 진행, 암호문과 shared_secret 획득
    //shared secret로 data key를 감쌈
    //소유자 정보와 함께 envelope 생성
    pub fn encapsulate_for_owner(
        &self,
        data_key: &[u8; 32],
        public_key: &[u8],
        key_id: impl Into<String>,
        owner_id: u64,
        owner_type: OwnerType,
        envelope_id: u64,
    ) -> Result<KeyEnvelope, MLKEMServiceError> {
        let encapsulation = KemBackend::encapsulate(self, public_key)?;
        let encapsulated_key = wrap_data_key(data_key, &encapsulation.shared_secret)
            .map_err(map_key_wrap_error)?;

        Ok(KeyEnvelope::new(
            envelope_id,
            key_id,
            owner_id,
            owner_type,
            encapsulation.ciphertext,
            encapsulated_key,
        ))
    }

    //개인키를 받아 data key를 복원
    pub fn decapsulate(
        &self,
        envelope: KeyEnvelope,
        private_key: &[u8],
    ) -> Result<[u8; 32], MLKEMServiceError> {
        self.decapsulate_ref(&envelope, private_key)
    }

    //봉투를 열어서 원래 data key를 꺼내는 함수
    pub fn decapsulate_ref(
        &self,
        envelope: &KeyEnvelope,
        private_key: &[u8],
    ) -> Result<[u8; 32], MLKEMServiceError> {
        let shared_secret = KemBackend::decapsulate(self, &envelope.kem_ciphertext, private_key)?;
        unwrap_data_key(&envelope.encapsulated_key, &shared_secret).map_err(map_key_wrap_error)
    }
}

impl KemBackend for MLKEMService {
    //어떤 알고리즘인지 반환
    fn algorithm_name(&self) -> &'static str {
        "ML-KEM-1024"
    }

    //공개키라 개인키 생성 함수
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), KemBackendError> {
        let (public_key, private_key) = self
            .kem
            .keypair()
            .map_err(|error| KemBackendError::OperationFailed(error.to_string()))?;

        Ok((public_key.as_ref().to_vec(), private_key.as_ref().to_vec()))
    }

    //공개키를 받아서 kem 암호화를 수행
    fn encapsulate(&self, public_key: &[u8]) -> Result<KemEncapsulation, KemBackendError> {
        let public_key_ref = self
            .kem
            .public_key_from_bytes(public_key)
            .ok_or(KemBackendError::InvalidPublicKeyLength {
                expected: self.kem.length_public_key(),
                actual: public_key.len(),
            })?;

        let (ciphertext, shared_secret) = self
            .kem
            .encapsulate(public_key_ref)
            .map_err(|error| KemBackendError::OperationFailed(error.to_string()))?;

        Ok(KemEncapsulation::new(
            ciphertext.as_ref().to_vec(),
            shared_secret.as_ref().to_vec(),
        ))
    }

    //개인키와 암호문을 받아서 shared secret를 복원
    fn decapsulate(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, KemBackendError> {
        let private_key_ref = self
            .kem
            .secret_key_from_bytes(private_key)
            .ok_or(KemBackendError::InvalidPrivateKeyLength {
                expected: self.kem.length_secret_key(),
                actual: private_key.len(),
            })?;

        let ciphertext_ref = self
            .kem
            .ciphertext_from_bytes(ciphertext)
            .ok_or(KemBackendError::InvalidCiphertextLength {
                expected: self.kem.length_ciphertext(),
                actual: ciphertext.len(),
            })?;

        let shared_secret = self
            .kem
            .decapsulate(private_key_ref, ciphertext_ref)
            .map_err(|error| KemBackendError::OperationFailed(error.to_string()))?;

        Ok(shared_secret.as_ref().to_vec())
    }
}

//프로그램 전체에서 oqs 초기화를 한번만 수행하게 하는 것
fn initialize_oqs() {
    static INIT: Once = Once::new();
    INIT.call_once(oqs::init);
}

//키를 감쌀 떄 발생하는 에러, 키를 풀 떄 발생하는 key wrap 관련 에러
fn map_key_wrap_error(error: KeyWrapError) -> MLKEMServiceError {
    match error {
        KeyWrapError::InvalidWrappedKeyLength { expected, actual } => {
            MLKEMServiceError::OperationFailed(format!(
                "invalid wrapped data key length: expected {expected} bytes, got {actual}"
            ))
        }
        KeyWrapError::InvalidSharedSecretLength { expected, actual } => {
            MLKEMServiceError::OperationFailed(format!(
                "invalid shared secret length: expected {expected} bytes, got {actual}"
            ))
        }
    }
}

pub type MlKemService = MLKEMService;

#[cfg(test)]
mod tests {
    use super::MLKEMService;

    // encapsulate_and_decapsulate_data_key 함수는 공개키로 shared secret을 만들고 필요한 값을 감쌈
    #[test]
    fn encapsulate_and_decapsulate_data_key() {
        let service = MLKEMService::new().expect("service should initialize");
        let (public_key, private_key) = service
            .generate_keypair()
            .expect("keypair should generate");
        let data_key = [42u8; 32];

        let envelope = service
            .encapsulate(&data_key, &public_key)
            .expect("encapsulation should succeed");
        let recovered = service
            .decapsulate(envelope, &private_key)
            .expect("decapsulation should succeed");

        assert_eq!(recovered, data_key);
    }

    // invalid_private_key_is_rejected 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
    #[test]
    fn invalid_private_key_is_rejected() {
        let service = MLKEMService::new().expect("service should initialize");
        let data_key = [1u8; 32];
        let (public_key, _) = service
            .generate_keypair()
            .expect("keypair should generate");

        let envelope = service
            .encapsulate(&data_key, &public_key)
            .expect("encapsulation should succeed");
        let result = service.decapsulate(envelope, &[0u8; 8]);

        assert!(result.is_err());
    }
}

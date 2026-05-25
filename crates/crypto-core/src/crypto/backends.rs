use std::error::Error;
use std::fmt;

pub const DATA_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

//AES-GCM(AEAD 계층)에서의 실패를 뜻함
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeadBackendError {
    EncryptionFailed, //암호화 실패
    DecryptionFailed, //복호화 실패, 인증 태그 불일치 포함
}

impl fmt::Display for AeadBackendError {
    // fmt 함수는 값이나 에러를 사람이 읽기 쉬운 문자열로 포맷
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "AEAD encryption failed"),
            Self::DecryptionFailed => {
                write!(f, "AEAD decryption failed or authentication tag is invalid")
            }
        }
    }
}

impl Error for AeadBackendError {}

//KEM 계층의 실패
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KemBackendError {
    OperationFailed(String), //연산 자체 실패
    //공개키, 개인키, 암호문 길이 오류
    InvalidPublicKeyLength { expected: usize, actual: usize },
    InvalidPrivateKeyLength { expected: usize, actual: usize },
    InvalidCiphertextLength { expected: usize, actual: usize },
}

impl fmt::Display for KemBackendError {
    // fmt 함수는 값이나 에러를 사람이 읽기 쉬운 문자열로 포맷
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperationFailed(message) => write!(f, "KEM operation failed: {message}"),
            Self::InvalidPublicKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid KEM public key length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidPrivateKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid KEM private key length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidCiphertextLength { expected, actual } => {
                write!(
                    f,
                    "invalid KEM ciphertext length: expected {expected} bytes, got {actual}"
                )
            }
        }
    }
}

impl Error for KemBackendError {}

//보안용 랜덤 파이트를 채우지 못함
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureRandomError {
    FillFailed(String),
}

impl fmt::Display for SecureRandomError {
    // fmt 함수는 값이나 에러를 사람이 읽기 쉬운 문자열로 포맷
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FillFailed(message) => {
                write!(f, "failed to generate secure random bytes: {message}")
            }
        }
    }
}

impl Error for SecureRandomError {}


// AEAD 암호화 결과를 담는 구조체
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AeadEncrypted {
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_SIZE],
}

impl AeadEncrypted {
    // new 함수는 필요한 값을 받아 새 인스턴스를 생성
    pub fn new(ciphertext: Vec<u8>, tag: [u8; TAG_SIZE]) -> Self {
        Self { ciphertext, tag }
    }
}

// KEM encapsulation 결과를 담는 구조체
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl KemEncapsulation {
    // new 함수는 필요한 값을 받아 새 인스턴스를 생성
    pub fn new(ciphertext: Vec<u8>, shared_secret: Vec<u8>) -> Self {
        Self {
            ciphertext,
            shared_secret,
        }
    }
}

//대칭 암호 backedn가 어떤 기능을 제공해야 하는지 정의
pub trait AeadBackend: Send + Sync {
    // encrypt_detached 함수는 평문과 키 정보를 사용해 암호화 결과를 만듦
    fn encrypt_detached(
        &self,
        key: &[u8; DATA_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<AeadEncrypted, AeadBackendError>;

    // decrypt_detached 함수는 암호문과 키 정보를 사용해 원문을 복원
    fn decrypt_detached(
        &self,
        key: &[u8; DATA_KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
        tag: &[u8; TAG_SIZE],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadBackendError>;
}

//ML-KEM이 어떤 기능을 제공해야 하는지 정의
pub trait KemBackend: Send + Sync {
    // algorithm_name 함수는 사용 중인 암호 알고리즘 이름을 반환
    fn algorithm_name(&self) -> &'static str;

    // generate_keypair 함수는 암호화에 사용할 새 키나 바이트 값을 생성
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), KemBackendError>;

    // encapsulate 함수는 공개키로 shared secret을 만들고 필요한 값을 감쌈
    fn encapsulate(&self, public_key: &[u8]) -> Result<KemEncapsulation, KemBackendError>;

    // decapsulate 함수는 개인키와 캡슐화 값을 사용해 shared secret을 복원
    fn decapsulate(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, KemBackendError>;
}

// 안전한 랜덤 생성기가 어떤 기능을 제공해야 하는지 정의
pub trait SecureRandom: Send + Sync {
    // fill_bytes 함수는 바이트 버퍼를 호출자가 사용할 형태로 변환
    fn fill_bytes(&self, out: &mut [u8]) -> Result<(), SecureRandomError>;
}

use std::error::Error;
use std::fmt;

use crate::crypto::backends::DATA_KEY_SIZE;

//감싸진 키 길이가 잘못됨
//shared secret 길이가 너무 짧음
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyWrapError {
    InvalidWrappedKeyLength { expected: usize, actual: usize },
    InvalidSharedSecretLength { expected: usize, actual: usize },
}

impl fmt::Display for KeyWrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWrappedKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid wrapped data key length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidSharedSecretLength { expected, actual } => {
                write!(
                    f,
                    "invalid shared secret length: expected {expected} bytes, got {actual}"
                )
            }
        }
    }
}

impl Error for KeyWrapError {}

//이미 존재하는 data_key와 shared_secret을 받아서 data key를 감싼 Vec<u8>을 만듦
pub fn wrap_data_key(
    data_key: &[u8; DATA_KEY_SIZE],
    shared_secret: &[u8],
) -> Result<Vec<u8>, KeyWrapError> {
    if shared_secret.len() < DATA_KEY_SIZE {
        return Err(KeyWrapError::InvalidSharedSecretLength {
            expected: DATA_KEY_SIZE,
            actual: shared_secret.len(),
        });
    }

    Ok(data_key
        .iter()
        .zip(shared_secret.iter())
        .map(|(key_byte, shared_secret_byte)| key_byte ^ shared_secret_byte)
        .collect())
}


// 감싸진 키와 shared_secret을 받아서 data eky를 복원
pub fn unwrap_data_key(
    wrapped_key: &[u8],
    shared_secret: &[u8],
) -> Result<[u8; DATA_KEY_SIZE], KeyWrapError> {
    if wrapped_key.len() != DATA_KEY_SIZE {
        return Err(KeyWrapError::InvalidWrappedKeyLength {
            expected: DATA_KEY_SIZE,
            actual: wrapped_key.len(),
        });
    }

    if shared_secret.len() < DATA_KEY_SIZE {
        return Err(KeyWrapError::InvalidSharedSecretLength {
            expected: DATA_KEY_SIZE,
            actual: shared_secret.len(),
        });
    }

    let mut recovered = [0u8; DATA_KEY_SIZE];
    for index in 0..DATA_KEY_SIZE {
        recovered[index] = wrapped_key[index] ^ shared_secret[index];
    }

    Ok(recovered)
}

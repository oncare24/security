// FFI 함수들이 주고받는 입력 구조체와 변환 로직
use std::time::{Duration, UNIX_EPOCH};

use crypto_core::domain::data_key::DataKey;
use crypto_core::domain::key_envelope::OwnerType;
use crypto_core::domain::Timestamp;
use crypto_core::service::encryption_service::EncryptionRequest;

use crate::buffers::FfiBorrowedBytes;
use crate::error::FfiErrorCode;

// unix timestamp초 단위로 받아 timestamp로 변환
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiTimestamp {
    pub unix_seconds: u64,
}

impl FfiTimestamp {
    pub fn to_system_time(self) -> Timestamp {
        UNIX_EPOCH + Duration::from_secs(self.unix_seconds)
    }
}

// Datakey를 만들기 위한 FFI입력 구조
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiDataKeyInput {
    pub key_id: FfiBorrowedBytes,
    pub key_value: [u8; 32],
    pub created_at: FfiTimestamp,
    pub expires_at: FfiTimestamp,
}

// envelope 관련 요청에서 호출자, 소유자가 누구인지 나타냄
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiOwnerType {
    User = 1,
    Guardian = 2,
}

impl TryFrom<FfiOwnerType> for OwnerType {
    type Error = FfiErrorCode;

    fn try_from(value: FfiOwnerType) -> Result<Self, Self::Error> {
        match value {
            FfiOwnerType::User => Ok(OwnerType::User),
            FfiOwnerType::Guardian => Ok(OwnerType::Guardian),
        }
    }
}

// 여러 요청 DTO
// 암호화 요청용
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiEncryptPackageRequest {
    pub plaintext: FfiBorrowedBytes,
    pub user_id: u64,
    pub user_public_key: FfiBorrowedBytes,
    pub guardian_id: u64,
    pub guardian_public_key: FfiBorrowedBytes,
    pub data_key: FfiDataKeyInput,
}

// 복호화 요청용
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiDecryptPackageRequest {
    pub package: FfiBorrowedBytes,
    pub caller_id: u64,
    pub caller_type: FfiOwnerType,
    pub private_key: FfiBorrowedBytes,
}

// data key를 특정 소유자 공개키로 감싸는 요청
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiCreateKeyEnvelopeRequest {
    pub data_key: FfiDataKeyInput,
    pub owner_id: u64,
    pub owner_type: FfiOwnerType,
    pub public_key: FfiBorrowedBytes,
}

// envelope를 열어서 data key를 복구하는 요청
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiOpenKeyEnvelopeRequest {
    pub envelope: FfiBorrowedBytes,
    pub caller_id: u64,
    pub caller_type: FfiOwnerType,
    pub private_key: FfiBorrowedBytes,
}

// envelope를 열수 있는 소유자가 자신의 개인키로 data key를 복구한 뒤, 새로운 수신자 공개키로 다시 envelope를 만드는 요청
// 수신자 추가 공유 요청 구조
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiCreateAdditionalRecipientEnvelopeRequest {
    pub source_envelope: FfiBorrowedBytes,
    pub current_owner_id: u64,
    pub current_owner_type: FfiOwnerType,
    pub current_private_key: FfiBorrowedBytes,
    pub new_owner_id: u64,
    pub new_owner_type: FfiOwnerType,
    pub new_public_key: FfiBorrowedBytes,
}

// Rust의 &[u8]로 바꿈
pub unsafe fn borrowed_bytes_as_slice<'a>(
    bytes: FfiBorrowedBytes,
) -> Result<&'a [u8], FfiErrorCode> {
    if bytes.ptr.is_null() {
        if bytes.len == 0 {
            return Ok(&[]);
        }
        return Err(FfiErrorCode::NullPointer);
    }

    unsafe { Ok(std::slice::from_raw_parts(bytes.ptr, bytes.len)) }
}

// 바이트를 UTF-8 문자열로 바꿈
pub unsafe fn borrowed_bytes_as_string(bytes: FfiBorrowedBytes) -> Result<String, FfiErrorCode> {
    let slice = unsafe { borrowed_bytes_as_slice(bytes)? };
    std::str::from_utf8(slice)
        .map(|value| value.to_owned())
        .map_err(|_| FfiErrorCode::InvalidUtf8)
}

// FfiDataKeyInput을 도메인 Datakey로 바꾸는 함수
pub unsafe fn data_key_from_ffi(input: FfiDataKeyInput) -> Result<DataKey, FfiErrorCode> {
    Ok(DataKey::new(
        unsafe { borrowed_bytes_as_string(input.key_id)? },
        input.key_value,
        input.created_at.to_system_time(),
        input.expires_at.to_system_time(),
    ))
}

// FfiEncryptPackageRequest를 EncryptionRequest로 바꾸는 함수
pub unsafe fn encryption_request_from_ffi(
    input: FfiEncryptPackageRequest,
) -> Result<EncryptionRequest, FfiErrorCode> {
    Ok(EncryptionRequest::new(
        unsafe { borrowed_bytes_as_slice(input.plaintext)? }.to_vec(),
        input.user_id,
        unsafe { borrowed_bytes_as_slice(input.user_public_key)? }.to_vec(),
        input.guardian_id,
        unsafe { borrowed_bytes_as_slice(input.guardian_public_key)? }.to_vec(),
    ))
}

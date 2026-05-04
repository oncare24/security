//! - facade 생성 / 해제
//! - 바이트 버퍼 해제
//! - generate_data_key
//! - encrypt_package
//! - decrypt_package
//! - 키 envelope 생성 / 열기 / 공유
//! - 마지막 오류 메시지 길이 조회 / 복사

pub mod api;
pub mod buffers;
pub mod error;
pub mod handle;
pub mod types;

pub use api::crypto::{
    crypto_ffi_byte_buffer_free, crypto_ffi_create_additional_recipient_envelope,
    crypto_ffi_create_key_envelope, crypto_ffi_decrypt_package, crypto_ffi_encrypt_package,
    crypto_ffi_generate_data_key, crypto_ffi_open_key_envelope,
};
pub use api::facade::{crypto_ffi_facade_free, crypto_ffi_facade_new_default};
pub use buffers::{FfiBorrowedBytes, FfiByteBuffer};
pub use error::{
    FfiErrorCode, FfiErrorInfo, crypto_ffi_last_error_message_copy,
    crypto_ffi_last_error_message_length,
};
pub use handle::{FfiFacadeHandle, FfiHandleInitError};
pub use types::{
    FfiCreateAdditionalRecipientEnvelopeRequest, FfiCreateKeyEnvelopeRequest,
    FfiDataKeyInput, FfiDecryptPackageRequest, FfiEncryptPackageRequest,
    FfiOpenKeyEnvelopeRequest, FfiOwnerType, FfiTimestamp,
};

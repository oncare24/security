//! 암호화 관련 기능들을 extern "C" API로 외부에 노출
//! 입력 검증, 타입 변환, 직렬화/역직렬화 에러 처리 담당

use std::time::{Duration, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crypto_core::domain::crypto_package::CryptoPackage;
use crypto_core::domain::data_key::DataKey;
use crypto_core::domain::encrypted_log::EncryptedLogData;
use crypto_core::domain::key_envelope::{KeyEnvelope, OwnerType};
use crypto_core::service::decryption_service::DecryptionCaller;

use crate::buffers::{FfiBorrowedBytes, FfiByteBuffer, free_buffer, vec_into_buffer};
use crate::error::{FfiErrorCode, catch_ffi_panic, fail_with_message};
use crate::handle::{FfiFacadeHandle, handle_from_ptr};
use crate::types::{
    FfiCreateAdditionalRecipientEnvelopeRequest, FfiCreateKeyEnvelopeRequest, FfiDataKeyInput,
    FfiDecryptPackageRequest, FfiEncryptPackageRequest, FfiOpenKeyEnvelopeRequest,
    borrowed_bytes_as_slice, data_key_from_ffi, encryption_request_from_ffi,
};

// Wire 구조체들
// Rust 도메인 객체를 바로 넘기지 않고 JSON 바이트로 직렬화해서 주고 받기 위한 중간 표현

#[derive(Serialize)]
struct CryptoPackageWire<'a> {
    encrypted_data: EncryptedLogDataWire<'a>,
    user_envelope: KeyEnvelopeWire<'a>,
    guardian_envelope: KeyEnvelopeWire<'a>,
}

#[derive(Serialize)]
struct EncryptedLogDataWire<'a> {
    encrypted_log_id: u64,
    user_id: u64,
    ciphertext: &'a [u8],
    iv: [u8; 12],
    tag: [u8; 16],
    key_id: &'a str,
    created_at_unix_seconds: u64,
}

#[derive(Serialize)]
struct KeyEnvelopeWire<'a> {
    envelope_id: u64,
    key_id: &'a str,
    owner_id: u64,
    owner_type: &'static str,
    kem_ciphertext: &'a [u8],
    encapsulated_key: &'a [u8],
}

#[derive(Serialize)]
struct MlKemKeypairWire<'a> {
    algorithm: &'static str,
    public_key: &'a [u8],
    private_key: &'a [u8],
}

// WireOwned 구조체
// 역직렬화한 뒤 Rust 내부 객체로 옮기기 위함
#[derive(Deserialize)]
struct CryptoPackageWireOwned {
    encrypted_data: EncryptedLogDataWireOwned,
    user_envelope: KeyEnvelopeWireOwned,
    guardian_envelope: KeyEnvelopeWireOwned,
}

#[derive(Deserialize)]
struct EncryptedLogDataWireOwned {
    encrypted_log_id: u64,
    user_id: u64,
    ciphertext: Vec<u8>,
    iv: [u8; 12],
    tag: [u8; 16],
    key_id: String,
    created_at_unix_seconds: u64,
}

#[derive(Deserialize)]
struct KeyEnvelopeWireOwned {
    envelope_id: u64,
    key_id: String,
    owner_id: u64,
    owner_type: String,
    kem_ciphertext: Vec<u8>,
    encapsulated_key: Vec<u8>,
}

// Rust가 만들어서 바깥에 넘긴 결과 버퍼를 회수하는 함수
#[unsafe(no_mangle)]
pub extern "C" fn crypto_ffi_byte_buffer_free(buffer: FfiByteBuffer) -> FfiErrorCode {
    catch_ffi_panic(|| {
        unsafe {
            free_buffer(buffer);
        }
        FfiErrorCode::Ok
    })
}

//  datakey 생성하고 32바이트 Key_value만 겨로가 버퍼로 돌려 받음
#[unsafe(no_mangle)]
pub extern "C" fn crypto_ffi_generate_mlkem_keypair(
    handle: *mut FfiFacadeHandle,
    out_buffer: *mut FfiByteBuffer,
) -> FfiErrorCode {
    catch_ffi_panic(|| {
        if out_buffer.is_null() {
            return fail_with_message(FfiErrorCode::NullPointer, "null output buffer");
        }

        let handle = match unsafe { handle_from_ptr(handle) } {
            Ok(handle) => handle,
            Err(_) => return fail_with_message(FfiErrorCode::InvalidHandle, "invalid handle"),
        };

        let (public_key, private_key) = match handle.core().generate_mlkem_keypair() {
            Ok(value) => value,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::CryptoError,
                    "crypto operation failed while generating ML-KEM keypair",
                );
            }
        };

        let serialized = match serde_json::to_vec(&MlKemKeypairWire {
            algorithm: "ML-KEM-1024",
            public_key: &public_key,
            private_key: &private_key,
        }) {
            Ok(bytes) => bytes,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::InternalError,
                    "failed to serialize ML-KEM keypair JSON",
                );
            }
        };

        unsafe {
            *out_buffer = vec_into_buffer(serialized);
        }

        FfiErrorCode::Ok
    })
}

// crypto_ffi_generate_data_key 함수는 외부 타입과 내부 타입 사이의 값을 변환
#[unsafe(no_mangle)]
pub extern "C" fn crypto_ffi_generate_data_key(
    handle: *mut FfiFacadeHandle,
    key_id: FfiBorrowedBytes,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    out_buffer: *mut FfiByteBuffer,
) -> FfiErrorCode {
    catch_ffi_panic(|| {
        if out_buffer.is_null() {
            return fail_with_message(FfiErrorCode::NullPointer, "null output buffer");
        }

        let handle = match unsafe { handle_from_ptr(handle) } {
            Ok(handle) => handle,
            Err(_) => return fail_with_message(FfiErrorCode::InvalidHandle, "invalid handle"),
        };

        let data_key_input = FfiDataKeyInput {
            key_id,
            key_value: [0u8; 32],
            created_at: crate::types::FfiTimestamp {
                unix_seconds: created_at_unix_seconds,
            },
            expires_at: crate::types::FfiTimestamp {
                unix_seconds: expires_at_unix_seconds,
            },
        };

        let key_id_string = match unsafe {
            crate::types::borrowed_bytes_as_string(data_key_input.key_id)
        } {
            Ok(value) => value,
            Err(FfiErrorCode::NullPointer) => {
                return fail_with_message(FfiErrorCode::NullPointer, "null data key id pointer");
            }
            Err(FfiErrorCode::InvalidUtf8) => {
                return fail_with_message(FfiErrorCode::InvalidUtf8, "invalid UTF-8 in data key id");
            }
            Err(code) => return fail_with_message(code, "invalid data key id"),
        };

        let data_key = match handle.core().generate_data_key(
            key_id_string,
            data_key_input.created_at.to_system_time(),
            data_key_input.expires_at.to_system_time(),
        ) {
            Ok(data_key) => data_key,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::CryptoError,
                    "crypto operation failed while generating data key",
                );
            }
        };

        unsafe {
            *out_buffer = vec_into_buffer(data_key.key_value.to_vec());
        }

        FfiErrorCode::Ok
    })
}

// 암호호 요청 전체를 처리함
// 펴문 + 사용자/보호자 공개키 + data key를 받아 암호화 패키지 전체를 JSON으로 돌려주는 함수
#[unsafe(no_mangle)]
pub extern "C" fn crypto_ffi_encrypt_package(
    handle: *mut FfiFacadeHandle,
    request: *const FfiEncryptPackageRequest,
    out_buffer: *mut FfiByteBuffer,
) -> FfiErrorCode {
    catch_ffi_panic(|| {
        if request.is_null() {
            return fail_with_message(FfiErrorCode::NullPointer, "null encrypt request pointer");
        }
        if out_buffer.is_null() {
            return fail_with_message(FfiErrorCode::NullPointer, "null output buffer");
        }

        let handle = match unsafe { handle_from_ptr(handle) } {
            Ok(handle) => handle,
            Err(_) => return fail_with_message(FfiErrorCode::InvalidHandle, "invalid handle"),
        };

        let request = unsafe { *request };
        let encryption_request = match unsafe { encryption_request_from_ffi(request) } {
            Ok(value) => value,
            Err(FfiErrorCode::NullPointer) => {
                return fail_with_message(
                    FfiErrorCode::NullPointer,
                    "null pointer in encrypt request bytes",
                );
            }
            Err(FfiErrorCode::InvalidUtf8) => {
                return fail_with_message(
                    FfiErrorCode::InvalidUtf8,
                    "invalid UTF-8 in encrypt request",
                );
            }
            Err(code) => return fail_with_message(code, "invalid encrypt request"),
        };
        let data_key = match unsafe { data_key_from_ffi(request.data_key) } {
            Ok(value) => value,
            Err(FfiErrorCode::NullPointer) => {
                return fail_with_message(
                    FfiErrorCode::NullPointer,
                    "null pointer in data key input",
                );
            }
            Err(FfiErrorCode::InvalidUtf8) => {
                return fail_with_message(
                    FfiErrorCode::InvalidUtf8,
                    "invalid UTF-8 in data key input",
                );
            }
            Err(code) => return fail_with_message(code, "invalid data key input"),
        };

        let package = match handle.core().encrypt_package(encryption_request, &data_key) {
            Ok(package) => package,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::CryptoError,
                    "crypto operation failed while encrypting package",
                );
            }
        };

        let serialized = match serde_json::to_vec(&CryptoPackageWire::from(&package)) {
            Ok(bytes) => bytes,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::InternalError,
                    "failed to serialize CryptoPackage JSON",
                );
            }
        };

        unsafe {
            *out_buffer = vec_into_buffer(serialized);
        }

        FfiErrorCode::Ok
    })
}

// 패키지를 복호화함
// 패키지 JSON과 호출자 개인키를 받아 최종 평문을 복원하는 함수
#[unsafe(no_mangle)]
pub extern "C" fn crypto_ffi_decrypt_package(
    handle: *mut FfiFacadeHandle,
    request: *const FfiDecryptPackageRequest,
    out_buffer: *mut FfiByteBuffer,
) -> FfiErrorCode {
    catch_ffi_panic(|| {
        if request.is_null() {
            return fail_with_message(FfiErrorCode::NullPointer, "null decrypt request pointer");
        }
        if out_buffer.is_null() {
            return fail_with_message(FfiErrorCode::NullPointer, "null output buffer");
        }

        let handle = match unsafe { handle_from_ptr(handle) } {
            Ok(handle) => handle,
            Err(_) => return fail_with_message(FfiErrorCode::InvalidHandle, "invalid handle"),
        };

        let request = unsafe { *request };
        let package_bytes = match unsafe { borrowed_bytes_as_slice(request.package) } {
            Ok(bytes) => bytes,
            Err(_) => {
                return fail_with_message(FfiErrorCode::NullPointer, "null package bytes pointer");
            }
        };
        if package_bytes.is_empty() {
            return fail_with_message(FfiErrorCode::InvalidLength, "empty package bytes");
        }

        let private_key = match unsafe { borrowed_bytes_as_slice(request.private_key) } {
            Ok(bytes) => bytes,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::NullPointer,
                    "null private key bytes pointer",
                );
            }
        };
        if private_key.is_empty() {
            return fail_with_message(FfiErrorCode::InvalidLength, "empty private key bytes");
        }

        let caller_type = match OwnerType::try_from(request.caller_type) {
            Ok(value) => value,
            Err(code) => return fail_with_message(code, "invalid caller owner type"),
        };

        let crypto_package = match deserialize_crypto_package(package_bytes) {
            Ok(package) => package,
            Err(code) => return fail_with_message(code, "malformed CryptoPackage JSON"),
        };

        let plaintext = match handle.core().decrypt_package(
            &crypto_package,
            DecryptionCaller::new(request.caller_id, caller_type),
            private_key,
        ) {
            Ok(value) => value,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::CryptoError,
                    "crypto operation failed while decrypting package",
                );
            }
        };

        unsafe {
            *out_buffer = vec_into_buffer(plaintext);
        }

        FfiErrorCode::Ok
    })
}

// 특정 DataKey를 특정 소유자의 공개키로 감싸서 KeyEnvelope를 만듦
#[unsafe(no_mangle)]
pub extern "C" fn crypto_ffi_create_key_envelope(
    handle: *mut FfiFacadeHandle,
    request: *const FfiCreateKeyEnvelopeRequest,
    out_buffer: *mut FfiByteBuffer,
) -> FfiErrorCode {
    catch_ffi_panic(|| {
        if request.is_null() {
            return fail_with_message(
                FfiErrorCode::NullPointer,
                "null create key envelope request pointer",
            );
        }
        if out_buffer.is_null() {
            return fail_with_message(FfiErrorCode::NullPointer, "null output buffer");
        }

        let handle = match unsafe { handle_from_ptr(handle) } {
            Ok(handle) => handle,
            Err(_) => return fail_with_message(FfiErrorCode::InvalidHandle, "invalid handle"),
        };

        let request = unsafe { *request };
        let public_key = match unsafe { borrowed_bytes_as_slice(request.public_key) } {
            Ok(bytes) => bytes,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::NullPointer,
                    "null public key bytes pointer",
                );
            }
        };
        if public_key.is_empty() {
            return fail_with_message(FfiErrorCode::InvalidLength, "empty public key bytes");
        }

        let owner_type = match OwnerType::try_from(request.owner_type) {
            Ok(value) => value,
            Err(code) => return fail_with_message(code, "invalid owner type"),
        };
        let data_key = match unsafe { data_key_from_ffi(request.data_key) } {
            Ok(value) => value,
            Err(FfiErrorCode::NullPointer) => {
                return fail_with_message(
                    FfiErrorCode::NullPointer,
                    "null pointer in data key input",
                );
            }
            Err(FfiErrorCode::InvalidUtf8) => {
                return fail_with_message(
                    FfiErrorCode::InvalidUtf8,
                    "invalid UTF-8 in data key input",
                );
            }
            Err(code) => return fail_with_message(code, "invalid data key input"),
        };

        let envelope = match handle.core().create_key_envelope(
            &data_key,
            request.owner_id,
            owner_type,
            public_key,
        ) {
            Ok(value) => value,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::CryptoError,
                    "crypto operation failed while creating key envelope",
                );
            }
        };

        let serialized = match serialize_key_envelope(&envelope) {
            Ok(bytes) => bytes,
            Err(code) => return fail_with_message(code, "failed to serialize KeyEnvelope JSON"),
        };

        unsafe {
            *out_buffer = vec_into_buffer(serialized);
        }

        FfiErrorCode::Ok
    })
}

// envelope를 열어서 안의 data key를 복구함
#[unsafe(no_mangle)]
pub extern "C" fn crypto_ffi_open_key_envelope(
    handle: *mut FfiFacadeHandle,
    request: *const FfiOpenKeyEnvelopeRequest,
    out_buffer: *mut FfiByteBuffer,
) -> FfiErrorCode {
    catch_ffi_panic(|| {
        if request.is_null() {
            return fail_with_message(
                FfiErrorCode::NullPointer,
                "null open key envelope request pointer",
            );
        }
        if out_buffer.is_null() {
            return fail_with_message(FfiErrorCode::NullPointer, "null output buffer");
        }

        let handle = match unsafe { handle_from_ptr(handle) } {
            Ok(handle) => handle,
            Err(_) => return fail_with_message(FfiErrorCode::InvalidHandle, "invalid handle"),
        };

        let request = unsafe { *request };
        let envelope_bytes = match unsafe { borrowed_bytes_as_slice(request.envelope) } {
            Ok(bytes) => bytes,
            Err(_) => {
                return fail_with_message(FfiErrorCode::NullPointer, "null envelope bytes pointer");
            }
        };
        if envelope_bytes.is_empty() {
            return fail_with_message(FfiErrorCode::InvalidLength, "empty envelope bytes");
        }

        let private_key = match unsafe { borrowed_bytes_as_slice(request.private_key) } {
            Ok(bytes) => bytes,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::NullPointer,
                    "null private key bytes pointer",
                );
            }
        };
        if private_key.is_empty() {
            return fail_with_message(FfiErrorCode::InvalidLength, "empty private key bytes");
        }

        let caller_type = match OwnerType::try_from(request.caller_type) {
            Ok(value) => value,
            Err(code) => return fail_with_message(code, "invalid caller owner type"),
        };
        let envelope = match deserialize_key_envelope(envelope_bytes) {
            Ok(value) => value,
            Err(code) => return fail_with_message(code, "malformed KeyEnvelope JSON"),
        };
        if !envelope_matches_owner(&envelope, request.caller_id, caller_type) {
            return fail_with_message(
                FfiErrorCode::InvalidArgument,
                "envelope owner metadata mismatch",
            );
        }

        let data_key = match handle.core().open_key_envelope(&envelope, private_key) {
            Ok(value) => value,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::CryptoError,
                    "crypto operation failed while opening key envelope",
                );
            }
        };

        unsafe {
            *out_buffer = vec_into_buffer(data_key.to_vec());
        }

        FfiErrorCode::Ok
    })
}

// 기존 수신자가 새 수신자를 추가 공유할 떄 쓰임
// 기존 envelope를 열 수 있는 사람이 같은 data key를 새 공개키로 다시 감싸서 추가 수신자용 envelope를 만드는 함수
#[unsafe(no_mangle)]
pub extern "C" fn crypto_ffi_create_additional_recipient_envelope(
    handle: *mut FfiFacadeHandle,
    request: *const FfiCreateAdditionalRecipientEnvelopeRequest,
    out_buffer: *mut FfiByteBuffer,
) -> FfiErrorCode {
    catch_ffi_panic(|| {
        if request.is_null() {
            return fail_with_message(
                FfiErrorCode::NullPointer,
                "null additional recipient envelope request pointer",
            );
        }
        if out_buffer.is_null() {
            return fail_with_message(FfiErrorCode::NullPointer, "null output buffer");
        }

        let handle = match unsafe { handle_from_ptr(handle) } {
            Ok(handle) => handle,
            Err(_) => return fail_with_message(FfiErrorCode::InvalidHandle, "invalid handle"),
        };

        let request = unsafe { *request };
        let source_envelope_bytes =
            match unsafe { borrowed_bytes_as_slice(request.source_envelope) } {
                Ok(bytes) => bytes,
                Err(_) => {
                    return fail_with_message(
                        FfiErrorCode::NullPointer,
                        "null source envelope bytes pointer",
                    );
                }
            };
        if source_envelope_bytes.is_empty() {
            return fail_with_message(FfiErrorCode::InvalidLength, "empty source envelope bytes");
        }

        let current_private_key =
            match unsafe { borrowed_bytes_as_slice(request.current_private_key) } {
                Ok(bytes) => bytes,
                Err(_) => {
                    return fail_with_message(
                        FfiErrorCode::NullPointer,
                        "null current private key bytes pointer",
                    );
                }
            };
        if current_private_key.is_empty() {
            return fail_with_message(
                FfiErrorCode::InvalidLength,
                "empty current private key bytes",
            );
        }

        let new_public_key = match unsafe { borrowed_bytes_as_slice(request.new_public_key) } {
            Ok(bytes) => bytes,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::NullPointer,
                    "null new public key bytes pointer",
                );
            }
        };
        if new_public_key.is_empty() {
            return fail_with_message(FfiErrorCode::InvalidLength, "empty new public key bytes");
        }

        let current_owner_type = match OwnerType::try_from(request.current_owner_type) {
            Ok(value) => value,
            Err(code) => return fail_with_message(code, "invalid current owner type"),
        };
        let new_owner_type = match OwnerType::try_from(request.new_owner_type) {
            Ok(value) => value,
            Err(code) => return fail_with_message(code, "invalid new owner type"),
        };

        let source_envelope = match deserialize_key_envelope(source_envelope_bytes) {
            Ok(value) => value,
            Err(code) => return fail_with_message(code, "malformed KeyEnvelope JSON"),
        };
        if !envelope_matches_owner(
            &source_envelope,
            request.current_owner_id,
            current_owner_type,
        ) {
            return fail_with_message(
                FfiErrorCode::InvalidArgument,
                "envelope owner metadata mismatch",
            );
        }

        let data_key_value = match handle
            .core()
            .open_key_envelope(&source_envelope, current_private_key)
        {
            Ok(value) => value,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::CryptoError,
                    "crypto operation failed while opening source envelope",
                );
            }
        };

        let temporary_data_key = DataKey::new(
            source_envelope.key_id.clone(),
            data_key_value,
            UNIX_EPOCH,
            UNIX_EPOCH,
        );

        let envelope = match handle.core().create_additional_recipient_envelope(
            &temporary_data_key,
            request.new_owner_id,
            new_owner_type,
            new_public_key,
        ) {
            Ok(value) => value,
            Err(_) => {
                return fail_with_message(
                    FfiErrorCode::CryptoError,
                    "crypto operation failed while creating additional recipient envelope",
                );
            }
        };

        let serialized = match serialize_key_envelope(&envelope) {
            Ok(bytes) => bytes,
            Err(code) => return fail_with_message(code, "failed to serialize KeyEnvelope JSON"),
        };

        unsafe {
            *out_buffer = vec_into_buffer(serialized);
        }

        FfiErrorCode::Ok
    })
}

// KeyEnvelope를 JSON 바이트로 바꿈
fn serialize_key_envelope(envelope: &KeyEnvelope) -> Result<Vec<u8>, FfiErrorCode> {
    serde_json::to_vec(&KeyEnvelopeWire::from(envelope)).map_err(|_| FfiErrorCode::InternalError)
}

// JSON 바이트를 CryptoPackage로 복원
fn deserialize_crypto_package(bytes: &[u8]) -> Result<CryptoPackage, FfiErrorCode> {
    let wire: CryptoPackageWireOwned =
        serde_json::from_slice(bytes).map_err(|_| FfiErrorCode::InvalidArgument)?;

    CryptoPackage::try_from(wire)
}

// JSON 바이트를 KeyEnvelope로 복원
fn deserialize_key_envelope(bytes: &[u8]) -> Result<KeyEnvelope, FfiErrorCode> {
    let wire: KeyEnvelopeWireOwned =
        serde_json::from_slice(bytes).map_err(|_| FfiErrorCode::InvalidArgument)?;

    KeyEnvelope::try_from(wire)
}

// 문자열 "USER", "GUARDIAN"를 OwnerType으로 바꿈
fn owner_type_from_wire(value: &str) -> Result<OwnerType, FfiErrorCode> {
    match value {
        "USER" => Ok(OwnerType::User),
        "GUARDIAN" => Ok(OwnerType::Guardian),
        _ => Err(FfiErrorCode::InvalidArgument),
    }
}

// envelope 안 메타데이터와 현재 요청자의 owner_id, owner_type이 일치하는지 확인함
fn envelope_matches_owner(envelope: &KeyEnvelope, owner_id: u64, owner_type: OwnerType) -> bool {
    envelope.owner_id == owner_id && envelope.owner_type == owner_type
}

// 도메인 객체와 Wire 객체간의 변환기
impl<'a> From<&'a CryptoPackage> for CryptoPackageWire<'a> {
    // from 함수는 외부 타입과 내부 타입 사이의 값을 변환
    fn from(value: &'a CryptoPackage) -> Self {
        Self {
            encrypted_data: EncryptedLogDataWire::from(&value.encrypted_data),
            user_envelope: KeyEnvelopeWire::from(&value.user_envelope),
            guardian_envelope: KeyEnvelopeWire::from(&value.guardian_envelope),
        }
    }
}

impl<'a> From<&'a EncryptedLogData> for EncryptedLogDataWire<'a> {
    // from 함수는 외부 타입과 내부 타입 사이의 값을 변환
    fn from(value: &'a EncryptedLogData) -> Self {
        let created_at_unix_seconds = value
            .created_at
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);

        Self {
            encrypted_log_id: value.encrypted_log_id,
            user_id: value.user_id,
            ciphertext: &value.ciphertext,
            iv: value.iv,
            tag: value.tag,
            key_id: &value.key_id,
            created_at_unix_seconds,
        }
    }
}

impl<'a> From<&'a KeyEnvelope> for KeyEnvelopeWire<'a> {
    // from 함수는 외부 타입과 내부 타입 사이의 값을 변환
    fn from(value: &'a KeyEnvelope) -> Self {
        Self {
            envelope_id: value.envelope_id,
            key_id: &value.key_id,
            owner_id: value.owner_id,
            owner_type: match value.owner_type {
                OwnerType::User => "USER",
                OwnerType::Guardian => "GUARDIAN",
            },
            kem_ciphertext: &value.kem_ciphertext,
            encapsulated_key: &value.encapsulated_key,
        }
    }
}

impl TryFrom<CryptoPackageWireOwned> for CryptoPackage {
    type Error = FfiErrorCode;

    // try_from 함수는 외부 타입과 내부 타입 사이의 값을 변환
    fn try_from(value: CryptoPackageWireOwned) -> Result<Self, Self::Error> {
        Ok(Self::new(
            EncryptedLogData::try_from(value.encrypted_data)?,
            KeyEnvelope::try_from(value.user_envelope)?,
            KeyEnvelope::try_from(value.guardian_envelope)?,
        ))
    }
}

impl TryFrom<EncryptedLogDataWireOwned> for EncryptedLogData {
    type Error = FfiErrorCode;

    // try_from 함수는 외부 타입과 내부 타입 사이의 값을 변환
    fn try_from(value: EncryptedLogDataWireOwned) -> Result<Self, Self::Error> {
        Ok(Self::new(
            value.encrypted_log_id,
            value.user_id,
            value.ciphertext,
            value.iv,
            value.tag,
            value.key_id,
            UNIX_EPOCH + Duration::from_secs(value.created_at_unix_seconds),
        ))
    }
}

impl TryFrom<KeyEnvelopeWireOwned> for KeyEnvelope {
    type Error = FfiErrorCode;

    // try_from 함수는 외부 타입과 내부 타입 사이의 값을 변환
    fn try_from(value: KeyEnvelopeWireOwned) -> Result<Self, Self::Error> {
        Ok(Self::new(
            value.envelope_id,
            value.key_id,
            value.owner_id,
            owner_type_from_wire(&value.owner_type)?,
            value.kem_ciphertext,
            value.encapsulated_key,
        ))
    }
}

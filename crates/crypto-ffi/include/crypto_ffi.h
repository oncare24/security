#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FfiFacadeHandle FfiFacadeHandle;

typedef enum FfiErrorCode {
    FFI_ERROR_OK = 0,
    FFI_ERROR_NULL_POINTER = 1,
    FFI_ERROR_INVALID_HANDLE = 2,
    FFI_ERROR_INVALID_ARGUMENT = 3,
    FFI_ERROR_INVALID_LENGTH = 4,
    FFI_ERROR_INVALID_UTF8 = 5,
    FFI_ERROR_BUFFER_ALLOCATION_FAILED = 6,
    FFI_ERROR_CRYPTO_ERROR = 100,
    FFI_ERROR_INTERNAL_ERROR = 1000,
    FFI_ERROR_PANIC = 1001
} FfiErrorCode;

typedef enum FfiOwnerType {
    FFI_OWNER_TYPE_USER = 1,
    FFI_OWNER_TYPE_GUARDIAN = 2
} FfiOwnerType;

typedef struct FfiBorrowedBytes {
    const uint8_t* ptr;
    size_t len;
} FfiBorrowedBytes;

typedef struct FfiByteBuffer {
    uint8_t* ptr;
    size_t len;
    size_t capacity;
} FfiByteBuffer;

typedef struct FfiTimestamp {
    uint64_t unix_seconds;
} FfiTimestamp;

typedef struct FfiDataKeyInput {
    FfiBorrowedBytes key_id;
    uint8_t key_value[32];
    FfiTimestamp created_at;
    FfiTimestamp expires_at;
} FfiDataKeyInput;

typedef struct FfiEncryptPackageRequest {
    FfiBorrowedBytes plaintext;
    uint64_t user_id;
    FfiBorrowedBytes user_public_key;
    uint64_t guardian_id;
    FfiBorrowedBytes guardian_public_key;
    FfiDataKeyInput data_key;
} FfiEncryptPackageRequest;

typedef struct FfiDecryptPackageRequest {
    FfiBorrowedBytes package;
    uint64_t caller_id;
    FfiOwnerType caller_type;
    FfiBorrowedBytes private_key;
} FfiDecryptPackageRequest;

typedef struct FfiCreateKeyEnvelopeRequest {
    FfiDataKeyInput data_key;
    uint64_t owner_id;
    FfiOwnerType owner_type;
    FfiBorrowedBytes public_key;
} FfiCreateKeyEnvelopeRequest;

typedef struct FfiOpenKeyEnvelopeRequest {
    FfiBorrowedBytes envelope;
    uint64_t caller_id;
    FfiOwnerType caller_type;
    FfiBorrowedBytes private_key;
} FfiOpenKeyEnvelopeRequest;

typedef struct FfiCreateAdditionalRecipientEnvelopeRequest {
    FfiBorrowedBytes source_envelope;
    uint64_t current_owner_id;
    FfiOwnerType current_owner_type;
    FfiBorrowedBytes current_private_key;
    uint64_t new_owner_id;
    FfiOwnerType new_owner_type;
    FfiBorrowedBytes new_public_key;
} FfiCreateAdditionalRecipientEnvelopeRequest;

FfiErrorCode crypto_ffi_facade_new_default(FfiFacadeHandle** out_handle);
FfiErrorCode crypto_ffi_facade_free(FfiFacadeHandle* handle);

FfiErrorCode crypto_ffi_byte_buffer_free(FfiByteBuffer buffer);

FfiErrorCode crypto_ffi_generate_data_key(
    FfiFacadeHandle* handle,
    FfiBorrowedBytes key_id,
    uint64_t created_at_unix_seconds,
    uint64_t expires_at_unix_seconds,
    FfiByteBuffer* out_buffer
);

// Generates a new ML-KEM-1024 keypair.
// The returned buffer contains UTF-8 JSON bytes:
// {"algorithm":"ML-KEM-1024","public_key":[...],"private_key":[...]}
// public_key and private_key are JSON arrays of byte values, matching the
// existing KeyEnvelope JSON byte representation. Release the returned buffer
// with crypto_ffi_byte_buffer_free.
FfiErrorCode crypto_ffi_generate_mlkem_keypair(
    FfiFacadeHandle* handle,
    FfiByteBuffer* out_buffer
);

FfiErrorCode crypto_ffi_encrypt_package(
    FfiFacadeHandle* handle,
    const FfiEncryptPackageRequest* request,
    FfiByteBuffer* out_buffer
);

FfiErrorCode crypto_ffi_decrypt_package(
    FfiFacadeHandle* handle,
    const FfiDecryptPackageRequest* request,
    FfiByteBuffer* out_buffer
);

FfiErrorCode crypto_ffi_create_key_envelope(
    FfiFacadeHandle* handle,
    const FfiCreateKeyEnvelopeRequest* request,
    FfiByteBuffer* out_buffer
);

FfiErrorCode crypto_ffi_open_key_envelope(
    FfiFacadeHandle* handle,
    const FfiOpenKeyEnvelopeRequest* request,
    FfiByteBuffer* out_buffer
);

FfiErrorCode crypto_ffi_create_additional_recipient_envelope(
    FfiFacadeHandle* handle,
    const FfiCreateAdditionalRecipientEnvelopeRequest* request,
    FfiByteBuffer* out_buffer
);

size_t crypto_ffi_last_error_message_length(void);
FfiErrorCode crypto_ffi_last_error_message_copy(uint8_t* buffer, size_t buffer_len);

#ifdef __cplusplus
}
#endif

use crypto_ffi::{
    FfiBorrowedBytes, FfiByteBuffer, FfiCreateAdditionalRecipientEnvelopeRequest,
    FfiCreateKeyEnvelopeRequest, FfiDataKeyInput, FfiDecryptPackageRequest,
    FfiEncryptPackageRequest, FfiErrorCode, FfiOpenKeyEnvelopeRequest, FfiOwnerType, FfiTimestamp,
    crypto_ffi_byte_buffer_free, crypto_ffi_create_additional_recipient_envelope,
    crypto_ffi_create_key_envelope, crypto_ffi_decrypt_package, crypto_ffi_encrypt_package,
    crypto_ffi_facade_free, crypto_ffi_facade_new_default, crypto_ffi_generate_data_key,
    crypto_ffi_generate_mlkem_keypair, crypto_ffi_last_error_message_copy,
    crypto_ffi_last_error_message_length, crypto_ffi_open_key_envelope,
};

// sample_bytes 함수는 테스트에서 사용할 샘플 값을 만듦
fn sample_bytes(value: &[u8]) -> FfiBorrowedBytes {
    FfiBorrowedBytes {
        ptr: value.as_ptr(),
        len: value.len(),
    }
}

// sample_data_key_input 함수는 테스트에서 사용할 샘플 값을 만듦
fn sample_data_key_input<'a>(key_id: &'a [u8], key_value: [u8; 32]) -> FfiDataKeyInput {
    FfiDataKeyInput {
        key_id: sample_bytes(key_id),
        key_value,
        created_at: FfiTimestamp {
            unix_seconds: 1_700_000_000,
        },
        expires_at: FfiTimestamp {
            unix_seconds: 1_700_086_400,
        },
    }
}

// buffer_as_slice 함수는 바이트 버퍼를 호출자가 사용할 형태로 변환
unsafe fn buffer_as_slice<'a>(buffer: &'a FfiByteBuffer) -> &'a [u8] {
    if buffer.ptr.is_null() || buffer.len == 0 {
        return &[];
    }

    unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) }
}

// read_last_error_message 함수는 조건에 맞는 값을 조회해 반환
fn read_last_error_message() -> String {
    let length = crypto_ffi_last_error_message_length();
    if length == 0 {
        return String::new();
    }

    let mut buffer = vec![0u8; length + 1];
    let code = crypto_ffi_last_error_message_copy(buffer.as_mut_ptr(), buffer.len());
    assert_eq!(code, FfiErrorCode::Ok);

    String::from_utf8(buffer[..length].to_vec()).expect("last error should be valid UTF-8")
}

// creates_and_frees_facade_handle 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
#[test]
fn creates_and_frees_facade_handle() {
    let mut handle = std::ptr::null_mut();

    let create_code = crypto_ffi_facade_new_default(&mut handle);
    assert_eq!(create_code, FfiErrorCode::Ok);
    assert!(!handle.is_null());

    let free_code = crypto_ffi_facade_free(handle);
    assert_eq!(free_code, FfiErrorCode::Ok);
}

// generate_data_key_returns_buffer 함수는 암호화에 사용할 새 키나 바이트 값을 생성
#[test]
fn generate_data_key_returns_buffer() {
    let mut handle = std::ptr::null_mut();
    assert_eq!(crypto_ffi_facade_new_default(&mut handle), FfiErrorCode::Ok);

    let key_id = b"ffi-key-1";
    let mut output = FfiByteBuffer::null();
    let code = crypto_ffi_generate_data_key(
        handle,
        sample_bytes(key_id),
        1_700_000_000,
        1_700_086_400,
        &mut output,
    );

    assert_eq!(code, FfiErrorCode::Ok);
    assert_eq!(output.len, 32);
    assert_eq!(crypto_ffi_last_error_message_length(), 0);

    assert_eq!(crypto_ffi_byte_buffer_free(output), FfiErrorCode::Ok);
    assert_eq!(crypto_ffi_facade_free(handle), FfiErrorCode::Ok);
}

// generate_mlkem_keypair_returns_json_buffer 함수는 암호화에 사용할 새 키나 바이트 값을 생성
#[test]
fn generate_mlkem_keypair_returns_json_buffer() {
    let mut handle = std::ptr::null_mut();
    assert_eq!(crypto_ffi_facade_new_default(&mut handle), FfiErrorCode::Ok);

    let mut output = FfiByteBuffer::null();
    let code = crypto_ffi_generate_mlkem_keypair(handle, &mut output);

    assert_eq!(code, FfiErrorCode::Ok);
    assert!(output.len > 0);
    let json: serde_json::Value =
        serde_json::from_slice(unsafe { buffer_as_slice(&output) }).expect("keypair JSON");
    assert_eq!(json["algorithm"], "ML-KEM-1024");
    assert!(
        json["public_key"]
            .as_array()
            .expect("public_key array")
            .len()
            > 0
    );
    assert!(
        json["private_key"]
            .as_array()
            .expect("private_key array")
            .len()
            > 0
    );
    assert_eq!(crypto_ffi_last_error_message_length(), 0);

    assert_eq!(crypto_ffi_byte_buffer_free(output), FfiErrorCode::Ok);
    assert_eq!(crypto_ffi_facade_free(handle), FfiErrorCode::Ok);
}

// encrypt_and_decrypt_package_round_trip_succeeds 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
#[test]
fn encrypt_and_decrypt_package_round_trip_succeeds() {
    let mut handle = std::ptr::null_mut();
    assert_eq!(crypto_ffi_facade_new_default(&mut handle), FfiErrorCode::Ok);

    let user_kem =
        crypto_adapters::mlkem_service::MLKEMService::new().expect("ml-kem should initialize");
    let guardian_kem =
        crypto_adapters::mlkem_service::MLKEMService::new().expect("ml-kem should initialize");
    let (user_public_key, user_private_key) = user_kem
        .generate_keypair()
        .expect("user keypair should work");
    let (guardian_public_key, _) = guardian_kem
        .generate_keypair()
        .expect("guardian keypair should work");
    let key_id = b"ffi-key-2";
    let plaintext = b"ffi decrypt payload";
    let encrypt_request = FfiEncryptPackageRequest {
        plaintext: sample_bytes(plaintext),
        user_id: 10,
        user_public_key: sample_bytes(&user_public_key),
        guardian_id: 20,
        guardian_public_key: sample_bytes(&guardian_public_key),
        data_key: sample_data_key_input(key_id, [9u8; 32]),
    };
    let mut encrypted_package = FfiByteBuffer::null();

    let encrypt_code = crypto_ffi_encrypt_package(handle, &encrypt_request, &mut encrypted_package);
    assert_eq!(encrypt_code, FfiErrorCode::Ok);
    assert!(encrypted_package.len > 0);

    let decrypt_request = FfiDecryptPackageRequest {
        package: FfiBorrowedBytes {
            ptr: encrypted_package.ptr.cast_const(),
            len: encrypted_package.len,
        },
        caller_id: 10,
        caller_type: FfiOwnerType::User,
        private_key: sample_bytes(&user_private_key),
    };
    let mut decrypted_plaintext = FfiByteBuffer::null();

    let decrypt_code =
        crypto_ffi_decrypt_package(handle, &decrypt_request, &mut decrypted_plaintext);
    assert_eq!(decrypt_code, FfiErrorCode::Ok);
    assert_eq!(unsafe { buffer_as_slice(&decrypted_plaintext) }, plaintext);
    assert_eq!(crypto_ffi_last_error_message_length(), 0);

    assert_eq!(
        crypto_ffi_byte_buffer_free(decrypted_plaintext),
        FfiErrorCode::Ok
    );
    assert_eq!(
        crypto_ffi_byte_buffer_free(encrypted_package),
        FfiErrorCode::Ok
    );
    assert_eq!(crypto_ffi_facade_free(handle), FfiErrorCode::Ok);
}

// create_and_open_key_envelope_round_trip_succeeds 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
#[test]
fn create_and_open_key_envelope_round_trip_succeeds() {
    let mut handle = std::ptr::null_mut();
    assert_eq!(crypto_ffi_facade_new_default(&mut handle), FfiErrorCode::Ok);

    let user_kem =
        crypto_adapters::mlkem_service::MLKEMService::new().expect("ml-kem should initialize");
    let (user_public_key, user_private_key) = user_kem
        .generate_keypair()
        .expect("user keypair should work");
    let key_value = [7u8; 32];
    let create_request = FfiCreateKeyEnvelopeRequest {
        data_key: sample_data_key_input(b"ffi-envelope-key", key_value),
        owner_id: 42,
        owner_type: FfiOwnerType::User,
        public_key: sample_bytes(&user_public_key),
    };
    let mut envelope_buffer = FfiByteBuffer::null();

    let create_code = crypto_ffi_create_key_envelope(handle, &create_request, &mut envelope_buffer);
    assert_eq!(create_code, FfiErrorCode::Ok);
    assert!(envelope_buffer.len > 0);

    let open_request = FfiOpenKeyEnvelopeRequest {
        envelope: FfiBorrowedBytes {
            ptr: envelope_buffer.ptr.cast_const(),
            len: envelope_buffer.len,
        },
        caller_id: 42,
        caller_type: FfiOwnerType::User,
        private_key: sample_bytes(&user_private_key),
    };
    let mut data_key_buffer = FfiByteBuffer::null();

    let open_code = crypto_ffi_open_key_envelope(handle, &open_request, &mut data_key_buffer);
    assert_eq!(open_code, FfiErrorCode::Ok);
    assert_eq!(unsafe { buffer_as_slice(&data_key_buffer) }, &key_value);
    assert_eq!(crypto_ffi_last_error_message_length(), 0);

    assert_eq!(
        crypto_ffi_byte_buffer_free(data_key_buffer),
        FfiErrorCode::Ok
    );
    assert_eq!(
        crypto_ffi_byte_buffer_free(envelope_buffer),
        FfiErrorCode::Ok
    );
    assert_eq!(crypto_ffi_facade_free(handle), FfiErrorCode::Ok);
}

// create_additional_recipient_envelope_and_open_with_new_recipient_succeeds 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
#[test]
fn create_additional_recipient_envelope_and_open_with_new_recipient_succeeds() {
    let mut handle = std::ptr::null_mut();
    assert_eq!(crypto_ffi_facade_new_default(&mut handle), FfiErrorCode::Ok);

    let source_kem =
        crypto_adapters::mlkem_service::MLKEMService::new().expect("ml-kem should initialize");
    let new_kem =
        crypto_adapters::mlkem_service::MLKEMService::new().expect("ml-kem should initialize");
    let (source_public_key, source_private_key) = source_kem
        .generate_keypair()
        .expect("source keypair should work");
    let (new_public_key, new_private_key) =
        new_kem.generate_keypair().expect("new keypair should work");
    let key_value = [11u8; 32];
    let create_request = FfiCreateKeyEnvelopeRequest {
        data_key: sample_data_key_input(b"ffi-share-key", key_value),
        owner_id: 7,
        owner_type: FfiOwnerType::User,
        public_key: sample_bytes(&source_public_key),
    };
    let mut source_envelope = FfiByteBuffer::null();
    assert_eq!(
        crypto_ffi_create_key_envelope(handle, &create_request, &mut source_envelope),
        FfiErrorCode::Ok
    );

    let additional_request = FfiCreateAdditionalRecipientEnvelopeRequest {
        source_envelope: FfiBorrowedBytes {
            ptr: source_envelope.ptr.cast_const(),
            len: source_envelope.len,
        },
        current_owner_id: 7,
        current_owner_type: FfiOwnerType::User,
        current_private_key: sample_bytes(&source_private_key),
        new_owner_id: 88,
        new_owner_type: FfiOwnerType::Guardian,
        new_public_key: sample_bytes(&new_public_key),
    };
    let mut additional_envelope = FfiByteBuffer::null();

    let additional_code = crypto_ffi_create_additional_recipient_envelope(
        handle,
        &additional_request,
        &mut additional_envelope,
    );
    assert_eq!(additional_code, FfiErrorCode::Ok);
    assert!(additional_envelope.len > 0);

    let open_request = FfiOpenKeyEnvelopeRequest {
        envelope: FfiBorrowedBytes {
            ptr: additional_envelope.ptr.cast_const(),
            len: additional_envelope.len,
        },
        caller_id: 88,
        caller_type: FfiOwnerType::Guardian,
        private_key: sample_bytes(&new_private_key),
    };
    let mut data_key_buffer = FfiByteBuffer::null();

    let open_code = crypto_ffi_open_key_envelope(handle, &open_request, &mut data_key_buffer);
    assert_eq!(open_code, FfiErrorCode::Ok);
    assert_eq!(unsafe { buffer_as_slice(&data_key_buffer) }, &key_value);
    assert_eq!(crypto_ffi_last_error_message_length(), 0);

    assert_eq!(
        crypto_ffi_byte_buffer_free(data_key_buffer),
        FfiErrorCode::Ok
    );
    assert_eq!(
        crypto_ffi_byte_buffer_free(additional_envelope),
        FfiErrorCode::Ok
    );
    assert_eq!(
        crypto_ffi_byte_buffer_free(source_envelope),
        FfiErrorCode::Ok
    );
    assert_eq!(crypto_ffi_facade_free(handle), FfiErrorCode::Ok);
}

// invalid_handle_failure_records_last_error_message 함수는 마지막 오류 정보를 읽거나 예외 객체로 변환
#[test]
fn invalid_handle_failure_records_last_error_message() {
    let public_key = [1u8; 4];
    let request = FfiCreateKeyEnvelopeRequest {
        data_key: sample_data_key_input(b"ffi-invalid-handle", [3u8; 32]),
        owner_id: 1,
        owner_type: FfiOwnerType::User,
        public_key: sample_bytes(&public_key),
    };
    let mut output = FfiByteBuffer::null();

    let code = crypto_ffi_create_key_envelope(std::ptr::null_mut(), &request, &mut output);
    assert_eq!(code, FfiErrorCode::InvalidHandle);
    assert_eq!(read_last_error_message(), "invalid handle");
}

// malformed_inputs_record_last_error_message 함수는 외부 타입과 내부 타입 사이의 값을 변환
#[test]
fn malformed_inputs_record_last_error_message() {
    let mut handle = std::ptr::null_mut();
    assert_eq!(crypto_ffi_facade_new_default(&mut handle), FfiErrorCode::Ok);

    let private_key = [1u8; 4];
    let request = FfiOpenKeyEnvelopeRequest {
        envelope: sample_bytes(b"{not-valid-json"),
        caller_id: 10,
        caller_type: FfiOwnerType::User,
        private_key: sample_bytes(&private_key),
    };
    let mut output = FfiByteBuffer::null();

    let code = crypto_ffi_open_key_envelope(handle, &request, &mut output);
    assert_eq!(code, FfiErrorCode::InvalidArgument);
    assert_eq!(read_last_error_message(), "malformed KeyEnvelope JSON");

    assert_eq!(crypto_ffi_facade_free(handle), FfiErrorCode::Ok);
}

// successful_call_clears_last_error_message 함수는 마지막 오류 정보를 읽거나 예외 객체로 변환
#[test]
fn successful_call_clears_last_error_message() {
    let public_key = [1u8; 4];
    let request = FfiCreateKeyEnvelopeRequest {
        data_key: sample_data_key_input(b"ffi-invalid-handle-2", [4u8; 32]),
        owner_id: 1,
        owner_type: FfiOwnerType::User,
        public_key: sample_bytes(&public_key),
    };
    let mut output = FfiByteBuffer::null();
    let error_code = crypto_ffi_create_key_envelope(std::ptr::null_mut(), &request, &mut output);
    assert_eq!(error_code, FfiErrorCode::InvalidHandle);
    assert!(crypto_ffi_last_error_message_length() > 0);

    let mut handle = std::ptr::null_mut();
    let success_code = crypto_ffi_facade_new_default(&mut handle);
    assert_eq!(success_code, FfiErrorCode::Ok);
    assert_eq!(crypto_ffi_last_error_message_length(), 0);

    assert_eq!(crypto_ffi_facade_free(handle), FfiErrorCode::Ok);
}

// last_error_message_copy_validates_buffer_rules 함수는 입력값이나 호출 결과가 유효한지 확인
#[test]
fn last_error_message_copy_validates_buffer_rules() {
    let public_key = [1u8; 4];
    let request = FfiCreateKeyEnvelopeRequest {
        data_key: sample_data_key_input(b"ffi-invalid-handle-3", [5u8; 32]),
        owner_id: 1,
        owner_type: FfiOwnerType::User,
        public_key: sample_bytes(&public_key),
    };
    let mut output = FfiByteBuffer::null();
    let code = crypto_ffi_create_key_envelope(std::ptr::null_mut(), &request, &mut output);
    assert_eq!(code, FfiErrorCode::InvalidHandle);

    let null_copy_code = crypto_ffi_last_error_message_copy(std::ptr::null_mut(), 10);
    assert_eq!(null_copy_code, FfiErrorCode::NullPointer);

    let mut too_small = [0u8; 4];
    let short_copy_code =
        crypto_ffi_last_error_message_copy(too_small.as_mut_ptr(), too_small.len());
    assert_eq!(short_copy_code, FfiErrorCode::InvalidLength);

    assert_eq!(read_last_error_message(), "invalid handle");
}

// envelope_functions_with_null_or_invalid_length_input_fail 함수는 외부 타입과 내부 타입 사이의 값을 변환
#[test]
fn envelope_functions_with_null_or_invalid_length_input_fail() {
    let mut handle = std::ptr::null_mut();
    assert_eq!(crypto_ffi_facade_new_default(&mut handle), FfiErrorCode::Ok);

    let create_request = FfiCreateKeyEnvelopeRequest {
        data_key: sample_data_key_input(b"ffi-invalid-len", [5u8; 32]),
        owner_id: 1,
        owner_type: FfiOwnerType::User,
        public_key: FfiBorrowedBytes {
            ptr: std::ptr::null(),
            len: 3,
        },
    };
    let mut output = FfiByteBuffer::null();
    let create_code = crypto_ffi_create_key_envelope(handle, &create_request, &mut output);
    assert_eq!(create_code, FfiErrorCode::NullPointer);

    let private_key = [1u8; 4];
    let open_request = FfiOpenKeyEnvelopeRequest {
        envelope: sample_bytes(b"{}"),
        caller_id: 1,
        caller_type: FfiOwnerType::User,
        private_key: FfiBorrowedBytes {
            ptr: private_key.as_ptr(),
            len: 0,
        },
    };
    let open_code = crypto_ffi_open_key_envelope(handle, &open_request, &mut output);
    assert_eq!(open_code, FfiErrorCode::InvalidLength);

    let additional_request = FfiCreateAdditionalRecipientEnvelopeRequest {
        source_envelope: sample_bytes(b"{}"),
        current_owner_id: 1,
        current_owner_type: FfiOwnerType::User,
        current_private_key: sample_bytes(&private_key),
        new_owner_id: 2,
        new_owner_type: FfiOwnerType::Guardian,
        new_public_key: FfiBorrowedBytes {
            ptr: private_key.as_ptr(),
            len: 0,
        },
    };
    let additional_code =
        crypto_ffi_create_additional_recipient_envelope(handle, &additional_request, &mut output);
    assert_eq!(additional_code, FfiErrorCode::InvalidLength);

    assert_eq!(crypto_ffi_facade_free(handle), FfiErrorCode::Ok);
}

// decrypt_package_with_invalid_handle_fails 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
#[test]
fn decrypt_package_with_invalid_handle_fails() {
    let package_bytes = b"{}";
    let private_key = [1u8; 4];
    let request = FfiDecryptPackageRequest {
        package: sample_bytes(package_bytes),
        caller_id: 10,
        caller_type: FfiOwnerType::User,
        private_key: sample_bytes(&private_key),
    };
    let mut output = FfiByteBuffer::null();

    let code = crypto_ffi_decrypt_package(std::ptr::null_mut(), &request, &mut output);

    assert_eq!(code, FfiErrorCode::InvalidHandle);
}

// decrypt_package_with_null_or_invalid_length_input_fails 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
#[test]
fn decrypt_package_with_null_or_invalid_length_input_fails() {
    let mut handle = std::ptr::null_mut();
    assert_eq!(crypto_ffi_facade_new_default(&mut handle), FfiErrorCode::Ok);

    let private_key = [1u8; 4];
    let request_with_null_package = FfiDecryptPackageRequest {
        package: FfiBorrowedBytes {
            ptr: std::ptr::null(),
            len: 3,
        },
        caller_id: 10,
        caller_type: FfiOwnerType::User,
        private_key: sample_bytes(&private_key),
    };
    let mut output = FfiByteBuffer::null();

    let null_code = crypto_ffi_decrypt_package(handle, &request_with_null_package, &mut output);
    assert_eq!(null_code, FfiErrorCode::NullPointer);

    let request_with_empty_private_key = FfiDecryptPackageRequest {
        package: sample_bytes(b"{}"),
        caller_id: 10,
        caller_type: FfiOwnerType::User,
        private_key: FfiBorrowedBytes {
            ptr: private_key.as_ptr(),
            len: 0,
        },
    };
    let length_code =
        crypto_ffi_decrypt_package(handle, &request_with_empty_private_key, &mut output);
    assert_eq!(length_code, FfiErrorCode::InvalidLength);

    assert_eq!(crypto_ffi_facade_free(handle), FfiErrorCode::Ok);
}

// decrypt_package_with_malformed_package_bytes_fails 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
#[test]
fn decrypt_package_with_malformed_package_bytes_fails() {
    let mut handle = std::ptr::null_mut();
    assert_eq!(crypto_ffi_facade_new_default(&mut handle), FfiErrorCode::Ok);

    let private_key = [1u8; 4];
    let request = FfiDecryptPackageRequest {
        package: sample_bytes(b"{not-valid-json"),
        caller_id: 10,
        caller_type: FfiOwnerType::User,
        private_key: sample_bytes(&private_key),
    };
    let mut output = FfiByteBuffer::null();

    let code = crypto_ffi_decrypt_package(handle, &request, &mut output);
    assert_eq!(code, FfiErrorCode::InvalidArgument);

    assert_eq!(crypto_ffi_facade_free(handle), FfiErrorCode::Ok);
}

// byte_buffer_free_accepts_null_buffer 함수는 FFI로 전달된 버퍼 메모리를 해제
#[test]
fn byte_buffer_free_accepts_null_buffer() {
    assert_eq!(
        crypto_ffi_byte_buffer_free(FfiByteBuffer::null()),
        FfiErrorCode::Ok
    );
}

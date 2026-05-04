use std::sync::Arc;
use std::time::SystemTime;

use crypto_adapters::aes_gcm_crypto::AESGCMCrypto;
use crypto_adapters::mlkem_service::MLKEMService;
use crypto_adapters::os_secure_random::OsSecureRandom;
use crypto_core::core_facade::CoreFacade;
use crypto_core::domain::data_key::DataKey;
use crypto_core::domain::key_envelope::OwnerType;
use crypto_core::service::decryption_service::{DecryptionCaller, DecryptionService};
use crypto_core::service::encryption_service::{EncryptionRequest, EncryptionService};
use crypto_core::service::key_management_service::KeyManagementService;
use crypto_core::service::sharing_service::SharingService;

fn build_encryption_request(
    user_public_key: Vec<u8>,
    guardian_public_key: Vec<u8>,
    plaintext: Vec<u8>,
) -> EncryptionRequest {
    EncryptionRequest::new(plaintext, 10, user_public_key, 20, guardian_public_key)
}

fn build_core_facade() -> CoreFacade {
    CoreFacade::from_backends(
        Arc::new(AESGCMCrypto),
        Arc::new(MLKEMService::new().expect("ml-kem should initialize")),
        Arc::new(OsSecureRandom),
    )
}

#[test]
fn encryption_service_encrypts_with_supplied_data_key() {
    let kem_backend: Arc<dyn crypto_core::crypto::backends::KemBackend> = Arc::new(MLKEMService::new().expect("ml-kem should initialize"));
    let key_management_service = KeyManagementService::with_kem_backend(kem_backend);
    let service = EncryptionService::with_dependencies(
        Arc::new(AESGCMCrypto),
        Arc::new(OsSecureRandom),
        key_management_service,
    );
    let ml_kem_service = MLKEMService::new().expect("ml-kem service should initialize");
    let (user_public_key, _) = ml_kem_service
        .generate_keypair()
        .expect("user keypair should be created");
    let (guardian_public_key, _) = ml_kem_service
        .generate_keypair()
        .expect("guardian keypair should be created");
    let timestamp = SystemTime::now();
    let data_key = DataKey::new("datakey-explicit", [17u8; 32], timestamp, timestamp);

    let package = service
        .encrypt_log_with_data_key_at(
            EncryptionRequest::new(
                b"log payload".to_vec(),
                100,
                user_public_key,
                200,
                guardian_public_key,
            ),
            &data_key,
            timestamp,
        )
        .expect("encryption should succeed");

    assert_eq!(package.encrypted_data.key_id, "datakey-explicit");
    assert_eq!(package.user_envelope.key_id, "datakey-explicit");
    assert_eq!(package.guardian_envelope.key_id, "datakey-explicit");
}

#[test]
fn decryption_service_decrypts_user_encrypted_log_end_to_end() {
    let kem_backend: Arc<dyn crypto_core::crypto::backends::KemBackend> = Arc::new(MLKEMService::new().expect("ml-kem should initialize"));
    let key_management_service = KeyManagementService::with_kem_backend(Arc::clone(&kem_backend));
    let encryption_service = EncryptionService::with_dependencies(
        Arc::new(AESGCMCrypto),
        Arc::new(OsSecureRandom),
        key_management_service,
    );
    let decryption_service = DecryptionService::with_backends(Arc::new(AESGCMCrypto), kem_backend);
    let ml_kem_service = MLKEMService::new().expect("ml-kem service should initialize");
    let (user_public_key, user_private_key) = ml_kem_service
        .generate_keypair()
        .expect("user keypair should be created");
    let (guardian_public_key, _) = ml_kem_service
        .generate_keypair()
        .expect("guardian keypair should be created");
    let plaintext = b"user log payload".to_vec();
    let timestamp = SystemTime::now();
    let data_key = DataKey::new("datakey-user", [21u8; 32], timestamp, timestamp);

    let crypto_package = encryption_service
        .encrypt_log_with_data_key_at(
            EncryptionRequest::new(
                plaintext.clone(),
                10,
                user_public_key,
                20,
                guardian_public_key,
            ),
            &data_key,
            timestamp,
        )
        .expect("encryption should succeed");

    let decrypted = decryption_service
        .decrypt_log(
            &crypto_package,
            DecryptionCaller::new(10, OwnerType::User),
            &user_private_key,
        )
        .expect("user decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn key_management_service_creates_and_opens_envelope() {
    let service = KeyManagementService::with_kem_backend(Arc::new(
        MLKEMService::new().expect("ml-kem should initialize"),
    ));
    let ml_kem_service = MLKEMService::new().expect("ml-kem should initialize");
    let (public_key, private_key) = ml_kem_service
        .generate_keypair()
        .expect("keypair should generate");
    let data_key = DataKey::new(
        "datakey-2026-03-16",
        [7u8; 32],
        SystemTime::now(),
        SystemTime::now(),
    );

    let envelope = service
        .create_key_envelope(&data_key, 30, OwnerType::User, &public_key)
        .expect("envelope should be created");
    let opened = service
        .open_key_envelope(&envelope, &private_key)
        .expect("envelope should open");

    assert_eq!(opened, data_key.key_value);
}

#[test]
fn sharing_service_creates_additional_recipient_envelope() {
    let key_management_service = KeyManagementService::with_kem_backend(Arc::new(
        MLKEMService::new().expect("ml-kem should initialize"),
    ));
    let sharing_service = SharingService::with_key_management_service(key_management_service);
    let ml_kem_service = MLKEMService::new().expect("ml-kem service should initialize");
    let (guardian_public_key, guardian_private_key) = ml_kem_service
        .generate_keypair()
        .expect("guardian keypair should generate");
    let data_key = DataKey::new(
        "datakey-2026-03-16",
        [11u8; 32],
        SystemTime::now(),
        SystemTime::now(),
    );

    let envelope = sharing_service
        .create_additional_recipient_envelope(
            &data_key,
            900,
            OwnerType::Guardian,
            &guardian_public_key,
        )
        .expect("recipient envelope should be created");
    let recovered = ml_kem_service
        .decapsulate(envelope.clone(), &guardian_private_key)
        .expect("guardian should recover the same data key");

    assert_eq!(envelope.owner_id, 900);
    assert_eq!(envelope.owner_type, OwnerType::Guardian);
    assert_eq!(recovered, data_key.key_value);
}

#[test]
fn core_facade_encrypts_and_decrypts_package() {
    let facade = build_core_facade();
    let ml_kem_service = MLKEMService::new().expect("ml-kem should initialize");
    let (user_public_key, user_private_key) = ml_kem_service
        .generate_keypair()
        .expect("user keypair should generate");
    let (guardian_public_key, _) = ml_kem_service
        .generate_keypair()
        .expect("guardian keypair should generate");
    let timestamp = SystemTime::now();
    let plaintext = b"facade round trip".to_vec();
    let data_key = facade
        .generate_data_key("datakey-facade", timestamp, timestamp)
        .expect("data key should be generated");

    let package = facade
        .encrypt_package_at(
            build_encryption_request(user_public_key, guardian_public_key, plaintext.clone()),
            &data_key,
            timestamp,
        )
        .expect("package should encrypt");
    let decrypted = facade
        .decrypt_package(
            &package,
            DecryptionCaller::new(10, OwnerType::User),
            &user_private_key,
        )
        .expect("package should decrypt");

    assert_eq!(decrypted, plaintext);
    assert_eq!(package.encrypted_data.key_id, data_key.key_id);
}

#[test]
fn core_facade_creates_and_opens_key_envelope() {
    let facade = build_core_facade();
    let ml_kem_service = MLKEMService::new().expect("ml-kem should initialize");
    let (public_key, private_key) = ml_kem_service
        .generate_keypair()
        .expect("keypair should generate");
    let timestamp = SystemTime::now();
    let data_key = facade
        .generate_data_key("datakey-envelope", timestamp, timestamp)
        .expect("data key should be generated");

    let envelope = facade
        .create_key_envelope(&data_key, 99, OwnerType::Guardian, &public_key)
        .expect("envelope should be created");
    let opened = facade
        .open_key_envelope(&envelope, &private_key)
        .expect("envelope should open");

    assert_eq!(opened, data_key.key_value);
    assert_eq!(envelope.key_id, data_key.key_id);
}

#[test]
fn core_facade_creates_additional_recipient_envelope() {
    let facade = build_core_facade();
    let ml_kem_service = MLKEMService::new().expect("ml-kem should initialize");
    let (public_key, private_key) = ml_kem_service
        .generate_keypair()
        .expect("keypair should generate");
    let timestamp = SystemTime::now();
    let data_key = facade
        .generate_data_key("datakey-share", timestamp, timestamp)
        .expect("data key should be generated");

    let envelope = facade
        .create_additional_recipient_envelope(&data_key, 77, OwnerType::Guardian, &public_key)
        .expect("additional envelope should be created");
    let opened = facade
        .open_key_envelope(&envelope, &private_key)
        .expect("additional envelope should open");

    assert_eq!(opened, data_key.key_value);
    assert_eq!(envelope.owner_id, 77);
    assert_eq!(envelope.owner_type, OwnerType::Guardian);
}

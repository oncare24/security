use std::sync::Arc;

use crypto_core::core_facade::CoreFacade;
use crypto_core::crypto::backends::KemBackendError;
use crypto_core::service::encryption_service::EncryptionService;
use crypto_core::service::key_management_service::KeyManagementService;

use crate::aes_gcm_crypto::AESGCMCrypto;
use crate::mlkem_service::MLKEMService;
use crate::os_secure_random::OsSecureRandom;

//각 객체를 생성해서 coreFacade를 완성
pub fn build_core_facade() -> Result<CoreFacade, KemBackendError> {
    let aead_backend = Arc::new(AESGCMCrypto);
    let kem_backend = Arc::new(MLKEMService::new()?);
    let secure_random = Arc::new(OsSecureRandom);

    Ok(CoreFacade::from_backends(
        aead_backend,
        kem_backend,
        secure_random,
    ))
}

//암호화에 필요한 구현체들을 조립해서 encryptionService를 만듦
pub fn build_encryption_service() -> Result<EncryptionService, KemBackendError> {
    let kem_backend = Arc::new(MLKEMService::new()?);
    let key_management_service = KeyManagementService::with_kem_backend(kem_backend);

    Ok(EncryptionService::with_dependencies(
        Arc::new(AESGCMCrypto),
        Arc::new(OsSecureRandom),
        key_management_service,
    ))
}

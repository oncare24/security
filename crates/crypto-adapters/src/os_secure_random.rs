use rand::TryRng;
use rand::rngs::SysRng;

use crypto_core::crypto::backends::{SecureRandom, SecureRandomError};

#[derive(Debug, Default, Clone, Copy)]
pub struct OsSecureRandom;

//os 기반 보안 난수 생성 구현체
impl SecureRandom for OsSecureRandom {
    // fill_bytes 함수는 바이트 버퍼를 호출자가 사용할 형태로 변환
    fn fill_bytes(&self, out: &mut [u8]) -> Result<(), SecureRandomError> {
        let mut rng = SysRng;
        rng.try_fill_bytes(out)
            .map_err(|error| SecureRandomError::FillFailed(error.to_string()))
    }
}

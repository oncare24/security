use std::collections::HashMap;
use std::sync::Mutex;

use crypto_core::domain::encrypted_log::EncryptedLogData;

use crate::repository::RepositoryError;

// 암호화된 로그를 저장하고 조회하기 위한 repository trait(인터페이스)
pub trait EncryptedLogRepository {
    // store_encrypted_log 함수는 전달받은 값을 저장소에 보관
    fn store_encrypted_log(&self, encrypted_log: &EncryptedLogData) -> Result<(), RepositoryError>;

    // get_encrypted_log_by_id 함수는 조건에 맞는 값을 조회해 반환
    fn get_encrypted_log_by_id(
        &self,
        encrypted_log_id: u64,
    ) -> Result<Option<EncryptedLogData>, RepositoryError>;
}

#[derive(Debug, Default)]
// trait의 메모리 기반 구현체 구조체
pub struct InMemoryEncryptedLogRepository {
    store: Mutex<HashMap<u64, EncryptedLogData>>,
}

//실제 저장 조회 동작을 구현하는 부분
impl EncryptedLogRepository for InMemoryEncryptedLogRepository {
    // key로 해서 메모리에 저장
    fn store_encrypted_log(&self, encrypted_log: &EncryptedLogData) -> Result<(), RepositoryError> {
        let mut store = self.store.lock().map_err(|error| -> RepositoryError {
            Box::new(std::io::Error::other(error.to_string()))
        })?;

        store.insert(encrypted_log.encrypted_log_id, encrypted_log.clone());
        Ok(())
    }

    // 저장된 암호화 로그를 ID로 찾아 반환
    fn get_encrypted_log_by_id(
        &self,
        encrypted_log_id: u64,
    ) -> Result<Option<EncryptedLogData>, RepositoryError> {
        let store = self.store.lock().map_err(|error| -> RepositoryError {
            Box::new(std::io::Error::other(error.to_string()))
        })?;

        Ok(store.get(&encrypted_log_id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    // stores_and_retrieves_encrypted_log_by_id 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
    #[test]
    fn stores_and_retrieves_encrypted_log_by_id() {
        let repository = InMemoryEncryptedLogRepository::default();
        let encrypted_log = EncryptedLogData::new(
            1,
            42,
            vec![1, 2, 3],
            [4u8; 12],
            [5u8; 16],
            "datakey-2026-03-16",
            SystemTime::now(),
        );

        repository
            .store_encrypted_log(&encrypted_log)
            .expect("encrypted log should be stored");
        let retrieved = repository
            .get_encrypted_log_by_id(1)
            .expect("encrypted log should be retrieved")
            .expect("encrypted log should exist");

        assert_eq!(retrieved.encrypted_log_id, 1);
        assert_eq!(retrieved.user_id, 42);
        assert_eq!(retrieved.key_id, "datakey-2026-03-16");
    }
}

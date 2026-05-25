use std::collections::HashMap;
use std::sync::Mutex;

use crypto_core::domain::key_envelope::KeyEnvelope;

use crate::repository::RepositoryError;

// key envelope를 저장하기 위한 trait
pub trait KeyEnvelopeRepository {
    // store_key_envelope 함수는 전달받은 값을 저장소에 보관
    fn store_key_envelope(&self, envelope: &KeyEnvelope) -> Result<(), RepositoryError>;

    // get_envelopes_by_key_id 함수는 조건에 맞는 값을 조회해 반환
    fn get_envelopes_by_key_id(&self, key_id: &str) -> Result<Vec<KeyEnvelope>, RepositoryError>;

    // get_envelopes_by_owner_id 함수는 조건에 맞는 값을 조회해 반환
    fn get_envelopes_by_owner_id(&self, owner_id: u64) -> Result<Vec<KeyEnvelope>, RepositoryError>;
}

#[derive(Debug, Default)]
//trait의 메모리 기반 구현체 구조체
pub struct InMemoryKeyEnvelopeRepository {
    store: Mutex<HashMap<u64, KeyEnvelope>>,
}

//실제 저장 조회 로직
impl KeyEnvelopeRepository for InMemoryKeyEnvelopeRepository {
    // envelope 저장
    fn store_key_envelope(&self, envelope: &KeyEnvelope) -> Result<(), RepositoryError> {
        let mut store = self.store.lock().map_err(|error| -> RepositoryError {
            Box::new(std::io::Error::other(error.to_string()))
        })?;

        store.insert(envelope.envelope_id, envelope.clone());
        Ok(())
    }

    // 특정 data key id에 연결된 envelope를 조회
    fn get_envelopes_by_key_id(&self, key_id: &str) -> Result<Vec<KeyEnvelope>, RepositoryError> {
        let store = self.store.lock().map_err(|error| -> RepositoryError {
            Box::new(std::io::Error::other(error.to_string()))
        })?;

        Ok(store
            .values()
            .filter(|envelope| envelope.key_id == key_id)
            .cloned()
            .collect())
    }

    //특정 소유자가 가진 envelope를 조회
    fn get_envelopes_by_owner_id(&self, owner_id: u64) -> Result<Vec<KeyEnvelope>, RepositoryError> {
        let store = self.store.lock().map_err(|error| -> RepositoryError {
            Box::new(std::io::Error::other(error.to_string()))
        })?;

        Ok(store
            .values()
            .filter(|envelope| envelope.owner_id == owner_id)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use crypto_core::domain::key_envelope::OwnerType;

    use super::*;

    // sample_envelope 함수는 테스트에서 사용할 샘플 값을 만듦
    fn sample_envelope(envelope_id: u64, key_id: &str, owner_id: u64) -> KeyEnvelope {
        KeyEnvelope::new(
            envelope_id,
            key_id,
            owner_id,
            OwnerType::Guardian,
            vec![1, 2, 3],
            vec![4; 32],
        )
    }

    // retrieves_envelopes_by_key_id_and_owner_id 함수는 해당 시나리오가 기대한 대로 동작하는지 검증
    #[test]
    fn retrieves_envelopes_by_key_id_and_owner_id() {
        let repository = InMemoryKeyEnvelopeRepository::default();

        repository
            .store_key_envelope(&sample_envelope(1, "datakey-1", 10))
            .expect("first envelope should be stored");
        repository
            .store_key_envelope(&sample_envelope(2, "datakey-1", 20))
            .expect("second envelope should be stored");
        repository
            .store_key_envelope(&sample_envelope(3, "datakey-2", 10))
            .expect("third envelope should be stored");

        let by_key = repository
            .get_envelopes_by_key_id("datakey-1")
            .expect("envelopes should be retrieved by key_id");
        let by_owner = repository
            .get_envelopes_by_owner_id(10)
            .expect("envelopes should be retrieved by owner_id");

        assert_eq!(by_key.len(), 2);
        assert_eq!(by_owner.len(), 2);
    }
}

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crypto_core::domain::data_key::DataKey;
use crypto_core::domain::key_envelope::OwnerType;

use crate::repository::RepositoryError;

//data key를 저장하고 조회하기 위한 trait
pub trait DataKeyRepository {
    fn store_data_key(&self, data_key: &DataKey) -> Result<(), RepositoryError>;
    fn get_data_key_by_id(&self, key_id: &str) -> Result<Option<DataKey>, RepositoryError>;
    fn get_todays_data_key(&self) -> Result<Option<DataKey>, RepositoryError>;
}

// 사용자와 보호자의 공개키를 저장하고 조회하기 위한 trait
pub trait KeyRepository {
    fn store_public_key(
        &self,
        owner_id: u64,
        owner_type: OwnerType,
        public_key: Vec<u8>,
    ) -> Result<(), RepositoryError>;

    fn get_public_key(
        &self,
        owner_id: u64,
        owner_type: OwnerType,
    ) -> Result<Option<Vec<u8>>, RepositoryError>;
}

#[derive(Debug, Default)]
//data key를 저장하기 위한 구조체
pub struct InMemoryDataKeyRepository {
    store: Mutex<HashMap<String, DataKey>>,
}

impl DataKeyRepository for InMemoryDataKeyRepository {
    // 사용자와 보호자에 맞게 공개키 메모리에 저장
    fn store_data_key(&self, data_key: &DataKey) -> Result<(), RepositoryError> {
        let mut store = self.store.lock().map_err(|error| -> RepositoryError {
            Box::new(std::io::Error::other(error.to_string()))
        })?;

        store.insert(data_key.key_id.clone(), data_key.clone());
        Ok(())
    }

    //특정 key_id에 해당하는 datakey를 찾는 함수
    fn get_data_key_by_id(&self, key_id: &str) -> Result<Option<DataKey>, RepositoryError> {
        let store = self.store.lock().map_err(|error| -> RepositoryError {
            Box::new(std::io::Error::other(error.to_string()))
        })?;

        Ok(store.get(key_id).cloned())
    }

    //오늘 날짜 기준의 data key를 가져오는 함수
    fn get_todays_data_key(&self) -> Result<Option<DataKey>, RepositoryError> {
        let today_key_id = key_id_for_timestamp(SystemTime::now());
        self.get_data_key_by_id(&today_key_id)
    }
}

#[derive(Debug, Default)]
// 공개 키를 저장하기 위한 구조체
pub struct InMemoryKeyRepository {
    store: Mutex<HashMap<(u64, OwnerType), Vec<u8>>>,
}

impl KeyRepository for InMemoryKeyRepository {
    //공개키를 저장하는 함수
    fn store_public_key(
        &self,
        owner_id: u64,
        owner_type: OwnerType,
        public_key: Vec<u8>,
    ) -> Result<(), RepositoryError> {
        let mut store = self.store.lock().map_err(|error| -> RepositoryError {
            Box::new(std::io::Error::other(error.to_string()))
        })?;

        store.insert((owner_id, owner_type), public_key);
        Ok(())
    }
    //공개키를 조회하는 함수
    fn get_public_key(
        &self,
        owner_id: u64,
        owner_type: OwnerType,
    ) -> Result<Option<Vec<u8>>, RepositoryError> {
        let store = self.store.lock().map_err(|error| -> RepositoryError {
            Box::new(std::io::Error::other(error.to_string()))
        })?;

        Ok(store.get(&(owner_id, owner_type)).cloned())
    }
}

// 주어진 시각을 data ky id 문자열로 바꾸는 함수
fn key_id_for_timestamp(timestamp: SystemTime) -> String {
    let seconds_since_epoch = timestamp
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let day_index = seconds_since_epoch / 86_400;
    let (year, month, day) = civil_from_days(day_index as i64);

    format!("datakey-{year:04}-{month:02}-{day:02}")
}

// epoch기준 day 수를 연월일로 바꾸는 날짜 계산 함수
fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };

    (year as i32, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    #[test]
    fn stores_and_retrieves_data_key_by_id() {
        let repository = InMemoryDataKeyRepository::default();
        let data_key = DataKey::new(
            "datakey-2026-03-16",
            [9u8; 32],
            SystemTime::now(),
            SystemTime::now(),
        );

        repository
            .store_data_key(&data_key)
            .expect("data key should be stored");
        let retrieved = repository
            .get_data_key_by_id("datakey-2026-03-16")
            .expect("data key should be retrieved")
            .expect("data key should exist");

        assert_eq!(retrieved.key_id, "datakey-2026-03-16");
        assert_eq!(retrieved.key_value, [9u8; 32]);
    }

    #[test]
    fn retrieves_todays_data_key() {
        let repository = InMemoryDataKeyRepository::default();
        let todays_key_id = key_id_for_timestamp(SystemTime::now());
        let data_key = DataKey::new(
            todays_key_id.clone(),
            [3u8; 32],
            SystemTime::now(),
            SystemTime::now(),
        );

        repository
            .store_data_key(&data_key)
            .expect("today's data key should be stored");
        let retrieved = repository
            .get_todays_data_key()
            .expect("today's data key should be retrieved")
            .expect("today's data key should exist");

        assert_eq!(retrieved.key_id, todays_key_id);
        assert_eq!(retrieved.key_value, [3u8; 32]);
    }

    #[test]
    fn stores_and_retrieves_public_key() {
        let repository = InMemoryKeyRepository::default();

        repository
            .store_public_key(7, OwnerType::Guardian, vec![1, 2, 3, 4])
            .expect("public key should be stored");
        let retrieved = repository
            .get_public_key(7, OwnerType::Guardian)
            .expect("public key should be retrieved")
            .expect("public key should exist");

        assert_eq!(retrieved, vec![1, 2, 3, 4]);
    }
}

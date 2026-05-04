use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crypto_adapters::os_secure_random::OsSecureRandom;
use crypto_core::crypto::backends::{SecureRandom, SecureRandomError};
use crypto_core::domain::Timestamp;
use crypto_core::domain::data_key::DataKey;

use crate::data_key_provider::DataKeyProvider;
use crate::repository::key_repository::DataKeyRepository;

const DATA_KEY_SIZE: usize = 32;
const SECONDS_PER_DAY: u64 = 86_400;

#[derive(Debug)]
pub enum DataKeyServiceError {
    Repository(String),
    RandomGenerationFailed(SecureRandomError),
    InvalidTimestamp,
    TimeCalculationFailed,
}

impl fmt::Display for DataKeyServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Repository(message) => write!(f, "data key repository error: {message}"),
            Self::RandomGenerationFailed(error) => {
                write!(f, "failed to generate a 256-bit data key: {error}")
            }
            Self::InvalidTimestamp => write!(f, "timestamp must be on or after Unix epoch"),
            Self::TimeCalculationFailed => write!(f, "failed to calculate key rotation time"),
        }
    }
}

impl Error for DataKeyServiceError {}

pub struct DataKeyService<R> {
    repository: R,
    secure_random: Arc<dyn SecureRandom>,
}

impl<R> DataKeyService<R>
where
    R: DataKeyRepository,
{
    //DataKeyService를 만드는 기본 생성 함수
    pub fn new(repository: R) -> Self {
        Self::with_random(repository, Arc::new(OsSecureRandom))
    }

    //난수 생성기를 외부에서 주입해 DataKeyService를 생성
    pub fn with_random(repository: R, secure_random: Arc<dyn SecureRandom>) -> Self {
        Self {
            repository,
            secure_random,
        }
    }

    //지금 시점에서 키가 있으면 가져오고 없으면 새로 만듦
    pub fn get_or_create_current_key(&self) -> Result<DataKey, DataKeyServiceError> {
        self.get_or_create_key_for(SystemTime::now())
    }

    //그 날짜에 해당하는 key schedule 계산
    //같은 key_id가 저장소 있으면 재사용 없으면 키 생성
    //저장소에 키저장 후 최종 DataKey 반환
    pub fn get_or_create_key_for(
        &self,
        timestamp: Timestamp,
    ) -> Result<DataKey, DataKeyServiceError> {
        let key_schedule = KeySchedule::from_timestamp(timestamp)?;

        if let Some(existing_key) = self.find_existing_key(&key_schedule.key_id)? {
            return Ok(existing_key);
        }

        let data_key = self.generate_data_key(key_schedule, timestamp)?;
        self.repository
            .store_data_key(&data_key)
            .map_err(|error| DataKeyServiceError::Repository(error.to_string()))?;

        Ok(data_key)
    }

    //dat key가 있는지 조회함
    fn find_existing_key(&self, key_id: &str) -> Result<Option<DataKey>, DataKeyServiceError> {
        self.repository
            .get_data_key_by_id(key_id)
            .map_err(|error| DataKeyServiceError::Repository(error.to_string()))
    }

    //실제 32바이트 랜덤 key를 만들어 datakey 객체로 조립하는 내부 함수
    fn generate_data_key(
        &self,
        key_schedule: KeySchedule,
        created_at: Timestamp,
    ) -> Result<DataKey, DataKeyServiceError> {
        let mut key_value = [0u8; DATA_KEY_SIZE];
        self.secure_random
            .fill_bytes(&mut key_value)
            .map_err(DataKeyServiceError::RandomGenerationFailed)?;

        Ok(DataKey::new(
            key_schedule.key_id,
            key_value,
            created_at,
            key_schedule.expires_at,
        ))
    }
}

impl<R> DataKeyProvider for DataKeyService<R>
where
    R: DataKeyRepository + Send + Sync,
{
    fn get_or_create_current_key(&self) -> Result<DataKey, DataKeyServiceError> {
        DataKeyService::get_or_create_current_key(self)
    }

    fn get_or_create_key_for(&self, timestamp: Timestamp) -> Result<DataKey, DataKeyServiceError> {
        DataKeyService::get_or_create_key_for(self, timestamp)
    }
}

#[derive(Debug)]
struct KeySchedule {
    key_id: String,
    expires_at: Timestamp,
}

//날짜 기반 key 생성 함수
impl KeySchedule {
    fn from_timestamp(timestamp: Timestamp) -> Result<Self, DataKeyServiceError> {
        let seconds_since_epoch = timestamp
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DataKeyServiceError::InvalidTimestamp)?
            .as_secs();
        let day_index = seconds_since_epoch / SECONDS_PER_DAY;
        let (year, month, day) = civil_from_days(day_index as i64);

        let next_day_seconds = day_index
            .checked_add(1)
            .and_then(|value| value.checked_mul(SECONDS_PER_DAY))
            .ok_or(DataKeyServiceError::TimeCalculationFailed)?;
        let expires_at = UNIX_EPOCH
            .checked_add(Duration::from_secs(next_day_seconds))
            .ok_or(DataKeyServiceError::TimeCalculationFailed)?;

        Ok(Self {
            key_id: format!("datakey-{year:04}-{month:02}-{day:02}"),
            expires_at,
        })
    }
}

//날짜 기반 key 정책을 만드는 함수
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
    use crate::repository::key_repository::InMemoryDataKeyRepository;

    use super::*;

    #[test]
    fn reuses_existing_key_for_same_day() {
        let repository = InMemoryDataKeyRepository::default();
        let service = DataKeyService::new(repository);
        let first_timestamp = UNIX_EPOCH + Duration::from_secs(SECONDS_PER_DAY * 20 + 10);
        let second_timestamp = UNIX_EPOCH + Duration::from_secs(SECONDS_PER_DAY * 20 + 60);

        let first_key = service
            .get_or_create_key_for(first_timestamp)
            .expect("first key should be created");
        let second_key = service
            .get_or_create_key_for(second_timestamp)
            .expect("same day key should be reused");

        assert_eq!(first_key.key_id, second_key.key_id);
        assert_eq!(first_key.key_value, second_key.key_value);
        assert_eq!(first_key.expires_at, second_key.expires_at);
    }

    #[test]
    fn rotates_key_when_day_changes() {
        let repository = InMemoryDataKeyRepository::default();
        let service = DataKeyService::new(repository);
        let first_timestamp = UNIX_EPOCH + Duration::from_secs(SECONDS_PER_DAY * 30 + 10);
        let second_timestamp = UNIX_EPOCH + Duration::from_secs(SECONDS_PER_DAY * 31 + 10);

        let first_key = service
            .get_or_create_key_for(first_timestamp)
            .expect("first day key should be created");
        let second_key = service
            .get_or_create_key_for(second_timestamp)
            .expect("next day key should be rotated");

        assert_ne!(first_key.key_id, second_key.key_id);
        assert_ne!(first_key.key_value, second_key.key_value);
        assert!(second_key.created_at > first_key.created_at);
    }
}

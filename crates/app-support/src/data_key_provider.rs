use crate::data_key_service::DataKeyServiceError;
use crypto_core::domain::Timestamp;
use crypto_core::domain::data_key::DataKey;

//datakey를 제공하는 역할에 대한 trait(인터페이스)를 정의하는 파일
//이런 객체라면 data key를 제공할 수 있어야 한다라는 제약
// 키를 가져오거나 없으면 만든다.
pub trait DataKeyProvider: Send + Sync {
    // get_or_create_current_key 함수는 조건에 맞는 값을 조회해 반환
    fn get_or_create_current_key(&self) -> Result<DataKey, DataKeyServiceError>;

    // get_or_create_key_for 함수는 조건에 맞는 값을 조회해 반환
    fn get_or_create_key_for(&self, timestamp: Timestamp) -> Result<DataKey, DataKeyServiceError>;
}

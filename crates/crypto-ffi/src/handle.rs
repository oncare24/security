// FFI에서 사용할 CoreFacade 핸들 객체를 만들고 검증하는 역할
use crypto_adapters::factory::build_core_facade;
use crypto_core::core_facade::CoreFacade;

use crate::error::{FfiErrorCode, FfiErrorInfo};

// 포인터로 들고 다닐 수 있는 핸들 형태로 감쌈
pub struct FfiFacadeHandle {
    inner: CoreFacade,
}

impl FfiFacadeHandle {
    // 암호화 백엔드 조합이 포함된 기본 facade를 생성하는 초기화 함수
    pub fn new_default() -> Result<Self, FfiHandleInitError> {
        let inner = build_core_facade().map_err(|error| {
            FfiHandleInitError::new(
                FfiErrorCode::InternalError,
                format!("failed to build default CoreFacade: {error}"),
            )
        })?;

        Ok(Self { inner })
    }

    // 핸들 내부의 실제 CoreFacde를 꺼내는 getter
    pub fn core(&self) -> &CoreFacade {
        &self.inner
    }
}

// 핸들 생성 실패 전용 에러 타입
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfiHandleInitError {
    pub code: FfiErrorCode,
    pub message: String,
}

impl FfiHandleInitError {
    pub fn new(code: FfiErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn as_error_info(&self) -> FfiErrorInfo {
        FfiErrorInfo::new(self.code, self.message.clone())
    }
}

// 함수는 외부에서 받은 핸들 포인터를 Rust 참조로 변경
pub unsafe fn handle_from_ptr<'a>(
    handle: *mut FfiFacadeHandle,
) -> Result<&'a mut FfiFacadeHandle, FfiErrorCode> {
    if handle.is_null() {
        return Err(FfiErrorCode::InvalidHandle);
    }

    unsafe { Ok(&mut *handle) }
}

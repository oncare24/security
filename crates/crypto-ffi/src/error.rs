// FFI 경계에서 발생한 오류를 코드와 메시지 형태로 관리하는 파일
// 숫자 코드 + 문자열 메시지 방식으로 바꾸는 역할
use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crypto_core::core_facade::CoreFacadeError;

// 스레드별 마지막 에러 메시지 저장소
thread_local! {
    static LAST_ERROR_MESSAGE: RefCell<String> = const { RefCell::new(String::new()) };
}

// 표준 에러 코드 체계
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiErrorCode {
    Ok = 0,
    NullPointer = 1,
    InvalidHandle = 2,
    InvalidArgument = 3,
    InvalidLength = 4,
    InvalidUtf8 = 5,
    BufferAllocationFailed = 6,
    CryptoError = 100,
    InternalError = 1000,
    Panic = 1001,
}

// Rust 내부에서 다루는 에러 묶음 객체
// ABI로 그대로 내보내기보다는 내부적으로 코드와 메시지를 함께 관리 하기 위함
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfiErrorInfo {
    pub code: FfiErrorCode,
    pub message: String,
}

impl FfiErrorInfo {
    pub fn new(code: FfiErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

// 내부 암호화 계층에서 오류가 나더라도 FFI 수준에서는 일단 암호 처리 실패로 분류 해줌
impl From<&CoreFacadeError> for FfiErrorCode {
    fn from(_: &CoreFacadeError) -> Self {
        Self::CryptoError
    }
}

// 마지막 에러를 저장
pub fn set_last_error_message(message: impl Into<String>) {
    LAST_ERROR_MESSAGE.with(|slot| {
        *slot.borrow_mut() = message.into();
    });
}

// 마지막 에러를 초기화
pub fn clear_last_error_message() {
    LAST_ERROR_MESSAGE.with(|slot| {
        slot.borrow_mut().clear();
    });
}

// 메시지를 저장하고 에러 코드 자체를 변환하는 헬퍼
pub fn fail_with_message(code: FfiErrorCode, message: impl Into<String>) -> FfiErrorCode {
    set_last_error_message(message);
    code
}

// Rust Panic을 ABI 친화적 에러로 변환하는 함수
pub fn catch_ffi_panic<F>(operation: F) -> FfiErrorCode
where
    F: FnOnce() -> FfiErrorCode,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(FfiErrorCode::Ok) => {
            clear_last_error_message();
            FfiErrorCode::Ok
        }
        Ok(code) => code,
        Err(_) => fail_with_message(FfiErrorCode::Panic, "panic in ffi boundary"),
    }
}

// 마지막 에러 메시지 길이를 알려줌
#[unsafe(no_mangle)]
pub extern "C" fn crypto_ffi_last_error_message_length() -> usize {
    LAST_ERROR_MESSAGE.with(|slot| slot.borrow().len())
}

// 마지막 에러 메시지를 호출자 버퍼에 복사
#[unsafe(no_mangle)]
pub extern "C" fn crypto_ffi_last_error_message_copy(
    buffer: *mut u8,
    buffer_len: usize,
) -> FfiErrorCode {
    match catch_unwind(AssertUnwindSafe(|| {
        let message = LAST_ERROR_MESSAGE.with(|slot| slot.borrow().clone());

        if buffer.is_null() {
            return FfiErrorCode::NullPointer;
        }

        let required_len = message.len() + 1;
        if buffer_len < required_len {
            return FfiErrorCode::InvalidLength;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(message.as_ptr(), buffer, message.len());
            *buffer.add(message.len()) = 0;
        }

        FfiErrorCode::Ok
    })) {
        Ok(code) => code,
        Err(_) => fail_with_message(FfiErrorCode::Panic, "panic while copying last error message"),
    }
}

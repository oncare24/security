//! CoreFacde를 FFI 바깥에서 쓸 수 있도록 생성, 해제를 가능 하게 해줌

use crate::error::{FfiErrorCode, catch_ffi_panic, fail_with_message};
use crate::handle::FfiFacadeHandle;

// Rust 내부 facade를 외부에서 계속 사용할 수 있는 핸들 포인터로 만들어 주는 함수
#[unsafe(no_mangle)]
pub extern "C" fn crypto_ffi_facade_new_default(
    out_handle: *mut *mut FfiFacadeHandle,
) -> FfiErrorCode {
    catch_ffi_panic(|| {
        if out_handle.is_null() {
            return fail_with_message(
                FfiErrorCode::NullPointer,
                "null facade handle output pointer",
            );
        }

        match FfiFacadeHandle::new_default() {
            Ok(handle) => {
                unsafe {
                    *out_handle = Box::into_raw(Box::new(handle));
                }
                FfiErrorCode::Ok
            }
            Err(error) => fail_with_message(error.code, error.message),
        }
    })
}

// 외부에서 사용을 마친 facade 핸들을 rust에서 정리하는 함수
#[unsafe(no_mangle)]
pub extern "C" fn crypto_ffi_facade_free(handle: *mut FfiFacadeHandle) -> FfiErrorCode {
    catch_ffi_panic(|| {
        if handle.is_null() {
            return fail_with_message(FfiErrorCode::InvalidHandle, "invalid handle");
        }

        unsafe {
            drop(Box::from_raw(handle));
        }

        FfiErrorCode::Ok
    })
}

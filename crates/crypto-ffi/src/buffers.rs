// Rust Vec<u8>와 C 호환 버퍼 구조체 사이를 변환하는 역할
// 포인터와 길이만 가진 C 스타일 구조체로 변경해야함
use std::ptr::{null, null_mut};

// 읽기 전용 바이트 슬라이스를 FFI용으로 표현한 구조체
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiBorrowedBytes {
    pub ptr: *const u8,
    pub len: usize,
}

impl FfiBorrowedBytes {
    pub const fn null() -> Self {
        Self { ptr: null(), len: 0 }
    }
}

// Rust가 소유권을 가진 바이트 버퍼를 FFI 밖으로 넘길 때 쓰는 구조체
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiByteBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

impl FfiByteBuffer {
    pub const fn null() -> Self {
        Self {
            ptr: null_mut(),
            len: 0,
            capacity: 0,
        }
    }
}

// 소유권 이전
// 함수가 끝날 때 Vec<u8>이 drop되면서 메모리가 해제, 외부에서는 이미 해제된 포인터를 들고 있게 됨
pub fn vec_into_buffer(mut data: Vec<u8>) -> FfiByteBuffer {
    let buffer = FfiByteBuffer {
        ptr: data.as_mut_ptr(),
        len: data.len(),
        capacity: data.capacity(),
    };
    std::mem::forget(data);
    buffer
}

// FFI로 넘긴 버퍼를 해제하는 함수
pub unsafe fn free_buffer(buffer: FfiByteBuffer) {
    if !buffer.ptr.is_null() && buffer.capacity > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.capacity);
        }
    }
}

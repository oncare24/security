from __future__ import annotations

import ctypes
import json
import os
import sys
from enum import IntEnum
from pathlib import Path
from typing import Optional, Union, Any

BytesLike = Union[bytes, bytearray, memoryview]



class FfiErrorCode(IntEnum):
    OK = 0
    NULL_POINTER = 1
    INVALID_HANDLE = 2
    INVALID_ARGUMENT = 3
    INVALID_LENGTH = 4
    INVALID_UTF8 = 5
    BUFFER_ALLOCATION_FAILED = 6
    CRYPTO_ERROR = 100
    INTERNAL_ERROR = 1000
    PANIC = 1001


class FfiOwnerType(IntEnum):
    USER = 1
    GUARDIAN = 2


class CryptoFfiError(RuntimeError):
    def __init__(self, code: int, message: str) -> None:
        self.code = FfiErrorCode(code) if code in FfiErrorCode._value2member_map_ else code
        self.message = message or "crypto-ffi call failed"
        super().__init__(f"[{self.code}] {self.message}")


class FfiFacadeHandle(ctypes.Structure):
    pass


LP_FfiFacadeHandle = ctypes.POINTER(FfiFacadeHandle)
LP_c_uint8 = ctypes.POINTER(ctypes.c_uint8)


class FfiBorrowedBytes(ctypes.Structure):
    _fields_ = [("ptr", LP_c_uint8), ("len", ctypes.c_size_t)]


class FfiByteBuffer(ctypes.Structure):
    _fields_ = [
        ("ptr", LP_c_uint8),
        ("len", ctypes.c_size_t),
        ("capacity", ctypes.c_size_t),
    ]


class FfiTimestamp(ctypes.Structure):
    _fields_ = [("unix_seconds", ctypes.c_uint64)]


class FfiDataKeyInput(ctypes.Structure):
    _fields_ = [
        ("key_id", FfiBorrowedBytes),
        ("key_value", ctypes.c_uint8 * 32),
        ("created_at", FfiTimestamp),
        ("expires_at", FfiTimestamp),
    ]


class FfiEncryptPackageRequest(ctypes.Structure):
    _fields_ = [
        ("plaintext", FfiBorrowedBytes),
        ("user_id", ctypes.c_uint64),
        ("user_public_key", FfiBorrowedBytes),
        ("guardian_id", ctypes.c_uint64),
        ("guardian_public_key", FfiBorrowedBytes),
        ("data_key", FfiDataKeyInput),
    ]


class FfiDecryptPackageRequest(ctypes.Structure):
    _fields_ = [
        ("package", FfiBorrowedBytes),
        ("caller_id", ctypes.c_uint64),
        ("caller_type", ctypes.c_uint32),
        ("private_key", FfiBorrowedBytes),
    ]


class FfiCreateKeyEnvelopeRequest(ctypes.Structure):
    _fields_ = [
        ("data_key", FfiDataKeyInput),
        ("owner_id", ctypes.c_uint64),
        ("owner_type", ctypes.c_uint32),
        ("public_key", FfiBorrowedBytes),
    ]


class FfiOpenKeyEnvelopeRequest(ctypes.Structure):
    _fields_ = [
        ("envelope", FfiBorrowedBytes),
        ("caller_id", ctypes.c_uint64),
        ("caller_type", ctypes.c_uint32),
        ("private_key", FfiBorrowedBytes),
    ]


class FfiCreateAdditionalRecipientEnvelopeRequest(ctypes.Structure):
    _fields_ = [
        ("source_envelope", FfiBorrowedBytes),
        ("current_owner_id", ctypes.c_uint64),
        ("current_owner_type", ctypes.c_uint32),
        ("current_private_key", FfiBorrowedBytes),
        ("new_owner_id", ctypes.c_uint64),
        ("new_owner_type", ctypes.c_uint32),
        ("new_public_key", FfiBorrowedBytes),
    ]


class _BorrowedArg:
    def __init__(self, data: Union[str, BytesLike, None]) -> None:
        if isinstance(data, str):
            raw = data.encode("utf-8")
        elif data is None:
            raw = b""
        else:
            raw = bytes(data)

        self._raw = raw
        if len(raw) == 0:
            self._buffer = None
            self.value = FfiBorrowedBytes(None, 0)
        else:
            self._buffer = (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw)
            self.value = FfiBorrowedBytes(
                ctypes.cast(self._buffer, LP_c_uint8),
                len(raw),
            )


class CryptoFacade:
    def __init__(self, library_path: Optional[Union[str, os.PathLike[str]]] = None) -> None:
        self._library_path = self._resolve_library_path(library_path)
        if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
            os.add_dll_directory(str(self._library_path.parent))
        self._lib = ctypes.CDLL(str(self._library_path))
        self._configure_functions()
        self._handle: Optional[LP_FfiFacadeHandle] = None
        self._create_handle()

    def __enter__(self) -> "CryptoFacade":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    @property
    def library_path(self) -> Path:
        return self._library_path

    @classmethod
    def _resolve_library_path(
        cls, library_path: Optional[Union[str, os.PathLike[str]]]
    ) -> Path:
        if library_path is not None:
            path = Path(library_path).expanduser().resolve()
            if not path.exists():
                raise FileNotFoundError(f"crypto-ffi library not found: {path}")
            return path

        env_path = os.environ.get("CRYPTO_FFI_LIBRARY")
        if env_path:
            path = Path(env_path).expanduser().resolve()
            if path.exists():
                return path

        repo_root = Path(__file__).resolve().parents[1]
        candidates = []
        names = cls._platform_library_names()
        target_roots = [repo_root / "target"]
        parent_target = repo_root.parent / "target"
        if parent_target not in target_roots:
            target_roots.append(parent_target)

        for target_root in target_roots:
            for name in names:
                candidates.extend(
                    [
                        target_root / "debug" / name,
                        target_root / "release" / name,
                        target_root / "debug" / "deps" / name,
                        target_root / "release" / "deps" / name,
                    ]
                )

        for candidate in candidates:
            if candidate.exists():
                return candidate.resolve()

        searched = "\n".join(str(path) for path in candidates)
        raise FileNotFoundError(
            "Unable to locate crypto-ffi shared library. Build it first with "
            "`cargo rustc -p crypto-ffi --crate-type cdylib` or set CRYPTO_FFI_LIBRARY.\n"
            f"Searched:\n{searched}"
        )

    @staticmethod
    def _platform_library_names() -> list[str]:
        if sys.platform == "win32":
            return ["crypto_ffi.dll"]
        if sys.platform == "darwin":
            return ["libcrypto_ffi.dylib", "crypto_ffi.dylib"]
        return ["libcrypto_ffi.so", "crypto_ffi.so"]

    def _configure_functions(self) -> None:
        self._lib.crypto_ffi_facade_new_default.argtypes = [ctypes.POINTER(LP_FfiFacadeHandle)]
        self._lib.crypto_ffi_facade_new_default.restype = ctypes.c_int32

        self._lib.crypto_ffi_facade_free.argtypes = [LP_FfiFacadeHandle]
        self._lib.crypto_ffi_facade_free.restype = ctypes.c_int32

        self._lib.crypto_ffi_byte_buffer_free.argtypes = [FfiByteBuffer]
        self._lib.crypto_ffi_byte_buffer_free.restype = ctypes.c_int32

        self._lib.crypto_ffi_generate_data_key.argtypes = [
            LP_FfiFacadeHandle,
            FfiBorrowedBytes,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.POINTER(FfiByteBuffer),
        ]
        self._lib.crypto_ffi_generate_data_key.restype = ctypes.c_int32

        self._lib.crypto_ffi_encrypt_package.argtypes = [
            LP_FfiFacadeHandle,
            ctypes.POINTER(FfiEncryptPackageRequest),
            ctypes.POINTER(FfiByteBuffer),
        ]
        self._lib.crypto_ffi_encrypt_package.restype = ctypes.c_int32

        self._lib.crypto_ffi_decrypt_package.argtypes = [
            LP_FfiFacadeHandle,
            ctypes.POINTER(FfiDecryptPackageRequest),
            ctypes.POINTER(FfiByteBuffer),
        ]
        self._lib.crypto_ffi_decrypt_package.restype = ctypes.c_int32

        self._lib.crypto_ffi_create_key_envelope.argtypes = [
            LP_FfiFacadeHandle,
            ctypes.POINTER(FfiCreateKeyEnvelopeRequest),
            ctypes.POINTER(FfiByteBuffer),
        ]
        self._lib.crypto_ffi_create_key_envelope.restype = ctypes.c_int32

        self._lib.crypto_ffi_open_key_envelope.argtypes = [
            LP_FfiFacadeHandle,
            ctypes.POINTER(FfiOpenKeyEnvelopeRequest),
            ctypes.POINTER(FfiByteBuffer),
        ]
        self._lib.crypto_ffi_open_key_envelope.restype = ctypes.c_int32

        self._lib.crypto_ffi_create_additional_recipient_envelope.argtypes = [
            LP_FfiFacadeHandle,
            ctypes.POINTER(FfiCreateAdditionalRecipientEnvelopeRequest),
            ctypes.POINTER(FfiByteBuffer),
        ]
        self._lib.crypto_ffi_create_additional_recipient_envelope.restype = ctypes.c_int32

        self._lib.crypto_ffi_last_error_message_length.argtypes = []
        self._lib.crypto_ffi_last_error_message_length.restype = ctypes.c_size_t

        self._lib.crypto_ffi_last_error_message_copy.argtypes = [LP_c_uint8, ctypes.c_size_t]
        self._lib.crypto_ffi_last_error_message_copy.restype = ctypes.c_int32

    def _create_handle(self) -> None:
        handle = LP_FfiFacadeHandle()
        code = self._lib.crypto_ffi_facade_new_default(ctypes.byref(handle))
        self._check_code(code)
        self._handle = handle

    def close(self) -> None:
        if self._handle is None:
            return
        handle = self._handle
        self._handle = None
        code = self._lib.crypto_ffi_facade_free(handle)
        if code != FfiErrorCode.OK:
            raise self._error_from_code(code)

    def last_error_message(self) -> str:
        length = int(self._lib.crypto_ffi_last_error_message_length())
        if length == 0:
            return ""
        buffer = (ctypes.c_uint8 * (length + 1))()
        code = self._lib.crypto_ffi_last_error_message_copy(buffer, len(buffer))
        if code != FfiErrorCode.OK:
            return f"unable to copy last error message (code={int(code)})"
        return bytes(buffer[:length]).decode("utf-8", errors="replace")

    def generate_data_key(
        self,
        key_id: Union[str, BytesLike],
        created_at_unix_seconds: int,
        expires_at_unix_seconds: int,
    ) -> bytes:
        key_id_arg = _BorrowedArg(key_id)
        return self._call_bytes_function(
            self._lib.crypto_ffi_generate_data_key,
            self._require_handle(),
            key_id_arg.value,
            ctypes.c_uint64(created_at_unix_seconds),
            ctypes.c_uint64(expires_at_unix_seconds),
        )

    def encrypt_package(
        self,
        plaintext: BytesLike,
        user_id: int,
        user_public_key: BytesLike,
        guardian_id: int,
        guardian_public_key: BytesLike,
        data_key_id: Union[str, BytesLike],
        data_key: BytesLike,
        created_at_unix_seconds: int,
        expires_at_unix_seconds: int,
    ) -> bytes:
        plaintext_arg = _BorrowedArg(plaintext)
        user_public_key_arg = _BorrowedArg(user_public_key)
        guardian_public_key_arg = _BorrowedArg(guardian_public_key)
        data_key_input, key_id_arg = self._make_data_key_input(
            data_key_id,
            data_key,
            created_at_unix_seconds,
            expires_at_unix_seconds,
        )
        request = FfiEncryptPackageRequest(
            plaintext=plaintext_arg.value,
            user_id=user_id,
            user_public_key=user_public_key_arg.value,
            guardian_id=guardian_id,
            guardian_public_key=guardian_public_key_arg.value,
            data_key=data_key_input,
        )
        return self._call_bytes_function(
            self._lib.crypto_ffi_encrypt_package,
            self._require_handle(),
            ctypes.byref(request),
            keepalive=[plaintext_arg, user_public_key_arg, guardian_public_key_arg, key_id_arg],
        )

    def decrypt_package(
        self,
        package_bytes: BytesLike,
        caller_id: int,
        caller_type: FfiOwnerType,
        private_key: BytesLike,
    ) -> bytes:
        package_arg = _BorrowedArg(package_bytes)
        private_key_arg = _BorrowedArg(private_key)
        request = FfiDecryptPackageRequest(
            package=package_arg.value,
            caller_id=caller_id,
            caller_type=int(caller_type),
            private_key=private_key_arg.value,
        )
        return self._call_bytes_function(
            self._lib.crypto_ffi_decrypt_package,
            self._require_handle(),
            ctypes.byref(request),
            keepalive=[package_arg, private_key_arg],
        )

    def create_key_envelope(
        self,
        data_key_id: Union[str, BytesLike],
        data_key: BytesLike,
        created_at_unix_seconds: int,
        expires_at_unix_seconds: int,
        owner_id: int,
        owner_type: FfiOwnerType,
        public_key: BytesLike,
    ) -> bytes:
        data_key_input, key_id_arg = self._make_data_key_input(
            data_key_id,
            data_key,
            created_at_unix_seconds,
            expires_at_unix_seconds,
        )
        public_key_arg = _BorrowedArg(public_key)
        request = FfiCreateKeyEnvelopeRequest(
            data_key=data_key_input,
            owner_id=owner_id,
            owner_type=int(owner_type),
            public_key=public_key_arg.value,
        )
        return self._call_bytes_function(
            self._lib.crypto_ffi_create_key_envelope,
            self._require_handle(),
            ctypes.byref(request),
            keepalive=[key_id_arg, public_key_arg],
        )

    def open_key_envelope(
        self,
        envelope_bytes: BytesLike,
        caller_id: int,
        caller_type: FfiOwnerType,
        private_key: BytesLike,
    ) -> bytes:
        envelope_arg = _BorrowedArg(envelope_bytes)
        private_key_arg = _BorrowedArg(private_key)
        request = FfiOpenKeyEnvelopeRequest(
            envelope=envelope_arg.value,
            caller_id=caller_id,
            caller_type=int(caller_type),
            private_key=private_key_arg.value,
        )
        return self._call_bytes_function(
            self._lib.crypto_ffi_open_key_envelope,
            self._require_handle(),
            ctypes.byref(request),
            keepalive=[envelope_arg, private_key_arg],
        )

    def create_additional_recipient_envelope(
        self,
        source_envelope_bytes: BytesLike,
        current_owner_id: int,
        current_owner_type: FfiOwnerType,
        current_private_key: BytesLike,
        new_owner_id: int,
        new_owner_type: FfiOwnerType,
        new_public_key: BytesLike,
    ) -> bytes:
        source_envelope_arg = _BorrowedArg(source_envelope_bytes)
        current_private_key_arg = _BorrowedArg(current_private_key)
        new_public_key_arg = _BorrowedArg(new_public_key)
        request = FfiCreateAdditionalRecipientEnvelopeRequest(
            source_envelope=source_envelope_arg.value,
            current_owner_id=current_owner_id,
            current_owner_type=int(current_owner_type),
            current_private_key=current_private_key_arg.value,
            new_owner_id=new_owner_id,
            new_owner_type=int(new_owner_type),
            new_public_key=new_public_key_arg.value,
        )
        return self._call_bytes_function(
            self._lib.crypto_ffi_create_additional_recipient_envelope,
            self._require_handle(),
            ctypes.byref(request),
            keepalive=[source_envelope_arg, current_private_key_arg, new_public_key_arg],
        )

    @staticmethod
    def load_wire_json(wire_bytes: BytesLike) -> Any:
        return json.loads(bytes(wire_bytes).decode("utf-8"))

    def _require_handle(self) -> LP_FfiFacadeHandle:
        if self._handle is None:
            raise RuntimeError("CryptoFacade is already closed")
        return self._handle

    def _make_data_key_input(
        self,
        key_id: Union[str, BytesLike],
        data_key: BytesLike,
        created_at_unix_seconds: int,
        expires_at_unix_seconds: int,
    ) -> tuple[FfiDataKeyInput, _BorrowedArg]:
        key_bytes = bytes(data_key)
        if len(key_bytes) != 32:
            raise ValueError(f"data_key must be exactly 32 bytes, got {len(key_bytes)}")

        key_id_arg = _BorrowedArg(key_id)
        key_array = (ctypes.c_uint8 * 32).from_buffer_copy(key_bytes)
        data_key_input = FfiDataKeyInput(
            key_id=key_id_arg.value,
            key_value=key_array,
            created_at=FfiTimestamp(unix_seconds=created_at_unix_seconds),
            expires_at=FfiTimestamp(unix_seconds=expires_at_unix_seconds),
        )
        return data_key_input, key_id_arg

    def _call_bytes_function(self, func, *args, keepalive=None) -> bytes:
        _ = keepalive
        out_buffer = FfiByteBuffer()
        code = func(*args, ctypes.byref(out_buffer))
        self._check_code(code)
        try:
            if not bool(out_buffer.ptr) or out_buffer.len == 0:
                return b""
            return ctypes.string_at(out_buffer.ptr, out_buffer.len)
        finally:
            free_code = self._lib.crypto_ffi_byte_buffer_free(out_buffer)
            if free_code != FfiErrorCode.OK:
                raise self._error_from_code(free_code)

    def _check_code(self, code: int) -> None:
        if code != FfiErrorCode.OK:
            raise self._error_from_code(code)

    def _error_from_code(self, code: int) -> CryptoFfiError:
        return CryptoFfiError(code, self.last_error_message())


__all__ = [
    "CryptoFacade",
    "CryptoFfiError",
    "FfiErrorCode",
    "FfiOwnerType",
]




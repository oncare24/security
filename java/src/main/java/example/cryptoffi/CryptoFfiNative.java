package example.cryptoffi;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.sun.jna.IntegerType;
import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;

interface CryptoFfiNative extends Library {
    int FFI_ERROR_OK = 0;
    int FFI_OWNER_TYPE_USER = 1;
    int FFI_OWNER_TYPE_GUARDIAN = 2;

    // load 함수는 외부 리소스나 라이브러리를 읽어 사용할 수 있게 준비
    static CryptoFfiNative load(String libraryPath) {
        return Native.load(libraryPath, CryptoFfiNative.class, Map.of(
                Library.OPTION_STRING_ENCODING, StandardCharsets.UTF_8.name()
        ));
    }

    int crypto_ffi_facade_new_default(PointerByReference outHandle);

    int crypto_ffi_facade_free(Pointer handle);

    int crypto_ffi_byte_buffer_free(FfiByteBuffer.ByValue buffer);

    int crypto_ffi_generate_data_key(
            Pointer handle,
            FfiBorrowedBytes.ByValue keyId,
            long createdAtUnixSeconds,
            long expiresAtUnixSeconds,
            FfiByteBuffer.ByReference outBuffer
    );

    int crypto_ffi_generate_mlkem_keypair(
            Pointer handle,
            FfiByteBuffer.ByReference outBuffer
    );

    int crypto_ffi_encrypt_package(
            Pointer handle,
            FfiEncryptPackageRequest.ByReference request,
            FfiByteBuffer.ByReference outBuffer
    );

    int crypto_ffi_decrypt_package(
            Pointer handle,
            FfiDecryptPackageRequest.ByReference request,
            FfiByteBuffer.ByReference outBuffer
    );

    int crypto_ffi_create_key_envelope(
            Pointer handle,
            FfiCreateKeyEnvelopeRequest.ByReference request,
            FfiByteBuffer.ByReference outBuffer
    );

    int crypto_ffi_open_key_envelope(
            Pointer handle,
            FfiOpenKeyEnvelopeRequest.ByReference request,
            FfiByteBuffer.ByReference outBuffer
    );

    int crypto_ffi_create_additional_recipient_envelope(
            Pointer handle,
            FfiCreateAdditionalRecipientEnvelopeRequest.ByReference request,
            FfiByteBuffer.ByReference outBuffer
    );

    SizeT crypto_ffi_last_error_message_length();

    int crypto_ffi_last_error_message_copy(Pointer buffer, SizeT bufferLen);

    final class SizeT extends IntegerType {
        // SizeT 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public SizeT() {
            this(0);
        }

        // SizeT 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public SizeT(long value) {
            super(Native.SIZE_T_SIZE, value, true);
        }
    }

    class FfiBorrowedBytes extends Structure {
        public Pointer ptr;
        public SizeT len;

        // FfiBorrowedBytes 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public FfiBorrowedBytes() {
            this(Pointer.NULL, 0);
        }

        // FfiBorrowedBytes 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public FfiBorrowedBytes(Pointer ptr, long len) {
            this.ptr = ptr;
            this.len = new SizeT(len);
        }

        // getFieldOrder 함수는 JNA 구조체 필드 순서를 네이티브 ABI와 맞춰 반환
        @Override
        protected List<String> getFieldOrder() {
            return List.of("ptr", "len");
        }

        public static class ByValue extends FfiBorrowedBytes implements Structure.ByValue {
            // ByValue 함수는 현재 버퍼 상태를 값 전달용 구조체로 복사
            public ByValue() {
            }

            // ByValue 함수는 현재 버퍼 상태를 값 전달용 구조체로 복사
            public ByValue(Pointer ptr, long len) {
                super(ptr, len);
            }
        }
    }

    class FfiByteBuffer extends Structure {
        public Pointer ptr;
        public SizeT len;
        public SizeT capacity;

        // FfiByteBuffer 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public FfiByteBuffer() {
            this.ptr = Pointer.NULL;
            this.len = new SizeT(0);
            this.capacity = new SizeT(0);
        }

        // getFieldOrder 함수는 JNA 구조체 필드 순서를 네이티브 ABI와 맞춰 반환
        @Override
        protected List<String> getFieldOrder() {
            return List.of("ptr", "len", "capacity");
        }

        byte[] toByteArray() {
            long byteLen = len.longValue();
            if (ptr == null || Pointer.nativeValue(ptr) == 0 || byteLen == 0) {
                return new byte[0];
            }
            if (byteLen > Integer.MAX_VALUE) {
                throw new IllegalStateException("native buffer is too large for a Java byte[]: " + byteLen);
            }
            return ptr.getByteArray(0, (int) byteLen);
        }

        ByValue byValue() {
            ByValue value = new ByValue();
            value.ptr = ptr;
            value.len = len;
            value.capacity = capacity;
            value.write();
            return value;
        }

        public static class ByReference extends FfiByteBuffer implements Structure.ByReference {
        }

        public static class ByValue extends FfiByteBuffer implements Structure.ByValue {
        }
    }

    class FfiTimestamp extends Structure {
        public long unix_seconds;

        // FfiTimestamp 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public FfiTimestamp() {
        }

        // FfiTimestamp 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public FfiTimestamp(long unixSeconds) {
            this.unix_seconds = unixSeconds;
        }

        // getFieldOrder 함수는 JNA 구조체 필드 순서를 네이티브 ABI와 맞춰 반환
        @Override
        protected List<String> getFieldOrder() {
            return List.of("unix_seconds");
        }
    }

    class FfiDataKeyInput extends Structure {
        public FfiBorrowedBytes key_id;
        public byte[] key_value = new byte[32];
        public FfiTimestamp created_at;
        public FfiTimestamp expires_at;

        // FfiDataKeyInput 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public FfiDataKeyInput() {
            this.key_id = new FfiBorrowedBytes();
            this.created_at = new FfiTimestamp();
            this.expires_at = new FfiTimestamp();
        }

        // FfiDataKeyInput 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public FfiDataKeyInput(FfiBorrowedBytes keyId, byte[] keyValue, long createdAt, long expiresAt) {
            if (keyValue.length != 32) {
                throw new IllegalArgumentException("key_value must be exactly 32 bytes, got " + keyValue.length);
            }
            this.key_id = keyId;
            this.key_value = Arrays.copyOf(keyValue, 32);
            this.created_at = new FfiTimestamp(createdAt);
            this.expires_at = new FfiTimestamp(expiresAt);
        }

        // getFieldOrder 함수는 JNA 구조체 필드 순서를 네이티브 ABI와 맞춰 반환
        @Override
        protected List<String> getFieldOrder() {
            return List.of("key_id", "key_value", "created_at", "expires_at");
        }
    }

    class FfiEncryptPackageRequest extends Structure {
        public FfiBorrowedBytes plaintext;
        public long user_id;
        public FfiBorrowedBytes user_public_key;
        public long guardian_id;
        public FfiBorrowedBytes guardian_public_key;
        public FfiDataKeyInput data_key;

        // FfiEncryptPackageRequest 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public FfiEncryptPackageRequest() {
            this.plaintext = new FfiBorrowedBytes();
            this.user_public_key = new FfiBorrowedBytes();
            this.guardian_public_key = new FfiBorrowedBytes();
            this.data_key = new FfiDataKeyInput();
        }

        // getFieldOrder 함수는 JNA 구조체 필드 순서를 네이티브 ABI와 맞춰 반환
        @Override
        protected List<String> getFieldOrder() {
            return List.of("plaintext", "user_id", "user_public_key", "guardian_id", "guardian_public_key", "data_key");
        }

        public static class ByReference extends FfiEncryptPackageRequest implements Structure.ByReference {
        }
    }

    class FfiDecryptPackageRequest extends Structure {
        public FfiBorrowedBytes package_;
        public long caller_id;
        public int caller_type;
        public FfiBorrowedBytes private_key;

        // FfiDecryptPackageRequest 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public FfiDecryptPackageRequest() {
            this.package_ = new FfiBorrowedBytes();
            this.private_key = new FfiBorrowedBytes();
        }

        // getFieldOrder 함수는 JNA 구조체 필드 순서를 네이티브 ABI와 맞춰 반환
        @Override
        protected List<String> getFieldOrder() {
            return List.of("package_", "caller_id", "caller_type", "private_key");
        }

        public static class ByReference extends FfiDecryptPackageRequest implements Structure.ByReference {
        }
    }

    class FfiCreateKeyEnvelopeRequest extends Structure {
        public FfiDataKeyInput data_key;
        public long owner_id;
        public int owner_type;
        public FfiBorrowedBytes public_key;

        // FfiCreateKeyEnvelopeRequest 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public FfiCreateKeyEnvelopeRequest() {
            this.data_key = new FfiDataKeyInput();
            this.public_key = new FfiBorrowedBytes();
        }

        // getFieldOrder 함수는 JNA 구조체 필드 순서를 네이티브 ABI와 맞춰 반환
        @Override
        protected List<String> getFieldOrder() {
            return List.of("data_key", "owner_id", "owner_type", "public_key");
        }

        public static class ByReference extends FfiCreateKeyEnvelopeRequest implements Structure.ByReference {
        }
    }

    class FfiOpenKeyEnvelopeRequest extends Structure {
        public FfiBorrowedBytes envelope;
        public long caller_id;
        public int caller_type;
        public FfiBorrowedBytes private_key;

        // FfiOpenKeyEnvelopeRequest 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public FfiOpenKeyEnvelopeRequest() {
            this.envelope = new FfiBorrowedBytes();
            this.private_key = new FfiBorrowedBytes();
        }

        // getFieldOrder 함수는 JNA 구조체 필드 순서를 네이티브 ABI와 맞춰 반환
        @Override
        protected List<String> getFieldOrder() {
            return List.of("envelope", "caller_id", "caller_type", "private_key");
        }

        public static class ByReference extends FfiOpenKeyEnvelopeRequest implements Structure.ByReference {
        }
    }

    class FfiCreateAdditionalRecipientEnvelopeRequest extends Structure {
        public FfiBorrowedBytes source_envelope;
        public long current_owner_id;
        public int current_owner_type;
        public FfiBorrowedBytes current_private_key;
        public long new_owner_id;
        public int new_owner_type;
        public FfiBorrowedBytes new_public_key;

        // FfiCreateAdditionalRecipientEnvelopeRequest 함수는 FFI 호출에 맞는 구조체 값을 초기화
        public FfiCreateAdditionalRecipientEnvelopeRequest() {
            this.source_envelope = new FfiBorrowedBytes();
            this.current_private_key = new FfiBorrowedBytes();
            this.new_public_key = new FfiBorrowedBytes();
        }

        // getFieldOrder 함수는 JNA 구조체 필드 순서를 네이티브 ABI와 맞춰 반환
        @Override
        protected List<String> getFieldOrder() {
            return List.of(
                    "source_envelope",
                    "current_owner_id",
                    "current_owner_type",
                    "current_private_key",
                    "new_owner_id",
                    "new_owner_type",
                    "new_public_key"
            );
        }

        public static class ByReference extends FfiCreateAdditionalRecipientEnvelopeRequest implements Structure.ByReference {
        }
    }

    final class BorrowedArg {
        private final Memory memory;
        private final FfiBorrowedBytes bytes;
        private final FfiBorrowedBytes.ByValue byValue;

        // BorrowedArg 함수는 FFI 호출에 맞는 구조체 값을 초기화
        private BorrowedArg(byte[] data) {
            if (data.length == 0) {
                this.memory = null;
                this.bytes = new FfiBorrowedBytes(Pointer.NULL, 0);
                this.byValue = new FfiBorrowedBytes.ByValue(Pointer.NULL, 0);
                return;
            }
            this.memory = new Memory(data.length);
            this.memory.write(0, data, 0, data.length);
            this.bytes = new FfiBorrowedBytes(memory, data.length);
            this.byValue = new FfiBorrowedBytes.ByValue(memory, data.length);
        }

        // of 함수는 Java 값을 FFI에 넘길 borrowed bytes 형태로 준비
        static BorrowedArg of(byte[] data) {
            return new BorrowedArg(Arrays.copyOf(data, data.length));
        }

        // utf8 함수는 Java 값을 FFI에 넘길 borrowed bytes 형태로 준비
        static BorrowedArg utf8(String value) {
            return new BorrowedArg(value.getBytes(StandardCharsets.UTF_8));
        }

        FfiBorrowedBytes asStruct() {
            return bytes;
        }

        FfiBorrowedBytes.ByValue asByValue() {
            return byValue;
        }
    }
}

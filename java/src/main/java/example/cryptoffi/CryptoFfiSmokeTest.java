package example.cryptoffi;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

public final class CryptoFfiSmokeTest {
    // CryptoFfiSmokeTest 함수는 예외나 헬퍼 객체의 기본 상태를 초기화
    private CryptoFfiSmokeTest() {
    }

    // main 함수는 예제 실행 흐름을 시작
    public static void main(String[] args) {
        Path dllPath = resolveLibraryPath(args);
        CryptoFfiNative lib = CryptoFfiNative.load(dllPath.toString());
        System.out.println("DLL load succeeded: " + dllPath);

        Pointer handle = createFacade(lib);
        try {
            CryptoFfiNative.BorrowedArg keyId = CryptoFfiNative.BorrowedArg.utf8("java-jna-smoke-key");
            byte[] dataKey = callBytes(lib, out -> lib.crypto_ffi_generate_data_key(
                    handle,
                    keyId.asByValue(),
                    1_700_000_000L,
                    1_800_000_000L,
                    out
            ));

            if (dataKey.length != 32) {
                throw new IllegalStateException("generate_data_key returned " + dataKey.length + " bytes, expected 32");
            }

            System.out.println("generate_data_key call succeeded");
            System.out.println("generate_data_key returned 32 bytes");
            System.out.println("data_key hex: " + HexFormat.of().formatHex(dataKey));
        } finally {
            int code = lib.crypto_ffi_facade_free(handle);
            check(lib, code);
        }
    }

    // createFacade 함수는 요청 값을 바탕으로 새 결과 객체를 생성
    private static Pointer createFacade(CryptoFfiNative lib) {
        PointerByReference outHandle = new PointerByReference();
        check(lib, lib.crypto_ffi_facade_new_default(outHandle));
        Pointer handle = outHandle.getValue();
        if (handle == null || Pointer.nativeValue(handle) == 0) {
            throw new IllegalStateException("crypto_ffi_facade_new_default returned a null handle");
        }
        return handle;
    }

    // callBytes 함수는 네이티브 호출 결과 버퍼를 bytes로 복사하고 해제
    private static byte[] callBytes(CryptoFfiNative lib, NativeBytesCall call) {
        CryptoFfiNative.FfiByteBuffer.ByReference out = new CryptoFfiNative.FfiByteBuffer.ByReference();
        check(lib, call.invoke(out));
        out.read();
        try {
            return out.toByteArray();
        } finally {
            check(lib, lib.crypto_ffi_byte_buffer_free(out.byValue()));
        }
    }

    // check 함수는 입력값이나 호출 결과가 유효한지 확인
    private static void check(CryptoFfiNative lib, int code) {
        if (code == CryptoFfiNative.FFI_ERROR_OK) {
            return;
        }
        throw new CryptoFfiException(code, lastErrorMessage(lib));
    }

    // lastErrorMessage 함수는 마지막 오류 정보를 읽거나 예외 객체로 변환
    private static String lastErrorMessage(CryptoFfiNative lib) {
        long len = lib.crypto_ffi_last_error_message_length().longValue();
        if (len <= 0) {
            return "";
        }
        if (len > Integer.MAX_VALUE - 1L) {
            return "last error message is too large: " + len;
        }

        Memory buffer = new Memory(len + 1L);
        int code = lib.crypto_ffi_last_error_message_copy(buffer, new CryptoFfiNative.SizeT(len + 1L));
        if (code != CryptoFfiNative.FFI_ERROR_OK) {
            return "unable to copy last error message; copy failed with code=" + code;
        }
        return buffer.getString(0, "UTF-8");
    }

    // resolveLibraryPath 함수는 사용할 경로나 설정 값을 찾아 확정
    private static Path resolveLibraryPath(String[] args) {
        if (args.length > 0 && !args[0].isBlank()) {
            return requireDll(Path.of(args[0]));
        }

        String env = System.getenv("CRYPTO_FFI_LIBRARY");
        if (env != null && !env.isBlank()) {
            return requireDll(Path.of(env));
        }

        Path cwd = Path.of("").toAbsolutePath().normalize();
        Path[] candidates = {
                cwd.resolve("../../target/release/crypto_ffi.dll").normalize(),
                cwd.resolve("../../target/release/deps/crypto_ffi.dll").normalize(),
                cwd.resolve("target/release/crypto_ffi.dll").normalize(),
                cwd.resolve("../../test/python_security/target/release/crypto_ffi.dll").normalize(),
                cwd.resolve("../python_security/target/release/crypto_ffi.dll").normalize()
        };

        for (Path candidate : candidates) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }

        throw new IllegalArgumentException(
                "crypto_ffi.dll not found. Pass the DLL path as the first argument or set CRYPTO_FFI_LIBRARY.");
    }

    // requireDll 함수는 입력값이나 호출 결과가 유효한지 확인
    private static Path requireDll(Path path) {
        Path absolute = path.toAbsolutePath().normalize();
        if (!Files.exists(absolute)) {
            throw new IllegalArgumentException("crypto_ffi.dll not found: " + absolute);
        }
        return absolute;
    }

    @FunctionalInterface
    private interface NativeBytesCall {
        int invoke(CryptoFfiNative.FfiByteBuffer.ByReference outBuffer);
    }

    private static final class CryptoFfiException extends RuntimeException {
        // CryptoFfiException 함수는 예외나 헬퍼 객체의 기본 상태를 초기화
        private CryptoFfiException(int code, String message) {
            super("crypto-ffi call failed: code=" + code + ", message=" + message);
        }
    }
}

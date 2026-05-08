package example.cryptoffi;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

final class CryptoFfiTestSupport implements AutoCloseable {
    private final CryptoFfiNative lib;
    private Pointer handle;

    private CryptoFfiTestSupport(CryptoFfiNative lib, Pointer handle) {
        this.lib = lib;
        this.handle = handle;
    }

    static Path resolveLibraryPath() {
        String env = System.getenv("CRYPTO_FFI_LIBRARY");
        if (env != null && !env.isBlank()) {
            return requireLibrary(Path.of(env));
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

        throw new IllegalStateException(
                "crypto_ffi.dll not found. Set CRYPTO_FFI_LIBRARY or build the Rust cdylib first.");
    }

    static CryptoFfiNative loadLibrary() {
        return CryptoFfiNative.load(resolveLibraryPath().toString());
    }

    static CryptoFfiTestSupport create() {
        CryptoFfiNative lib = loadLibrary();
        PointerByReference outHandle = new PointerByReference();
        check(lib, lib.crypto_ffi_facade_new_default(outHandle));
        Pointer handle = outHandle.getValue();
        if (handle == null || Pointer.nativeValue(handle) == 0) {
            throw new IllegalStateException("crypto_ffi_facade_new_default returned a null handle");
        }
        return new CryptoFfiTestSupport(lib, handle);
    }

    byte[] generateDataKey(String keyId, long createdAtUnixSeconds, long expiresAtUnixSeconds) {
        CryptoFfiNative.BorrowedArg keyIdArg = CryptoFfiNative.BorrowedArg.utf8(keyId);
        return callBytes(out -> lib.crypto_ffi_generate_data_key(
                requireHandle(),
                keyIdArg.asByValue(),
                createdAtUnixSeconds,
                expiresAtUnixSeconds,
                out
        ));
    }

    MlKemKeypair generateMlKemKeypair() {
        byte[] jsonBytes = callBytes(out -> lib.crypto_ffi_generate_mlkem_keypair(requireHandle(), out));
        String json = new String(jsonBytes, StandardCharsets.UTF_8);
        return new MlKemKeypair(
                readJsonStringField(json, "algorithm"),
                readJsonByteArrayField(json, "public_key"),
                readJsonByteArrayField(json, "private_key")
        );
    }

    byte[] encryptPackage(
            byte[] plaintext,
            long userId,
            byte[] userPublicKey,
            long guardianId,
            byte[] guardianPublicKey,
            String dataKeyId,
            byte[] dataKey,
            long createdAtUnixSeconds,
            long expiresAtUnixSeconds
    ) {
        CryptoFfiNative.BorrowedArg plaintextArg = CryptoFfiNative.BorrowedArg.of(plaintext);
        CryptoFfiNative.BorrowedArg userPublicKeyArg = CryptoFfiNative.BorrowedArg.of(userPublicKey);
        CryptoFfiNative.BorrowedArg guardianPublicKeyArg = CryptoFfiNative.BorrowedArg.of(guardianPublicKey);
        CryptoFfiNative.BorrowedArg dataKeyIdArg = CryptoFfiNative.BorrowedArg.utf8(dataKeyId);

        CryptoFfiNative.FfiEncryptPackageRequest.ByReference request =
                new CryptoFfiNative.FfiEncryptPackageRequest.ByReference();
        request.plaintext = plaintextArg.asStruct();
        request.user_id = userId;
        request.user_public_key = userPublicKeyArg.asStruct();
        request.guardian_id = guardianId;
        request.guardian_public_key = guardianPublicKeyArg.asStruct();
        request.data_key = dataKeyInput(dataKeyIdArg, dataKey, createdAtUnixSeconds, expiresAtUnixSeconds);

        return callBytes(out -> lib.crypto_ffi_encrypt_package(requireHandle(), request, out));
    }

    byte[] decryptPackage(byte[] packageBytes, long callerId, int callerType, byte[] privateKey) {
        CryptoFfiNative.BorrowedArg packageArg = CryptoFfiNative.BorrowedArg.of(packageBytes);
        CryptoFfiNative.BorrowedArg privateKeyArg = CryptoFfiNative.BorrowedArg.of(privateKey);

        CryptoFfiNative.FfiDecryptPackageRequest.ByReference request =
                new CryptoFfiNative.FfiDecryptPackageRequest.ByReference();
        request.package_ = packageArg.asStruct();
        request.caller_id = callerId;
        request.caller_type = callerType;
        request.private_key = privateKeyArg.asStruct();

        return callBytes(out -> lib.crypto_ffi_decrypt_package(requireHandle(), request, out));
    }

    byte[] createKeyEnvelope(
            String dataKeyId,
            byte[] dataKey,
            long createdAtUnixSeconds,
            long expiresAtUnixSeconds,
            long ownerId,
            int ownerType,
            byte[] publicKey
    ) {
        CryptoFfiNative.BorrowedArg dataKeyIdArg = CryptoFfiNative.BorrowedArg.utf8(dataKeyId);
        CryptoFfiNative.BorrowedArg publicKeyArg = CryptoFfiNative.BorrowedArg.of(publicKey);

        CryptoFfiNative.FfiCreateKeyEnvelopeRequest.ByReference request =
                new CryptoFfiNative.FfiCreateKeyEnvelopeRequest.ByReference();
        request.data_key = dataKeyInput(dataKeyIdArg, dataKey, createdAtUnixSeconds, expiresAtUnixSeconds);
        request.owner_id = ownerId;
        request.owner_type = ownerType;
        request.public_key = publicKeyArg.asStruct();

        return callBytes(out -> lib.crypto_ffi_create_key_envelope(requireHandle(), request, out));
    }

    byte[] openKeyEnvelope(byte[] envelopeBytes, long callerId, int callerType, byte[] privateKey) {
        CryptoFfiNative.BorrowedArg envelopeArg = CryptoFfiNative.BorrowedArg.of(envelopeBytes);
        CryptoFfiNative.BorrowedArg privateKeyArg = CryptoFfiNative.BorrowedArg.of(privateKey);

        CryptoFfiNative.FfiOpenKeyEnvelopeRequest.ByReference request =
                new CryptoFfiNative.FfiOpenKeyEnvelopeRequest.ByReference();
        request.envelope = envelopeArg.asStruct();
        request.caller_id = callerId;
        request.caller_type = callerType;
        request.private_key = privateKeyArg.asStruct();

        return callBytes(out -> lib.crypto_ffi_open_key_envelope(requireHandle(), request, out));
    }

    byte[] createAdditionalRecipientEnvelope(
            byte[] sourceEnvelopeBytes,
            long currentOwnerId,
            int currentOwnerType,
            byte[] currentPrivateKey,
            long newOwnerId,
            int newOwnerType,
            byte[] newPublicKey
    ) {
        CryptoFfiNative.BorrowedArg sourceEnvelopeArg = CryptoFfiNative.BorrowedArg.of(sourceEnvelopeBytes);
        CryptoFfiNative.BorrowedArg currentPrivateKeyArg = CryptoFfiNative.BorrowedArg.of(currentPrivateKey);
        CryptoFfiNative.BorrowedArg newPublicKeyArg = CryptoFfiNative.BorrowedArg.of(newPublicKey);

        CryptoFfiNative.FfiCreateAdditionalRecipientEnvelopeRequest.ByReference request =
                new CryptoFfiNative.FfiCreateAdditionalRecipientEnvelopeRequest.ByReference();
        request.source_envelope = sourceEnvelopeArg.asStruct();
        request.current_owner_id = currentOwnerId;
        request.current_owner_type = currentOwnerType;
        request.current_private_key = currentPrivateKeyArg.asStruct();
        request.new_owner_id = newOwnerId;
        request.new_owner_type = newOwnerType;
        request.new_public_key = newPublicKeyArg.asStruct();

        return callBytes(out -> lib.crypto_ffi_create_additional_recipient_envelope(requireHandle(), request, out));
    }

    @Override
    public void close() {
        if (handle == null) {
            return;
        }
        Pointer handleToFree = handle;
        handle = null;
        check(lib, lib.crypto_ffi_facade_free(handleToFree));
    }

    private byte[] callBytes(NativeBytesCall call) {
        CryptoFfiNative.FfiByteBuffer.ByReference out = new CryptoFfiNative.FfiByteBuffer.ByReference();
        check(lib, call.invoke(out));
        out.read();
        try {
            return out.toByteArray();
        } finally {
            check(lib, lib.crypto_ffi_byte_buffer_free(out.byValue()));
        }
    }

    private Pointer requireHandle() {
        if (handle == null) {
            throw new IllegalStateException("CryptoFfiTestSupport is already closed");
        }
        return handle;
    }

    private static CryptoFfiNative.FfiDataKeyInput dataKeyInput(
            CryptoFfiNative.BorrowedArg dataKeyIdArg,
            byte[] dataKey,
            long createdAtUnixSeconds,
            long expiresAtUnixSeconds
    ) {
        return new CryptoFfiNative.FfiDataKeyInput(
                dataKeyIdArg.asStruct(),
                Arrays.copyOf(dataKey, dataKey.length),
                createdAtUnixSeconds,
                expiresAtUnixSeconds
        );
    }

    private static Path requireLibrary(Path path) {
        Path absolute = path.toAbsolutePath().normalize();
        if (!Files.exists(absolute)) {
            throw new IllegalStateException("crypto_ffi.dll not found: " + absolute);
        }
        return absolute;
    }

    private static String readJsonStringField(String json, String fieldName) {
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\"([^\"]*)\"");
        Matcher matcher = pattern.matcher(json);
        if (!matcher.find()) {
            throw new IllegalStateException("JSON field not found: " + fieldName);
        }
        return matcher.group(1);
    }

    private static byte[] readJsonByteArrayField(String json, String fieldName) {
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\\[(.*?)\\]");
        Matcher matcher = pattern.matcher(json);
        if (!matcher.find()) {
            throw new IllegalStateException("JSON byte array field not found: " + fieldName);
        }

        String body = matcher.group(1).trim();
        if (body.isEmpty()) {
            return new byte[0];
        }

        String[] parts = body.split("\\s*,\\s*");
        List<Byte> bytes = new ArrayList<>(parts.length);
        for (String part : parts) {
            int value = Integer.parseInt(part);
            if (value < 0 || value > 255) {
                throw new IllegalStateException("JSON byte value is out of range: " + value);
            }
            bytes.add((byte) value);
        }

        byte[] result = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) {
            result[i] = bytes.get(i);
        }
        return result;
    }

    private static void check(CryptoFfiNative lib, int code) {
        if (code == CryptoFfiNative.FFI_ERROR_OK) {
            return;
        }
        throw new CryptoFfiException(code, lastErrorMessage(lib));
    }

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
        return buffer.getString(0, StandardCharsets.UTF_8.name());
    }

    @FunctionalInterface
    private interface NativeBytesCall {
        int invoke(CryptoFfiNative.FfiByteBuffer.ByReference outBuffer);
    }

    static final class CryptoFfiException extends RuntimeException {
        private final int code;

        private CryptoFfiException(int code, String message) {
            super("crypto-ffi call failed: code=" + code + ", message=" + message);
            this.code = code;
        }

        int code() {
            return code;
        }
    }

    record MlKemKeypair(String algorithm, byte[] publicKey, byte[] privateKey) {
    }
}

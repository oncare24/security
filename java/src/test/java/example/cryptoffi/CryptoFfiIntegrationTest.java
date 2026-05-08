package example.cryptoffi;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

final class CryptoFfiIntegrationTest {
    private static final long CREATED_AT = 1_700_000_000L;
    private static final long EXPIRES_AT = 1_700_086_400L;

    @Test
    void dllLoadSucceeds() {
        Path dllPath = CryptoFfiTestSupport.resolveLibraryPath();
        CryptoFfiNative lib = CryptoFfiNative.load(dllPath.toString());

        assertTrue(Files.exists(dllPath));
        assertNotNull(lib);
    }

    @Test
    void facadeCreateCloseSucceeds() {
        CryptoFfiNative lib = CryptoFfiTestSupport.loadLibrary();
        PointerByReference outHandle = new PointerByReference();
        assertEquals(CryptoFfiNative.FFI_ERROR_OK, lib.crypto_ffi_facade_new_default(outHandle));

        Pointer handle = outHandle.getValue();
        assertTrue(handle != null && Pointer.nativeValue(handle) != 0);
        assertEquals(CryptoFfiNative.FFI_ERROR_OK, lib.crypto_ffi_facade_free(handle));
    }

    @Test
    void generateDataKeyReturnsThirtyTwoBytes() {
        try (CryptoFfiTestSupport ffi = CryptoFfiTestSupport.create()) {
            byte[] dataKey = ffi.generateDataKey("junit-datakey-1", CREATED_AT, EXPIRES_AT);

            assertEquals(32, dataKey.length);
        }
    }

    @Test
    void generateMlKemKeypairReturnsPublicAndPrivateKeys() {
        try (CryptoFfiTestSupport ffi = CryptoFfiTestSupport.create()) {
            CryptoFfiTestSupport.MlKemKeypair keypair = ffi.generateMlKemKeypair();

            assertEquals("ML-KEM-1024", keypair.algorithm());
            assertNotNull(keypair.publicKey());
            assertNotNull(keypair.privateKey());
            assertTrue(keypair.publicKey().length > 0);
            assertTrue(keypair.privateKey().length > 0);
        }
    }

    @Test
    void generatedMlKemKeypairOpensCreatedKeyEnvelope() {
        try (CryptoFfiTestSupport ffi = CryptoFfiTestSupport.create()) {
            byte[] dataKey = ffi.generateDataKey("junit-datakey-generated-mlkem", CREATED_AT, EXPIRES_AT);
            CryptoFfiTestSupport.MlKemKeypair keypair = ffi.generateMlKemKeypair();
            byte[] envelope = ffi.createKeyEnvelope(
                    "junit-datakey-generated-mlkem",
                    dataKey,
                    CREATED_AT,
                    EXPIRES_AT,
                    101L,
                    CryptoFfiNative.FFI_OWNER_TYPE_USER,
                    keypair.publicKey()
            );
            byte[] openedDataKey = ffi.openKeyEnvelope(
                    envelope,
                    101L,
                    CryptoFfiNative.FFI_OWNER_TYPE_USER,
                    keypair.privateKey()
            );

            assertArrayEquals(dataKey, openedDataKey);
        }
    }

    @Test
    void encryptDecryptRoundTrip() {
        byte[] plaintext = "java jna roundtrip".getBytes(StandardCharsets.UTF_8);

        try (CryptoFfiTestSupport ffi = CryptoFfiTestSupport.create()) {
            byte[] dataKey = ffi.generateDataKey("junit-datakey-2", CREATED_AT, EXPIRES_AT);
            byte[] packageBytes = ffi.encryptPackage(
                    plaintext,
                    1L,
                    CryptoFfiTestFixtures.USER_PUBLIC_KEY,
                    2L,
                    CryptoFfiTestFixtures.GUARDIAN_PUBLIC_KEY,
                    "junit-datakey-2",
                    dataKey,
                    CREATED_AT,
                    EXPIRES_AT
            );
            byte[] decrypted = ffi.decryptPackage(
                    packageBytes,
                    1L,
                    CryptoFfiNative.FFI_OWNER_TYPE_USER,
                    CryptoFfiTestFixtures.USER_PRIVATE_KEY
            );

            assertArrayEquals(plaintext, decrypted);
        }
    }

    @Test
    void keyEnvelopeRoundTrip() {
        try (CryptoFfiTestSupport ffi = CryptoFfiTestSupport.create()) {
            byte[] dataKey = ffi.generateDataKey("junit-datakey-3", CREATED_AT, EXPIRES_AT);
            byte[] envelope = ffi.createKeyEnvelope(
                    "junit-datakey-3",
                    dataKey,
                    CREATED_AT,
                    EXPIRES_AT,
                    10L,
                    CryptoFfiNative.FFI_OWNER_TYPE_USER,
                    CryptoFfiTestFixtures.USER_PUBLIC_KEY
            );
            byte[] openedDataKey = ffi.openKeyEnvelope(
                    envelope,
                    10L,
                    CryptoFfiNative.FFI_OWNER_TYPE_USER,
                    CryptoFfiTestFixtures.USER_PRIVATE_KEY
            );

            assertArrayEquals(dataKey, openedDataKey);
        }
    }

    @Test
    void additionalRecipientEnvelopeRoundTrip() {
        try (CryptoFfiTestSupport ffi = CryptoFfiTestSupport.create()) {
            byte[] dataKey = ffi.generateDataKey("junit-datakey-4", CREATED_AT, EXPIRES_AT);
            byte[] userEnvelope = ffi.createKeyEnvelope(
                    "junit-datakey-4",
                    dataKey,
                    CREATED_AT,
                    EXPIRES_AT,
                    11L,
                    CryptoFfiNative.FFI_OWNER_TYPE_USER,
                    CryptoFfiTestFixtures.USER_PUBLIC_KEY
            );
            byte[] guardianEnvelope = ffi.createAdditionalRecipientEnvelope(
                    userEnvelope,
                    11L,
                    CryptoFfiNative.FFI_OWNER_TYPE_USER,
                    CryptoFfiTestFixtures.USER_PRIVATE_KEY,
                    22L,
                    CryptoFfiNative.FFI_OWNER_TYPE_GUARDIAN,
                    CryptoFfiTestFixtures.GUARDIAN_PUBLIC_KEY
            );
            byte[] openedDataKey = ffi.openKeyEnvelope(
                    guardianEnvelope,
                    22L,
                    CryptoFfiNative.FFI_OWNER_TYPE_GUARDIAN,
                    CryptoFfiTestFixtures.GUARDIAN_PRIVATE_KEY
            );

            assertArrayEquals(dataKey, openedDataKey);
        }
    }

    @Test
    void nativeErrorBecomesJavaExceptionWithLastErrorMessage() {
        try (CryptoFfiTestSupport ffi = CryptoFfiTestSupport.create()) {
            CryptoFfiTestSupport.CryptoFfiException error = assertThrows(
                    CryptoFfiTestSupport.CryptoFfiException.class,
                    () -> ffi.decryptPackage(
                            "{not-valid-json".getBytes(StandardCharsets.UTF_8),
                            1L,
                            CryptoFfiNative.FFI_OWNER_TYPE_USER,
                            CryptoFfiTestFixtures.USER_PRIVATE_KEY
                    )
            );

            assertEquals(3, error.code());
            assertTrue(error.getMessage().contains("malformed CryptoPackage JSON"));
        }
    }
}

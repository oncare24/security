package example.cryptoffi;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Optional;

import org.junit.jupiter.api.Test;

final class OpenBaoIntegrationTest {
    private static final long CREATED_AT = 1_700_000_000L;
    private static final long EXPIRES_AT = 1_700_086_400L;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Test
    void storesDataKeyInOpenBao() {
        OpenBaoClient client = requireOpenBaoClient();
        OpenBaoClient.StoredDataKey dataKey = newDataKey("java-openbao-store");

        client.storeDataKey(dataKey);
        String baoKeyPath = client.baoKeyPath(dataKey.keyId());
        Optional<OpenBaoClient.StoredDataKey> stored = client.readDataKeyByBaoKeyPath(baoKeyPath);

        assertTrue(stored.isPresent());
        assertEquals(dataKey.keyId(), stored.orElseThrow().keyId());
    }

    @Test
    void readsDataKeyFromOpenBao() {
        OpenBaoClient client = requireOpenBaoClient();
        OpenBaoClient.StoredDataKey dataKey = newDataKey("java-openbao-read");
        client.storeDataKey(dataKey);

        String baoKeyPath = client.baoKeyPath(dataKey.keyId());
        OpenBaoClient.StoredDataKey read = client.readDataKeyByBaoKeyPath(baoKeyPath).orElseThrow();

        assertArrayEquals(dataKey.keyValue(), read.keyValue());
        assertEquals(CREATED_AT, read.createdAtUnixSeconds());
        assertEquals(EXPIRES_AT, read.expiresAtUnixSeconds());
    }

    @Test
    void readDataKeyIsThirtyTwoBytes() {
        OpenBaoClient client = requireOpenBaoClient();
        OpenBaoClient.StoredDataKey dataKey = newDataKey("java-openbao-32-bytes");
        client.storeDataKey(dataKey);

        String baoKeyPath = client.baoKeyPath(dataKey.keyId());
        OpenBaoClient.StoredDataKey read = client.readDataKeyByBaoKeyPath(baoKeyPath).orElseThrow();

        assertEquals(32, read.keyValue().length);
        assertTrue(baoKeyPath.endsWith("cap2/data-keys/" + dataKey.keyId()));
    }

    @Test
    void dataKeyReadByBaoKeyPathCanBeUsedByJnaEncryption() {
        OpenBaoClient client = requireOpenBaoClient();
        OpenBaoClient.StoredDataKey dataKey = newDataKey("java-openbao-jna");
        client.storeDataKey(dataKey);

        String baoKeyPath = client.baoKeyPath(dataKey.keyId());
        OpenBaoClient.StoredDataKey read = client.readDataKeyByBaoKeyPath(baoKeyPath).orElseThrow();
        byte[] plaintext = "java openbao jna roundtrip".getBytes(StandardCharsets.UTF_8);

        try (CryptoFfiTestSupport ffi = CryptoFfiTestSupport.create()) {
            byte[] packageBytes = ffi.encryptPackage(
                    plaintext,
                    1L,
                    CryptoFfiTestFixtures.USER_PUBLIC_KEY,
                    2L,
                    CryptoFfiTestFixtures.GUARDIAN_PUBLIC_KEY,
                    baoKeyPath,
                    read.keyValue(),
                    read.createdAtUnixSeconds(),
                    read.expiresAtUnixSeconds()
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

    private static OpenBaoClient requireOpenBaoClient() {
        Optional<OpenBaoClient> client = OpenBaoClient.fromEnvironment();
        assumeTrue(client.isPresent(), "BAO_ADDR and BAO_TOKEN must be set for OpenBao integration tests");
        return client.orElseThrow();
    }

    private static OpenBaoClient.StoredDataKey newDataKey(String keyIdPrefix) {
        byte[] keyValue = new byte[32];
        SECURE_RANDOM.nextBytes(keyValue);
        return new OpenBaoClient.StoredDataKey(
                keyIdPrefix + "-" + System.nanoTime(),
                keyValue,
                CREATED_AT,
                EXPIRES_AT
        );
    }
}

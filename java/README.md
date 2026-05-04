# Java crypto_ffi.dll JNA and OpenBao tests

This project verifies the existing `crypto_ffi.dll` C ABI from Java through JNA. It also contains a small Java-to-OpenBao HTTP integration test for storing and reading AES-256-GCM data keys by `bao_key_path`.

## What Is Covered

| Python FFI test scenario | Java JNA test |
| --- | --- |
| DLL/shared-library loading through `CryptoFacade` | `dllLoadSucceeds` |
| facade handle creation and cleanup | `facadeCreateCloseSucceeds` |
| `generate_data_key` returns a 32-byte key | `generateDataKeyReturnsThirtyTwoBytes` |
| encrypt package, then decrypt package back to plaintext | `encryptDecryptRoundTrip` |
| create key envelope, then open it back to the original data key | `keyEnvelopeRoundTrip` |
| create an additional recipient envelope and open it as the new recipient | `additionalRecipientEnvelopeRoundTrip` |
| convert native error code and last error message into a Java exception | `nativeErrorBecomesJavaExceptionWithLastErrorMessage` |

The Java tests reuse the public/private key fixtures from `../../test/python_security/python/fixtures.py` by reading the hex constants as text. They do not execute Python.

## Run JNA Tests With Gradle

Requirements:

- JDK 17 or newer
- Gradle or a Gradle Wrapper
- A built `crypto_ffi.dll`

From this directory:

```powershell
cd security/java
gradle test
```

If a Gradle Wrapper exists:

```powershell
cd security/java
./gradlew test
```

The older smoke-test `main` is still available:

```powershell
cd security/java
gradle run
```

## OpenBao Integration

The OpenBao tests assume an OpenBao server is already running and that a KV v2 mount exists. The tests use the same storage shape as the Python OpenBao scripts:

```text
secret/data/cap2/data-keys/{key_id}
```

The stored value is a JSON secret containing:

```json
{
  "key_id": "...",
  "data_key_b64": "...",
  "created_at_unix_seconds": 1700000000,
  "expires_at_unix_seconds": 1700086400
}
```

`data_key_b64` is a base64-encoded 32-byte AES-256-GCM data key. The key is stored in OpenBao only for this test; no DB integration is included.

### Start OpenBao

Development-server example:

```powershell
openbao server -dev
```

In another PowerShell window, set the environment variables printed by the dev server:

```powershell
$env:BAO_ADDR="http://127.0.0.1:8200"
$env:BAO_TOKEN="<dev-root-token>"
```

The Java tests default to the `secret` KV mount. To use another mount:

```powershell
$env:BAO_KV_MOUNT="secret"
```

### Run OpenBao Tests

```powershell
cd security/java
gradle test --tests "example.cryptoffi.OpenBaoIntegrationTest"
```

If `BAO_ADDR` or `BAO_TOKEN` is missing, the OpenBao tests are skipped. When both are set, the tests:

- store a generated 32-byte data key in OpenBao
- read it back by `bao_key_path`, for example `secret/data/cap2/data-keys/{key_id}`
- verify the read key is exactly 32 bytes
- use the read key bytes as the `data_key` argument for the existing Rust JNA `encrypt_package` call

## DLL Path

The tests look for the DLL in this order:

1. `CRYPTO_FFI_LIBRARY`
2. `../../test/python_security/target/release/crypto_ffi.dll`
3. `../python_security/target/release/crypto_ffi.dll`
4. `../../target/release/crypto_ffi.dll`
5. `../../target/release/deps/crypto_ffi.dll`
6. `target/release/crypto_ffi.dll`

To set the path explicitly:

```powershell
$env:CRYPTO_FFI_LIBRARY="D:\Cap2-BoSalPim\test\python_security\target\release\crypto_ffi.dll"
cd security/java
gradle test
```

## Notes

- `CryptoFfiNative.java` is the JNA binding layer for the C ABI in `crypto_ffi.h`.
- Returned `FfiByteBuffer` values are copied into Java `byte[]` and always released with `crypto_ffi_byte_buffer_free` in `finally`.
- Ciphertext/package bytes are not compared to Python output. AES-GCM nonces and ML-KEM encapsulation are randomized, so ciphertext is expected to change on every run.
- The meaningful assertions are round-trip properties: decrypted plaintext equals the original plaintext, and opened envelope data keys equal the original data keys.
- OpenBao integration is limited to direct Java HTTP calls against KV v2 and passing the retrieved key bytes into JNA encryption. Spring Boot and DB storage are intentionally not included.

package example.cryptoffi;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class OpenBaoClient {
    private final HttpClient httpClient;
    private final URI address;
    private final String token;
    private final String kvMount;

    OpenBaoClient(URI address, String token, String kvMount) {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        this.address = address;
        this.token = token;
        this.kvMount = normalizePathPart(kvMount);
    }

    static Optional<OpenBaoClient> fromEnvironment() {
        String address = System.getenv("BAO_ADDR");
        String token = System.getenv("BAO_TOKEN");
        if (address == null || address.isBlank() || token == null || token.isBlank()) {
            return Optional.empty();
        }

        String kvMount = System.getenv("BAO_KV_MOUNT");
        if (kvMount == null || kvMount.isBlank()) {
            kvMount = "secret";
        }

        return Optional.of(new OpenBaoClient(URI.create(stripTrailingSlash(address)), token, kvMount));
    }

    void storeDataKey(StoredDataKey dataKey) {
        if (dataKey.keyValue().length != 32) {
            throw new IllegalArgumentException("OpenBao data key must be 32 bytes, got " + dataKey.keyValue().length);
        }

        String body = """
                {"data":{"key_id":"%s","data_key_b64":"%s","created_at_unix_seconds":%d,"expires_at_unix_seconds":%d}}
                """.formatted(
                jsonString(dataKey.keyId()),
                Base64.getEncoder().encodeToString(dataKey.keyValue()),
                dataKey.createdAtUnixSeconds(),
                dataKey.expiresAtUnixSeconds()
        );

        HttpRequest request = requestBuilder(dataKeyUri(dataKey.keyId()))
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .header("Content-Type", "application/json")
                .build();
        HttpResponse<String> response = send(request);
        requireStatus(response, 200, 204);
    }

    Optional<StoredDataKey> readDataKey(String keyId) {
        return readDataKeyByBaoKeyPath(baoKeyPath(keyId));
    }

    Optional<StoredDataKey> readDataKeyByBaoKeyPath(String baoKeyPath) {
        HttpRequest request = requestBuilder(address.resolve("/v1/" + normalizePathPart(baoKeyPath)))
                .GET()
                .build();
        HttpResponse<String> response = send(request);
        if (response.statusCode() == 404) {
            return Optional.empty();
        }
        requireStatus(response, 200);
        return Optional.of(parseStoredDataKey(response.body()));
    }

    String baoKeyPath(String keyId) {
        return kvMount + "/data/" + dataKeyPath(keyId);
    }

    private HttpRequest.Builder requestBuilder(URI uri) {
        return HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10))
                .header("X-Vault-Token", token)
                .header("X-Bao-Token", token)
                .header("Accept", "application/json");
    }

    private URI dataKeyUri(String keyId) {
        return address.resolve("/v1/" + kvMount + "/data/" + dataKeyPath(keyId));
    }

    private static String dataKeyPath(String keyId) {
        return "cap2/data-keys/" + encodePathSegment(keyId);
    }

    private HttpResponse<String> send(HttpRequest request) {
        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException error) {
            throw new OpenBaoException("OpenBao HTTP request failed: " + request.uri(), error);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new OpenBaoException("OpenBao HTTP request interrupted: " + request.uri(), error);
        }
    }

    private static void requireStatus(HttpResponse<String> response, int... expectedStatuses) {
        for (int expectedStatus : expectedStatuses) {
            if (response.statusCode() == expectedStatus) {
                return;
            }
        }
        throw new OpenBaoException("OpenBao returned HTTP " + response.statusCode() + ": " + response.body());
    }

    private static StoredDataKey parseStoredDataKey(String body) {
        String keyId = readJsonString(body, "key_id");
        byte[] keyValue = Base64.getDecoder().decode(readJsonString(body, "data_key_b64"));
        if (keyValue.length != 32) {
            throw new OpenBaoException("stored data key must be 32 bytes, got " + keyValue.length);
        }

        return new StoredDataKey(
                keyId,
                keyValue,
                readJsonLong(body, "created_at_unix_seconds"),
                readJsonLong(body, "expires_at_unix_seconds")
        );
    }

    private static String readJsonString(String body, String fieldName) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"")
                .matcher(body);
        if (!matcher.find()) {
            throw new OpenBaoException("OpenBao response is missing JSON string field: " + fieldName);
        }
        return unescapeJsonString(matcher.group(1));
    }

    private static long readJsonLong(String body, String fieldName) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*(-?\\d+)")
                .matcher(body);
        if (!matcher.find()) {
            throw new OpenBaoException("OpenBao response is missing JSON number field: " + fieldName);
        }
        return Long.parseLong(matcher.group(1));
    }

    private static String jsonString(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String unescapeJsonString(String value) {
        return value.replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private static String encodePathSegment(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String normalizePathPart(String value) {
        String normalized = value.strip();
        while (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private static String stripTrailingSlash(String value) {
        String stripped = value.strip();
        while (stripped.endsWith("/")) {
            stripped = stripped.substring(0, stripped.length() - 1);
        }
        return stripped;
    }

    record StoredDataKey(String keyId, byte[] keyValue, long createdAtUnixSeconds, long expiresAtUnixSeconds) {
    }

    static final class OpenBaoException extends RuntimeException {
        private OpenBaoException(String message) {
            super(message);
        }

        private OpenBaoException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

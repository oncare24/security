package example.cryptoffi;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class CryptoFfiTestFixtures {
    static final byte[] USER_PUBLIC_KEY = readHexFixture("USER_PUBLIC_KEY_HEX");
    static final byte[] USER_PRIVATE_KEY = readHexFixture("USER_PRIVATE_KEY_HEX");
    static final byte[] GUARDIAN_PUBLIC_KEY = readHexFixture("GUARDIAN_PUBLIC_KEY_HEX");
    static final byte[] GUARDIAN_PRIVATE_KEY = readHexFixture("GUARDIAN_PRIVATE_KEY_HEX");

    // CryptoFfiTestFixtures 함수는 예외나 헬퍼 객체의 기본 상태를 초기화
    private CryptoFfiTestFixtures() {
    }

    // readHexFixture 함수는 조건에 맞는 값을 조회해 반환
    private static byte[] readHexFixture(String constantName) {
        Path fixturesPath = resolveFixturesPath();
        String text;
        try {
            text = Files.readString(fixturesPath, StandardCharsets.UTF_8);
        } catch (IOException error) {
            throw new IllegalStateException("unable to read Python FFI fixtures: " + fixturesPath, error);
        }

        Pattern pattern = Pattern.compile("^" + Pattern.quote(constantName) + "\\s*=\\s*\"([0-9a-fA-F]+)\"",
                Pattern.MULTILINE);
        Matcher matcher = pattern.matcher(text);
        if (!matcher.find()) {
            throw new IllegalStateException("fixture constant not found in " + fixturesPath + ": " + constantName);
        }
        return HexFormat.of().parseHex(matcher.group(1));
    }

    // resolveFixturesPath 함수는 사용할 경로나 설정 값을 찾아 확정
    private static Path resolveFixturesPath() {
        Path cwd = Path.of("").toAbsolutePath().normalize();
        Path[] candidates = {
                cwd.resolve("../../test/python_security/python/fixtures.py").normalize(),
                cwd.resolve("../python_security/python/fixtures.py").normalize(),
                cwd.resolve("test/python_security/python/fixtures.py").normalize()
        };
        for (Path candidate : candidates) {
            if (Files.exists(candidate)) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        throw new IllegalStateException("python FFI fixtures.py not found");
    }
}

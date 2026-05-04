from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "python") not in sys.path:
    sys.path.insert(0, str(ROOT / "python"))
from crypto_ffi import CryptoFacade, CryptoFfiError, FfiErrorCode, FfiOwnerType
from fixtures import (
    GUARDIAN_PRIVATE_KEY,
    GUARDIAN_PUBLIC_KEY,
    USER_PRIVATE_KEY,
    USER_PUBLIC_KEY,
)


class CryptoFfiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.facade = CryptoFacade()
        except FileNotFoundError as error:
            raise unittest.SkipTest(str(error)) from error

    @classmethod
    def tearDownClass(cls) -> None:
        cls.facade.close()

    def test_facade_create_close(self) -> None:
        facade = CryptoFacade()
        self.assertTrue(facade.library_path.exists())
        facade.close()

    def test_encrypt_decrypt_round_trip(self) -> None:
        data_key = self.facade.generate_data_key(
            key_id="pytest-datakey-1",
            created_at_unix_seconds=1_700_000_000,
            expires_at_unix_seconds=1_700_086_400,
        )
        package_bytes = self.facade.encrypt_package(
            plaintext=b"python ffi roundtrip",
            user_id=1,
            user_public_key=USER_PUBLIC_KEY,
            guardian_id=2,
            guardian_public_key=GUARDIAN_PUBLIC_KEY,
            data_key_id="pytest-datakey-1",
            data_key=data_key,
            created_at_unix_seconds=1_700_000_000,
            expires_at_unix_seconds=1_700_086_400,
        )
        plaintext = self.facade.decrypt_package(
            package_bytes,
            caller_id=1,
            caller_type=FfiOwnerType.USER,
            private_key=USER_PRIVATE_KEY,
        )
        self.assertEqual(plaintext, b"python ffi roundtrip")

    def test_envelope_round_trip(self) -> None:
        data_key = self.facade.generate_data_key(
            key_id="pytest-datakey-2",
            created_at_unix_seconds=1_700_000_000,
            expires_at_unix_seconds=1_700_086_400,
        )
        envelope_bytes = self.facade.create_key_envelope(
            data_key_id="pytest-datakey-2",
            data_key=data_key,
            created_at_unix_seconds=1_700_000_000,
            expires_at_unix_seconds=1_700_086_400,
            owner_id=10,
            owner_type=FfiOwnerType.USER,
            public_key=USER_PUBLIC_KEY,
        )
        opened_data_key = self.facade.open_key_envelope(
            envelope_bytes,
            caller_id=10,
            caller_type=FfiOwnerType.USER,
            private_key=USER_PRIVATE_KEY,
        )
        self.assertEqual(opened_data_key, data_key)

    def test_additional_recipient_round_trip(self) -> None:
        data_key = self.facade.generate_data_key(
            key_id="pytest-datakey-3",
            created_at_unix_seconds=1_700_000_000,
            expires_at_unix_seconds=1_700_086_400,
        )
        user_envelope = self.facade.create_key_envelope(
            data_key_id="pytest-datakey-3",
            data_key=data_key,
            created_at_unix_seconds=1_700_000_000,
            expires_at_unix_seconds=1_700_086_400,
            owner_id=11,
            owner_type=FfiOwnerType.USER,
            public_key=USER_PUBLIC_KEY,
        )
        guardian_envelope = self.facade.create_additional_recipient_envelope(
            source_envelope_bytes=user_envelope,
            current_owner_id=11,
            current_owner_type=FfiOwnerType.USER,
            current_private_key=USER_PRIVATE_KEY,
            new_owner_id=22,
            new_owner_type=FfiOwnerType.GUARDIAN,
            new_public_key=GUARDIAN_PUBLIC_KEY,
        )
        opened_data_key = self.facade.open_key_envelope(
            guardian_envelope,
            caller_id=22,
            caller_type=FfiOwnerType.GUARDIAN,
            private_key=GUARDIAN_PRIVATE_KEY,
        )
        self.assertEqual(opened_data_key, data_key)

    def test_python_exception_includes_last_error_message(self) -> None:
        with self.assertRaises(CryptoFfiError) as context:
            self.facade.decrypt_package(
                package_bytes=b"{not-valid-json",
                caller_id=1,
                caller_type=FfiOwnerType.USER,
                private_key=USER_PRIVATE_KEY,
            )

        self.assertEqual(context.exception.code, FfiErrorCode.INVALID_ARGUMENT)
        self.assertIn("malformed CryptoPackage JSON", str(context.exception))


if __name__ == "__main__":
    unittest.main()



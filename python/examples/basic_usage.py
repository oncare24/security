from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "python") not in sys.path:
    sys.path.insert(0, str(ROOT / "python"))
from crypto_ffi import CryptoFacade, CryptoFfiError, FfiOwnerType
from fixtures import (
    GUARDIAN_PRIVATE_KEY,
    GUARDIAN_PUBLIC_KEY,
    USER_PRIVATE_KEY,
    USER_PUBLIC_KEY,
)


# main 함수는 예제 실행 흐름을 시작
def main() -> None:
    try:
        with CryptoFacade() as facade:
            data_key = facade.generate_data_key(
                key_id="datakey-2026-03-22",
                created_at_unix_seconds=1_700_000_000,
                expires_at_unix_seconds=1_700_086_400,
            )

            package_bytes = facade.encrypt_package(
                plaintext=b"hello from python wrapper",
                user_id=100,
                user_public_key=USER_PUBLIC_KEY,
                guardian_id=200,
                guardian_public_key=GUARDIAN_PUBLIC_KEY,
                data_key_id="datakey-2026-03-22",
                data_key=data_key,
                created_at_unix_seconds=1_700_000_000,
                expires_at_unix_seconds=1_700_086_400,
            )
            package = facade.load_wire_json(package_bytes)
            print("encrypted package key_id:", package["encrypted_data"]["key_id"])

            plaintext = facade.decrypt_package(
                package_bytes,
                caller_id=100,
                caller_type=FfiOwnerType.USER,
                private_key=USER_PRIVATE_KEY,
            )
            print("decrypted:", plaintext.decode("utf-8"))

            envelope_bytes = facade.create_key_envelope(
                data_key_id="datakey-2026-03-22",
                data_key=data_key,
                created_at_unix_seconds=1_700_000_000,
                expires_at_unix_seconds=1_700_086_400,
                owner_id=100,
                owner_type=FfiOwnerType.USER,
                public_key=USER_PUBLIC_KEY,
            )
            envelope = json.loads(envelope_bytes.decode("utf-8"))
            print("envelope owner:", envelope["owner_id"], envelope["owner_type"])

            opened_data_key = facade.open_key_envelope(
                envelope_bytes,
                caller_id=100,
                caller_type=FfiOwnerType.USER,
                private_key=USER_PRIVATE_KEY,
            )
            print("opened data key matches:", opened_data_key == data_key)

            additional_envelope = facade.create_additional_recipient_envelope(
                source_envelope_bytes=envelope_bytes,
                current_owner_id=100,
                current_owner_type=FfiOwnerType.USER,
                current_private_key=USER_PRIVATE_KEY,
                new_owner_id=200,
                new_owner_type=FfiOwnerType.GUARDIAN,
                new_public_key=GUARDIAN_PUBLIC_KEY,
            )
            guardian_data_key = facade.open_key_envelope(
                additional_envelope,
                caller_id=200,
                caller_type=FfiOwnerType.GUARDIAN,
                private_key=GUARDIAN_PRIVATE_KEY,
            )
            print("guardian data key matches:", guardian_data_key == data_key)

    except CryptoFfiError as error:
        print(f"crypto ffi error: {error}")
        raise


if __name__ == "__main__":
    main()



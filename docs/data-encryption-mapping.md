# 데이터 암호화 매핑

## 문서 목적

이 문서는 OnCare24 보안 모듈에서 어떤 데이터가 암호화되고, 암호화 후 생성된 데이터가 DB와 OpenBao에 각각 어떻게 저장되는지 예시와 함께 정리한다.

문서에 사용된 값은 실제 사용자 데이터가 아닌 예시 데이터이다.

## 현재 구현상 주의점

현재 암호화 구조는 `encrypted_activity_log`와 OpenBao를 중심으로 동작한다.

복약 일정과 복약 기록은 민감한 원본 데이터를 암호화 로그에 저장하고,
도메인 테이블에는 연결 정보와 상태 관리용 값 위주로 남기는 구조이다.

위치 보고 데이터와 기기 상태 데이터도 `encrypted_activity_log`에 암호화되어 저장된다.
다만 현재 백엔드의 일부 기능은 아직 원본 도메인 테이블을 기준으로 동작하는 흐름이 남아 있을 수 있다.

예를 들어 다음 기능들은 위치/기기 평문 테이블을 제거할 경우 함께 수정이 필요하다.

- 마지막 위치 조회
- 기기 연결 끊김 감지 배치
- 병원 추천 위치 해석
- SOS 위치 fallback
- `source_table`, `source_id` 기반 원본 row 연결 방식

따라서 위치/기기 데이터를 완전한 encryption-only 구조로 전환하려면,
해당 기능들이 `encrypted_activity_log`에서 최신 이벤트를 조회하고 복호화하는 방식으로 변경되어야 한다.

---

## 1. 복약 일정 데이터

- `source_table`: `medication_schedule`
- `event_type`: `MEDICATION_EVENT`
- payload class: `MedicationSchedulePayload`

### 1.1 암호화 전 입력 데이터

복약 일정 생성 시, 복약명, 복약 시간, 허용 지연 시간, 반복 유형 등의 원본 데이터와 메타데이터를 함께 구성한다.

```json
{
  "metadata": {
    "ward_id": 10,
    "event_type": "MEDICATION_EVENT",
    "occurred_at": "2026-05-25T08:00:00",
    "source_table": "medication_schedule",
    "source_id": 101
  },
  "payload": {
    "action": "CREATED",
    "scheduleId": 101,
    "medicationName": "타이레놀",
    "scheduledTime": "08:00:00",
    "allowedEarlyMinutes": 10,
    "allowedDelayMinutes": 30,
    "scheduleType": "DAILY",
    "dayOfWeek": null,
    "daysOfWeek": [],
    "active": true,
    "startDate": "2026-05-25",
    "endDate": "2026-06-01"
  }
}
```

### 1.2 암호화 후 생성 데이터

암호화 후에는 원본 payload가 그대로 저장되지 않고, 암호화된 패키지와 검증용 메타데이터가 생성된다.

```json
{
  "dataKeyId": "datakey-2026-05-25",
  "encryptedPackage": "<CryptoPackage JSON bytes>",
  "aadJson": "{\"ward_id\":10,\"event_type\":\"MEDICATION_EVENT\",\"occurred_at\":\"2026-05-25T08:00:00\",\"source_table\":\"medication_schedule\",\"source_id\":101}"
}
```

### 1.3 DB에 저장되는 데이터

```json
{
  "encrypted_activity_log": {
    "id": 9001,
    "ward_id": 10,
    "data_key_id": "datakey-2026-05-25",
    "event_type": "MEDICATION_EVENT",
    "source_table": "medication_schedule",
    "source_id": 101,
    "occurred_at": "2026-05-25T08:00:00",
    "encrypted_package": "<LONGBLOB>",
    "aad_json": "{...metadata...}"
  },
  "medication_schedule": {
    "id": 101,
    "ward_id": 10,
    "encrypted_activity_log_id": 9001,
    "is_active": true,
    "end_date": "2026-06-01",
    "codef_key_bidx": null
  }
}
```

### 1.4 OpenBao에 저장되는 데이터

```json
{
  "mlkem_key_pair": {
    "path": "secret/data/cap2/users/10/mlkem",
    "stored_data": {
      "algorithm": "ML-KEM-1024",
      "public_key_b64": "base64-public-key...",
      "private_key_b64": "base64-private-key...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  },
  "data_key": {
    "path": "secret/data/cap2/data-keys/datakey-2026-05-25",
    "stored_data": {
      "key_id": "datakey-2026-05-25",
      "data_key_b64": "base64-32byte-data-key...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  },
  "user_envelope": {
    "path": "secret/data/cap2/key-envelopes/datakey-2026-05-25/user-10",
    "stored_data": {
      "key_id": "datakey-2026-05-25",
      "owner_id": 10,
      "owner_type": "USER",
      "envelope_b64": "base64-key-envelope-json...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  },
  "guardian_envelope": {
    "path": "secret/data/cap2/key-envelopes/datakey-2026-05-25/guardian-20",
    "stored_data": {
      "key_id": "datakey-2026-05-25",
      "ward_id": 10,
      "owner_id": 20,
      "owner_type": "GUARDIAN",
      "envelope_b64": "base64-key-envelope-json...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  }
}
```

---

## 2. 복약 기록 데이터

- `source_table`: `medication_log`
- `event_type`: `MEDICATION_EVENT`
- payload class: `MedicationLogPayload`

### 2.1 암호화 전 입력 데이터

복약 기록 생성 시, 복약 일정 ID, 실제 복약 시간, 복약명, 기록 출처 등의 원본 데이터와 메타데이터를 함께 구성한다.

```json
{
  "metadata": {
    "ward_id": 10,
    "event_type": "MEDICATION_EVENT",
    "occurred_at": "2026-05-25T08:03:00",
    "source_table": "medication_log",
    "source_id": 501
  },
  "payload": {
    "scheduleId": 101,
    "plannedAt": null,
    "takenAt": "2026-05-25T08:03:00",
    "medicationName": "타이레놀",
    "logSource": "USER_INPUT",
    "allowedEarlyMinutes": null,
    "allowedDelayMinutes": null
  }
}
```

### 2.2 암호화 후 생성 데이터

```json
{
  "dataKeyId": "datakey-2026-05-25",
  "encryptedPackage": "<CryptoPackage JSON bytes>",
  "aadJson": "{\"ward_id\":10,\"event_type\":\"MEDICATION_EVENT\",\"occurred_at\":\"2026-05-25T08:03:00\",\"source_table\":\"medication_log\",\"source_id\":501}"
}
```

### 2.3 DB에 저장되는 데이터

```json
{
  "encrypted_activity_log": {
    "id": 9002,
    "ward_id": 10,
    "data_key_id": "datakey-2026-05-25",
    "event_type": "MEDICATION_EVENT",
    "source_table": "medication_log",
    "source_id": 501,
    "occurred_at": "2026-05-25T08:03:00",
    "encrypted_package": "<LONGBLOB>",
    "aad_json": "{...metadata...}"
  },
  "medication_log": {
    "id": 501,
    "ward_id": 10,
    "schedule_id": 101,
    "encrypted_activity_log_id": 9002
  }
}
```

### 2.4 OpenBao에 저장되는 데이터

```json
{
  "mlkem_key_pair": {
    "path": "secret/data/cap2/users/10/mlkem",
    "stored_data": {
      "algorithm": "ML-KEM-1024",
      "public_key_b64": "base64-public-key...",
      "private_key_b64": "base64-private-key...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  },
  "data_key": {
    "path": "secret/data/cap2/data-keys/datakey-2026-05-25",
    "stored_data": {
      "key_id": "datakey-2026-05-25",
      "data_key_b64": "base64-32byte-data-key...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  },
  "user_envelope": {
    "path": "secret/data/cap2/key-envelopes/datakey-2026-05-25/user-10",
    "stored_data": {
      "key_id": "datakey-2026-05-25",
      "owner_id": 10,
      "owner_type": "USER",
      "envelope_b64": "base64-key-envelope-json...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  },
  "guardian_envelope": {
    "path": "secret/data/cap2/key-envelopes/datakey-2026-05-25/guardian-20",
    "stored_data": {
      "key_id": "datakey-2026-05-25",
      "ward_id": 10,
      "owner_id": 20,
      "owner_type": "GUARDIAN",
      "envelope_b64": "base64-key-envelope-json...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  }
}
```

---

## 3. 위치 보고 데이터

- `source_table`: `location_report`
- `event_type`: `LOCATION_EVENT`
- payload class: `LocationSourcePayload`

### 3.1 암호화 전 입력 데이터

위치 보고 시, 위도, 경도, 정확도, 보고 시각, 보고 출처 등의 원본 데이터와 메타데이터를 함께 구성한다.

```json
{
  "metadata": {
    "ward_id": 10,
    "event_type": "LOCATION_EVENT",
    "occurred_at": "2026-05-25T08:00:00",
    "source_table": "location_report",
    "source_id": 301
  },
  "payload": {
    "wardId": 10,
    "latitude": 37.5665123,
    "longitude": 126.9780123,
    "accuracy": 18.5,
    "reportedAt": "2026-05-25T08:00:00",
    "sourceTable": "location_report",
    "sourceId": 301,
    "eventType": "LOCATION_EVENT",
    "reportSource": "BACKGROUND_SCHEDULED"
  }
}
```

### 3.2 암호화 후 생성 데이터

```json
{
  "dataKeyId": "datakey-2026-05-25",
  "encryptedPackage": "<CryptoPackage JSON bytes>",
  "aadJson": "{\"ward_id\":10,\"event_type\":\"LOCATION_EVENT\",\"occurred_at\":\"2026-05-25T08:00:00\",\"source_table\":\"location_report\",\"source_id\":301}"
}
```

### 3.3 DB에 저장되는 데이터

```json
{
  "encrypted_activity_log": {
    "id": 9003,
    "ward_id": 10,
    "data_key_id": "datakey-2026-05-25",
    "event_type": "LOCATION_EVENT",
    "source_table": "location_report",
    "source_id": 301,
    "occurred_at": "2026-05-25T08:00:00",
    "encrypted_package": "<LONGBLOB>",
    "aad_json": "{...metadata...}"
  },
  "location_reports": {
    "id": 301,
    "user_id": 10,
    "latitude": 37.5665123,
    "longitude": 126.9780123,
    "accuracy": 18.5,
    "report_source": "BACKGROUND_SCHEDULED"
  }
}
```

현재 구현 기준으로 위치 보고 데이터는 `encrypted_activity_log`에 암호화되어 저장되지만, `location_reports` 테이블에도 위도, 경도, 정확도 값이 평문으로 남아 있다.

### 3.4 OpenBao에 저장되는 데이터

```json
{
  "mlkem_key_pair": {
    "path": "secret/data/cap2/users/10/mlkem",
    "stored_data": {
      "algorithm": "ML-KEM-1024",
      "public_key_b64": "base64-public-key...",
      "private_key_b64": "base64-private-key...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  },
  "data_key": {
    "path": "secret/data/cap2/data-keys/datakey-2026-05-25",
    "stored_data": {
      "key_id": "datakey-2026-05-25",
      "data_key_b64": "base64-32byte-data-key...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  },
  "user_envelope": {
    "path": "secret/data/cap2/key-envelopes/datakey-2026-05-25/user-10",
    "stored_data": {
      "key_id": "datakey-2026-05-25",
      "owner_id": 10,
      "owner_type": "USER",
      "envelope_b64": "base64-key-envelope-json...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  },
  "guardian_envelope": {
    "path": "secret/data/cap2/key-envelopes/datakey-2026-05-25/guardian-20",
    "stored_data": {
      "key_id": "datakey-2026-05-25",
      "ward_id": 10,
      "owner_id": 20,
      "owner_type": "GUARDIAN",
      "envelope_b64": "base64-key-envelope-json...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  }
}
```

---

## 4. 기기 상태 데이터

- `source_table`: `device_status`
- `event_type`: `DEVICE_EVENT`
- payload class: `DeviceStatusSourcePayload`

### 4.1 암호화 전 입력 데이터

기기 상태 변경 시, 기기 상태, 마지막 활동 시각, 연결 끊김 시각, 보고 시각 등의 원본 데이터와 메타데이터를 함께 구성한다.

```json
{
  "metadata": {
    "ward_id": 10,
    "event_type": "DEVICE_EVENT",
    "occurred_at": "2026-05-25T08:35:00",
    "source_table": "device_status",
    "source_id": 44
  },
  "payload": {
    "wardId": 10,
    "deviceStatus": "DISCONNECTED",
    "lastActiveAt": "2026-05-25T08:00:00",
    "disconnectedAt": "2026-05-25T08:35:00",
    "reportedAt": "2026-05-25T08:35:00",
    "sourceTable": "device_status",
    "sourceId": 44,
    "eventType": "DEVICE_EVENT"
  }
}
```

### 4.2 암호화 후 생성 데이터

```json
{
  "dataKeyId": "datakey-2026-05-25",
  "encryptedPackage": "<CryptoPackage JSON bytes>",
  "aadJson": "{\"ward_id\":10,\"event_type\":\"DEVICE_EVENT\",\"occurred_at\":\"2026-05-25T08:35:00\",\"source_table\":\"device_status\",\"source_id\":44}"
}
```

### 4.3 DB에 저장되는 데이터

```json
{
  "encrypted_activity_log": {
    "id": 9004,
    "ward_id": 10,
    "data_key_id": "datakey-2026-05-25",
    "event_type": "DEVICE_EVENT",
    "source_table": "device_status",
    "source_id": 44,
    "occurred_at": "2026-05-25T08:35:00",
    "encrypted_package": "<LONGBLOB>",
    "aad_json": "{...metadata...}"
  },
  "device_status": {
    "id": 44,
    "user_id": 10,
    "state": "DISCONNECTED",
    "last_report_at": "2026-05-25T08:00:00",
    "disconnect_notified": true
  }
}
```

현재 구현 기준으로 기기 상태 데이터는 `encrypted_activity_log`에 암호화되어 저장되지만, `device_status` 테이블에도 상태값과 마지막 보고 시각 등 일부 값이 평문으로 남아 있다.

### 4.4 OpenBao에 저장되는 데이터

```json
{
  "mlkem_key_pair": {
    "path": "secret/data/cap2/users/10/mlkem",
    "stored_data": {
      "algorithm": "ML-KEM-1024",
      "public_key_b64": "base64-public-key...",
      "private_key_b64": "base64-private-key...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  },
  "data_key": {
    "path": "secret/data/cap2/data-keys/datakey-2026-05-25",
    "stored_data": {
      "key_id": "datakey-2026-05-25",
      "data_key_b64": "base64-32byte-data-key...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  },
  "user_envelope": {
    "path": "secret/data/cap2/key-envelopes/datakey-2026-05-25/user-10",
    "stored_data": {
      "key_id": "datakey-2026-05-25",
      "owner_id": 10,
      "owner_type": "USER",
      "envelope_b64": "base64-key-envelope-json...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  },
  "guardian_envelope": {
    "path": "secret/data/cap2/key-envelopes/datakey-2026-05-25/guardian-20",
    "stored_data": {
      "key_id": "datakey-2026-05-25",
      "ward_id": 10,
      "owner_id": 20,
      "owner_type": "GUARDIAN",
      "envelope_b64": "base64-key-envelope-json...",
      "created_at": "2026-05-25T00:00:00Z"
    }
  }
}
```
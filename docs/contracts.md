# 팀원 연결 규약 v1 (합의용 초안)

확정: LightGBM 모델을 전달받는다. 미정: 특징 필드·전처리·분석기 Python 함수 또는 CLI 방식.
아래 JSON 구조는 연결 가능한 초기 구현이며, 팀 합의에 따라 버전을 올려 수정한다.

## 1. CLI → 분석기

`depbee plan <project> --base-lock <path>`의 JSON을 그대로 전달한다.

- `schema_version`: 현재 1
- `request_id`: 두 lockfile 해시와 변경 목록의 결정적 식별자
- `base_lock_sha256`, `head_lock_sha256`: 원본 lockfile 바이트 해시
- `changes[]`: change_id, lockfile location, before/after의 name/version/resolved/integrity/link
- `analyzable`: 현재 분석 가능한 기존 패키지의 버전 변경 여부
- `reason`: 신규 추가·미지원·삭제의 구체적 이유

중첩 의존성은 경로별로 식별한다. alias는 name과 설치 경로를 구분한다.
분석기는 `analyzable=true`인 항목만 처리하고 다운로드한 파일이 lockfile integrity와 일치하는지
검증해야 한다. 예시의 가상 integrity를 실제 데이터로 사용하지 않는다.

## 2. 분석기 → CLI

```json
{
  "schema_version": 1,
  "request_id": "plan 명령이 반환한 값",
  "analyzer_version": "team-analyzer-0.1",
  "feature_schema": "team-features-v1",
  "results": [
    {
      "change_id": "요청의 change_id",
      "status": "complete",
      "features": {"feature_a": 1.0, "feature_b": 0.0},
      "evidence": ["확인된 코드·설정 변화 요약"]
    }
  ]
}
```

feature_a/b는 예시일 뿐 실제 특징이 아니다. 실제 이름·단위·결측값 정책·전처리는 팀이 확정한다.
값은 유한한 숫자만 허용하며 boolean·NaN·Infinity는 거부한다. 특징을 임의로 생략하거나 0으로
채우지 않는다. `complete`는 분석기의 지원 범위를 정상 수행했다는 의미로 합의해야 한다.

실패한 항목은 `{"change_id":"...","status":"failed","error":"실패 이유"}`로 전달한다.
누락 항목도 CLI는 미완료로 처리한다. 현재 evidence는 문자열 배열이며 다음 버전에서
파일·줄·변경 전후의 구조화된 근거로 확장할 수 있다.

Python 함수 형태의 제안:

```python
def analyze(request: dict) -> dict:
    # 팀원 분석기 호출과 결과 변환
    ...
```

CLI 호출 규약을 선택하면 요청/응답 파일, timeout, 반환 코드부터 합의한다.
현재 도구에는 외부 분석기 프로세스 실행 기능이 없다.

## 3. 모델 담당 → 추론 어댑터

`models/<model-id>/` 아래 두 파일:

1. `model.txt`: `Booster.save_model()`로 내보낸 native text 모델
2. `manifest.json`: 아래 메타데이터

```json
{
  "schema_version": 1,
  "model_id": "team-model-001",
  "model_sha256": "model.txt 파일의 실제 SHA-256",
  "objective": "binary",
  "positive_class": "malicious",
  "feature_schema": "team-features-v1",
  "feature_names": ["feature_a", "feature_b"],
  "threshold": 0.5
}
```

0.5는 구조 설명용 예시다. 실제 임계값은 모델 담당자가 검증 세트에서 정해 전달한다.
양성 라벨 1이 악성이어야 한다. feature_names는 학습 시 모델에 저장된 순서·이름과 정확히 같아야 한다.
현재 adapter는 이미 전처리된 수치 특징을 받는다. 별도 scaler·categorical 변환이 필요하면
해당 변환과 버전을 규약에 먼저 추가한다. arbitrary Python 객체를 모델에 동봉하지 않는다.

SHA-256은 파일 변조·혼동 확인용이다. 모델은 신뢰하는 팀원과 보호된 경로를 통해 받아야 한다.
모델 export 예시(학습 코드가 아니라 팀원 전달용):

```python
booster.save_model("model.txt")
# feature_names = booster.feature_name()
# model_sha256 = hashlib.sha256(Path("model.txt").read_bytes()).hexdigest()
```

모델과 함께 학습 데이터 범위, 분할 방법, 검증 결과, LightGBM 버전도 기록해 전달한다.

## 4. CLI → 사용자·CI

보고서는 request_id, model_id, threshold, analyzer_version, scope, results를 포함한다.
패키지 상태는 `flagged`, `not_flagged`, `incomplete`, `removed`다.
하나라도 미완료면 전체 종료 코드 2, 그 외 위험이 있으면 1, 나머지는 0이다.
위험과 미완료가 함께 있으면 보고서에 둘 다 남기고 2로 보류한다.
입력/manifest 자체의 오류는 stderr의 error JSON과 종료 코드 2로 반환한다.

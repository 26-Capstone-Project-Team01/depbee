# 연결 규약 v1

확정: LightGBM native 모델을 전달받는다. 내장 분석기(`--extract`)는 feature-extractor의 feature를 `depbee-features-v1` 스키마로 낸다.
아래 JSON 구조는 지금 구현과 일치한다. 필드를 바꿀 때는 팀 합의 후 `schema_version`을 올린다.

## 1. CLI → 분석기

`depbee plan <project> --base-lock <path>`의 JSON을 그대로 전달한다.

- `schema_version`: 현재 1
- `request_id`: 두 lockfile 해시와 변경 목록의 결정적 식별자
- `base_lock_sha256`, `head_lock_sha256`: 원본 lockfile 바이트 해시
- `changes[]`: change_id, lockfile location, kind(`updated`/`added`/`removed`), before/after의 name/version/resolved/integrity/link. 새로 추가된 의존성은 before가 null이다.
- `analyzable`: 분석 대상 여부. 설치될 버전(after)이 npm 공식 registry의 semver 버전이고 integrity가 있으면 true다. 새로 추가된 의존성도 포함한다.
- `reason`: 분석하지 않는 이유(삭제·미지원 출처 등)

중첩 의존성은 경로별로 식별한다. alias는 name과 설치 경로를 구분한다.
분석기는 `analyzable=true`인 항목만 처리하고, 다운로드한 버전이 lockfile integrity와 일치하는지 확인해야 한다. 예시의 가상 integrity를 실제 데이터로 사용하지 않는다.

## 2. 분석기 → CLI

```json
{
  "schema_version": 1,
  "request_id": "plan 명령이 반환한 값",
  "analyzer_version": "feature-extractor 0.1.0",
  "feature_schema": "depbee-features-v1",
  "results": [
    {
      "change_id": "요청의 change_id",
      "status": "complete",
      "baseline_version": "비교 기준으로 쓴 버전",
      "features": {"installScriptAdded": true, "updateType": "patch", "obfHexIdentRatioNew": null},
      "evidence": ["확인된 코드·설정 변화 요약"]
    }
  ]
}
```

- feature 값은 숫자, true/false, 문자열, null만 쓴다. 어떤 feature가 어떤 자료형을 받는지는 모델 manifest가 정하고 추론기가 검사한다. 특징을 임의로 생략하거나 0으로 채우지 않는다.
- `baseline_version`(선택)은 새 버전과 비교한 버전이다. 내장 분석기는 같은 release line의 직전 stable을 쓴다(README "동작 방식").
- `evidence`는 문자열 배열이다. 패키지에서 온 문자열을 담을 수 있으므로 CLI가 출력할 때 제어 문자를 이스케이프한다.
- 분석에 실패한 항목: `{"change_id":"...","status":"failed","error":"실패 이유"}`
- 모델의 학습 범위 밖이라 분석하지 않은 항목: `{"change_id":"...","status":"unsupported","reason":"out_of_training_scope","error":"설명"}`. reason은 `out_of_training_scope`(새 버전이 pre-release 등), `no_baseline`(비교할 이전 stable 없음)을 쓴다.
- 결과가 없는 항목도 CLI는 미완료로 처리한다.

다른 분석기를 붙일 때는 `contracts.Analyzer`의 `analyze(request) -> dict`를 구현하고, 결과는 `analysis.artifact.validate()`로 같은 검사를 거친다.
외부 프로세스로 붙인다면 셸 문자열 조합 없이 argv·timeout·출력 한도를 둔다.

## 3. 모델 담당 → 추론 어댑터

`models/<model-id>/` 아래 두 파일:

1. `model.txt`: `Booster.save_model()`로 내보낸 native text 모델
2. `manifest.json`: 아래 메타데이터. `scripts/write_manifest.py`로 만든다.

```json
{
  "schema_version": 1,
  "model_id": "team-model-001",
  "model_sha256": "model.txt 파일의 실제 SHA-256",
  "objective": "binary",
  "positive_class": "malicious",
  "feature_schema": "depbee-features-v1",
  "feature_names": ["installScriptPresent", "...", "obfWhitespaceRatioChangedCode"],
  "boolean_features": ["installScriptPresent", "installScriptAdded", "scriptEntryAdded", "newDependencyAdded"],
  "categorical_features": {"updateType": ["major", "minor", "patch"]},
  "nullable_features": ["obfHexIdentRatioNew", "..."],
  "threshold": 0.5,
  "note": "데이터 버전, 임계값 근거 등 자유 기록(선택)"
}
```

- 양성 라벨 1이 악성이어야 한다. `feature_names`는 모델에 저장된 이름·순서와 정확히 같아야 한다.
- 분석기는 `feature_schema`의 feature를 모두 뽑고, 예측기는 그중 `feature_names`에 있는 것만 그 순서로 모델에 넣는다. 그래서 feature 일부만 쓰는 모델(예: package.json feature 7개)도 같은 분석기로 붙는다. 모델 feature가 분석 결과에 없으면 채우지 않고 오류(보류)로 둔다.
- `boolean_features`(선택): true/false를 1/0으로 넣는다. 학습 CSV의 True/False와 같다.
- `categorical_features`(선택): 값의 목록 내 위치가 범주 코드다. pandas로 학습한 모델은 범주 순서를 모델 파일에 저장하므로, 그 순서와 다르면 로딩을 거부한다. 목록에 없는 값은 학습 범위 밖으로 보고 점수를 내지 않는다.
- `nullable_features`(선택): null을 LightGBM 결측값(NaN)으로 넣는다. 학습 데이터에서 계산할 대상이 없어 비어 있던 feature만 여기에 둔다. 나머지 feature의 null은 거부한다.
- 임계값은 모델 담당자가 검증 세트에서 정해 전달한다. 학습 기본값 0.5를 쓰면 `note`에 검증 전이라고 적는다.
- arbitrary Python 객체(pickle·joblib)를 모델에 동봉하지 않는다.

SHA-256은 파일 변조·혼동 확인용이다. 모델은 신뢰하는 팀원과 보호된 경로를 통해 받아야 한다.
모델과 함께 학습 데이터 범위, 분할 방법, 검증 결과, LightGBM 버전도 기록해 전달한다.

## 4. CLI → 사용자·CI

보고서는 request_id, model_id, threshold, analyzer_version, scope, results를 포함한다.
패키지 상태는 `flagged`, `not_flagged`, `incomplete`, `removed`다.
점수가 나온 항목에는 `compared_version`(비교 기준 버전), `features`, `evidence`(추출된 사실), `explanation`(점수에 크게 작용한 feature 3개와 SHAP 기여도, log-odds 단위)이 있다. 추출된 사실과 모델 설명은 구분한다.
`explanation_rest`는 `explanation`에 없는 feature의 기여도 합(`others_sum`)과 개수(`others_count`), 모델 기준값(`base_value`)이다. `explanation`의 기여도와 이 두 값을 모두 더하면 점수의 log-odds가 된다.
`incomplete` 항목에는 `reason`과, 있으면 `detail`이 있다. 학습 범위 밖 입력은 `out_of_training_scope` 또는 `no_baseline`이다.
하나라도 미완료면 전체 종료 코드 2, 그 외 위험이 있으면 1, 나머지는 0이다.
위험과 미완료가 함께 있으면 보고서에 둘 다 남기고 2로 보류한다.
입력/manifest 자체의 오류는 stderr의 error JSON과 종료 코드 2로 반환한다.

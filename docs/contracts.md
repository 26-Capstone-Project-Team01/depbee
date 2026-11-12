# 연결 규약 v1

확정: LightGBM native 모델을 전달받는다. 내장 분석기(`--extract`)는 feature-extractor의 feature를 `depbee-features-v1` 스키마로 낸다.
아래 JSON 구조는 지금 구현과 일치한다. 필드를 바꿀 때는 팀 합의 후 `schema_version`을 올린다.

## 1. CLI → 분석기

`depbee plan <project> [--base-lock <path> | --base-ref <ref>]`의 JSON을 그대로 전달한다. 기준이 파일이든 Git 커밋이든 요청 형식은 같다. Git 커밋 기준(`--base-ref`, 기준을 주지 않은 HEAD)은 Git 2.45 이상이 필요하고, 오래된 Git이면 요청을 만들지 않고 오류(종료 코드 2)로 끝난다.

- `schema_version`: 현재 1
- `request_id`: 두 lockfile 해시와 변경 목록의 결정적 식별자
- `base_lock_sha256`, `head_lock_sha256`: 원본 lockfile 바이트 해시. Git 기준이면 커밋에 저장된 파일 바이트의 해시다.
- `changes[]`: change_id, lockfile location, kind(`updated`/`added`/`removed`), before/after의 name/version/resolved/integrity/link. 새로 추가된 의존성은 before가 null이다.
- `analyzable`: 분석 대상 여부. 설치될 버전(after)이 npm 공식 registry의 semver 버전이고 integrity가 있으면 true다. 새로 추가된 의존성도 포함한다.
- `reason`: 분석하지 않는 이유(삭제·미지원 출처 등)

중첩 의존성은 경로별로 식별한다. alias는 name과 설치 경로를 구분한다.
분석기는 `analyzable=true`인 항목만 처리하고, 다운로드한 버전이 lockfile integrity와 일치하는지 확인해야 한다. 내장 분석기는 lockfile integrity가 registry 메타데이터의 `dist.integrity`와 같은 값을 공유하는지 확인하고, 받은 tarball 바이트를 그 registry 값(가장 강한 알고리즘)과 대조한다. 예시의 가상 integrity를 실제 데이터로 사용하지 않는다.

### 1.1 lockfile 없는 단일 패키지 요청 (`depbee check NAME@VERSION`)

`check`는 lockfile 없이 npm 공식 registry의 버전 하나를 검사하는 요청을 만든다. 위 lockfile 요청의 필드와 순서, 해시 계산은 그대로이고, 이 요청에만 아래 차이가 있다.

```json
{
  "request_id": "아래 필드의 결정적 digest",
  "schema_version": 1,
  "input_kind": "package",
  "changes": [
    {
      "change_id": "location·before·after의 digest",
      "location": "registry.npmjs.org",
      "before": null,
      "after": {"name": "lodash", "version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "integrity": "sha512-...", "link": false},
      "kind": "added",
      "analyzable": true,
      "reason": null
    }
  ]
}
```

- `input_kind: "package"`로 lockfile 요청과 구분한다. lockfile 요청에는 이 필드가 없다.
- lockfile이 없으므로 `base_lock_sha256`·`head_lock_sha256`이 없다. 존재하지 않는 파일의 해시를 만들지 않는다.
- 이름과 버전은 네트워크 접근 전에 검사한다. scope가 있거나 없는 registry 이름과, 숫자 부분과 숫자로만 된 pre-release 식별자에 선행 0이 없는 SemVer 버전을 받는다. build metadata(`+...`)가 붙은 버전은 SemVer 문법상 유효하지만 이 명령의 지원 범위 밖이라 거부한다. 이것은 npm이 버전을 표시하는 형식에 맞춘 지원 정책이며, registry의 저장 규칙 전체를 검증한 결과는 아니다.
- `after`는 registry 메타데이터의 그 버전 manifest에서 만든다. manifest의 `name`·`version`이 요청과 같고, `dist.tarball`이 `https://registry.npmjs.org`이며, `dist.integrity`가 있어야 한다. 하나라도 어긋나면 요청을 만들지 않고 오류(종료 코드 2)다. 이 integrity는 registry 메타데이터 값이고, 분석기는 받은 tarball 바이트를 이 값과 대조한 뒤에 푼다.
- 분석기는 lockfile 요청의 새로 추가된 의존성과 같은 방식으로 처리하고(같은 release line의 직전 stable과 비교), 근거에 "lockfile 없이 registry 정보로 검사"를 넣는다. 요청을 만든 메타데이터를 비교 기준 선정과 feature 추출(old/new snapshot)에도 그대로 쓰고 registry를 다시 조회하지 않는다. 분석 결과(2절)와 모델 manifest(3절) 형식은 같다.

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

보고서는 request_id, model_id, threshold, analyzer_version, provenance, scope, results를 포함한다.
`provenance`는 `analyzer_version` 바로 다음에 오는 출처 객체이며 `model`과 `feature_extractor` 두 키가 항상 있다. `model`은 확인한 모델 파일과 manifest의 SHA-256(`model_sha256`, `manifest_sha256`)이고 모델 없이 실행하면 null이다. `feature_extractor`는 설치된 feature-extractor의 고정 커밋(`commit`), 설치 파일 해시(`files_sha256`), Python 버전(`python`)이고, feature를 추출하지 않는 실행(`--extract` 없는 `scan`, `--analysis`)이거나 고정 커밋 그대로 설치됐는지 확인하지 못하면(편집 가능 설치, 로컬 폴더 설치, 설치 후 수정) null이다. 설치 주소(URL)는 넣지 않는다. `plan`의 출력(요청)과 오류 JSON에는 없다.
`check`의 보고서에만 `input_kind: "package"`가 request_id 다음에 더 있고, scope는 `one npm registry version checked without a lockfile; not a whole-project safety assessment`다. lockfile 보고서의 필드와 scope 문구는 그대로다.
패키지 상태는 `flagged`, `not_flagged`, `incomplete`, `removed`다.
점수가 나온 항목에는 `compared_version`(비교 기준 버전), `features`, `evidence`(추출된 사실), `explanation`(점수에 크게 작용한 feature 3개와 SHAP 기여도, log-odds 단위)이 있다. 추출된 사실과 모델 설명은 구분한다.
`explanation_rest`는 `explanation`에 없는 feature의 기여도 합(`others_sum`)과 개수(`others_count`), 모델 기준값(`base_value`)이다. `explanation`의 기여도와 이 두 값을 모두 더하면 점수의 log-odds가 된다.
`incomplete` 항목에는 `reason`과, 있으면 `detail`이 있다. 학습 범위 밖 입력은 `out_of_training_scope` 또는 `no_baseline`이다.

feature를 추출한 보고서(`scan --extract`, `check`)에만 소요 시간과 캐시 사용 여부가 더 있다. 그 밖의 필드와 순서는 그대로이고, `--extract` 없는 `scan`과 `plan`의 출력에는 이 필드가 없다.

- 최상위 `elapsed_seconds`: `provenance` 다음, `results` 앞. 서비스 함수(`scan_project`, `check_package`) 호출부터 판정 완료까지의 시간이다.
- 각 결과의 끝 `elapsed_seconds`: 그 항목의 메타데이터 조회·캐시 조회·추출 시간이며 추론 시간은 들어가지 않는다. 분석하지 않은 항목(삭제, 미지원 출처 등)은 null이다. `check`는 요청을 만들기 전에 받은 메타데이터의 조회 시간도 그 결과의 값에 더한다.
- 각 결과의 끝 `cache_hit`: 캐시한 feature를 썼으면 true, 추출했거나 분석하지 않았거나 실패한 항목은 false다.
- 시간은 단조 시계(`time.monotonic`)로 재며 초 단위, 소수 셋째 자리까지, 항상 유한한 0 이상의 값이다. 실행마다 달라지므로 보고서끼리 비교할 때는 이 필드를 빼고 비교한다.
- 캐시 파일 형식은 depbee 내부 형식이며 이 규약에 속하지 않는다. 캐시는 추출한 feature만 담고, 판정·점수·근거·설명은 매번 다시 계산한다. 캐시한 feature를 쓴 결과의 `features`도 추출한 결과와 키 순서와 값이 같아, 같은 요청의 JSON 출력은 위 시간 필드와 `cache_hit`만 다르다.

`--format markdown`(`scan`, `check`)은 같은 보고서를 GitHub Flavored Markdown으로 보여 주는 표시 형식이며 위 JSON 구조는 바뀌지 않는다. `--output`은 이 형식에서도 JSON 파일이고, 진행 표시는 텍스트에서만 나온다.

- 순서: 제목(전체 판정과 종료 코드), 개수·모델·범위·소요 시간 목록, 결과 표(판정, 패키지, 설치될 버전, 비교 버전, 점수, 이유, 위치, 시간이 있으면 분석 시간), 근거나 설명이 있는 결과별 절(상세, 추출된 사실, 모델 설명), 안전 보증이 아니라는 문구. 결과 순서는 텍스트와 같은 위험 → 보류 → 통과 → 삭제, 같은 판정 안에서는 점수 순이다.
- 점수가 없으면 `-`, 0이면 `0.000`이다. 추출된 사실과 모델 설명은 서로 다른 목록이다.
- 보고서에서 온 문자열(패키지, 버전, 위치, 근거, 상세, model_id, 알 수 없는 이유 코드, feature 이름과 값)은 텍스트 출력과 같이 제어 문자를 `\uXXXX`로 바꾼 뒤, 안에 있는 어떤 백틱 묶음보다 긴 백틱으로 감싼 code span으로만 넣는다. 표 칸에서는 code span 안의 `|`도 `\|`로 쓴다(GFM은 code span 안의 `|`로도 칸을 나눈다). 그래서 HTML, 링크, 이미지, 강조, 자동 링크, 줄바꿈으로 해석되지 않는다. depbee가 만든 한국어 문구와 숫자만 code span 밖에 있다.
하나라도 미완료면 전체 종료 코드 2, 그 외 위험이 있으면 1, 나머지는 0이다.
위험과 미완료가 함께 있으면 보고서에 둘 다 남기고 2로 보류한다.
입력/manifest 자체의 오류는 stderr의 error JSON과 종료 코드 2로 반환한다.

기지 악성·규칙 근거·ML 위험 점수·미완료를 구분해 담는 필드는 [결과 계약 초안](result-contract-draft.md)에 있다. 결정은 채택됐지만 그중 위 `provenance`만 구현됐고, 나머지는 구현 전까지 위 보고서 구조와 상태·종료 코드 규칙이 그대로다.

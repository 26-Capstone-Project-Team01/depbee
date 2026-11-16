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

보고서는 request_id, model_id, threshold, analyzer_version, detectors, provenance, scope, results를 포함한다.
`provenance`는 `detectors` 바로 다음에 오는 출처 객체이며 `model`과 `feature_extractor` 두 키가 항상 있다. `model`은 확인한 모델 파일과 manifest의 SHA-256(`model_sha256`, `manifest_sha256`)이고 모델 없이 실행하면 null이다. `feature_extractor`는 설치된 feature-extractor의 고정 커밋(`commit`), 설치 파일 해시(`files_sha256`), Python 버전(`python`)이고, feature를 추출하지 않는 실행(`--extract` 없는 `scan`, `--analysis`)이거나 고정 커밋 그대로 설치됐는지 확인하지 못하면(편집 가능 설치, 로컬 폴더 설치, 설치 후 수정) null이다. 설치 주소(URL)는 넣지 않는다. 둘 다 필요한 키가 모두 문자열로 있는 확인된 identity만 옮기고, 그렇지 않으면(다른 예측기·backend를 주입한 경우) 오류 대신 null이다. `feature_extractor`는 설치 출처라 그 실행에서 추출한 변경이 0건이거나 모두 실패해도 값이 있다(`analyzer_version`과 같다). `plan`의 출력(요청)과 오류 JSON에는 없다.

`detectors`는 `analyzer_version` 바로 다음에 오며 이 실행에 연결된 ML 외 탐지기다. `known_malicious`(기지 악성 목록의 `source`, `list_as_of`, `list_sha256`)와 `rules`(`ruleset_version`) 두 키가 항상 있고, 연결되지 않은 탐지기는 null이다. `list_as_of`는 ISO 8601 UTC(`Z`)이며, 형식이 어긋나면 값은 받은 그대로 두고 그 목록으로 일치를 찾지 못한 항목을 `failed`로 둔다(일치는 그대로 `hit`). 각 결과의 끝(시간 필드가 있으면 그 앞)에는 `known_malicious`(`status`, `reason`, `detail`, `matches`), `rules`(`status`, `reason`, `detail`, `checks`), `ml`(`status`), `rule_ml_agreement`가 이 순서로 있다. 탐지기 상태는 `hit`, `not_hit`, `not_run`, `failed`이고, 연결되지 않은 탐지기는 `not_run`(`detector_not_configured`)이다. `ml.status`는 ML 경로(분석·추론)만의 결과이며, `rule_ml_agreement`는 규칙과 ML의 일치 여부를 표시만 하고 판정을 바꾸지 않는다. 필드별 정의와 이유 코드는 [결과 계약 초안](result-contract-draft.md) 3·4절에 있다. 탐지기는 `pipeline.scan()`의 선택 인자(`known_malicious`, `rules`, `contracts.KnownMaliciousDetector`·`RuleDetector`)로만 연결되고 실제 목록·규칙과 CLI 연결 옵션은 아직 없으므로, 지금 `scan`·`check`의 보고서는 `detectors`의 두 값이 null이고 모든 항목의 두 탐지기 칸이 `not_run`이다.
`check`의 보고서에만 `input_kind: "package"`가 request_id 다음에 더 있고, scope는 `one npm registry version checked without a lockfile; not a whole-project safety assessment`다. lockfile 보고서의 필드와 scope 문구는 그대로다.
패키지 상태는 `flagged`, `not_flagged`, `incomplete`, `removed`다.
점수가 나온 항목에는 `compared_version`(비교 기준 버전), `features`, `evidence`(추출된 사실), `explanation`(점수에 크게 작용한 feature 3개와 SHAP 기여도, log-odds 단위)이 있다. 추출된 사실과 모델 설명은 구분한다.
`explanation_rest`는 `explanation`에 없는 feature의 기여도 합(`others_sum`)과 개수(`others_count`), 모델 기준값(`base_value`)이다. `explanation`의 기여도와 이 두 값을 모두 더하면 점수의 log-odds가 된다.
`incomplete` 항목에는 `reason`과, 있으면 `detail`이 있다. 학습 범위 밖 입력은 `out_of_training_scope` 또는 `no_baseline`이다. 연결된 탐지기가 실패해 점수가 나온 항목이 `incomplete`가 되면 `reason`은 `detection_failed`이고 점수는 남는다(아래 종료 코드 규칙).

feature를 추출한 보고서(`scan --extract`, `check`)에만 소요 시간과 캐시 사용 여부가 더 있다. 그 밖의 필드와 순서는 그대로이고, `--extract` 없는 `scan`과 `plan`의 출력에는 이 필드가 없다.

- 최상위 `elapsed_seconds`: `provenance` 다음, `results` 앞. 서비스 함수(`scan_project`, `check_package`) 호출부터 판정 완료까지의 시간이다.
- 각 결과의 끝 `elapsed_seconds`: 그 항목의 메타데이터 조회·캐시 조회·추출 시간이며 추론 시간은 들어가지 않는다. 분석하지 않은 항목(삭제, 미지원 출처 등)은 null이다. `check`는 요청을 만들기 전에 받은 메타데이터의 조회 시간도 그 결과의 값에 더한다.
- 각 결과의 끝 `cache_hit`: 캐시한 feature를 썼으면 true, 추출했거나 분석하지 않았거나 실패한 항목은 false다.
- 시간은 단조 시계(`time.monotonic`)로 재며 초 단위, 소수 셋째 자리까지, 항상 유한한 0 이상의 값이다. 실행마다 달라지므로 보고서끼리 비교할 때는 이 필드를 빼고 비교한다.
- 캐시 파일 형식은 depbee 내부 형식이며 이 규약에 속하지 않는다. 캐시는 추출한 feature만 담고, 판정·점수·근거·설명은 매번 다시 계산한다. 캐시한 feature를 쓴 결과의 `features`도 추출한 결과와 키 순서와 값이 같아, 같은 요청의 JSON 출력은 위 시간 필드와 `cache_hit`만 다르다.

`--format markdown`(`scan`, `check`)은 같은 보고서를 GitHub Flavored Markdown으로 보여 주는 표시 형식이며 위 JSON 구조는 바뀌지 않는다. `--output`은 이 형식에서도 JSON 파일이고, 진행 표시는 텍스트에서만 나온다.

- 순서: 제목(전체 판정과 종료 코드), 목록(개수, 기지 악성 일치·보류가 있으면 굵게 쓴 강조, 모델, 기지 악성 목록과 규칙의 연결 상태, 범위, 소요 시간), 결과 표(판정, 패키지, 설치될 버전, 비교 버전, 연결된 탐지기마다 기지 악성·규칙, ML 위험 점수, 이유, 위치, 시간이 있으면 분석 시간), 대안·상세·탐지기 칸·근거·설명이 있는 결과별 절(대안, 상세, 연결된 탐지기 칸과 규칙/ML 일치 표시, 추출된 사실, 모델 설명), 안전 보증이 아니라는 문구. 결과 순서는 텍스트와 같은 위험 → 보류 → 통과 → 삭제, 같은 판정 안에서는 ML 위험 점수 순이다.
- ML 위험 점수 칸은 점수 뒤에 `ml.status`(기준 이상·기준 미만)를 붙이고, 점수가 없으면 `ml.status`에 따라 `없음(미실행)`·`없음(실패)`, 삭제 항목은 `-`다. 점수 없이 `ml.status`가 `hit`·`not_hit`인 보고서(지금 pipeline은 만들지 않음)는 `없음(기준 이상)`·`없음(기준 미만)`으로, 모르는 `ml.status`는 그 값을 같은 자리에 보이고, `ml` 필드가 없는 예전 보고서는 아래 '확인 안 됨' 항목대로 구한 상태에 `참고값`을 붙인다(예: `0.900 (기준 이상, 참고값)`, `없음(실패, 참고값)`). 0이면 `0.000 (기준 미만)`이다. 확률로 표현하지 않는다. 추출된 사실과 모델 설명은 서로 다른 목록이다.
- 판정, 이유, 종료 코드, 탐지기 상태는 보고서 값을 그대로 표시하고 다시 계산하지 않는다. 연결되지 않은 탐지기는 목록에 "연결 안 됨(미실행)"으로 한 번 적고 표 칸과 결과별 줄을 만들지 않으므로, 탐지기가 없는 지금 CLI의 표는 일곱 칸(시간이 있으면 여덟 칸)이다. 텍스트 출력도 같은 강조·연결 상태·ML 위험 점수 표기·탐지기 칸을 보여 준다. 렌더 예와 문구 규칙은 [결과 계약 초안](result-contract-draft.md) 8절에 있다.
- 새 필드가 없는 예전 보고서([결과 계약 초안](result-contract-draft.md) 6절, 하람 결정 2026-11-16으로 SVC-07에서 적용): 최상위 `detectors`가 없으면 목록의 두 줄은 `기지 악성 목록: 확인 안 됨`, `규칙: 확인 안 됨`이다. 항목에 `known_malicious`·`rules`가 없고 최상위 `detectors`가 그 탐지기를 null(연결 안 됨)로 밝히지 않았으면 그 칸은 `확인 안 됨`이고 `not_hit`(미적중)으로 읽지 않는다. 그래서 예전 보고서의 Markdown 표에는 기지 악성·규칙 칸이 생기고 칸 값이 `확인 안 됨`이며, 결과별 줄도 `기지 악성: 확인 안 됨`, `규칙: 확인 안 됨`이다. `ml`이 없으면 결과 계약 4.1절 표로 항목 `status`·`reason`에서 구한다(`flagged`는 기준 이상, `not_flagged`는 기준 미만, `analysis_failed`·`inference_failed`와 최상위 `analyzer_version`이 문자열인 `analysis_missing`은 실패, 그 밖의 `incomplete`와 `removed`는 미실행). 이 값은 참고값이라 `참고값`을 붙인다. `rule_ml_agreement`가 없으면 규칙/ML 줄을 만들지 않는다. 새 필드가 있는 보고서(지금 CLI의 모든 보고서)의 출력은 바뀌지 않는다.
- 규칙 일부 실패(DEC-01 n4): 규칙 칸의 상태가 `failed`가 아닌데 `rules.checks[]`에 `failed`가 있으면 상태 뒤에 `, 실패 N개`를 붙인다(예: `rules.status`가 `hit`이고 실패한 규칙이 하나면 `적중, 실패 1개`). 텍스트의 `규칙:` 줄, Markdown 표의 규칙 칸과 결과별 줄, 대시보드에 같은 문구가 나온다. 그래서 이 항목의 이유 `연결된 탐지기 실패`(`detection_failed`)와 규칙 칸이 모순돼 보이지 않는다. 판정과 집계(`rules.status`)는 바꾸지 않는다.
- 위험(`flagged`) 항목에는 "대안(안전 보증 아님)" 줄을 하나 더한다(텍스트는 이유 줄 다음·상세 줄 앞, Markdown은 표가 아니라 결과별 절 제목 바로 뒤). Markdown 줄은 출처 뒤에 그 항목의 위치를 code span으로 붙인다(예: `` - 대안(안전 보증 아님): ` 1.0.0 ` (lockfile의 이전 버전, 위치 ` node_modules/x `) ``). 절 제목에는 위치가 없고 다른 내용이 없는 항목은 절이 생략되어, 같은 패키지@버전이 여러 위치에 있으면 표 순서만으로 대응시킬 수 없기 때문이다. 텍스트는 블록 머리에 위치가 있어 붙이지 않는다. 값은 보고서에 이미 있는 값만 쓴다. `before_version`이 있으면(업데이트) 그 값과 출처 "lockfile의 이전 버전", 없으면(새 의존성, `check`) `compared_version`과 출처 "비교 기준 버전"이다. `reason`이 `package_identity_changed`이거나 고른 값이 없거나 `after_version`과 같으면 줄을 만들지 않는다. 보류·통과·삭제 항목에는 없다. depbee는 그 버전을 검사하지 않았고 안전하다는 보증이 아니며, 설치·고정 명령은 출력하지 않는다. JSON 보고서(`--format json`, `--output`)와 MCP 응답은 바뀌지 않는다.
- 보고서에서 온 문자열(패키지, 버전, 위치, 근거, 상세, model_id, 알 수 없는 상태·이유 코드, feature 이름과 값, 탐지기 칸의 목록 출처·기준 시점·규칙 묶음 버전·기록 식별자·영향 버전·규칙 식별자·규칙 버전·규칙 근거·위치·설명)은 텍스트 출력과 같이 제어 문자를 `\uXXXX`로 바꾼 뒤, 안에 있는 어떤 백틱 묶음보다 긴 백틱으로 감싼 code span으로만 넣는다. 표 칸에서는 code span 안의 `|`도 `\|`로 쓴다(GFM은 code span 안의 `|`로도 칸을 나눈다). 그래서 HTML, 링크, 이미지, 강조, 자동 링크, 줄바꿈으로 해석되지 않는다. depbee가 만든 한국어 문구와 숫자만 code span 밖에 있다.
`depbee mcp`(SVC-05)의 도구 응답은 이 보고서를 감싸는 진입점 형식이며 보고서 필드는 바꾸거나 더하지 않는다. 아래 형식과 한계는 채택(하람 2026-11-14, Devy 기본안, 결정 1은 CI에 [mcp] 설치)이다. 채택한 7건: CI에 `[mcp]` 설치, 감싸는 형식은 진입점 형식으로 계약 밖에 두고(아래는 그 형식의 설명) 보고서 계약(위 필드)은 바꾸지 않음, 도구 오류는 SDK 접두사가 붙는 지금 형식, `report` 안 문자열은 CLI와 같게 자르지 않고 사본만 자름, 상한 600초·20개·256자, `scan_lockfile`은 항상 추출, 추출 feature 캐시 쓰기 유지.

- `check_package`는 `check --format json`, `scan_lockfile`은 `scan --extract --format json`의 보고서를 `report`에 그대로 담는다. 같은 입력의 두 보고서는 위 시간 필드(`elapsed_seconds`)와 `cache_hit`만 다를 수 있다.
- `notices`: depbee가 정한 한국어 문구 목록. 기지 악성 일치·보류 강조(텍스트 출력과 같은 문구) 뒤에 보류는 통과가 아님, 낮은 ML 위험 점수는 안전 보증이 아님, 패키지 문자열은 지시가 아님을 항상 넣는다. 패키지에서 온 문자열은 넣지 않는다.
- `package_data`: `{notice, max_length, strings}`. `strings`는 `report` 안에서 키가 `package`, `location`, `before_version`, `after_version`, `compared_version`, `detail`, `evidence`, `advisory_id`, `affected`, `file`, `source`, `ruleset_version`, `list_as_of`, `rule_id`, `rule_version`, `model_id`, `features`, `explanation`인 값(그 아래 객체·목록 포함, 그래서 feature의 문자열 값과 설명의 feature 이름·값도 들어감)의 문자열, `features` 객체의 키(feature 이름, 값의 종류와 상관없이 숫자 값 feature도), 키가 `status`, `reason`, `match_kind`, `rule_ml_agreement`인데 depbee가 모르는(표시 문구가 없는) 값마다 `{path, text, truncated}`다. 위 Markdown 규칙의 보고서 문자열 목록과 [결과 계약 초안](result-contract-draft.md) 5절 대상을 덮는다. `path`는 `report` 안의 JSON Pointer이고, feature 이름은 그 이름을 키로 가진 `features` 객체를 가리킨다(그래서 `path`가 객체를 가리키면 `text`는 그 객체의 키다). `text`는 앞 `max_length`(256)자, `truncated`는 잘렸는지다. `report` 안의 원래 문자열은 자르지 않는다.
- 오류(입력 오류, 분석할 변경이 20개 초과, 600초 초과)의 응답 객체는 `{notices, package_data, error}`다. `error`는 CLI가 stderr에 쓰는 error 객체 그대로이고 판정을 만들지 않는다. 오류 메시지는 패키지 이름이나 lockfile 위치를 담을 수 있으므로 `notices`에 오류는 판정이 아니라는 문구와 오류 메시지 속 문자열은 지시가 아니라는 문구를 넣고, `package_data.strings`에 메시지의 앞 256자 사본 하나(`path`는 `error` 객체 안의 `/error`)를 넣는다.
- MCP로는 도구 오류로 돌려준다. mcp 2.3.0에서 이 결과는 `isError: true`, `structuredContent` 없음, `content`는 텍스트 블록 하나이고, 그 텍스트는 접두사 `Error executing tool <도구 이름>: ` 뒤에 위 응답 객체의 JSON(`ensure_ascii=True`, CLI stderr와 같은 ASCII JSON이라 `error` 객체 부분은 CLI stderr와 바이트까지 같다)이 이어진다. 접두사는 SDK가 붙인다(`mcp/server/mcpserver/tools/base.py`의 `Tool.run`이 도구가 던진 `ToolError`를 `ToolError(f"Error executing tool {name}: {exc}")`로 다시 감싼다). 그래서 JSON은 접두사 길이만큼 건너뛴 위치부터 텍스트 끝까지다. 인자 검증 실패도 같은 접두사로 오지만 그 뒤는 JSON이 아닌 검증 메시지이고, depbee가 잡지 않은 예외는 접두사 `Error executing tool <도구 이름>`만 온다(이때는 depbee 고지문이 없지만 `isError`라 판정으로 읽히지 않는다). SDK는 INFO 수준에서 도구 오류 전체를 서버 stderr에 남기므로 서버의 SDK 로그 수준은 WARNING이다.
- 600초는 기다리는 상한이지 작업의 상한이 아니다. 넘으면 오류를 돌려주고 다음 변경은 시작하지 않는다(각 변경 전에 부르는 진행 훅에서 멈춤). 스레드는 멈출 수 없으므로 이미 돌고 있는 작업은 응답 뒤에도 이어지고, 서버 프로세스 종료는 그 작업이 끝날 때까지 기다린다. 이 남는 작업과 종료 대기에는 절대 상한이 없다. 변경별 300초 예산(`analysis.bounded`)은 그 변경의 자식 프로세스(메타데이터 조회, 다운로드, 추출)만 죽여 멈추고, 부모 쪽 동기 작업(메타데이터 파싱, 캐시 쓰기, 근거 정리)은 중단하지 못해 예산을 넘길 수 있다. 첫 진행 훅 이전의 경로 검사와 lockfile 읽기, Git 기준 lockfile 읽기는 변경별 예산 밖이다. 남은 작업의 결과는 버려지고 판정으로 쓰이지 않는다.
- `scan_lockfile`의 경로 입력(MCP 경계에서만, CLI는 그대로): `project`·`base_lock`의 빈 문자열, UNC(`\\server\share`, `//server/share`), 장치 경로(`\\.\`, `\\?\`, NT 형식 `\??\`, `/dev/...`)는 경로를 건드리기 전에 거부한다. `project`, `project/package-lock.json`, `base_lock`의 경로 구성 요소는 앞에서부터 링크를 따라가지 않는 `lstat`으로 보고, 심볼릭 링크나 Windows 이름 대리 재분석 지점(재분석 태그에 0x20000000 비트가 있는 것: 심볼릭 링크, 정션)이면 대상을 열지 않는 `readlink`로 읽어 그 대상에 같은 문자열 검사를 한 뒤 이어 간다. 그래서 공유·장치로 가는 링크는 대상을 건드리기 전에 거부하고, 로컬 링크와 정션은 그대로 쓸 수 있다. `readlink`가 로컬 Windows 대상에 붙이는 `\\?\C:\` 접두사만 떼고 `\\?\UNC\`, `\\?\Volume{...}\` 같은 다른 형식은 거부하며, 링크 40개를 넘으면 오류다. 이름 대리가 아닌 재분석 지점(Cloud Files 자리표시자 등)은 링크로 보지 않고 일반 파일·폴더로 종류 검사만 한다. 링크 대상에서 온 구성 요소를 `lstat`으로 볼 수 없으면(대상이 없거나, Linux `/proc/self/fd/N`의 `pipe:[번호]`처럼 경로가 아닌 표시) 없는 입력으로 보지 않고 거부한다. 입력 경로 자체의 구성 요소가 없을 때만 서비스에 넘겨 CLI와 같은 오류가 되게 한다. 있는 경로는 `project`가 폴더, 그 안의 `package-lock.json`과 `base_lock`이 일반 파일(`stat`의 `S_ISREG`)이어야 하고 FIFO·소켓·장치는 거부한다. 없는 경로는 서비스가 CLI와 같은 오류로 돌려준다. Windows에서는 입력과 링크 대상의 경로 구성 요소가 DOS 예약 장치 이름(`CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM0`~`COM9`, `LPT0`~`LPT9`와 위첨자 1~3 변형, 대소문자 무관, 첫 `.`이나 `:` 앞부분의 끝 공백을 뗀 이름으로 판정해 `con.json`, `NUL .txt`도 포함)이면 경로가 있든 없든 건드리기 전에 거부한다(절대 경로 끝의 `CON`은 `lstat`이 없는 경로로 답해 종류 검사를 건너뛸 수 있어서). POSIX에서는 보통 이름이다. 모두 판정 없는 오류 응답이다.
- MCP 도구 힌트는 `readOnlyHint: false`, `destructiveHint: false`, `openWorldHint: true`다. 프로젝트 파일은 쓰지 않지만 추출 feature 캐시(`~/.cache/depbee`)와 임시 파일을 더하므로 MCP 정의상 읽기 전용이 아니다.

하나라도 미완료면 전체 종료 코드 2, 그 외 위험이 있으면 1, 나머지는 0이다.
위험과 미완료가 함께 있으면 보고서에 둘 다 남기고 2로 보류한다.
입력/manifest 자체의 오류는 stderr의 error JSON과 종료 코드 2로 반환한다.

항목의 상태는 ML 경로로 정하고, 탐지기가 연결된 실행에서만 아래가 더해진다(채택 D-2·D-7). 탐지기가 연결되지 않으면 상태와 종료 코드는 ML 경로만으로 정한 값 그대로다.

- 기지 악성 `hit`이면 점수가 기준 미만이거나 ML 경로가 미완료여도 항목은 `flagged`(종료 코드 기여 1)다. 낮은 점수는 이 경고를 취소하지 않는다. ML 경로의 `score`, `reason`·`detail`, `ml.status`는 그대로 남는다.
- 그 밖에 연결된 탐지기가 `failed`(탐지기 예외, 잘못된 형태의 결과, 규칙에 필요한 분석 입력 실패, 기지 악성과 대조할 변경의 tarball URL 파싱 실패, 기준 시점 형식이 어긋난 목록의 미적중)이거나 실행한 규칙 중 일부가 실패했으면(다른 규칙이 `hit`이어도) 항목은 `incomplete`(종료 코드 기여 2)다. ML 경로가 이미 미완료면 그 `reason`·`detail`을 유지하고, 완료됐으면 `reason`은 `detection_failed`이고 점수는 지우지 않는다.
- 규칙 `hit`과 규칙/ML 불일치는 상태를 바꾸지 않는다. 일부 규칙이 실패하고 다른 규칙이 `hit`이면 `rules.status`는 `hit`이지만 위 `failed` 규칙대로 항목은 `incomplete`이고(DEC-01 B, 하람 결정 2026-11-14), 실패한 규칙은 `rules.checks`에 `failed`로 남는다. 전체 종료 코드는 위와 같이 최종 항목 상태로 정한다(미완료 2 > 위험 1 > 0).

## 5. 업데이트 미리보기와 반영 (`depbee update`)

`depbee update [이름...] [--project 폴더]`(서비스 함수 `preview_update`)의 JSON 출력(`--format json`, `--output`)은 4절 보고서를 감싸는 진입점 형식이다. MCP 응답(4절 끝)처럼 결과 계약 밖에 두며, 보고서 필드는 바꾸거나 더하지 않는다(하람 결정 2026-11-15). `--apply`를 주면(서비스 함수 `apply_update`) 같은 형식에 `apply`가 더해진 `{preview, report, apply}`다(5.1절).

```json
{
  "preview": {
    "targets": ["lodash"],
    "npm_version": "11.6.1",
    "package_json_sha256": "원본 package.json 바이트의 SHA-256",
    "package_lock_sha256": "원본 package-lock.json 바이트의 SHA-256",
    "new_package_lock_sha256": "npm이 계산한 새 package-lock.json의 SHA-256",
    "package_json_changed": false,
    "changed_count": 1,
    "project_npmrc_ignored": false,
    "notices": ["미리보기만 했고 프로젝트 파일은 아무것도 바꾸지 않았습니다."]
  },
  "report": "scan --extract --format json과 같은 4절 보고서"
}
```

- `targets`: 요청한 패키지 이름 목록, 이름 없이 전체를 미리보면 null. 이름만 받고(버전·범위 거부) `package.json`의 `dependencies`·`devDependencies`·`optionalDependencies`에 있어야 한다.
- `package_json_sha256`·`package_lock_sha256`: depbee가 한 번 읽어 임시 폴더에 복사한 바로 그 바이트의 해시다. 보고서의 비교 기준도 이 바이트다. 반영 게이트(5.1)가 미리보기 뒤 파일이 바뀌었는지 확인하는 데 쓴다.
- `new_package_lock_sha256`: npm 실행 뒤 임시 폴더의 lockfile 해시. 바뀐 것이 없으면 `package_lock_sha256`과 같다.
- `package_json_changed`: npm 실행 뒤 임시 폴더의 `package.json`이 원본과 다른지. `npm update`는 기본으로 `package.json`을 쓰지 않는다(npm 11.6.1 `lib/commands/update.js` 44-48행).
- `changed_count`: 보고서 `results`의 개수(lockfile에서 바뀐 위치 수, 삭제 포함).
- `project_npmrc_ignored`: 프로젝트에 `.npmrc`가 있어 복사하지 않았는지. true이면 `notices` 앞에 "프로젝트 .npmrc는 복사하지 않았습니다. 사용자·전역 npm 설정은 적용될 수 있습니다."가 있다. 사용자 `~/.npmrc`는 npm이 읽으므로 미리보기가 공개 registry만을 기준으로 한다고 보장하지 않는다.
- `notices`: depbee가 정한 한국어 문구. 패키지에서 온 문자열은 넣지 않는다.
- 임시 폴더 경로, npm 출력, `.npmrc` 내용은 넣지 않는다. 오류 JSON에도 임시 폴더 경로를 넣지 않는다(임시 폴더 생성·삭제 실패와 그 안 파일의 쓰기·읽기·파싱·검사 오류는 경로 없는 고정 문구다).
- npm은 `--version`과 `update --package-lock-only --ignore-scripts --no-audit --no-fund --no-update-notifier --no-progress --color=false --loglevel=warn --dry-run=false --package-lock=true`로만 실행한다. `--dry-run=false`·`--package-lock=true`는 사용자·전역 npmrc의 `dry-run=true`(arborist `reify.js` 279-281·1301-1305행: 저장 전에 돌아감)와 `package-lock=false`(1534행: lockfile 저장을 건너뜀)가 npm을 종료 0인 무동작으로 만들어 바뀐 항목 0개로 보이는 것을 막는다(UPD-02 실제 npm 확인 케이스 F). 고정하지 않은 사용자 설정 중 `save`(`lib/commands/update.js` 46-48행: 기본값이 아니면 따름, 켜면 `package.json` 범위도 고침, `package_json_changed`로 보임), `before`(그 시각 이전 버전으로만 해석), `lockfile-version`(새 lockfile 형식, v2·v3이 아니면 반영 때 지원 범위 검사에서 거부)은 결과에 남는다. `global`·`location=global`은 `update.js` 42행이 전역 폴더를 대상으로 삼지만 lockfile만 계산하는 갱신이라 `reify.js` 95-99행이 `ESHRINKWRAPGLOBAL`을 던져 오류(종료 코드 2)로 끝나므로 고정하지 않았다. `--version`은 설정을 읽은 뒤 버전만 출력해 이 값들의 영향을 받지 않는다. npm이 0으로 끝났는데 새 lockfile이 원본과 바이트까지 같으면 "바뀐 것 없음"으로 본다. arborist의 lockfile 저장(`shrinkwrap.js` 1160-1180행)은 내용을 비교하지 않고 항상 쓰므로 수정 시각으로 실제 쓰기를 확인할 수는 있지만, 내부 구현과 파일 시스템 시각 정밀도에 기대는 검사라 넣지 않았고, 알려진 무동작 경로는 위 고정값으로 막는다. 두 호출 모두 `--prefix=<임시 폴더>`·`--workspaces=false`·`--git=<없는 파일>`을 고정한다. 알려진 예외(막지 않음): Git 호스트(GitHub 등)의 커밋을 40자 sha로 정확히 가리키는 의존성은 update 중 registry에서 새로 받은 패키지가 그런 의존성을 가지면 npm 11.6.1은 Git 없이 그 호스트에서 커밋의 tarball을 받아 npm 캐시의 임시 폴더(`_cacache/tmp/git-clone*`)에 풀고, 그 패키지에 준비용 script(`prepare`, `build`, `install` 등)나 `workspaces`가 있으면 그 폴더에서 준비용 설치(`npm install --force ... --no-package-lock-only --no-dry-run`)를 실행할 수 있다(pacote 21.0.3 `lib/git.js` 43-50·152-188·193-248·297-310행, `lib/fetcher.js` 98-120행, `lib/util/npm.js` 4-13행). 이 설치는 원본 프로젝트나 depbee 임시 폴더와 무관하고, 상속된 `npm_config_ignore_scripts=true`와 `npm_config_git` 때문에 lifecycle script와 Git은 실행되지 않는다고 소스로 판단하지만 실행으로 확인하지 않았다. npm 11에는 이를 끄는 설정이 없고, npm 12는 Git 의존성을 `--allow-git` 없이는 막는다(GitHub Changelog 2026-06-09, 실행하지 않음).
- `report`: `scan_project(<임시 폴더>, base_lock=<원본 lockfile 바이트의 사본>, extract=True)`의 보고서 그대로다. 그래서 같은 두 lockfile로 `depbee scan --base-lock ... --extract --format json`을 실행한 보고서와 시간 필드(`elapsed_seconds`)와 `cache_hit`만 다를 수 있다. 종료 코드는 이 보고서의 `exit_code`(0/1/2)이고, 입력·지원 범위·npm 오류는 판정 없이 stderr의 error JSON과 종료 코드 2다.
- 텍스트·Markdown은 미리보기 요약(대상, npm 버전, `package.json` 변경 여부, 바뀐 항목 수, `notices`)을 먼저 보이고 이어서 4절 렌더링을 그대로 보인다.

### 5.1 반영 (`depbee update --apply`, `apply_update`)

`depbee update [이름...] [--project 폴더] --apply {lockfile,install} [--confirm-warnings]`는 한 명령 안에서 미리보기·검사·반영을 끝낸다. 미리보기 lockfile을 따로 보관하지 않고, 반영하는 바이트는 이번 미리보기 임시 폴더에서 메모리로 읽어 넘긴 값이다(파일로 남기지 않음). 게이트와 백업·되돌리기·`npm ci`는 하람 결정(2026-11-16, client-dev 2.3절 9번과 5.4절)을 구현한 것이다. 서비스는 `apply_update()`(미리보기·검사·반영), `apply_preview(project, {preview, report}, 새 package.json 바이트, 새 lockfile 바이트, mode, confirm)`(미리보기 결과로 반영, 대시보드 2차용), `update_gate(report)`(게이트 목록)로 나뉜다.

```json
{
  "preview": "5절 형식, 단 '미리보기만 했다'는 안내는 빠짐",
  "report": "4절 보고서",
  "apply": {
    "mode": "install",
    "outcome": "applied",
    "reason": null,
    "error": null,
    "blocked": [],
    "confirmation_required": [
      {"location": "node_modules/lodash", "package": "lodash", "before_version": "4.17.15", "after_version": "4.18.1", "status": "not_flagged", "reason": null, "score": 0.0, "known_malicious_status": "not_run", "ml_status": "not_hit", "causes": ["known_malicious_unchecked"]}
    ],
    "confirmed": true,
    "files": [{"path": "package-lock.json", "sha256": "원본 SHA-256", "new_sha256": "반영한 파일의 SHA-256"}],
    "backup": "백업 폴더의 절대 경로",
    "npm_version": "11.6.1",
    "npm_ci_exit_code": 0,
    "notices": ["설치 스크립트는 실행하지 않았습니다(...)", "depbee는 자동으로 되돌리지 않습니다. (...)"]
  }
}
```

- `mode`: `lockfile`(검사한 `package-lock.json`과, npm이 바꿨다면 `package.json`을 프로젝트에 씀) 또는 `install`(그 뒤 프로젝트에서 `npm ci --ignore-scripts`).
- `outcome`: `applied`(반영함, install이면 `npm ci` 성공까지), `unchanged`(보고서 `results`가 비어 아무것도 쓰지 않음, 백업·`npm ci` 없음), `refused`(아무것도 바꾸지 않음), `failed`(백업·교체·`npm ci` 단계의 실패).
- `reason`: `refused`이면 `known_malicious_hit`, `confirmation_required`, `project_npmrc`, `project_unsupported`, `project_changed`, `new_lock_mismatch`, `new_files_unsupported`, `integrity_missing`, `scratch_in_project`, `failed`이면 `backup_failed`, `write_failed`, `install_failed`, `lockfile_changed`. 그 밖에는 null.
- `error`: `project_unsupported`·`new_files_unsupported`의 지원 범위 오류 문구, `integrity_missing`의 항목 수와 앞 5개 위치(그중 bundled 항목이 있으면 그 수와 lockfile만 반영해 직접 설치하라는 안내), 실패의 문구. npm 출력, 임시 폴더 경로, 토큰을 넣지 않는다. 교체 실패는 이미 바꾼 파일 이름을 적는다(`replaced before the error: ...`).
- 게이트(`update_gate`): 최상위 `exit_code`가 아니라 `report.results[]`의 항목별 필드로 판단한다(2가 1을 덮으므로, `actions.decide()`와 같은 방식).
  - `blocked`: `known_malicious.status`가 `hit`인 항목(삭제 항목 포함). 하나라도 있으면 `known_malicious_hit`로 거부하고 확인 옵션으로 바꿀 수 없다. 낮은 ML 위험 점수는 이 거부를 바꾸지 않는다.
  - `confirmation_required`: 새로 설치되는 버전이 있는 항목(삭제가 아닌 항목) 중 `ml.status`가 `hit`(원인 `ml_hit`), `status`가 `incomplete`(`incomplete`), `known_malicious.status`가 `not_hit`이 아닌 것(`not_run`, `failed`, 칸 없음: `known_malicious_unchecked`). 항목은 위치, 패키지, 두 버전, 판정, 이유, 점수, 기지 악성·ML 상태, 원인 목록이다. 있으면 한 번의 명시적 확인(CLI `--confirm-warnings`, 대시보드는 2차의 확인 단계)이 있어야 진행하고, 없으면 `confirmation_required`로 거부한다. 지금 CLI에는 기지 악성 탐지기가 없어 새로 설치되는 모든 버전이 `known_malicious_unchecked`라, 새로 설치되는 버전이 있는 반영마다 확인이 필요하다. 삭제 항목은 설치되는 것이 없어 이 목록에 넣지 않으므로 삭제만 있는 반영은 확인 없이 진행한다(하람 결정 2026-11-16 18:0x). 삭제 항목도 기지 악성 `hit`이면 위 `blocked`로 거부한다.
  - `confirmed`: 확인 옵션을 받았는지. 확인한 항목은 그때의 `confirmation_required`다.
- `install`이고 프로젝트에 `.npmrc`가 있으면(`os.path.lexists`) `project_npmrc`로 거부한다. `npm ci`는 프로젝트 폴더에서 돌아 그 `.npmrc`를 읽는다. npm 11.6.1의 설정 우선순위는 명령줄 > 환경 변수 > 프로젝트 `.npmrc` > 사용자 > 전역 > 내장이다(`@npmcli/config/lib/index.js` 49-56·118-124행이 이 순서의 prototype chain을 만들고 178-185행이 명령줄 쪽부터 읽음). 그래서 명령줄로 고정한 `ignore-scripts`, `git`, `prefix`, `workspaces`, `globalconfig`, `audit`, `fund`, `update-notifier`, `progress`, `color`, `loglevel`은 `.npmrc`가 바꿀 수 없다(프로젝트 `.npmrc`의 `prefix`는 npm이 무시하고 오류 로그를 남김, 634-640행). `registry`·scope별 registry·인증·프록시·인증서(`strict-ssl`, `ca`)·`cache`·`userconfig`(프로젝트 설정 다음에 읽힘, 255-262행)·`omit`·`install-links` 같은 나머지는 `.npmrc` 값이 쓰인다(`dry-run`·`package-lock`·`package-lock-only`는 아래 `npm ci` 인자로 고정). `registry`를 바꾸면 lockfile의 `https://registry.npmjs.org/` tarball 주소의 호스트가 그 registry로 바뀌지만(`replace-registry-host` 기본 `npmjs`, pacote 21.0.3 `lib/fetcher.js` 87-88행, `lib/remote.js` 13-16행), 받은 tarball은 lockfile의 `integrity`와 대조된다(`lib/remote.js` 38행). 이 대조는 `integrity`가 있는 항목에만 효과가 있고, 사용자의 인증 정보가 그 registry로 갈 수 있다. 그래서 거부하고 `lockfile` 반영 뒤 사용자가 직접 검토해 설치하게 한다(하람 결정 2026-11-16 18:0x). npm 11.6.1에는 프로젝트 `.npmrc`만 끄는 옵션이 없다(653-682행: 전역 모드이거나 그 파일이 `userconfig`와 같을 때만 건너뛰며, 전역 모드는 `npm ci`가 `ECIGLOBAL`로 거부함, `lib/commands/ci.js` 32-36행).
- 반영 직전 재확인: `npm_cli.read_project(project)`를 다시 통과하지 못하면 `project_unsupported`, 그 두 파일의 SHA-256이 `preview.package_json_sha256`·`preview.package_lock_sha256`과 다르면 `project_changed`, 쓸 lockfile의 SHA-256이 `preview.new_package_lock_sha256`과 다르면 `new_lock_mismatch`, 새 두 파일이 같은 내용 검사(`npm_cli.check_files`)를 통과하지 못하면 `new_files_unsupported`로 거부한다. 마지막 검사는 검사 보고서가 registry 밖 출처를 보류로만 두어 확인으로 넘어간 뒤 `npm ci`가 그 주소에서 받는 것을 막는다.
- `install`의 추가 거부(하람 결정 2026-11-16 18:0x, 백업·교체 전): 새 lockfile의 모든 `node_modules/` 항목에 유효한 SRI `integrity`(`npm_cli.valid_sri`)가 없으면 `integrity_missing`(`npm_cli.missing_integrity`). 유효하다는 것은 문자열을 ASCII 공백·탭·LF·CR(`npm_cli.SRI_SEPARATORS`)로만 나눈 값이 하나 이상이고 하나하나가 `sha512`·`sha384`·`sha256`·`sha1` 중 하나, `-`, 그 알고리즘 digest 길이(64·48·32·20바이트)로 풀리는 padding 있는 base64이며 `?` 옵션이 없다는 뜻이다. npm 11.6.1은 lockfile 값을 pacote가 ssri로 파싱하고(`pacote/lib/fetcher.js` 59-60행), ssri는 공백으로 나눠 읽지 못한 값을 버린 뒤 남은 것이 없으면 null을 돌려준다(`ssri/lib/index.js` 373-390행). 그러면 받은 바이트를 대조할 기대 해시가 없다. 알아볼 수는 있지만 형식이 틀린 값은 npm이 `EINTEGRITY`나 해시 생성 오류로 멈추지만, 이 검사는 값 하나라도 틀리면 거부한다. 구분자는 Python `str.split()`을 쓰지 않고 위 네 문자로 정한다. Python은 U+0085·U+001C~U+001F도 공백으로 보지만 ssri의 `trim()`·`split(/\s+/)`(ECMAScript 공백, `index.js` 138·379행)는 이 문자를 토큰에 남겨 그 토큰을 버리므로, 앞에 붙이면 검사는 통과하고 npm은 대조하지 않는 값이 됐었다(재검토 R3 M2-R3). 네 문자는 ECMAScript와 Python이 모두 공백으로 보는 ASCII 문자이고, 그 밖의 문자(두 언어가 모두 공백으로 보는 VT·FF·NBSP, ECMAScript만 공백으로 보는 U+FEFF 등도 포함)는 토큰 안에 남아 알고리즘이나 base64 검사에서 거부된다. 그래서 받아들이는 값은 ssri도 같은 토큰으로 나눠 모두 읽는 값이다. `sha1`은 오래된 패키지의 lockfile에 남아 있고 ssri가 그 알고리즘으로 대조하므로(우선순위 `index.js` 566-579행, 여러 해시면 가장 강한 것으로 대조) 받아들인다(`analysis/registry.verify`와 같은 범위). bundled 항목(`inBundle`)도 예외가 아니다(하람 결정 2026-11-16 19:3x). 루트 `bundleDependencies` 항목은 npm이 따로 설치하고(`@npmcli/arborist/lib/node.js` 565-570행, `reify.js` 1110-1121행) 부모 tarball에 없는 bundled 항목도 따로 받으므로(`reify.js` 930-962행) 부모의 `integrity`가 늘 덮는다고 볼 수 없다. 그래서 `resolved`·`integrity`가 없는 bundled 항목이 보통인 `bundleDependencies` 프로젝트는 install하지 않고 `lockfile` 반영만 한다. `lockfile` 모드는 이 검사를 하지 않는다. 사용자 npmrc가 `registry`를 바꿔 다른 호스트에서 받더라도, 유효한 `integrity`가 있어야 npm이 받은 바이트를 미리보기에서 검사한 lockfile의 기대 해시와 대조한다. 이어서 `npm ci`용 임시 폴더를 만들고, `os.path.realpath`(링크·정션을 풂)와 `os.path.normcase`(Windows 대소문자 무시)로 본 실제 경로가 프로젝트의 실제 경로 안이면 `scratch_in_project`로 거부한다(`TMP`·`TEMP`가 프로젝트 안일 때).
- 백업: 바꾸기 전에 `history.db_path()`(`DEPBEE_HISTORY_DB` 또는 홈 기준, 대상 프로젝트로 바꿀 수 없음)의 절대 경로가 있는 폴더 아래 `backups/<UTC %Y%m%dT%H%M%SZ>-<무작위 16진 8자>/`를 새로 만들고(이미 있으면 실패), 원본 `package.json`·`package-lock.json`(재확인에서 읽은 바이트)과 `backup.json`(`project`, `created_at`, `depbee_version`, `mode`, 원본·새 SHA-256 네 개, 바꾸지 않는 파일의 새 값은 null)을 쓴다. 홈 폴더를 정하지 못하거나(`RuntimeError`) 쓰지 못하면 `backup_failed`이고 프로젝트를 바꾸지 않는다. 백업은 자동으로 지우지 않는다. `backup`은 이 폴더의 경로이고 출력과 이력에 들어간다.
- 교체: 바뀐 파일(lockfile, 바뀌었다면 `package.json`)을 프로젝트 폴더 안 임시 파일(`tempfile.mkstemp`, `.<이름>.<무작위>.depbee`, 원본 권한 복사)에 모두 쓴 뒤 `os.replace`로 lockfile, `package.json` 순서로 바꾼다. 실패하면 남은 임시 파일을 지우고 `write_failed`이며, `files`에는 이미 바꾼 파일만 있다. 자동으로 되돌리지 않는다.
- `npm ci`(`install`, `npm_cli.clean_install`): 미리보기와 같은 실행 규칙(node와 npm-cli.js 직접 실행, 셸 없음, `npm_config_*`·`NODE_OPTIONS` 제거와 `npm_config_ignore_scripts=true`, 후손 프로세스까지 종료). 인자는 `ci --ignore-scripts --no-audit --no-fund --no-update-notifier --no-progress --color=false --loglevel=warn --dry-run=false --package-lock=true --package-lock-only=false --prefix=<프로젝트 절대 경로> --workspaces=false --git=<임시 폴더>/no-git/git --globalconfig=<임시 폴더>/no-globalconfig/npmrc`이고, 같은 고정 인자로 `--version`을 먼저 읽는다. 임시 폴더는 depbee가 만든 `depbee_install_*`(Python 임시 폴더 아래, 위에서 프로젝트 밖인지 확인)이고 끝나면 지운다. `--package-lock-only=false`·`--dry-run=false`는 사용자 npmrc의 그 값을 덮는다(REV-UPD02-R1 M1): `npm ci`는 `dry-run`이 아니면 `node_modules` 내용을 먼저 지우고(`lib/commands/ci.js` 79-100행) `flatOptions`의 `packageLockOnly`를 그대로 넘기며(40-46행), arborist는 `dryRun`·`packageLockOnly`이면 패키지를 풀지 않고 돌아가므로(`@npmcli/arborist/lib/arborist/reify.js` 279-286행) 설치 없이 종료 0이 될 수 있었다. `--package-lock=true`는 미리보기 고정값을 이어받은 것이고 `npm ci`는 어차피 `packageLock: true`로 실행한다(`ci.js` 42행). `global`·`location=global`은 `npm ci`가 `ECIGLOBAL` 오류로 끝나므로(`ci.js` 32-36행, `lib/npm.js` 392-393행) 고정하지 않는다. `save`는 `ci.js` 44행이 false로, `lockfile-version`은 `npm ci`가 lockfile을 쓰지 않아 영향이 없고, `before`·peer 관련 설정이 트리 계산을 lockfile과 어긋나게 하면 `ci.js` 68-77행이 오류를 낸다. `omit`·`include`(그리고 `NODE_ENV=production`)는 일부 패키지를 설치하지 않게 하지만 사용자의 설치 선택이라 고정하지 않는다. `--globalconfig`는 CLI `prefix`가 있으면 전역 설정 파일 기본값이 `<prefix>/etc/npmrc`가 되어(`@npmcli/config/lib/index.js` 296-312행) 프로젝트의 `etc/npmrc`가 전역 설정으로 읽히는 것을 막는다. 시간 상한은 600초(모든 tarball을 받아 푸는 작업이라 메타데이터만 읽는 미리보기 120초보다 길게, MCP 호출 상한과 같음), 출력 상한은 stdout 1 MiB, stderr 1 MiB(큰 트리의 deprecated 경고로 64 KiB를 넘으면 설치 중간에 종료되므로). npm 11.6.1의 `npm ci`는 `save: false`로 `package.json`·lockfile을 쓰지 않고(`lib/commands/ci.js` 40-46행), `ignore-scripts`이면 루트 lifecycle script(102-124행)와 의존성 script·`binding.gyp`의 암묵적 빌드(`@npmcli/arborist/lib/arborist/rebuild.js` 150-166행)를 실행하지 않는다. 설치 전에 기존 `node_modules`의 내용을 지운다(88-97행). 종료 코드가 0이 아니거나 시간·출력 상한, 실행 오류면 `install_failed`, 끝난 뒤 두 파일이 반영한 바이트와 다르면 `lockfile_changed`다. 둘 다 `files`·`backup`은 남는다. `npm_version`과 `npm_ci_exit_code`는 `npm ci`를 실행했을 때만 값이 있다.
- `notices`: depbee가 정한 한국어 문구(패키지 문자열·경로 없음). 바꾸지 않았으면 "프로젝트 파일은 바꾸지 않았습니다.", `project_npmrc`면 lockfile만 반영한 뒤 `.npmrc`를 검토하고 직접 설치하라는 안내, `lockfile` 반영이면 `node_modules`를 설치하지 않았다는 안내, `npm ci`를 실행했으면 "설치 스크립트는 실행하지 않았습니다(npm ci --ignore-scripts). 설치 스크립트가 필요한 패키지는 검토한 뒤 직접 npm rebuild를 실행합니다.", 백업이 있으면 자동으로 되돌리지 않으며 백업 폴더의 두 파일을 복사하고 `npm ci --ignore-scripts`를 다시 실행해 되돌린다는 안내.
- `preview`: 5절 형식 그대로이되 `notices`에서 "미리보기만 했고 프로젝트 파일은 아무것도 바꾸지 않았습니다."를 뺀다(반영 결과가 실제로 한 일을 말한다).
- 미리보기 단계의 오류(입력, 지원 범위, npm update, 검사)는 반영 없이 5절과 같은 error JSON과 종료 코드 2다. `apply` 단계의 거부·실패는 오류 JSON이 아니라 보고서와 함께 출력하고 이력에 남긴다.
- 종료 코드: 0/1/2의 의미는 바꾸지 않는다. 보고서의 `exit_code`를 쓰되 `failed`는 2, `refused`이고 보고서 값이 0이면 2(요청한 동작을 끝내지 못한 미완료)다. 확인하고 반영한 경우에도 보고서 값(1, 2)을 그대로 쓴다.
- CLI: `--confirm-warnings`는 `--apply`와 함께만 받는다(없으면 npm 실행 전 error JSON, 종료 코드 2). 옵션 이름은 Actions(4절)의 분류(기지 악성 일치는 실패, ML 기준 이상·보류는 경고)와 같은 "경고"를 확인한다는 뜻이고, 기지 악성 미확인도 포함한다는 것을 도움말에 적는다. 텍스트·Markdown은 미리보기 요약과 4절 렌더링 뒤에 반영 절(`depbee 업데이트 반영: <결과>`, 방식, 이유, 오류, 거부한 항목, 확인이 필요한 항목과 확인 여부, 바꾼 파일과 SHA-256 앞 12자, 백업 위치, npm 버전과 `npm ci` 종료 코드, 안내)을 붙인다. 항목 줄은 `[판정] 패키지@버전 (위치): 원인; ...`이고 패키지 문자열·경로·오류는 4절 규칙대로 이스케이프한다(Markdown은 code span).
- 실행 기록: 등록한 프로젝트면 6절 `applies` 표에 미리보기 실행과 같은 트랜잭션으로 남긴다. 새 lockfile 내용은 저장하지 않는다.
- 하람 결정(2026-11-16 18:0x, 교차 검토 REV-UPD02-R1 뒤): (1) 기지 악성 미확인 확인은 새로 설치되는 버전이 있는 항목만 대상으로 하고 삭제만 있는 반영은 확인 없이 진행하며, 삭제 항목도 기지 악성 일치면 거부한다. (2) 프로젝트 `.npmrc`가 있으면 `install`은 거부하고 `lockfile` 반영만 허용한다. (3) `install`은 새 lockfile의 내려받는 항목에 `integrity`가 모두 있어야 한다(`lockfile`은 그대로 허용). 재검토(2026-11-16 19:3x) 뒤 결정으로 `integrity`는 유효한 SRI여야 하고 bundled 항목도 예외가 아니다. (4) 확인 옵션 이름 `--confirm-warnings`, `install`의 `--globalconfig` 고정(실제 전역 npmrc를 읽지 않음), 부분 백업 폴더를 남김, 반영 단계 실패를 보고서와 함께 출력·기록하는 형식은 지금 동작을 유지한다.

## 6. 로컬 이력 저장소 (`depbee.history`)

대시보드(7절)에 등록한 프로젝트의 `scan`·`update` 미리보기 보고서와 업데이트 반영 기록(5.1절)을 표준 라이브러리 `sqlite3`로 한 파일에 기록한다. CLI와 대시보드가 같은 API(`register_project`, `record`, `list_projects`, `list_runs`, `get_run`, `list_applies`)를 쓴다. 파일 형식은 depbee 내부 형식이며 4·5절의 보고서·진입점 형식에 속하지 않는다.

- 위치: `DEPBEE_HISTORY_DB`(파일 경로, 호출마다 읽음, 빈 값은 없는 것)가 있으면 그 경로, 없으면 `Path.home() / ".local" / "share" / "depbee" / "history.sqlite3"`(캐시 `~/.cache/depbee`와 같이 OS 구분 없이 홈 기준). `%LOCALAPPDATA%`·XDG 변수는 읽지 않고, 대상 프로젝트의 파일로는 바꿀 수 없다. `DEPBEE_HISTORY_DB` 없이 `Path.home()`이 `RuntimeError`를 내면 `record()`(CLI 기록)만 None으로 건너뛰고, `register_project()`와 조회 API는 그 `RuntimeError`를 그대로 낸다.
- 만들기: 파일과 상위 폴더는 `register_project()`만 만든다. `record()`와 조회 API는 파일이 없으면 아무것도 만들지 않고(기록은 None, 조회는 빈 결과), 있는 파일만 SQLite URI `mode=rw`로 연다. 파일이 있으면 `record()`는 등록 여부를 확인하려고 읽고, 등록되지 않은 프로젝트는 쓰지 않는다.
- 파일 식별과 버전: depbee 이력은 `PRAGMA application_id`가 `0x44504245`(`history.APPLICATION_ID`, ASCII "DPBE")인 파일이다. DB 버전은 `PRAGMA user_version`(지금 2, 1에 `applies` 표를 더함)이고 `contracts.SCHEMA_VERSION`과 별개다. 새 DB는 스키마와 두 값을 한 트랜잭션에서 만들므로 실패하면 함께 되돌아간다. 버전 1 파일은 그대로 읽고(조회는 올리지 않으며 반영 기록은 빈 목록), `register_project()`나 `record()`가 쓸 때 그 쓰기 트랜잭션 안에서 `applies` 표를 만들고 `user_version`을 2로 올린다(쓰기가 실패하면 함께 되돌아가 버전 1 그대로). 미등록 프로젝트라 쓰지 않는 `record()`는 올리지 않는다. 올린 파일은 이전 depbee(버전 1 코드)가 더 새 파일로 보고 쓰지 않는다. application_id가 다른 파일(다른 프로그램의 SQLite 파일, `user_version`이 1이고 같은 이름의 표가 있어도), application_id는 같지만 `user_version`이 이 코드보다 큰 파일, SQLite 파일이 아닌 파일에는 쓰지 않는다(`HistoryError` 또는 `sqlite3.DatabaseError`). application_id와 `user_version`이 0이고 표가 없는 파일(0바이트 포함)만 `register_project()`가 초기화한다.
- 표: `projects`(id, 식별 키, 표시용 경로, 등록 시각), `runs`(프로젝트, 종류 `scan`·`update_preview`, UTC 시각, depbee 버전, `base_ref`(`--base-ref` 값), `base_lock`(`--base-lock` 사용 여부, update는 null), 보고서의 `status`·`exit_code`·`model_id`·`provenance.model.model_sha256`, 항목 판정별 개수 `flagged`·`not_flagged`·`incomplete`·`removed`, 보고서 원문, update면 `preview` 원문), `results`(실행, 보고서 안 순서, `change_id`, `location`, `package`, `before_version`, `after_version`, `status`, `score`, `known_malicious`·`rules`·`ml`의 `status`). 값은 보고서 그대로이고 다시 계산하지 않는다. `score`가 null이면 null이다. `applies`(버전 2): 연결된 `update_preview` 실행 `run_id`(실행마다 하나), UTC 시각, `mode`, `outcome`, `reason`, `confirmed`, 미리보기의 원본 `package_json_sha256`·`package_lock_sha256`, 실제로 바꾼 파일의 새 `new_package_json_sha256`·`new_package_lock_sha256`(바꾸지 않았으면 null), `backup`, `npm_version`, `npm_ci_exit_code`, 5.1절 `apply` 원문. 확인한 항목은 `apply` 원문의 `confirmation_required`다. 미리보기가 만든 새 lockfile 내용은 어느 표에도 저장하지 않는다.
- 문자열: 원문은 `_emit`과 같은 `json.dumps(..., ensure_ascii=True, allow_nan=False)`로 저장해 그대로 되읽힌다. 질의용 열과 표시용 프로젝트 경로는 UTF-8로 인코딩할 수 없는 문자(lockfile에서 온 lone surrogate 등)를 `\udc80` 같은 텍스트로 바꿔 저장한다(원래 값은 원문에 있다).
- 프로젝트 식별: `Path(project).resolve()`의 절대 경로에 `os.path.normcase`를 적용한 문자열(Windows에서 대소문자 무시)을 `json.dumps(..., ensure_ascii=True)`로 저장한 값이 키다. 이 표현은 되돌릴 수 있고 역슬래시도 구별하므로, lone surrogate가 든 경로(POSIX의 바이트 `0x80` 이름)와 글자 그대로 `\udc80`이 든 경로는 다른 프로젝트다. 표시용 경로는 resolve 결과에 위 문자열 변환만 적용한 값이다. 다시 등록하면 처음 등록을 유지한다. `register_project()`는 존재하는 폴더인지만 확인하며, 웹 입력의 경로 검사(UNC, 장치 경로, 예약 이름, 링크)는 대시보드 경계에서 한다. 폴더가 사라져도 기록을 지우지 않는다.
- 조회: `list_projects()`(등록 순), `list_runs(project_id, limit=None)`(최근순, 원문 없이 실행 열과 판정별 개수 `counts`), `get_run(run_id)`(실행 열, 되읽은 `report`·`preview`, 순서대로의 `results`, 반영 기록 `apply` 또는 null), `list_applies(project_id, limit=None)`(그 프로젝트의 반영 기록 최근순, `applies` 열과 되읽은 `apply` 원문). 추이는 실행의 판정별 개수로 계산한다.
- 기록 대상과 시점: `cli.main`의 `scan`·`update` 분기가 `_emit`으로 보고서를 출력한 뒤 `record()`를 부른다. `update --apply`는 같은 호출에 `apply`를 넘겨 실행과 반영 기록을 함께 쓴다(반영 단계의 거부·실패도 출력되므로 기록된다). 서비스 함수와 `pipeline.scan()`은 기록하지 않으므로 `check`, `plan`, 오류로 끝난 실행(예외로 `_emit`에 닿지 못함), MCP 도구는 기록되지 않는다. update의 프로젝트는 `--project`(기본 현재 폴더)다. 파일이 없거나 프로젝트가 등록되지 않았으면 아무것도 쓰지 않는다. GitHub Action은 같은 CLI `scan`을 쓰므로, 이력 파일이 없는 러너(GitHub 호스팅 러너 등)에서는 기록되지 않고, 이력 파일이 있는 PC에서 그 체크아웃 폴더를 등록한 자기 호스팅 러너라면 등록한 프로젝트의 실행으로 기록된다.
- 연결과 잠금: 작업마다 연결을 열고 반드시 닫는다(`contextlib.closing`). `isolation_level=None`과 명시적 `BEGIN IMMEDIATE`로 쓰고(Python 3.11~3.13 공통), 잠금은 1.5초까지 기다린다. journal은 SQLite 기본 rollback journal(DELETE)이다. WAL은 `-wal`·`-shm` 파일이 파일 옆에 계속 남고 네트워크 폴더에서 동작하지 않으며, 기록은 실행마다 한 번이라 동시 쓰기 이점이 작다.
- 실패 처리: CLI의 기록 함수는 `Exception`을 모두 자기 안에서 잡고(`history`와 `sqlite3` import도 그 안에서 해 `sqlite3`가 없는 Python에서도 다른 동작은 같다), 실패하면 stderr에 경로·패키지 문자열이 없는 고정 한국어 문구 한 줄만 쓴다(모든 형식 공통). stdout과 종료 코드(보고서의 `exit_code`)는 바뀌지 않고, 성공과 건너뜀은 아무것도 출력하지 않는다. 새 CLI 옵션은 없다.
- 신뢰 경계: 이력은 이 PC 사용자의 로컬 데이터이고 내용은 depbee가 만든 보고서(패키지에서 온 문자열 포함)다. 표시할 때는 4절 텍스트·Markdown과 같이 다시 이스케이프하고, 이력의 값을 업데이트 반영 게이트(5.1)나 다른 판정의 입력으로 쓰지 않는다.

## 7. 로컬 대시보드 (`depbee dashboard`)

`depbee dashboard [--port N]`(SVC-07 조회·이력 화면, 하람 결정 2026-11-16)은 6절 이력과 등록한 프로젝트의 lockfile을 보여 주는 로컬 웹 화면이다. Starlette + Jinja2 + uvicorn(`web` extra)이고, 이 라이브러리는 `depbee.dashboard.app`만 import한다(`depbee.dashboard.serve()`가 지연 import, 없으면 설치 안내 `GuardError`로 종료 코드 2). 하위 명령 분기는 `mcp`처럼 `--output` 검사보다 앞이다. 보고서·이력 형식을 바꾸지 않는다.

- 실행: `127.0.0.1`에만 바인딩하고 host 옵션은 없다. `--port` 기본 0(OS가 빈 포트를 고름). 시작하면 stdout에 `http://127.0.0.1:<포트>/login?token=<토큰>` 한 줄과 종료 안내 한 줄을 쓴다. 브라우저를 자동으로 열지 않는다. uvicorn은 `access_log=False`, `server_header=False`, `proxy_headers=False`, 로그 수준 warning, lifespan·websocket 없음이다. depbee는 토큰을 이 시작 줄 밖(화면, 오류 문구, 쿠키, 접속 기록)에 쓰지 않는다. 처리하지 못한 예외는 uvicorn이 표준 오류에 traceback으로 남길 수 있다(depbee 코드는 토큰을 예외 메시지에 넣지 않는다).
- Host: 모든 요청에 Host 헤더가 정확히 하나이고 `127.0.0.1:<실제 포트>`와 같아야 한다(대소문자 무관). 아니면 400. Starlette `TrustedHostMiddleware`는 포트를 비교하지 않아 쓰지 않는다.
- 세션: 토큰은 실행마다 `secrets.token_urlsafe(32)`. `GET /login?token=`을 `hmac.compare_digest`로 비교해 맞으면 토큰과 다른 무작위 세션 값을 쿠키 `depbee_session_<포트>`(HttpOnly, SameSite=Strict, Path=/)로 주고 303으로 `/`에 보낸다. 세션은 프로세스 메모리에만 있다. 로그인 토큰은 서버가 끝날 때까지 다시 쓸 수 있고(로그인마다 새 세션과 CSRF 토큰), 세션에는 만료가 없다(서버가 끝나면 모두 사라짐). `/login` 밖의 모든 요청(GET 포함)은 유효한 세션이 없으면 403이다. 쿠키 이름의 포트는 이 실행의 쿠키가 다른 실행·앱의 쿠키와 섞이지 않게 할 뿐이다.
- 세션 쿠키와 다른 로컬 서버(받아들인 한계, 하람 결정 2026-11-16, REV-SVC07VIEW-R1 M1): 쿠키는 포트를 구분하지 않는다(RFC 6265 8.5). 그래서 대시보드에 로그인한 같은 브라우저로 `127.0.0.1`(같은 호스트)의 다른 포트에 떠 있는 로컬 웹 서버를 열면, 브라우저가 그 서버로 가는 요청에도 대시보드 세션 쿠키를 싣는다. 그 서버는 받은 값으로 대시보드 화면을 읽고(목록의 등록 폼에 있는 CSRF 토큰 포함) 서버 쪽 요청에 `Origin`을 직접 붙여 등록 POST를 보낼 수 있다. 쿠키 이름의 포트, SameSite=Strict(두 포트는 같은 site), HttpOnly(스크립트 읽기만 막음)는 이를 막지 못한다. 이와 달리 다른 포트에서 열린 페이지의 브라우저 스크립트가 대시보드로 직접 보내는 POST는 브라우저가 붙인 `Origin`이 다르므로 403이다. 대시보드는 같은 브라우저에서 여는 다른 로컬 웹 서버를 믿는 것으로 본다. 같은 사용자 계정의 프로그램은 이력 파일을 직접 읽고 쓸 수 있어 이 경계로 막는 대상이 아니고, 실제로 남는 위험은 같은 PC의 다른 계정이 띄운 서버다. 이 화면은 조회와 경로 등록만 하고 npm을 실행하지 않는다. npm을 실행하는 업데이트 확인·수행 화면을 더하기 전에 인증 방식을 다시 정한다.
- 상태 변경: `POST /projects`(프로젝트 등록) 하나뿐이다. GET·HEAD가 아닌 요청은 `Origin`이 정확히 `http://127.0.0.1:<포트>`여야 하고(없거나 `null`이거나 다르면 403), 등록 폼은 세션마다 만든 CSRF 토큰을 `hmac.compare_digest`로 확인한다(403). 본문은 `application/x-www-form-urlencoded`만(아니면 415) 16 KiB까지(넘으면 413, Starlette `max_body_size`) 받고, `urllib.parse.parse_qs`(필드 4개 상한, 엄격한 디코딩)로 푼다. `python-multipart`는 쓰지 않는다.
- 등록 경로: 1024자 이하, `mcp._local_path`(빈 값, UNC·장치 경로, Windows 예약 이름)를 통과한 절대 경로, `mcp._unlinked`로 링크를 따라간 결과가 폴더이고 그 안의 `package-lock.json`이 일반 파일(FIFO·장치·폴더 아님)이어야 한다. 공유·장치로 가는 링크와 확인할 수 없는 링크는 거부하고 로컬 링크는 MCP처럼 허용한다. 통과하면 `history.register_project()`를 부르고 303으로 그 프로젝트 화면에 보낸다. 오류는 고정 문구(400)이고 입력을 되싣지 않는다.
- 응답 헤더(오류 포함 모든 응답): `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`(no-referrer면 폼 POST의 Origin이 `null`이 된다), `Cache-Control: no-store`. JS와 인라인 스타일이 없고, 기여도 막대는 SVG 속성으로 그린다.
- 이스케이프: Jinja2 `Environment(autoescape=True)`를 직접 만들고, `finalize`로 출력하는 모든 문자열을 `cli._clean`에 통과시킨 뒤 이스케이프한다(제어·양방향·영폭 문자와 lone surrogate가 `\uXXXX` 글자로 보임). 응답은 UTF-8 `backslashreplace`로 인코딩한다. 처리하지 못한 예외는 예외 내용 없는 고정 문구 500이다.
- 링크: npm 페이지 링크는 `inputs.npm.PACKAGE_NAME`에 맞는 214자 이하 이름일 때만 `https://www.npmjs.com/package/` + `urllib.parse.quote(이름, safe="@/")`로 만든다. 릴리스 노트 링크와 보고서·lockfile·registry에서 온 URL로는 링크를 만들지 않는다.
- 읽기: 이력은 `history.list_projects`·`list_runs`·`get_run`으로만 읽고(호출마다 연결을 열고 닫음), 의존성은 `service.list_dependencies()`(`inputs.npm.read_dependencies()`, `scan`과 같은 lockfile 검사)로 읽는다. 등록 폴더와 lockfile은 읽기 전에 등록 때와 같은 경로 검사를 한다. 폴더가 없으면 "찾을 수 없음", lockfile이 없거나 읽을 수 없으면 그 사실만 보인다.
- 표시: 판정·이유·종료 코드·탐지기 상태는 저장된 값 그대로이고, 문구와 판단은 텍스트 출력과 같은 `cli` 함수(`_ordered`, `_notices`, `_detector_setup`, `_detector_lines`, `_ml_score`, `_alternative`, `_preview_lines`, `_rest_line`)를 쓴다. 그래서 4절의 '확인 안 됨'·참고값·`실패 N개` 규칙이 대시보드에도 같다. 모든 화면에 `cli.SAFETY_NOTE`가 있고, 점수는 "ML 위험 점수"이며 확률로 쓰지 않는다. 추이는 프로젝트마다 최근 10개 실행의 판정 개수 표이고(차트 없음), 프로젝트 화면의 실행 기록은 상한 없이 모두 보인다. 목록의 최근 실행 요약은 종류와 관계없이 가장 최근 실행 하나이며, update 미리보기 실행은 종류와 '설치되지 않은 버전' 안내로 따로 표시한다. 일부 칸만 없는 혼합 형식 보고서는 4절 규칙(최상위가 연결 안 됨으로 밝힌 탐지기는 '확인 안 됨'을 쓰지 않음)을 따른다. 모델 정보는 저장된 실행의 `model_id`, `threshold`, `provenance`, `analyzer_version`만 보이고 학습 데이터 버전과 공격 유형별 탐지율은 출처가 없어 보이지 않는다.
- 하지 않는 것: 대시보드에서 검사·미리보기·반영·설치 실행, 등록 해제·이력 삭제, Actions `report.json` 가져오기, 추이 그래프, 의심 코드 위치, 과거 캠페인 정보.

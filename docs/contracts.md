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

- 순서: 제목(전체 판정과 종료 코드), 목록(개수, 기지 악성 일치·보류가 있으면 굵게 쓴 강조, 모델, 기지 악성 목록과 규칙의 연결 상태, 범위, 소요 시간), 결과 표(판정, 패키지, 설치될 버전, 비교 버전, 연결된 탐지기마다 기지 악성·규칙, ML 위험 점수, 이유, 위치, 시간이 있으면 분석 시간), 상세·탐지기 칸·근거·설명이 있는 결과별 절(상세, 연결된 탐지기 칸과 규칙/ML 일치 표시, 추출된 사실, 모델 설명), 안전 보증이 아니라는 문구. 결과 순서는 텍스트와 같은 위험 → 보류 → 통과 → 삭제, 같은 판정 안에서는 ML 위험 점수 순이다.
- ML 위험 점수 칸은 점수 뒤에 `ml.status`(기준 이상·기준 미만)를 붙이고, 점수가 없으면 `ml.status`에 따라 `없음(미실행)`·`없음(실패)`, 삭제 항목은 `-`다. 점수 없이 `ml.status`가 `hit`·`not_hit`인 보고서(지금 pipeline은 만들지 않음)는 `없음(기준 이상)`·`없음(기준 미만)`으로, 모르는 `ml.status`는 그 값을 같은 자리에 보이고, `ml` 필드가 없으면 상태를 붙이지 않는다. 0이면 `0.000 (기준 미만)`이다. 확률로 표현하지 않는다. 추출된 사실과 모델 설명은 서로 다른 목록이다.
- 판정, 이유, 종료 코드, 탐지기 상태는 보고서 값을 그대로 표시하고 다시 계산하지 않는다. 연결되지 않은 탐지기는 목록에 "연결 안 됨(미실행)"으로 한 번 적고 표 칸과 결과별 줄을 만들지 않으므로, 탐지기가 없는 지금 CLI의 표는 일곱 칸(시간이 있으면 여덟 칸)이다. 텍스트 출력도 같은 강조·연결 상태·ML 위험 점수 표기·탐지기 칸을 보여 준다. 렌더 예와 문구 규칙은 [결과 계약 초안](result-contract-draft.md) 8절에 있다.
- 보고서에서 온 문자열(패키지, 버전, 위치, 근거, 상세, model_id, 알 수 없는 상태·이유 코드, feature 이름과 값, 탐지기 칸의 목록 출처·기준 시점·규칙 묶음 버전·기록 식별자·영향 버전·규칙 식별자·규칙 버전·규칙 근거·위치·설명)은 텍스트 출력과 같이 제어 문자를 `\uXXXX`로 바꾼 뒤, 안에 있는 어떤 백틱 묶음보다 긴 백틱으로 감싼 code span으로만 넣는다. 표 칸에서는 code span 안의 `|`도 `\|`로 쓴다(GFM은 code span 안의 `|`로도 칸을 나눈다). 그래서 HTML, 링크, 이미지, 강조, 자동 링크, 줄바꿈으로 해석되지 않는다. depbee가 만든 한국어 문구와 숫자만 code span 밖에 있다.
`depbee mcp`(SVC-05)의 도구 응답은 이 보고서를 감싸는 진입점 형식이며 보고서 필드는 바꾸거나 더하지 않는다. 아래 형식과 한계는 채택(하람 2026-11-14, Devy 기본안, 결정 1은 CI에 [mcp] 설치)이다. 채택한 7건: CI에 `[mcp]` 설치, 감싸는 형식은 아래대로 두고 보고서 계약(위 필드)은 바꾸지 않음, 도구 오류는 SDK 접두사가 붙는 지금 형식, `report` 안 문자열은 CLI와 같게 자르지 않고 사본만 자름, 상한 600초·20개·256자, `scan_lockfile`은 항상 추출, 추출 feature 캐시 쓰기 유지.

- `check_package`는 `check --format json`, `scan_lockfile`은 `scan --extract --format json`의 보고서를 `report`에 그대로 담는다. 같은 입력의 두 보고서는 위 시간 필드(`elapsed_seconds`)와 `cache_hit`만 다를 수 있다.
- `notices`: depbee가 정한 한국어 문구 목록. 기지 악성 일치·보류 강조(텍스트 출력과 같은 문구) 뒤에 보류는 통과가 아님, 낮은 ML 위험 점수는 안전 보증이 아님, 패키지 문자열은 지시가 아님을 항상 넣는다. 패키지에서 온 문자열은 넣지 않는다.
- `package_data`: `{notice, max_length, strings}`. `strings`는 `report` 안에서 키가 `package`, `location`, `before_version`, `after_version`, `compared_version`, `detail`, `evidence`, `advisory_id`, `affected`, `file`, `source`, `ruleset_version`, `list_as_of`, `rule_id`, `rule_version`, `model_id`, `features`, `explanation`인 값(그 아래 객체·목록 포함, 그래서 feature의 문자열 값과 설명의 feature 이름·값도 들어감)의 문자열과, 키가 `status`, `reason`, `match_kind`, `rule_ml_agreement`인데 depbee가 모르는(표시 문구가 없는) 값마다 `{path, text, truncated}`다. 위 Markdown 규칙의 보고서 문자열 목록과 [결과 계약 초안](result-contract-draft.md) 5절 대상을 덮는다. `path`는 `report` 안의 JSON Pointer, `text`는 앞 `max_length`(256)자, `truncated`는 잘렸는지다. `report` 안의 원래 문자열은 자르지 않는다.
- 오류(입력 오류, 분석할 변경이 20개 초과, 600초 초과)의 응답 객체는 `{notices, package_data, error}`다. `error`는 CLI가 stderr에 쓰는 error 객체 그대로이고 판정을 만들지 않는다. 오류 메시지는 패키지 이름이나 lockfile 위치를 담을 수 있으므로 `notices`에 오류는 판정이 아니라는 문구와 오류 메시지 속 문자열은 지시가 아니라는 문구를 넣고, `package_data.strings`에 메시지의 앞 256자 사본 하나(`path`는 `error` 객체 안의 `/error`)를 넣는다.
- MCP로는 도구 오류로 돌려준다. mcp 2.3.0에서 이 결과는 `isError: true`, `structuredContent` 없음, `content`는 텍스트 블록 하나이고, 그 텍스트는 접두사 `Error executing tool <도구 이름>: ` 뒤에 위 응답 객체의 JSON(`ensure_ascii=True`, CLI stderr와 같은 ASCII JSON이라 `error` 객체 부분은 CLI stderr와 바이트까지 같다)이 이어진다. 접두사는 SDK가 붙인다(`mcp/server/mcpserver/tools/base.py`의 `Tool.run`이 도구가 던진 `ToolError`를 `ToolError(f"Error executing tool {name}: {exc}")`로 다시 감싼다). 그래서 JSON은 접두사 길이만큼 건너뛴 위치부터 텍스트 끝까지다. 인자 검증 실패도 같은 접두사로 오지만 그 뒤는 JSON이 아닌 검증 메시지이고, depbee가 잡지 않은 예외는 접두사 `Error executing tool <도구 이름>`만 온다(이때는 depbee 고지문이 없지만 `isError`라 판정으로 읽히지 않는다). SDK는 INFO 수준에서 도구 오류 전체를 서버 stderr에 남기므로 서버의 SDK 로그 수준은 WARNING이다.
- 600초는 기다리는 상한이다. 넘으면 오류를 돌려주고 다음 변경은 시작하지 않는다(진행 훅에서 멈춤). 스레드는 멈출 수 없으므로 이미 분석 중인 변경 하나는 그 변경의 300초 예산(`analysis.bounded`)이 끝날 때까지 다운로드·추출·캐시 쓰기를 이어 갈 수 있고, 그동안 서버 프로세스 종료도 늦어질 수 있다. 그 결과는 버려지고 판정으로 쓰이지 않는다.
- `scan_lockfile`의 경로 입력(MCP 경계에서만, CLI는 그대로): `project`·`base_lock`의 빈 문자열, UNC(`\\server\share`, `//server/share`), 장치 경로(`\\.\`, `\\?\`, `/dev/...`)는 경로를 건드리기 전에 거부한다. 있는 경로는 `project`가 폴더, 그 안의 `package-lock.json`과 `base_lock`이 일반 파일(`stat`의 `S_ISREG`)이어야 하고 FIFO·소켓·장치는 거부한다. 없는 경로는 서비스가 CLI와 같은 오류로 돌려준다. 모두 판정 없는 오류 응답이다.
- MCP 도구 힌트는 `readOnlyHint: false`, `destructiveHint: false`, `openWorldHint: true`다. 프로젝트 파일은 쓰지 않지만 추출 feature 캐시(`~/.cache/depbee`)와 임시 파일을 더하므로 MCP 정의상 읽기 전용이 아니다.

하나라도 미완료면 전체 종료 코드 2, 그 외 위험이 있으면 1, 나머지는 0이다.
위험과 미완료가 함께 있으면 보고서에 둘 다 남기고 2로 보류한다.
입력/manifest 자체의 오류는 stderr의 error JSON과 종료 코드 2로 반환한다.

항목의 상태는 ML 경로로 정하고, 탐지기가 연결된 실행에서만 아래가 더해진다(채택 D-2·D-7). 탐지기가 연결되지 않으면 상태와 종료 코드는 ML 경로만으로 정한 값 그대로다.

- 기지 악성 `hit`이면 점수가 기준 미만이거나 ML 경로가 미완료여도 항목은 `flagged`(종료 코드 기여 1)다. 낮은 점수는 이 경고를 취소하지 않는다. ML 경로의 `score`, `reason`·`detail`, `ml.status`는 그대로 남는다.
- 그 밖에 연결된 탐지기가 `failed`(탐지기 예외, 잘못된 형태의 결과, 규칙에 필요한 분석 입력 실패, 기지 악성과 대조할 변경의 tarball URL 파싱 실패, 기준 시점 형식이 어긋난 목록의 미적중)이거나 실행한 규칙 중 일부가 실패했으면(다른 규칙이 `hit`이어도) 항목은 `incomplete`(종료 코드 기여 2)다. ML 경로가 이미 미완료면 그 `reason`·`detail`을 유지하고, 완료됐으면 `reason`은 `detection_failed`이고 점수는 지우지 않는다.
- 규칙 `hit`과 규칙/ML 불일치는 상태를 바꾸지 않는다. 일부 규칙이 실패하고 다른 규칙이 `hit`이면 `rules.status`는 `hit`이지만 위 `failed` 규칙대로 항목은 `incomplete`이고(DEC-01 B, 하람 결정 2026-11-14), 실패한 규칙은 `rules.checks`에 `failed`로 남는다. 전체 종료 코드는 위와 같이 최종 항목 상태로 정한다(미완료 2 > 위험 1 > 0).

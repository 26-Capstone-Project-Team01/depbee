# 결과 계약 초안: 기지 악성·규칙 근거·ML 위험 점수·미완료

> **필드는 구현됐고 실제 탐지기는 아직 없다.** 3절의 필드는 모두 `pipeline.scan()`이 출력한다(`provenance`는 SVC-02, 나머지는 SVC-03에서 구현). 실제 기지 악성 목록과 규칙은 구현되지 않았고 진입점(CLI 등)에 탐지기를 연결하는 옵션도 없으므로, 지금 명령의 출력은 탐지기 미연결 상태다(최상위 `detectors`의 두 값이 null, 항목 `known_malicious`·`rules`는 `not_run`·`detector_not_configured`). 지금 보고서와 일치하는 요약은 [연결 규약](contracts.md) 4절이다.
> 기준 코드: main `daabb54`(PR #11 병합, SVC-03)에 SVC-04(텍스트·Markdown 표시) 변경을 더한 것. 본문에서 `90a61bb`로 적은 코드의 행 번호와 성질은 그 커밋 기준이고, 그 뒤 `pipeline.py`는 SVC-02·SVC-03에서 바뀌었다. 9절의 결정 16개는 하람이 2026-11-11에 권장안대로 모두 채택했다(이 문서에서는 "채택(D-n)"으로 적는다). 채택한 내용 중 현행 동작을 바꾸는 D-2·D-7(그리고 D-5의 대조 범위)은 SVC-03에서 적용했고(9.1절), 8절 예시 JSON은 적용 후 동작이다.

CLI, GitHub Actions, MCP, 로컬 대시보드가 함께 쓸 보고서 JSON에 네 근거와 네 상태를 구분해 담는 방법을 제안한다. 판정과 결합은 지금처럼 `pipeline.scan()` 한 곳에서만 만들고, 진입점은 같은 보고서를 표시만 한다.

## 1. 구분과 원칙

네 근거는 서로 다른 칸에 둔다.

| 근거 | 뜻 | 보고서 위치(초안) |
|---|---|---|
| 기지 악성(known malicious record 일치) | 신뢰하는 악성 기록의 npm 이름·영향 버전과 설치될 버전이 일치 | 결과 항목의 `known_malicious` |
| 규칙 근거(rule evidence) | 별도 규칙 탐지기의 적중 조건과 근거 | 결과 항목의 `rules` |
| ML 위험 점수(ML risk score) | LightGBM 모델의 점수와 임계값 판정 | 기존 `score`·`status`·`explanation`과 새 `ml.status` |
| 미완료(incomplete) | 식별·조회·분석·추론을 끝내지 못함 | 기존 `status: "incomplete"`·`reason`·`detail` |

탐지기마다 상태를 같은 네 값으로 적는다. 서로 대체하지 않는다.

| 값 | 뜻 | 대체 금지 |
|---|---|---|
| `hit` | 탐지기가 실행됐고 적중 | |
| `not_hit` | 미적중. 탐지기가 실행됐고 조건에 맞지 않음 | 정상·안전 판정이 아니다. 특히 규칙 미적중을 정상 판정으로 쓰지 않는다 |
| `not_run` | 미실행. 탐지기가 없거나, 대상이 아니거나, 입력이 분석 대상이 아님 | `not_hit`로 쓰지 않는다 |
| `failed` | 실패. 실행하려 했으나 끝내지 못함 | `not_run`이나 `not_hit`로 쓰지 않는다 |

규칙/ML 불일치(disagreement)는 규칙과 ML이 모두 실행됐는데 한쪽만 적중한 경우다. 분석 실패가 아니므로 `incomplete`에 섞지 않는다(4.3절).

계약 문장:

- **낮은 ML 점수는 기지 악성 경고를 취소하지 않는다.** `known_malicious.status`가 `hit`이면 `score`, `ml.status`, 결과 항목의 `status`와 관계없이 그 값과 일치 내용을 보고서에 남기고, 모든 진입점이 표시한다. 모델이 없거나 비교할 이전 버전이 없어 ML이 실행되지 않아도 같다.
- ML 점수는 "ML 위험 점수"라고 부르고 악성 확률로 표시하지 않는다. 확률 보정을 검증하기 전까지 그렇다.
- 점수 누락·실패를 0점이나 정상으로 바꾸지 않는다. 점수가 없으면 `score`는 지금처럼 null이다.
- 규칙·ML·기지 악성 결과를 임의로 더하거나 평균해 단일 점수를 만들지 않는다. OR·AND·우선순위 결합 정책은 실험 뒤 정하고, 그때까지 근거별 표시와 `rule_ml_agreement` 표기만 한다(채택(D-4)).
- 새 필드를 추가하는 것만으로는 지금의 `status`, `reason`, `exit_code`와 차단 동작이 바뀌지 않는다. 다만 채택(D-2)은 기지 악성 `hit`을 항목 `flagged`·종료 코드 1로, 채택(D-7)은 연결된 탐지기의 `failed`를 항목 `incomplete`·종료 코드 2로 연결한다. 이 둘은 SVC-03에서 적용했다(하람 확정, 11/11, 9.1절). 탐지기가 연결된 실행에서만 생기므로 탐지기 미연결 실행의 값은 그 전과 같다. 한 항목에 둘이 함께 걸리면 기지 악성 쪽(`flagged`, 종료 코드 기여 1)이 우선한다(4.2절). 탐지기 미연결(`not_run`)은 종료 코드에 영향이 없다(채택(D-6)).

## 2. 이미 있는 필드 재사용

새 필드는 아래 기존 필드를 다시 만들지 않고 참조한다. 같은 값을 다른 위치에 복사하지 않는다.

| 기존 필드 | 위치 | 초안에서의 쓰임 |
|---|---|---|
| `schema_version` | 최상위 | 그대로. 1을 유지한다(7절, 채택(D-1)) |
| `request_id`, `input_kind`, `scope` | 최상위 | 그대로 |
| `status`(`passed`/`flagged`/`incomplete`), `exit_code` | 최상위 | 그대로. 지금 계산 규칙(미완료 2 > 위험 1 > 0)을 바꾸지 않는다 |
| `model_id`, `threshold` | 최상위 | ML 모델 식별과 임계값. `ml` 안에 복사하지 않는다 |
| `analyzer_version` | 최상위 | 그대로. null이면 분석기가 연결되지 않은 실행이다(4.1절). feature-extractor 출처의 상세는 `provenance.feature_extractor`(SVC-02에서 구현)에 둔다 |
| `elapsed_seconds` | 최상위·결과 항목 | 그대로. 채택(D-11)은 결과 항목의 값(그 항목의 메타데이터 조회·캐시 조회·추출 시간, 추론 제외)에 탐지기 시간을 넣지 않고 필요하면 탐지기별 필드를 따로 둔다는 것이다. 항목 값은 `ExtractorAnalyzer`가 변경마다 잰 시간(`extractor.py` 268~271행)이라 `pipeline.scan()` 안에서 돈 탐지기 시간은 들어가지 않는다. 최상위 값은 [연결 규약](contracts.md) 4절 정의대로 서비스 함수 호출부터 판정 완료까지의 전체 시간(`service._timed()`의 `elapsed_since(started)`)이므로, 탐지기를 `pipeline.scan()` 안에서 실행하면 그 시간이 포함된다. 최상위에서도 탐지기 시간을 빼려면 별도의 동작 변경과 확인이 필요하다 |
| `status`(`flagged`/`not_flagged`/`incomplete`/`removed`) | 결과 항목 | 값은 그대로. SVC-03부터 ML 경로(분석·추론)와 연결된 탐지기의 기지 악성 `hit`(채택(D-2))·`failed`(채택(D-7))로 정한다(4.2절). 탐지기 미연결이면 ML 경로로만 정해진 그 전 값과 같다. ML 경로만의 결과는 `ml.status`가 나타낸다 |
| `score` | 결과 항목 | ML 위험 점수. `ml`에 복사하지 않는다. 채택(D-2)·채택(D-7)로 항목 `status`가 바뀌어도 지우지 않는다 |
| `reason`, `detail` | 결과 항목 | 그대로 ML 경로의 미완료·삭제 이유. `ml.status`가 `not_run`/`failed`인 이유는 이 두 필드를 본다. 예외: ML 경로가 완료(`flagged`/`not_flagged`)된 항목이 채택(D-7)로 `incomplete`가 되면 `reason`은 `detection_failed`이고 `detail`은 없다(설명은 실패한 탐지기 칸에 있다). 이 값은 SVC-03에서 정했다(하람 승인(11/13)) |
| `compared_version`, `features` | 결과 항목 | 그대로 |
| `evidence` | 결과 항목 | 그대로 "추출된 사실"(분석기가 만든 사실). 규칙 근거를 여기에 섞지 않고 `rules.checks[].evidence`에 따로 둔다 |
| `explanation`, `explanation_rest` | 결과 항목 | 그대로 ML 모델 설명(SHAP, log-odds) |
| `cache_hit` | 결과 항목 | 그대로 feature 캐시 사용 여부. 캐시는 feature만 담고 탐지기 결과는 매번 다시 계산한다 |
| `change_id`, `location`, `package`, `before_version`, `after_version` | 결과 항목 | 기지 악성 대조 대상은 이 항목의 `package`와 `after_version`(설치될 버전)이다. 일치 기록에 다시 적지 않는다 |

## 3. 새 필드 정의

모든 새 필드는 추가만 한다. 기존 키의 이름과 값, 기존 키끼리의 순서를 바꾸지 않는다. 필드 이름은 이 문서의 이름을 쓰되, 채택(D-1)대로 리뷰 뒤 하람 승인을 받으며 그 승인은 PR #9 병합 검토에서 받는다.

키 순서는 90a61bb의 조립 순서를 따른다. `pipeline.scan()`이 보고서를 만들고, `--extract` 실행과 `check`에서는 그 뒤에 `service._timed()`(`service.py` 123~134행)가 시간 필드를 붙인다. `_timed()`는 이미 있는 결과 항목 dict마다 `elapsed_seconds`, `cache_hit`을 대입해 항목의 맨 끝에 두고, 최상위는 `results`를 뺐다가 `elapsed_seconds`, `results` 순으로 다시 붙인다. 분석기 없는 `scan`과 `--analysis` 실행은 `_timed()`를 거치지 않아 시간 필드가 없다. 새 필드는 `pipeline.scan()`이 만들므로 시간 필드보다 앞에 온다.

- 최상위: 기존 `analyzer_version` 다음에 `detectors`, `provenance`, 그다음 (있으면) `elapsed_seconds`, 마지막에 `results`.
- 결과 항목: `pipeline.scan()`이 만드는 기존 필드(경로에 따라 `reason`·`detail`, 또는 `compared_version`·`features`·`explanation`·`explanation_rest`까지, 채택(D-7)로 붙는 `reason`은 그 뒤) 다음에 `known_malicious`, `rules`, `ml`, `rule_ml_agreement`, 그다음 (있으면) `elapsed_seconds`, `cache_hit`.

SVC-03은 새 필드를 `pipeline.scan()`에서 항목 dict와 최상위 dict에 넣었고(항목은 `results.append()` 전, 최상위는 `analyzer_version` 다음), `_timed()`는 고치지 않았다. 그래서 위 순서가 그대로 나온다. 이때 최상위 `elapsed_seconds`에는 `pipeline.scan()` 안에서 실행한 탐지기 시간도 들어가고, 결과 항목의 `elapsed_seconds`에는 들어가지 않는다(2절 표). 새 필드를 `service.py` 쪽에서 넣는 경우(SVC-00 계획은 SVC-02의 `provenance`를 service 조립부에 넣는 안과 pipeline 최상위에 넣는 안을 함께 적었고, SVC-02는 `pipeline.scan()` 최상위에 넣었다)에는 `_timed()`가 `results`를 다시 붙이는 방식처럼 `elapsed_seconds`와 `results` 앞에 넣는다. 8절 예시 JSON은 이 순서를 따른다.

### 3.1 최상위

| 필드 | 자료형 | null | 값과 의미 |
|---|---|---|---|
| `detectors` | object | 아니오 | 이 실행에 연결된 ML 외 탐지기. ML 모델은 기존 `model_id`·`threshold`가 나타낸다 |
| `detectors.known_malicious` | object | 예 | null이면 기지 악성 탐지기가 이 실행에 연결되지 않음. 연결되면 아래 세 필드 |
| `detectors.known_malicious.source` | string | 아니오 | 기지 악성 목록의 출처 식별자. 출처는 채택(D-3)대로 소은 명세를 따른다 |
| `detectors.known_malicious.list_as_of` | string | 아니오 | 목록의 기준 시점, ISO 8601 UTC(`Z`). 이 시점 뒤에 알려진 기록은 반영되지 않았다는 뜻이다. `pipeline.scan()`은 `YYYY-MM-DDTHH:MM:SS`(소수 초 1~6자리는 선택)에 대문자 `Z`로 끝나는 실제 날짜·시각인지 검사한다(SVC-03-FIX-01 n3). 문자열이 아니면 설정 오류(3.2절 아래 SVC-03 구현 문단)다. 문자열인데 형식만 어긋나면 이 값은 받은 그대로 두고, 대조를 마쳤는데 일치가 없는 항목의 `known_malicious`를 `not_hit` 대신 `failed`(`detector_failed`, `detail`에 설명)로 둔다. 기준 시점을 모르는 목록으로는 미적중을 확정할 수 없기 때문이다. 일치(`hit`)는 낮추지 않고, 대조하지 않은 항목(`not_run`)은 그대로다. `detectors.known_malicious`를 null로 바꾸지 않는 것은 null이 "연결되지 않음"을 뜻하기 때문이다 |
| `detectors.known_malicious.list_sha256` | string | 예 | 사용한 목록 스냅샷 파일의 SHA-256. 스냅샷 없이 조회하면 null(채택(D-3)) |
| `detectors.rules` | object | 예 | null이면 규칙 탐지기가 연결되지 않음 |
| `detectors.rules.ruleset_version` | string | 아니오 | 규칙 묶음의 버전. 표기 형식은 규칙 저장 위치가 정해진 뒤 정하고 그 전에는 문자열(채택(D-9)) |
| `provenance` | object | 아니오 | **SVC-02에서 구현했다(채택(D-10)).** 코드가 이미 확인하던 출처 정보(모델 파일 해시, feature-extractor 설치 출처). `pipeline.scan()`이 `detectors` 다음에 넣는다(SVC-02에서는 `analyzer_version` 바로 다음이었고, SVC-03이 그 사이에 `detectors`를 넣었다) |
| `provenance.model` | object | 예 | `LightGBMPredictor.identity`를 그대로 옮긴 `{"model_sha256", "manifest_sha256"}`. 모델이 없거나, identity가 두 키를 모두 문자열로 갖지 않으면(주입한 예측기, PR #10 리뷰 m1) null. `model_id`·`threshold`는 기존 최상위 필드에 있으므로 넣지 않는다 |
| `provenance.feature_extractor` | object | 예 | `FeatureExtractorBackend.identity`에서 `commit`, `files_sha256`, `python`만 옮긴다. feature-extractor로 추출하지 않는 실행(`--extract` 없는 `scan`, `--analysis`)이거나 설치 출처를 확인하지 못하면(identity가 None이거나 세 키를 모두 문자열로 갖지 않음) null. `url`은 설치 기록(`direct_url.json`)에서 온 값이라 넣지 않는다(채택(D-10)). 설치 출처이므로 이번 실행에서 추출한 변경이 0건이거나 모두 실패해도 값이 있다(`analyzer_version`과 같음, PR #10 리뷰 n3) |

### 3.2 결과 항목

| 필드 | 자료형 | null | 값과 의미 |
|---|---|---|---|
| `known_malicious` | object | 아니오 | 기지 악성 대조 결과 |
| `known_malicious.status` | string | 아니오 | `hit`, `not_hit`, `not_run`, `failed` |
| `known_malicious.reason` | string | 예 | `not_run`·`failed`의 이유 코드(3.3절). `hit`·`not_hit`이면 null. 항목의 `reason`과 별개이며 서로 복사하지 않는다 |
| `known_malicious.detail` | string | 예 | 이유가 `detector_failed`일 때 설명. 요청의 출처 검사가 실패한 `input_failed`(3.3절)도 그 항목에 `detail`이 없으므로 여기에 원인을 적는다. 그 밖에는 null |
| `known_malicious.matches` | array | 아니오 | `hit`일 때 일치한 기록, 그 밖에는 빈 배열 |
| `known_malicious.matches[].advisory_id` | string | 아니오 | 기록 식별자(예시는 `EXAMPLE-ADVISORY-0001`) |
| `known_malicious.matches[].match_kind` | string | 아니오 | `listed_version`(기록의 버전 목록에 있음) 또는 `affected_range`(검증한 영향 범위에 들어감) |
| `known_malicious.matches[].affected` | string | 예 | 기록에 적힌 영향 버전 표현. 외부 데이터다(5절) |
| `rules` | object | 아니오 | 규칙 탐지 결과 |
| `rules.status` | string | 아니오 | `hit`, `not_hit`, `not_run`, `failed`. 집계 규칙은 아래 |
| `rules.reason` | string | 예 | `not_run`·`failed`의 이유 코드(3.3절) |
| `rules.detail` | string | 예 | 탐지기 자체 오류(`detector_failed`, `checks`가 빈 배열)의 설명. 그 밖에는 null(`input_failed`면 항목 `detail`, 규칙별 실패면 `checks[].detail`을 본다) |
| `rules.checks` | array | 아니오 | 실행한 규칙마다 하나. 실행하지 않았으면 빈 배열 |
| `rules.checks[].rule_id` | string | 아니오 | 규칙 식별자 |
| `rules.checks[].rule_version` | string | 아니오 | 규칙 버전 |
| `rules.checks[].status` | string | 아니오 | `hit`, `not_hit`, `failed` |
| `rules.checks[].evidence` | array of string | 아니오 | 적중 조건의 근거. 추출된 사실(`evidence`)이나 모델 설명과 구분한다. 패키지에서 온 문자열을 담을 수 있다(5절) |
| `rules.checks[].locations` | array | 아니오 | 근거 위치. 원소는 `{"file": string, "line": integer 또는 null}`, `file`은 tarball 안의 경로. 형식은 이것에서 시작한다(채택(D-8)) |
| `rules.checks[].detail` | string | 예 | 이 규칙이 `failed`일 때 설명 |
| `ml` | object | 아니오 | ML 위험 점수 경로의 상태 |
| `ml.status` | string | 아니오 | `hit`, `not_hit`, `not_run`, `failed`. `pipeline.scan()`이 ML 경로의 결과(분석·추론 상태, 점수와 임계값 비교)로 정하며 값은 4.1절 표의 ML 경로 값과 같다. 탐지기 결과로 바뀌지 않는다. 점수·임계값·모델·이유는 기존 필드를 본다 |
| `rule_ml_agreement` | string | 아니오 | `both_hit`, `rule_only`, `ml_only`, `neither_hit`, `undetermined`(4.3절). `rule_only`·`ml_only`가 불일치다 |

`rules.status` 정하기: 탐지기를 실행하지 않았으면 `not_run`, 필요한 입력을 얻지 못했거나 탐지기 자체가 오류로 끝났으면 `failed`이고, 두 경우 모두 이유 코드가 있고 `checks`는 빈 배열이다. 실행했으면 `checks`에서 집계한다. 하나라도 `hit`이면 `hit`, 아니고 하나라도 `failed`면 `failed`(이유 `detector_failed`, 설명은 그 규칙의 `checks[].detail`), 모두 `not_hit`이면 `not_hit`이다. 탐지기가 실행됐는데 규칙 목록이 비어 있으면(`checks`가 빈 배열) 적중도 실패도 없으므로 `not_hit`이다(SVC-03-FIX-01 n2). `hit`과 `failed`가 함께 있으면 `rules.status`는 `hit`이고, 실패한 규칙은 숨기지 않고 `checks[]`에 `failed`와 `detail`로 남는다. 이때 `rules.status`는 `failed`가 아니므로 채택(D-7)은 걸리지 않는다(4.2절의 해석, SVC-03-FIX-01 m3). 연결된 탐지기의 `failed`는 채택(D-7)대로 다룬다. 실행하지 않은 이유는 3.3절 표에서 고른다. 분석 입력이 필요한 규칙 탐지기는 분석기가 연결되지 않은 실행에서 `analyzer_not_configured`, 연결된 분석기가 그 변경을 `unsupported`로 돌려준 경우(`ExtractorAnalyzer`의 `no_baseline`, prerelease의 `out_of_training_scope` 등)에 `analysis_unsupported`를 쓴다. `known_malicious.status`도 앞의 두 경우(`not_run`, `failed`)는 같고, 대조를 마쳤으면 `matches`가 있을 때 `hit`, 없을 때 `not_hit`이다.

SVC-03 구현(`pipeline.py`의 `_known_malicious()`, `_rules()`): 탐지기가 예외를 내거나 잘못된 형태(목록이 아님, 계약 필드가 없거나 자료형·값이 다름)를 돌려주면 그 칸은 `failed`(`detector_failed`, 칸의 `detail`에 설명)이고 `not_hit`이 되지 않는다. 탐지기 기록은 계약 필드만 계약 순서로 복사하고 나머지 키는 버린다. 규칙 탐지기는 분석이 완료된 변경에만 실행하며 그 변경의 요청 항목과 분석 결과의 복사본을 받는다(`contracts.RuleDetector`). 탐지기가 받은 값을 바꿔도 보고서의 `features`·`evidence`는 바뀌지 않는다(SVC-03-FIX-01 n1). 분석 대상이 아닌 변경을 기지 악성과 대조하기 전의 출처 검사가 그 변경의 tarball URL을 파싱하지 못하면(`GuardError`) 그 변경의 `known_malicious`만 `failed`(`input_failed`)이고 실행은 계속된다(SVC-03-FIX-01 m1). 이 검사의 다른 예외는 잡지 않는다. 최상위 `detectors`에 들어갈 탐지기 값(목록 출처·기준 시점, 규칙 묶음 버전)이 없거나 문자열이 아니면 결과가 아니라 설정 오류(`GuardError`, 종료 코드 2의 오류 JSON)다.

`not_run` 이유가 여럿 해당하면 3.3절 표의 위쪽 코드 하나를 쓴다(예: 탐지기가 연결되지 않은 실행의 삭제 항목은 `detector_not_configured`).

### 3.3 탐지기 이유 코드(초안)

`known_malicious.reason`과 `rules.reason`에 쓴다. 항목의 기존 `reason` 코드와 이름공간이 다르다. 코드 목록은 채택(D-1)에 포함된다. `analysis_unsupported`는 채택(2026-11-11) 뒤 리뷰 지적(M3)을 반영해 추가한 코드이며, 하람 승인(11/11, Clover 전달)을 받았다. `input_failed`의 뜻을 기지 악성 칸까지 넓힌 것(SVC-03-FIX-01 m1)은 PR #11 병합으로 승인된 것으로 처리한다(Clover, 11/14).

| 코드 | 상태 | 뜻 |
|---|---|---|
| `detector_not_configured` | `not_run` | 이 실행에 탐지기가 연결되지 않음(최상위 `detectors`의 해당 값이 null). 지금 main의 상태 |
| `not_installed_in_head` | `not_run` | 삭제된 의존성이라 설치될 버전이 없음(항목 `status`가 `removed`). 기존 코드 값을 같은 뜻으로 재사용 |
| `not_analyzable` | `not_run` | 요청에서 `analyzable=false`인 변경(미지원 출처 등). 항목 `reason`에 원래 이유가 있다. 기지 악성 대조에서는 채택(D-5)대로 출처가 registry가 아닌 경우에만 이 코드를 쓴다(registry 이름·버전이 확실하면 대조한다). SVC-03은 요청의 출처 검사(`inputs/npm.py`의 `registry_version_problem()`)가 문제를 돌려주는 변경(workspace·link, semver가 아닌 버전, registry 밖 tarball)만 이 코드로 두고, `missing_integrity`·`same_version_artifact_changed`와 registry tarball인 `package_identity_changed`는 대조한다. 출처 검사가 URL을 파싱하지 못하면 이 코드가 아니라 `input_failed`다 |
| `analyzer_not_configured` | `not_run` | 탐지기에 필요한 분석 입력(tarball, 추출)을 만드는 분석기가 이 실행에 연결되지 않음(`--analysis`·`--extract` 없는 `scan`, 항목 `reason`은 `analysis_missing`, 최상위 `analyzer_version`은 null). 이름·버전만 쓰는 기지 악성 대조에는 해당하지 않는다 |
| `analysis_unsupported` | `not_run` | 연결된 분석기가 이 변경을 `unsupported`로 돌려줘 탐지기에 필요한 분석 입력을 만들지 않음. 항목 `reason`·`detail`에 분석기의 이유가 있다(`ExtractorAnalyzer`는 prerelease면 `out_of_training_scope`, 비교할 이전 stable이 없으면 `no_baseline`). 기지 악성 대조에는 해당하지 않는다(채택(D-5)대로 `no_baseline`도 이름·버전으로 대조) |
| `input_failed` | `failed` | 탐지기에 필요한 입력을 얻지 못함. 규칙: 연결된 분석기에서 분석 입력을 얻지 못함(항목 `reason`이 `analysis_failed`이거나, 분석기가 연결됐는데 `analysis_missing`). 항목 `reason`·`detail`에 원래 실패가 있다. 기지 악성: 분석 대상이 아닌 변경의 출처 검사(`registry_version_problem()`)가 tarball URL을 파싱하지 못해 대조할 registry 이름·버전을 확정하지 못함(SVC-03-FIX-01 m1). 원인은 `known_malicious.detail`에 있다 |
| `detector_failed` | `failed` | 탐지기 자체가 오류로 끝났거나(`detail`에 설명), 실행한 규칙 중 적중 없이 실패한 규칙이 있음(`checks[].detail`에 설명). 기지 악성: 최상위 `detectors.known_malicious.list_as_of`가 문자열이지만 형식이 어긋난 목록으로 대조해 일치가 없음(`detail`에 설명, 3.1절, SVC-03-FIX-01 n3) |

`analysis_unsupported`를 새로 둔 이유: 기존 `not_analyzable`은 분석기를 부르기 전 요청 단계(`analyzable=false`)의 이유라 분석기의 판단과 섞지 않는다. 항목 `reason` 값(`no_baseline` 등)을 그대로 쓰지 않는 것은 위 이름공간 구분 때문이다. 근거 코드: `ExtractorAnalyzer._analyze_change()`는 prerelease면 registry 조회 전에(`extractor.py` 332~337행), 이전 stable이 없으면 baseline 선정 직후 다운로드 전에(347~353행) `unsupported`를 돌려주므로 규칙이 볼 tarball이 없다. 새 버전 하나만으로 규칙을 실행하도록 바꿀지는 정하지 않았다(SVC-00 계획에 없음). 추론 단계의 `out_of_training_scope`(4.1절, `OutOfScopeError`)는 분석을 마친 뒤라 규칙 입력이 있으므로 이 코드를 쓰지 않는다.

## 4. 상태 의미표

### 4.1 ML 위험 점수: `ml.status`와 기존 필드

`ml.status`는 ML 경로의 결과(탐지기를 반영하기 전의 항목 `status`·`reason`)와 분석기 연결 여부에서 정해지는 값이다. `pipeline.scan()`은 이 값을 ML 경로를 처리하면서 직접 정하고(`pipeline.py`의 `ml` 변수), 분석기 연결 여부는 인자(`analyzer`가 None인지)로 안다.

`analysis_missing`은 90a61bb 코드에서 두 경로로 나온다.

- 분석기 미연결: `service.scan_project()`는 `--analysis`와 `--extract`가 모두 없으면 분석기를 None으로 넘기고, `pipeline.scan()`은 분석 대상인 모든 변경을 `analysis_missing`(`incomplete`, 종료 코드 2)으로 둔다. 최상위 `analyzer_version`은 null이다. 분석기가 실행되지 않았으므로 `ml.status`는 `not_run`이다.
- 연결된 분석기의 결과 누락: `--analysis` 파일이 어떤 분석 대상 변경의 결과를 담지 않으면 `analysis.artifact.validate()`가 통과시키고 `pipeline.scan()`이 그 변경을 `analysis_missing`으로 둔다. 최상위 `analyzer_version`은 문자열이다. 연결된 분석기가 결과를 내지 못한 것이므로 `ml.status`는 `failed`다. `--extract`(`ExtractorAnalyzer`)와 `check`는 분석 대상 변경마다 결과(`complete`·`failed`·`unsupported`)를 만들므로 이 경로로 `analysis_missing`을 내지 않는다.

분석기가 `unsupported`를 돌려준 변경은 `pipeline.scan()`의 `unsupported` 분기가 항목 `status`를 `incomplete`로 두고 `reason`에 분석기의 이유 코드, `detail`에 분석기의 설명을 옮긴다(`score`는 null, 종료 코드 2). `analysis.artifact.validate()`는 이유 코드가 비어 있지 않은 문자열인지만 검사한다. [연결 규약](contracts.md) 2절은 `out_of_training_scope`, `no_baseline`을 쓴다고 정하고 `ExtractorAnalyzer`도 이 둘만 내지만, `--analysis` 파일은 다른 코드를 담아도 통과한다. 분석기가 모델의 범위 밖이라고 판단해 ML을 실행하지 않은 것이므로 이유 코드와 관계없이 `ml.status`는 `not_run`이다.

| ML 경로의 항목 `status` | ML 경로의 항목 `reason` | `ml.status` | `score` | 항목의 종료 코드 기여(탐지기 반영 전) |
|---|---|---|---|---|
| `flagged` | 없음 | `hit` | 숫자, `>= threshold` | 1 |
| `not_flagged` | 없음 | `not_hit` | 숫자, `< threshold` | 0 |
| `incomplete` | `model_missing` | `not_run` | null | 2 |
| `incomplete` | `out_of_training_scope`(추론 단계의 `OutOfScopeError`) | `not_run` | null | 2 |
| `incomplete` | 분석기가 `unsupported`로 돌려준 이유 코드(`out_of_training_scope`, `no_baseline`, `--analysis` 파일의 그 밖의 코드) | `not_run` | null | 2 |
| `incomplete` | 변경의 이유(`package_identity_changed`, `workspace_or_non_registry_version`, `unsupported_registry_source`, `missing_integrity`, `same_version_artifact_changed`) | `not_run` | null | 2 |
| `incomplete` | `analysis_missing`, 분석기 미연결(최상위 `analyzer_version` null) | `not_run` | null | 2 |
| `incomplete` | `analysis_missing`, 분석기 연결됨(최상위 `analyzer_version` 문자열) | `failed` | null | 2 |
| `incomplete` | `analysis_failed`, `inference_failed` | `failed` | null | 2 |
| `removed` | `not_installed_in_head` | `not_run` | null | 0 |

기존 보고서(새 필드 없음) 해석의 한계: 위 표는 기존 보고서에도 적용할 수 있지만, `analysis_missing` 두 행의 구분은 항목 필드만으로는 안 되고 최상위 `analyzer_version`에 기댄다. 이것은 90a61bb 코드의 성질(분석기가 None일 때만 null이고, 연결된 분석기의 결과는 `validate()`가 비어 있지 않은 문자열을 요구함)에서 나온 추론이며 보고서 계약으로 정한 규칙이 아니다. 분석기를 여럿 연결하거나 `analyzer_version` 없이 결과를 받는 경로가 생기면 기존 보고서만으로는 확실히 구분할 수 없다. 분석기의 `unsupported` 이유도 같다. 표에 없는 이유 코드는 분석기의 `unsupported`로 보고 `not_run`으로 읽지만, 분석기가 표에 있는 코드(예: `analysis_failed`)를 이유로 쓰면 기존 보고서만으로는 구분할 수 없다. `pipeline.scan()`은 분석 결과의 `status`를 직접 보므로 새 필드에서는 이 문제가 없다. 그래서 기존 보고서를 이 표로 해석한 `not_run`/`failed`는 참고값이고, 확정 값은 새 필드 `ml.status`다(채택(D-12)). 기존 `reason`, `status`, `exit_code`는 바꾸지 않는다.

`ml.status`가 `not_run`이어도 항목은 ML 경로에서 `incomplete`(종료 코드 2)이므로 미실행이 통과로 바뀌지 않는다(기지 악성 `hit`이면 `flagged`, 4.2절). `ml.status`를 따로 두는 이유는 미실행(분석기·모델 미연결, 범위 밖 입력)과 실패(분석·추론 오류, 연결된 분석기의 결과 누락)를 진입점마다 다시 나누지 않게 하려는 것이다(채택(D-12)).

위 표의 항목 `status`·`reason`과 종료 코드 기여는 ML 경로만의 값이다. SVC-03부터 탐지기가 연결된 실행에서는 채택(D-2)·채택(D-7)로 항목 `status`가 탐지기 결과로도 바뀌므로(예: 기지 악성 `hit`이면 점수가 낮아도 `flagged`, 4.2절), `pipeline.scan()`은 `ml.status`를 최종 항목 `status`가 아니라 ML 경로의 결과(점수와 임계값 비교, 분석·추론 상태)로 정한다. 새 필드가 있는 보고서의 `ml.status`를 이 표로 다시 계산하거나 최종 항목 `status`에서 거꾸로 해석하지 않는다. 탐지기 미연결 실행에서는 최종 항목 `status`가 ML 경로 값과 같다.

### 4.2 기지 악성과 규칙: 항목 `status`·종료 코드와의 관계

아래 첫 표는 채택(D-2)·채택(D-7)을 적용하기 전(SVC-02까지 초안의 규칙)의 관계이고 기록으로 남긴다. SVC-03부터는 그다음 표(채택 후)가 구현이다(`pipeline.scan()`에서 `_known_malicious()`·`_rules()`의 결과로 항목 `status`를 고치는 D-2·D-7 분기).

| `known_malicious.status` / `rules.status` | 항목 `status` | 최상위 `exit_code` | 표시 |
|---|---|---|---|
| `hit` | 바꾸지 않음(ML 경로대로) | 바꾸지 않음 | 기지 악성 `hit`은 경고로 눈에 띄게 표시하고 낮은 점수로 숨기지 않는다. 규칙 `hit`은 근거와 함께 표시한다 |
| `not_hit` | 바꾸지 않음 | 바꾸지 않음 | "미적중". 정상·안전으로 쓰지 않는다 |
| `not_run` | 바꾸지 않음 | 바꾸지 않음 | "미실행"과 이유. 미적중과 다른 문구 |
| `failed` | 바꾸지 않음 | 바꾸지 않음 | "실패"와 설명. 미실행·미적중과 다른 문구 |

그래서 적용 전 규칙대로면 기지 악성 `hit`과 낮은 ML 점수가 함께 있는 항목은 `not_flagged`, 최상위 `exit_code` 0이 될 수 있었다(예시 3의 적용 전 값). 종료 코드만 보는 소비자는 이 경고를 놓친다. 그래서 다음을 채택했고 SVC-03에서 적용했다. 적용 내용은 9.1절에 있다.

| 탐지기 결과 | 채택 후 항목 `status` | 채택 후 최상위 `exit_code` | 근거 |
|---|---|---|---|
| 기지 악성 `hit` | `flagged`. `score`는 그대로 남는다 | 1 이상(다른 항목이 미완료면 2) | 채택(D-2) |
| 연결된 탐지기의 `failed` | `incomplete`. ML 경로가 완료(`flagged`/`not_flagged`)였으면 항목 `reason`은 `detection_failed`(SVC-03에서 정함, 하람 승인(11/13))이고 `score`는 지우지 않는다. ML 경로가 이미 `incomplete`면 그 `reason`·`detail`을 유지한다 | 2 | 채택(D-7) |
| 탐지기 미연결(`not_run`, `detector_not_configured`) | 바꾸지 않음 | 바꾸지 않음 | 채택(D-6). 정책 파일이 생기면 필수 여부를 거기서 정한다 |
| 규칙 `hit`, 규칙/ML 불일치 | 바꾸지 않음 | 바꾸지 않음 | 채택(D-4) |
| 규칙 일부 `failed`와 다른 규칙 `hit`이 함께 있음(`rules.status`는 `hit`) | 바꾸지 않음. 실패한 규칙은 `checks[]`에 `failed`로 남는다 | 바꾸지 않음 | 'hit 우선, 실패한 규칙은 따로 표시'는 Clover 결정(11/13, SVC-03-FIX-01 m3). 그 결과 ML 점수가 낮으면 항목이 `not_flagged`·0인 것은 Clover 결정이 아니라 3.2절의 규칙 집계(SVC-03 이전 계약 `0ccd0f9`와 같음)와 채택(D-4)을 따른 결과다. 아래 문단 |
| 한 항목에 기지 악성 `hit`(D-2)과 연결된 탐지기의 `failed`(D-7)가 함께 있음 | `flagged`(종료 코드 기여 1이 우선) | 1 이상(다른 항목이 미완료면 2) | 하람·Clover 확정(11/11, Clover 전달 작업 지시) |
| 한 항목에 기지 악성 `hit`과 ML 경로의 미완료가 함께 있고 D-7은 없음 | `flagged`. ML 경로의 `reason`·`detail`과 `ml.status`(4.1절 값 그대로: ML이 실행되지 않았으면 `not_run`, 실행하려다 실패했으면 `failed`)는 남긴다 | 1 이상(다른 항목이 미완료면 2) | 11/13 Clover 지시로 확정(SVC-03), `ml.status`는 4.1절·채택(D-12) |

`detection_failed`를 고른 이유: 항목 `reason`의 기존 실패 코드가 단계 이름에 `_failed`를 붙인 꼴(`analysis_failed`, `inference_failed`)이라 같은 꼴로 탐지 단계를 나타냈다. 탐지기 칸의 이유 코드 `detector_failed`(3.3절)와는 이름공간이 달라 같은 이름을 쓰지 않았다. 어느 탐지기가 왜 실패했는지는 그 탐지기 칸의 `status`·`reason`·`detail`에 있다.

한 항목에 채택(D-2)과 채택(D-7)이 함께 걸리면 항목은 `flagged`, 종료 코드 기여 1이 우선한다. 근거는 1절 계약 문장 "낮은 ML 점수는 기지 악성 경고를 취소하지 않는다"에 담긴, 기지 악성 경고를 다른 결과로 취소하지 않는다는 원칙이고, 이 우선순위는 Clover가 전달한 이번 작업 지시(하람·Clover 확정, 11/11)로 정해졌다. 이때도 실패한 탐지기는 자기 칸(`rules.status`의 `failed`와 `rules.reason`의 이유 코드처럼 해당 탐지기 칸의 `failed`와 이유 코드)에 실패 근거로 따로 보여 준다. 최상위 집계(`pipeline.scan()` 끝의 `exit_code` 계산, 미완료 2 > 위험 1 > 0, SVC-03에서 바꾸지 않음)대로면 다른 미완료 항목이 없을 때 최상위는 `flagged`/1이므로, 그 탐지기의 실패는 `status`·`exit_code`가 아니라 탐지기 칸에서 드러난다. 이 우선순위에는 조건이 없다. 항목이 ML 경로에서 이미 `incomplete`여도(예: 규칙이 `input_failed`인 `analysis_failed` 항목에 기지 악성 `hit`이 나온 경우) D-2와 D-7이 함께 성립하면 항목은 `flagged`, 종료 코드 기여 1이다. 이때 ML 경로의 미완료는 기존 `reason`·`detail`과 `ml.status`에, 실패한 탐지기는 그 탐지기 칸에 각각 따로 남는다.

기지 악성 `hit`과 ML 경로의 미완료가 한 항목에 함께 있고 D-7(연결된 탐지기의 `failed`)은 걸리지 않는 경우에는 항목 `flagged`, 종료 코드 기여 1이다(11/13 Clover 지시로 확정, SVC-03에서 적용). ML 경로의 미완료는 기존 `reason`·`detail`과 `ml.status`에 남는다. `ml.status`는 4.1절 표의 값을 그대로 쓰며 기지 악성 `hit`으로 바뀌지 않는다(3.2절, 채택(D-12)). 그래서 11/13 Clover 지시의 "ML `not_run`"은 ML이 실행되지 않은 경우의 값이다(`no_baseline` 등 분석기의 `unsupported`, `model_missing`, 추론 단계의 `out_of_training_scope`, 분석기 미연결의 `analysis_missing`, 분석 대상이 아닌 변경). 예: `no_baseline` 항목을 채택(D-5)대로 대조해 `hit`이 나오고 규칙은 `not_run`이면 `ml.status`는 `not_run`이다. ML을 실행하려다 실패한 경우(4.1절이 `failed`로 정하는 `analysis_failed`, 분석기가 연결된 `analysis_missing`, `inference_failed`)에는 기지 악성 `hit`이어도 `ml.status`는 `failed`로 남고 판정은 `flagged`/1이다(SVC-03-FIX-01 m2, Clover 확인, 동작 변경 없음). 이 중 D-7 없이 나오는 경로는 규칙 탐지기가 연결되지 않은 실행의 `analysis_failed`·`analysis_missing`, 그리고 `inference_failed`(규칙 탐지기가 분석 결과로 정상 실행된 경우 포함)다. 규칙 탐지기가 연결된 실행의 `analysis_failed`·`analysis_missing`은 규칙이 `input_failed`라 D-7이 함께 걸리고, 판정은 위 문단대로 같은 `flagged`/1이다. 최상위 집계는 최종 항목 `status`만 보므로 다른 미완료 항목이 없으면 최상위는 `flagged`/1이고, `status`·`exit_code`만 보는 소비자에게 그 항목의 ML 미완료는 드러나지 않는다(항목 `reason`과 `ml.status`에 있다). 일치 내용은 `known_malicious`에 남는다(1절 계약 문장).

규칙 일부 실패의 해석(채택(D-7) 항목 이름의 "일부 규칙 실패", SVC-03-FIX-01 m3): 결정 출처를 나눠 적는다(REV-SVC-03-R2 M1).

- Clover 결정(11/13): 규칙 `hit`이 실패한 규칙보다 우선하고(`rules.status`는 `hit`), 실패한 규칙은 따로 표시한다. 채택(D-7)은 `rules.status`가 `failed`일 때만 걸린다. 실행한 규칙 중 적중 없이 실패한 규칙이 있으면 `rules.status`가 `failed`(`detector_failed`)라 항목은 `incomplete`·2다. 다른 규칙이 `hit`이면 채택(D-7)은 걸리지 않고, 실패한 규칙은 `checks[]`에 `failed`와 `detail`로 따로 남아 실패를 정상으로 바꾸지 않는다. 경고 근거가 실패를 덮되 실패를 숨기지 않는다는 점에서 위 D-2·D-7 겹침과 같은 원칙이다.
- Clover 결정이 아닌 부분: 규칙 `hit`은 채택(D-4)대로 항목 `status`를 바꾸지 않으므로, ML 점수가 기준 미만이면 그 항목은 `not_flagged`(종료 코드 기여 0)이고 규칙 적중과 실패는 `rules` 칸과 `rule_ml_agreement`(`rule_only`)에서만 드러난다. 이것은 SVC-03 이전 계약(`0ccd0f9`의 이 문서 112행)의 규칙 집계(하나라도 `hit`이면 `hit`)와 채택(D-4)을 함께 적용한 결과다. 새 OR·AND 결합 정책이 아니다.
- 이 조합의 성질(사실 기록, 정책 판단 아님): 기지 악성 일치가 없고 ML 점수가 기준 미만일 때, 규칙이 `[failed]`뿐이면 항목은 `incomplete`·2(`detection_failed`)인데 여기에 적중한 규칙 하나를 더한 `[hit, failed]`는 `not_flagged`·0이다. 규칙 근거가 늘었는데 종료 코드가 2에서 0으로 내려가므로 종료 코드는 규칙 결과에 단조적이지 않다(`pipeline.py`의 `_rules()` 집계와 D-7 분기, `tests/test_detectors.py`의 `test_a_rule_hit_with_a_failed_rule_is_not_d7`). 이 효과를 의도한 것으로 볼지는 정해지지 않았다(SVC-04 보고의 결정 필요 항목).

### 4.3 규칙/ML 불일치: `rule_ml_agreement`

| `rules.status` | `ml.status` | `rule_ml_agreement` | 불일치 |
|---|---|---|---|
| `hit` | `hit` | `both_hit` | 아니오 |
| `hit` | `not_hit` | `rule_only` | 예 |
| `not_hit` | `hit` | `ml_only` | 예 |
| `not_hit` | `not_hit` | `neither_hit` | 아니오. 두 탐지기의 미적중일 뿐 정상 판정이 아니다 |
| 하나라도 `not_run` 또는 `failed` | | `undetermined` | 판단하지 않음. 실패·미실행은 각 탐지기 칸과 항목 `status`가 나타낸다 |

불일치는 표시만 하고 항목 `status`나 `exit_code`를 바꾸지 않는다. `incomplete`로 만들지 않는다. 불일치의 처리 정책(근거별 표시 유지, OR, AND, 규칙 종류별 우선순위)은 실험 뒤 결정한다(채택(D-4)). 기지 악성 `hit`은 이 값과 별개의 경로이며, 이 값의 어떤 경우도 기지 악성 경고를 취소하지 않는다.

## 5. 패키지와 외부 기록에서 온 문자열

새 필드 중 아래 값은 패키지나 외부 기록에서 올 수 있으므로 지시가 아니라 데이터로 다룬다. 기존 `evidence`·`detail`과 같은 규칙을 적용한다.

- 대상: `rules.checks[].evidence`, `rules.checks[].locations[].file`, `rules.checks[].detail`, `rules.detail`, `known_malicious.detail`, `known_malicious.matches[].advisory_id`, `known_malicious.matches[].affected`, `detectors.known_malicious.source`, `detectors.rules.ruleset_version`, 그리고 알 수 없는 상태·이유 코드.
- 텍스트 출력은 제어 문자를 `\uXXXX`로 바꾼다(`cli._clean`).
- Markdown 출력은 그 뒤 안의 어떤 백틱 묶음보다 긴 백틱의 code span으로만 넣고, 표 칸에서는 `|`를 `\|`로 쓴다(`cli._md`, `cli._cell`, [연결 규약](contracts.md) 4절). depbee가 만든 한국어 문구와 숫자만 code span 밖에 둔다.
- JSON은 지금처럼 `ensure_ascii=True`로 쓴다. 웹은 HTML 이스케이프, MCP는 별도 필드에 길이를 제한해 담고 패키지에서 온 데이터이며 지시가 아님을 표시한다(진입점별 세부는 SVC-05·SVC-07).

## 6. 호환성

- 새 필드만 추가하는 단계(SVC-02)와 SVC-03의 탐지기 미연결 실행에서는 기존 소비자가 새 필드를 무시해도 뜻이 그대로다. `status`, `reason`, `score`, `exit_code`는 지금과 같은 규칙으로 계산되고, 새 필드는 그 값에서 아무것도 빼거나 덮지 않는다. SVC-03은 채택(D-2)·채택(D-7)을 적용하므로 탐지기가 연결된 실행에서는 기존 `status`·`exit_code`의 계산이 바뀐다(4.2절의 우선순위, 9.1절, `schema_version`은 7절).
- 새 필드가 없는 보고서(이 초안 이전 출력)는 "정보 없음"으로 해석한다. `known_malicious`나 `rules`가 없다는 것을 `not_hit`으로 읽지 않는다. 표시할 때는 "확인 안 됨"으로 쓴다. `ml`이 없으면 4.1절 표로 기존 필드에서 구하되, `analysis_missing`의 미실행·실패 구분과 분석기 `unsupported` 이유의 해석은 참고값이다(4.1절의 한계, 채택(D-12)).
- 필드가 있고 값이 `not_run`이면 그 실행에서 탐지기가 돌지 않았다는 뜻이고, 이유가 함께 있다. "필드 없음"(구버전)과 구분한다.
- 결과 순서(위험 → 보류 → 통과 → 삭제, 같은 판정 안에서는 ML 위험 점수 내림차순)는 바뀌지 않는다. 새 칸의 표시는 채택(D-13)대로 SVC-04에서 텍스트·Markdown에 넣었다(8절 "텍스트·Markdown 렌더"). JSON 출력은 SVC-04에서 바뀌지 않았다.
- 보고서 JSON 전체를 비교하는 기존 테스트가 있으면 새 필드가 생기는 단계(SVC-02·SVC-03)에서 기대값을 함께 고쳐야 한다. SVC-03에서는 보고서 키 순서를 비교하던 `tests/test_cache.py`의 기대값에 `detectors`를 넣었고, 탐지기 미연결 보고서에서 새 필드를 빼면 그 전 보고서와 같음을 확인한다. 나머지 기존 테스트는 고치지 않고 통과했다.

## 7. schema_version 영향 (채택(D-1))

지금 `contracts.SCHEMA_VERSION`(1) 하나를 요청(1절), 분석 결과(2절), 모델 manifest(3절), 보고서(4절)가 함께 쓴다. `LightGBMPredictor`와 `analysis.artifact.validate()`는 이 값이 정확히 1인지 검사한다.

| 안 | 내용 | 영향 |
|---|---|---|
| A. 1 유지 | 추가만 하므로 그대로 둔다 | 기존 소비자와 모델·분석 파일이 그대로 동작한다. `input_kind`, `elapsed_seconds`, `cache_hit`도 1을 유지한 채 추가했다. 소비자는 필드 유무로 초안 이후 보고서를 구분한다 |
| B. 공유 값을 2로 올림 | `SCHEMA_VERSION = 2` | 이미 만든 manifest와 분석 JSON이 거부된다. 보고서만 바뀌는데 모델 재발급이 필요해진다 |
| C. 보고서 버전을 따로 둠 | 보고서에 별도 버전 필드(예: `report_version`)를 추가하거나 보고서용 상수를 분리 | 공유 값과 분리돼 다른 파일에 영향이 없다. 버전 필드 하나가 늘고 [연결 규약](contracts.md)의 "필드를 바꿀 때 `schema_version`을 올린다" 문장의 대상을 고쳐야 한다 |

채택안: A. 이유는 추가만 하는 변경이고 같은 방식의 선례가 있으며, B는 보고서와 무관한 모델·분석 파일을 깨뜨린다. 권장안은 "기존 필드의 뜻을 바꾸는 결정(D-2 등)이 채택되면 그때 C를 다시 검토한다"였는데, D-2가 같은 날 함께 채택됐다. 따라서 C 재검토는 채택(D-2)·채택(D-7)을 적용하는 SVC-03(하람 확정, 11/11)을 시작하기 전에 해야 한다. C 재검토의 결과: 하람이 11/13에 `schema_version` 1 유지(A)로 정했고 C는 채택하지 않았다(Clover 전달, SVC-03-FIX-01 m4). 하람의 결정에는 이유가 따로 적혀 있지 않다. 아래는 이 문서에 이미 있는 근거이며 하람의 말이 아니다.

- 새 필드는 모두 추가만 한다. 기존 키의 이름·값·순서를 바꾸지 않는다(3절).
- 기존 필드의 계산이 바뀌는 것(채택(D-2)·채택(D-7))은 탐지기가 연결된 실행에서만 생기고, 지금 진입점(CLI 등)은 탐지기를 연결하지 않으므로 지금 출력의 `status`·`exit_code`는 그 전과 같다(1절 계약 문장, 6절).
- B는 보고서와 무관한 모델 manifest·분석 파일을 깨뜨린다(위 표).

남는 영향: 채택(D-2)로 `flagged`의 뜻이 "ML 위험 점수가 기준 이상"에서 "ML 위험 점수가 기준 이상이거나 기지 악성 기록과 일치"로 넓어졌다(8절 예시 3). `schema_version`으로는 이 차이를 구분할 수 없으므로, 소비자는 `known_malicious.status`(`hit`이면 기지 악성 일치)와 `ml.status`(ML 경로만의 결과)로 어느 근거인지 구분한다. 이 필드가 없는 보고서는 SVC-03 이전 출력이며 `flagged`는 ML 경로만의 판정이다(6절).

## 8. 예시

[`examples/result-contract/`](examples/result-contract/)의 JSON 여섯 개는 모두 합성이다. 패키지 이름은 `example-`·`demo-`로 시작하는 가짜 이름이고, `request_id`, `change_id`, 해시는 반복 패턴의 가짜 값이며, 기록 식별자는 `EXAMPLE-ADVISORY-0001`이다. 실제 보고서와 같은 기존 최상위 필드와 키 순서를 따르되, 읽기 쉽게 한국어를 그대로 썼다(실제 CLI JSON은 `ensure_ascii=True`라 `\uXXXX`로 나온다. 값은 같다). `explanation`의 기여도, `explanation_rest`, `base_value`를 더하면 점수의 log-odds가 되도록 맞췄다. 키 순서는 3절 서술(새 필드 다음에 시간 필드)을 따르며 SVC-03 구현의 출력 순서와 같다. 기존 필드의 값과 `status`·`exit_code`는 모두 SVC-03 구현(채택(D-2)·채택(D-7) 적용 후)의 규칙으로 계산한 값이다. 탐지기가 연결된 예시(05 말고 모두)는 가짜 탐지기를 연결한 실행을 가정한다. 지금 CLI에는 탐지기를 연결하는 옵션이 없다.

| 파일 | 상황 | 항목 `status` | 최상위 `status` / `exit_code` |
|---|---|---|---|
| `01-rule-only.json` | 규칙 적중, ML 기준 미만(`rule_only`) | `not_flagged` | `passed` / 0 |
| `02-ml-only.json` | ML 기준 이상, 규칙 미적중(`ml_only`) | `flagged` | `flagged` / 1 |
| `03-known-malicious-low-ml.json` | `check`, 기지 악성 일치, ML 점수 낮음 | `flagged` | `flagged` / 1 |
| `04-analysis-failed.json` | 한 항목 다운로드 실패, 한 항목 통과 | `incomplete`, `not_flagged` | `incomplete` / 2 |
| `05-detectors-not-configured.json` | 지금 main: 기지 악성·규칙 탐지기 없음 | `not_flagged`, `removed` | `passed` / 0 |
| `06-analyzer-not-configured.json` | `--analysis`·`--extract` 없는 `scan`(분석기 미연결), 기지 악성·규칙 탐지기는 연결 | `incomplete`(`analysis_missing`) | `incomplete` / 2 |

예시 06은 분석기가 없어 `_timed()`를 거치지 않으므로 시간 필드(`elapsed_seconds`, `cache_hit`)가 없고 최상위 `analyzer_version`과 `provenance.feature_extractor`가 null이다. 기지 악성 대조는 이름·버전만 쓰므로 실행되고(`not_hit`), 규칙은 분석 입력이 없어 `not_run`(`analyzer_not_configured`), `ml.status`는 `not_run`이다(4.1절).

예시 1의 종료 코드 0은 규칙 적중이 통과라는 뜻이 아니다. 규칙 `hit`과 불일치는 `status`를 바꾸지 않는다(채택(D-4)). 채택(D-2)·채택(D-7)을 적용하기 전(SVC-02까지)과 지금(SVC-03, 예시 JSON)의 값은 아래와 같다.

| 파일 | 적용 전 값(SVC-02까지) | 지금 값(예시 JSON) | 근거 |
|---|---|---|---|
| `01-rule-only.json` | `not_flagged`, `passed` / 0 | 같음 | 규칙 `hit`과 불일치는 `status`를 바꾸지 않음(채택(D-4)) |
| `02-ml-only.json` | `flagged`, `flagged` / 1 | 같음 | |
| `03-known-malicious-low-ml.json` | `not_flagged`, `passed` / 0 | 항목 `flagged`, 최상위 `flagged` / 1. `score` 0.04와 `ml.status: not_hit`, `rule_ml_agreement: neither_hit`은 그대로 | 채택(D-2) |
| `04-analysis-failed.json` | `incomplete`·`not_flagged`, `incomplete` / 2 | 같음. 규칙 `failed`(`input_failed`)인 항목은 ML 경로에서 이미 `incomplete`라 `reason`(`analysis_failed`)·`detail`을 유지한다 | 채택(D-7) |
| `05-detectors-not-configured.json` | `not_flagged`·`removed`, `passed` / 0 | 같음 | 채택(D-6) |
| `06-analyzer-not-configured.json` | `incomplete`, `incomplete` / 2 | 같음 | 규칙 `not_run`은 영향 없음(채택(D-6)) |

예시 3처럼 기지 악성으로 `flagged`가 된 항목은 `score`가 `threshold`보다 낮을 수 있다. 그래서 SVC-03부터는 "`flagged`이면 점수가 기준 이상"이라는 성질이 탐지기가 연결된 실행에서 성립하지 않고, ML 판정은 `ml.status`로 본다(4.1절).

### 텍스트·Markdown 렌더 (예시 3)

아래는 예시 3의 JSON을 SVC-04의 `cli._print_markdown()`·`cli._print_text()`로 렌더한 실제 출력이다(채택(D-13)). 표시 규칙은 다음과 같다.

- 표시만 한다. 판정(`status`), 이유(`reason`), 종료 코드(`exit_code`), 탐지기 칸의 상태와 `ml.status`는 보고서 값을 그대로 읽고 진입점에서 다시 계산하지 않는다. JSON 출력(`--format json`, `--output`)은 바뀌지 않았다.
- 순서는 그대로다(위험 → 보류 → 통과 → 삭제, 같은 판정 안에서는 ML 위험 점수 내림차순). 기지 악성 경고를 맨 앞으로 옮기지 않고 강조한다.
- 머리 목록: 기지 악성 `hit` 항목이 있으면 "경고: 기지 악성 기록 일치 N개."와 낮은 ML 위험 점수가 경고를 취소하지 않는다는 문장, `incomplete` 항목이 있으면 "보류 N개."와 통과가 아니라는 문장을 넣는다(Markdown은 앞부분을 굵게). 이어서 최상위 `detectors`로 탐지기 연결 상태를 적는다. 연결되지 않은 탐지기는 "연결 안 됨(미실행)"으로 한 번만 적고 항목마다 반복하지 않는다.
- 점수는 "ML 위험 점수"로 적고 확률로 표현하지 않는다. 점수 뒤에 `ml.status`(`hit`은 "기준 이상", `not_hit`은 "기준 미만")를 붙여, 기지 악성으로 위험이 된 항목의 점수가 기준 미만임을 보인다. 점수가 없는 항목은 `ml.status`에 따라 "없음(미실행)"과 "없음(실패)"를 나눈다(삭제 항목은 적지 않는다).
- 탐지기 칸: 연결된 탐지기만 항목마다 적는다. 상태는 기지 악성 `hit`을 "일치", 규칙 `hit`을 "적중", `not_hit`을 "미적중", `not_run`을 "미실행", `failed`를 "실패"로 쓰고, 이유 코드(3.3절)와 `detail`을 함께 적는다. 기지 악성 일치 기록과 실행한 규칙(`checks[]`, 실패한 규칙 포함)은 하위 목록이다. Markdown 결과 표에는 연결된 탐지기마다 칸(기지 악성, 규칙)을 더하고 기지 악성 일치를 굵게 쓴다. 탐지기가 하나도 연결되지 않은 보고서의 표는 기존 일곱 칸(시간이 있으면 여덟 칸) 그대로이고 "점수" 머리글만 "ML 위험 점수"다.
- `rule_ml_agreement`는 규칙 탐지기가 연결된 항목에만 "규칙/ML: ..."로 적고 "판정에 쓰지 않는 표시입니다."를 붙인다. `neither_hit`은 정상 판정이 아니라고 적는다.
- 패키지와 외부 기록에서 온 문자열(5절의 대상 전부)은 기존 규칙대로 텍스트는 `cli._clean`, Markdown은 `cli._md`(code span)와 `cli._cell`로 넣는다. 안전 보증이 아니라는 끝 문구는 그대로다.

````markdown
## depbee 검사 결과: 위험 판정 있음 (종료 코드 1)

- 검사한 패키지 1개: 위험 1, 통과 0, 보류 0
- **경고: 기지 악성 기록 일치 1개.** 낮은 ML 위험 점수는 이 경고를 취소하지 않습니다. 이 일치로 위험 판정했습니다.
- 모델: ` example-model-001 `, 판정 기준 점수 0.5
- 기지 악성 목록: ` EXAMPLE-KNOWN-MALICIOUS-LIST `, 기준 시점 ` 2026-11-01T00:00:00Z `
- 규칙: ` example-ruleset-0.0.0 `
- 범위: lockfile 없이 registry 정보로 이 버전 하나만 검사했습니다. 프로젝트 전체의 안전성 평가가 아닙니다.
- 소요 시간: 2.468초

| 판정 | 패키지 | 설치될 버전 | 비교 버전 | 기지 악성 | 규칙 | ML 위험 점수 | 이유 | 위치 | 분석 시간 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 위험 | ` demo-config-loader ` | ` 2.0.1 ` | ` 2.0.0 ` | **일치** | 미적중 | 0.040 (기준 미만) | - | ` registry.npmjs.org ` | 2.101초 |

### 위험: ` demo-config-loader@2.0.1 `

- 기지 악성: 일치
  - ` EXAMPLE-ADVISORY-0001 ` (버전 목록에 있음, 영향 버전 ` 2.0.1 `)
- 규칙: 미적중
  - 미적중 ` EXAMPLE-RULE-0001 ` ` 0.0.0-example `
  - 미적중 ` EXAMPLE-RULE-0002 ` ` 0.0.0-example `
- 규칙/ML: 둘 다 미적중(정상 판정이 아님). 판정에 쓰지 않는 표시입니다.
- 추출된 사실:
  - ` 비교: 2.0.0 → 2.0.1 (같은 release line의 직전 stable) `
  - ` lockfile 없이 registry 정보로 검사 `
  - ` 추가·수정된 JS 파일 1개 `
- 모델 설명, ML 위험 점수에 크게 작용한 특징(기여도 + 위험 쪽, - 정상 쪽):
  - 설치 스크립트 추가 = ` 아니오 ` (-1.40)
  - 새 버전에 설치 스크립트 있음 = ` 아니오 ` (-0.90)
  - 추가·수정된 JS 파일 수 = ` 1 ` (+0.20)
  - 나머지 특징 26개 합 -0.08, 모델 기준값 -1.00 (합계 -3.18 → 점수 0.040)

> '통과'는 모델의 판정일 뿐 패키지가 안전하다는 보증이 아닙니다.
````

````text
depbee 검사 결과: 위험 판정 있음 (종료 코드 1)
검사한 패키지 1개: 위험 1, 통과 0, 보류 0
경고: 기지 악성 기록 일치 1개. 낮은 ML 위험 점수는 이 경고를 취소하지 않습니다. 이 일치로 위험 판정했습니다.
모델: example-model-001, 판정 기준 점수 0.5
기지 악성 목록: EXAMPLE-KNOWN-MALICIOUS-LIST, 기준 시점 2026-11-01T00:00:00Z
규칙: example-ruleset-0.0.0
범위: lockfile 없이 registry 정보로 이 버전 하나만 검사했습니다. 프로젝트 전체의 안전성 평가가 아닙니다.
소요 시간: 2.468초

[위험] demo-config-loader@2.0.1  (registry.npmjs.org)
  ML 위험 점수: 0.040 (기준 미만)
  기지 악성: 일치
    - EXAMPLE-ADVISORY-0001 (버전 목록에 있음, 영향 버전 2.0.1)
  규칙: 미적중
    - 미적중 EXAMPLE-RULE-0001 0.0.0-example
    - 미적중 EXAMPLE-RULE-0002 0.0.0-example
  규칙/ML: 둘 다 미적중(정상 판정이 아님). 판정에 쓰지 않는 표시입니다.
  분석 시간: 2.101초
  추출된 사실:
    - 비교: 2.0.0 → 2.0.1 (같은 release line의 직전 stable)
    - lockfile 없이 registry 정보로 검사
    - 추가·수정된 JS 파일 1개
  판단에 크게 작용한 특징 (+ 위험 쪽, - 정상 쪽):
    - 설치 스크립트 추가 = 아니오 (-1.40)
    - 새 버전에 설치 스크립트 있음 = 아니오 (-0.90)
    + 추가·수정된 JS 파일 수 = 1 (+0.20)
    나머지 특징 26개 합 -0.08, 모델 기준값 -1.00 (합계 -3.18 → 점수 0.040)

'통과'는 모델의 판정일 뿐 패키지가 안전하다는 보증이 아닙니다.
````

## 9. 채택됨(하람, 11/11)

16개 항목 모두 하람이 2026-11-11 17:00 KST에 권장안대로 채택했다(Clover 전달 원문: "SVC-01 결정 16개는 Devy 권장안대로 모두 채택해"). 채택안 열은 이전의 권장안(`09f9002`의 9절 권장안 열)을 글자 그대로 옮긴 것이고, 선택지 열은 기록으로 남긴다. 주석 열은 채택 뒤 Devy가 덧붙인 설명과 이후 확정 사항의 참조이며, 채택 내용이 아니고 승인 대상도 아니다. 현행 동작과 달라지는 항목과 적용 단계는 9.1절에 있다.

| ID | 항목 | 선택지(기록) | 채택안 | 주석(Devy, 승인 대상 아님) |
|---|---|---|---|---|
| D-1 | 필드 이름과 schema_version | 이 문서의 이름 그대로 / 다른 이름. schema_version은 7절 A·B·C | 이름은 리뷰 뒤 하람 승인, 버전은 A(1 유지) | 필드 이름의 하람 승인은 PR #9 병합 검토에서 받는다. 7절의 C안 재검토 결과는 1 유지다(하람, 11/13, 7절) |
| D-2 | 기지 악성 `hit`의 항목 `status`·`exit_code` 매핑 | (a) 지금처럼 바꾸지 않고 경고로만 표시 (b) `hit`이면 항목을 `flagged`, 종료 코드 1 (c) (a)에 최상위 경고 개수 필드를 더함 | (b). 종료 코드만 보는 CI가 경고를 놓치지 않고 "1 = 위험 판정 있음"의 뜻과 맞는다. 채택 전까지는 (a)다 | SVC-03에서 적용했다(하람 확정, 11/11). 그 전까지는 (a)였다. 한 항목에 D-7과 함께 걸리면 D-2(`flagged`, 종료 코드 기여 1)가 우선한다(4.2절, 하람·Clover 확정). ML 경로 미완료와만 겹쳐도 `flagged`다(4.2절, 11/13 Clover 지시). 9.1절 참고 |
| D-3 | 기지 악성 목록의 출처·기준 시점 | 출처(OSV의 악성 기록 등)·오프라인 스냅샷 파일 / 실행 시 조회, 철회 기록 제외 방법, 갱신 주기 | 소은의 기지 악성 일치 명세를 따른다. 서비스는 `source`·`list_as_of`·`list_sha256` 칸과 `not_run`만 준비 | |
| D-4 | 규칙/ML 불일치 표기와 처리 | 근거별 표시 유지 / OR / AND / 검증된 규칙 종류별 우선순위 | 실험 전까지 근거별 표시 유지와 `rule_ml_agreement` 표기만. 단일 통합 판정 보류 | |
| D-5 | 분석 대상이 아닌 변경의 기지 악성 대조 | `analyzable=false`(미지원 출처, integrity 없음 등)와 `no_baseline` 항목도 이름·버전으로 대조 / 하지 않음 | registry 이름·버전이 확실한 항목은 대조(이전 버전 없이도 경고 가능). 출처가 registry가 아니면 `not_run`, `not_analyzable` | |
| D-6 | 탐지기 `not_run`(미연결)의 종료 코드 영향 | 영향 없음 / 정책으로 필수 지정 시 `incomplete`·2 | 탐지기가 배포되기 전까지 영향 없음. 정책 파일(client-dev 4.6절)이 생기면 필수 여부를 거기서 정함 | |
| D-7 | 탐지기 `failed`의 종료 코드 영향과 일부 규칙 실패 | 영향 없음 / 항목 `incomplete`·2 / 일부 규칙만 실패하면 경고 | 연결된 탐지기의 `failed`는 `incomplete`·2(실패를 정상으로 대체하지 않는 원칙). 이때 항목 `reason` 값은 새로 정해야 함 | SVC-03에서 적용했다(하람 확정, 11/11). 한 항목에 D-2와 함께 걸리면 D-2가 우선하고 실패는 탐지기 칸에 남는다(4.2절). 새 항목 `reason` 값은 SVC-03에서 `detection_failed`로 정했다(ML 경로가 완료된 항목에만 쓰고 점수는 남김, 하람 승인(11/13), 4.2절). "일부 규칙 실패"는 `rules.status`가 `failed`일 때만 해당한다고 해석한다(4.2절, SVC-03-FIX-01 m3) |
| D-8 | 규칙 근거 위치 형식 | `{"file", "line"}` / 열·범위 추가 / 위치 없이 문자열만 | `{"file", "line"}`에서 시작. 규칙 후보(R_download_exec 등)의 근거 형태를 보고 확정 | |
| D-9 | ruleset·rule 버전 표기 | SemVer / 날짜 / 커밋 해시 | 규칙 저장 위치가 정해진 뒤 결정. 그 전에는 문자열 | |
| D-10 | `provenance` 위치와 범위(SVC-02) | `provenance` 객체 / 최상위 평면 필드(`model_sha256` 등). feature-extractor의 `url` 포함 여부 | `provenance` 객체, `url`은 제외(고정 커밋은 depbee 메타데이터에 이미 있고, 설치 기록의 URL을 보고서에 옮기지 않음) | SVC-02(PR #10)에서 구현했다(3.1절). 현행 동작을 바꾸지 않아 9.1절 표에는 없다 |
| D-11 | 탐지기 소요 시간 | 결과 항목 `elapsed_seconds`에 포함 / 탐지기별 시간 필드 / 기록 안 함 | 기존 `elapsed_seconds`의 뜻(추론 제외 분석 시간)을 바꾸지 않고, 필요하면 탐지기별로 따로 추가 | 대상은 결과 항목의 값이며, 최상위 전체 시간에는 `pipeline.scan()` 안의 탐지기 시간이 들어간다(2절 표) |
| D-12 | `ml.status`를 보고서에 둘지, 기존 보고서의 `analysis_missing` 해석 | 필드로 둠 / 4.1절 표로 진입점이 계산. 기존 보고서의 `analysis_missing`은 최상위 `analyzer_version` 유무로 미실행·실패를 나눔 / 항목 `reason`을 `analyzer_missing` 같은 새 코드로 나눔(기존 `reason` 변경) | 필드로 둠. 판정 해석을 `pipeline.scan()` 한 곳에 두고, `analyzer_version`에 기댄 구분은 계약이 아닌 90a61bb 코드의 성질이라 기존 보고서 해석에만 참고로 쓴다. 기존 `reason`은 바꾸지 않는다 | |
| D-13 | 표시 순서와 강조(텍스트·Markdown·대시보드) | 기지 경고를 맨 앞에 / 지금 순서 유지 후 강조만 | 지금 순서(위험 → 보류 → 통과 → 삭제, 같은 모델 점수 내림차순)를 유지하고 기지 경고·미완료를 강조 | SVC-04에서 텍스트·Markdown에 적용했다(8절 렌더, 9.1절). 대시보드는 SVC-07 |
| D-14 | top-k 보기 | 없음 / 선택 보기로 제공 | 선택 보기. 전체 목록을 유지하고 동점을 모두 포함하며 실제 건수 표시 | |
| D-15 | 규칙 결과의 전달 경로 | 분석 결과 JSON(연결 규약 2절)에 규칙 결과 추가 / `pipeline.scan()`에 별도 탐지기 인자 | 별도 탐지기 인자(SVC-03 계획). 2절과 schema_version을 건드리지 않는다 | |
| D-16 | 비교 기준 버전(`compared_version`)의 기지 악성 표시 | 표시 안 함 / 비교 기준이 기지 악성이면 경고·미완료 | 기준 선정에서 기지 악성을 제외하는 문제와 함께 결정(README "현재 제한"의 OSV 미대조) | 채택안이 결정을 그 문제로 미룬 것이라 지금 정해진 표시는 없다 |

### 9.1 현행 동작과 달라지는 채택 항목과 적용 단계

이 절의 "현행 코드"는 채택 시점의 코드(`90a61bb`, 9절 채택 당시 main)다. 그 뒤 SVC-02(PR #10)가 `provenance`를 넣었고, SVC-03이 탐지기 칸과 D-2·D-7·D-5를 적용했다(아래 표의 적용 단계 열). 적용 단계는 SVC-00 계획(`svc00_status_plan.md` 7절 (b) 표와 "순서와 파일 겹침")을 근거로 적었고, D-2·D-7은 하람 확정(11/11, Clover 전달)을 따른다.

SVC-03 완료 기준 변경: D-2·D-7을 SVC-03에서 적용하기로 확정되면서(하람, 11/11), SVC-03 완료 기준의 "exit_code 규칙 불변 테스트"는 "탐지기 미연결 시 `status`·`exit_code` 불변, 탐지기 연결 시 D-2·D-7과 4.2절의 우선순위(한 항목에 둘이 함께 걸리면 `flagged`, 종료 코드 기여 1)대로 바뀌는 테스트"로 바뀐다. SVC-00 계획 파일의 수정은 Devy가 따로 한다.

| ID | 현행 코드와의 차이 | 적용 단계 |
|---|---|---|
| D-2 | 현행 코드에는 기지 악성 탐지기가 없어 `hit`이 나오지 않고, 항목 `status`·`exit_code`는 ML 경로로만 정해진다. 채택안은 `hit`을 `flagged`·1로 연결하므로 탐지기가 연결된 실행의 판정과 종료 코드가 바뀐다(예시 3: `passed`/0 → `flagged`/1) | SVC-03에서 적용했다(하람 확정, 11/11, `pipeline.scan()`의 D-2 분기). 판정은 `pipeline.scan()`에만 두므로 탐지기 칸을 만드는 SVC-03에서 함께 적용했고, SVC-03 완료 기준은 위 문단대로 바뀌었다. 한 항목에 D-7과 함께 걸리면 D-2가 우선한다(4.2절, 하람·Clover 확정). 실제 기지 악성 목록을 구현하는 단계는 계획에 없다(SVC-03은 가짜 탐지기로만 테스트했고, 목록은 채택(D-3)대로 소은 명세를 따른다). 실제 탐지기와 그 연결 옵션이 없으므로 지금 CLI의 판정은 그 전과 같다 |
| D-7 | 현행 코드에는 탐지기가 없어 탐지기 `failed`가 없다. 채택안은 연결된 탐지기의 `failed`를 항목 `incomplete`·2로 바꾸며, 이때 쓸 항목 `reason` 값이 새로 필요하다 | SVC-03에서 적용했다(하람 확정, 11/11, `pipeline.scan()`의 D-7 분기). 탐지기 예외와 잘못된 형태의 반환값은 `failed`(not_hit 아님)이고, 연결된 탐지기의 `failed`는 항목 `incomplete`·2다. 한 항목에 D-2와 함께 걸리면 D-2(`flagged`, 종료 코드 기여 1)가 우선하고, 실패는 그 탐지기 칸의 `failed`와 이유 코드로 보여 준다(4.2절). 새 항목 `reason` 값은 `detection_failed`로 정했다(SVC-03에서 정함, 하람 승인(11/13)). 규칙 일부 실패는 `rules.status`가 `failed`일 때만 D-7이다(4.2절, SVC-03-FIX-01 m3). ML 경로가 이미 미완료면 그 `reason`을 유지한다 |
| D-5 | 현행 코드는 어떤 항목도 기지 악성과 대조하지 않는다. 채택안은 `analyzable=false` 중 registry 이름·버전이 확실한 항목과 `no_baseline` 항목도 대조한다. D-2와 함께 적용되면 이런 항목의 경고가 판정에 반영된다(4.2절) | SVC-03에서 적용했다. `no_baseline`을 포함해 분석 대상인 변경은 모두 대조하고, `analyzable=false`는 요청의 출처 검사(`inputs/npm.py`의 `registry_version_problem()`)를 통과한 변경만 대조한다(3.3절 `not_analyzable`). `analyzable=false` 항목의 대조 범위는 계획에 명시되지 않아 SVC-03에서 이렇게 정했다 |
| D-6 | 현행과 같다(탐지기 미연결은 영향 없음). 정책 파일로 탐지기를 필수로 지정하면 `incomplete`·2가 될 수 있다 | 정책 파일(client-dev 4.6절)은 SVC-00 계획이 순서에 넣지 않았으므로 적용 단계가 정해지지 않았다 |
| D-13 | 현행 출력에는 탐지기 칸이 없다. 결과 순서는 유지하고 기지 경고·미완료 강조를 더한다 | SVC-04에서 텍스트·Markdown에 적용했다(`cli.py`의 표시 함수만 바꿈, 8절 렌더). JSON은 SVC-03의 보고서 그대로라 바꾸지 않았다. 탐지기가 연결되지 않은 지금 CLI 출력에서 바뀐 곳은 머리 목록의 보류 강조 줄과 탐지기 연결 상태 두 줄, "점수"를 "ML 위험 점수"로 바꾼 표기와 그 뒤의 ML 상태(기준 이상·미만, 없음(미실행)·없음(실패)), Markdown 모델 설명 머리말이다. 대시보드는 SVC-07 |
| D-14 | 현행 출력에 top-k 보기가 없다 | SVC-00 계획의 SVC-02~07 범위에 top-k가 없어 단계가 정해지지 않았다 |

나머지 항목은 기존 필드의 값을 바꾸지 않는다. D-1·D-8·D-12·D-15는 새 필드의 이름·형식·전달 경로라 새 필드를 만드는 SVC-03에서 반영했고, D-10은 SVC-02에서 반영했다. D-3·D-4·D-9·D-11·D-16은 채택안이 현행을 유지하거나 결정을 명세·실험·후속 판단으로 미룬 것이라 지금 적용할 동작 변경이 없다.

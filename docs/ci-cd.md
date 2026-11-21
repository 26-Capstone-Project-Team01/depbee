# 개발 CI와 GitHub Action

## 현재 포함한 개발 CI

`.github/workflows/ci.yml`의 `checks` job은 이 도구 자체의 Linux/Windows, Python 3.11/3.13 검사다.
lint·회귀 테스트·native LightGBM 합성 테스트·wheel/sdist 빌드를 수행한다.
`action` job은 아래 GitHub Action을 예시 보고서와 설치본의 내장 자산으로 검사한다(자기 검사 절).
Action은 확인한 commit SHA로 고정했고 권한은 contents:read다.
의존성은 pyproject의 범위로 설치한다. 첫 환경 검증 후 팀 공통 lock/constraints를 도입한다.

## GitHub Action (`action.yml`)

저장소 루트의 `action.yml`은 pull request가 바꾼 `package-lock.json` 항목을 depbee로 검사하는 composite action이다.
workflow에는 commit SHA로 고정한 `uses:` 한 줄이면 된다. 모델과 기지 악성 색인은 그 커밋의 depbee 패키지에 들어 있는 것을 쓰므로, 따로 받거나 입력으로 줄 것이 없고 secret도 없다.
탐지는 depbee CLI(`depbee scan --base-ref <PR base sha> --extract`)가 하고, action은 그 보고서를 읽어 성공·실패와 주석만 정한다(`src/depbee/actions.py`, 표준 라이브러리만 사용).

하는 일과 하지 않는 일은 다음과 같다.

- 하는 일: PR의 기준 커밋과 PR의 `package-lock.json`을 비교해 바뀐 항목을 찾고, 그 버전의 tarball을 npm registry(`https://registry.npmjs.org`)에서 받아 `dist.integrity`와 대조한 뒤 파일을 읽어 분석한다. 받은 패키지는 임시 폴더에 풀어 읽기만 하고 설치하거나 실행하지 않는다.
- 하지 않는 일: 대상 프로젝트를 빌드하거나 설치하지 않는다. `npm install`, `npm ci`, 설치 스크립트, 테스트, 프로젝트의 어떤 코드도 실행하지 않고 npm 자체를 실행하지 않는다.
- PR checkout에서 읽는 것은 lockfile과 git에 있는 기준 커밋의 lockfile뿐이다. PR 안의 분석기, 모델, 색인, depbee 설정은 쓰지 않는다(아래 "모델과 색인의 출처").

### 사용 예시

```yaml
name: depbee
on:
  pull_request:
permissions:
  contents: read
jobs:
  depbee:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: 26-Capstone-Project-Team01/depbee@<40자리 commit SHA> # <태그>
        # with:
        #   fail-on: ml-hit, incomplete
```

- `uses:`의 ref는 태그나 브랜치가 아니라 40자리 commit SHA로 고정한다. 이 SHA 하나가 action 코드, 설치되는 depbee(`$GITHUB_ACTION_PATH`), 그 안의 모델과 색인을 함께 정한다. 태그와 브랜치는 다른 커밋으로 옮겨질 수 있다.
- `pull_request` 이벤트에서만 동작한다. 기준은 `github.event.pull_request.base.sha`이고, 이 값이 없으면(다른 이벤트) 입력 오류로 실패한다.
- checkout은 `fetch-depth: 0`으로 기준 커밋까지 받는다. depbee가 기준 lockfile을 `git cat-file`로 읽기 때문이다. 토큰은 checkout 뒤 남기지 않는다(`persist-credentials: false`).
- job `timeout-minutes`는 호출하는 workflow가 정한다(composite action은 job 시간 제한을 둘 수 없다). depbee는 변경 하나에 300초 예산을 쓰므로 `max-changes`와 함께 정한다.
- 이 action을 필수 검사로 쓰면 workflow에 `paths` 필터를 두지 않는다. 필터로 건너뛴 workflow의 검사는 "Pending"으로 남아 병합을 막는다([GitHub 문서](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/collaborating-on-repositories-with-code-quality-features/troubleshooting-required-status-checks)).
- 저장소 공개 전에는 다른 저장소에서 이 예시가 동작하지 않는다(아래 "공개 전 제한과 미검증").

### 선택: Release의 모델과 색인

고정한 커밋에 든 것과 다른 모델이나 색인을 쓰려면, 또는 이전 버전의 workflow처럼 Release 파일을 쓰려면 다음 다섯 입력을 모두 준다.

```yaml
      - uses: 26-Capstone-Project-Team01/depbee@<40자리 commit SHA> # <태그>
        with:
          model-version: <모델이 첨부된 Release 태그>
          model-sha256: <model.txt의 sha256>
          manifest-sha256: <manifest.json의 sha256>
          known-malicious-version: <기지 악성 색인이 첨부된 Release 태그>
          known-malicious-sha256: <known-malicious-index.json의 sha256>
```

- 다섯 값은 모두 주거나 모두 비운다. 일부만 주거나 형식이 틀리면 설치와 다운로드 전에 첫 단계가 실패하고, 빠진 입력 이름이나 틀린 입력을 오류에 적는다.
- 모두 주면 action이 두 Release에서 파일 넷을 받아 입력의 sha256과 비교한 뒤 그 폴더만 scan에 넘긴다. 이때 설치본에 든 모델과 색인은 쓰지 않는다.
- 색인은 모델보다 자주 갱신하므로 두 태그는 달라도 된다.
- 모델과 색인을 첨부한 Release는 아직 없다. 그래서 이 경로는 기본 사용법이 아니다.

### 입력

| 입력 | 기본값 | 내용 |
|---|---|---|
| `lockfile` | `package-lock.json` | 검사할 `package-lock.json`의 저장소 루트 기준 경로. 이름이 `package-lock.json`이어야 하고 workspace 안의 파일이어야 한다. 심볼릭 링크나 Windows junction을 거치면 그 실제 대상까지 workspace 안이어야 한다(밖을 가리키면 입력 오류). 구분자는 `/`만 받고(`\`는 거부), `-`로 시작하는 경로 구성 요소도 받지 않는다. 제어 문자(줄바꿈, 탭 등 U+0000~U+001F와 DEL)가 든 경로도 받지 않는다. |
| `fail-on` | 빈 값 | 실패로 더할 조건. `ml-hit`(ML 위험 점수 기준 이상), `incomplete`(보류). 쉼표나 공백으로 구분한다. 그 밖의 값은 입력 오류다. |
| `max-changes` | `20` | 바뀐 lockfile 항목이 이보다 많으면 검사하지 않고 실패한다. 양의 정수. |
| `model-version` | 빈 값(선택) | `model.txt`·`manifest.json`이 첨부된 depbee Release의 태그. |
| `model-sha256` | 빈 값(선택) | `model.txt`의 기대 sha256(소문자 16진수 64자). |
| `manifest-sha256` | 빈 값(선택) | `manifest.json`의 기대 sha256(소문자 16진수 64자). |
| `known-malicious-version` | 빈 값(선택) | 기지 악성 색인 `known-malicious-index.json`·`known-malicious-manifest.json`이 첨부된 depbee Release의 태그. 형식은 `model-version`과 같다. |
| `known-malicious-sha256` | 빈 값(선택) | `known-malicious-index.json`(색인 본문 `index.json`)의 기대 sha256(소문자 16진수 64자). 보고서의 `detectors.known_malicious.list_sha256`과 같은 값이다. |
| `report` | 빈 값 | depbee 자체 CI의 자기 검사 전용. 일반 workflow에서는 비워 둔다. 값이 있으면 설치·scan 없이 그 보고서로만 판정한다. 경로 규칙은 `lockfile`과 같다(링크의 실제 대상까지 workspace 안). |

`lockfile`·`report`의 경로 검사는 첫 단계(`actions.py inputs`)에서 한 번만 한다. 그 뒤 단계가 같은 경로를 다시 열 때까지 workspace의 파일이나 링크가 바뀌는 경우(검사와 사용 사이)는 막지 않는다.

Release 다섯 입력은 "전부 또는 전무"다. GitHub는 composite action 입력의 `required`를 강제하지 않으므로 표시를 달지 않았고, 첫 단계가 값을 직접 검사한다.
빈 문자열만 "주지 않음"으로 본다. 공백만 든 값은 준 값으로 보고 형식 오류로 실패한다.
모델만 또는 색인만 Release에서 받는 조합은 없다. 색인 없이 돈 실행은 기지 악성 일치로 실패할 수 없고(이 action의 기본 실패 조건은 그 일치뿐이다), 한 실행의 모델과 색인 출처를 섞지 않기 위해서다.
`known-malicious-manifest.json`의 sha256은 따로 받지 않는다. depbee가 색인을 열 때 manifest의 `index_sha256`을 확인한 본문의 해시와, manifest의 `source`·`list_as_of`·`snapshot_sha256`을 본문 머리와 대조해 다르면 오류(보고서 없음)로 끝나기 때문이다.
`report` 자기 검사 모드에서는 Release 입력을 읽지 않는다(예전 자기 검사 workflow가 준 값이 남아 있어도 무시).

### 모델과 색인의 출처

depbee 서비스는 모델과 색인을 각각 옵션, 환경 변수(`DEPBEE_MODEL_DIR`, `DEPBEE_KNOWN_MALICIOUS_DIR`), `depbee setup`이 저장한 사용자 설정, 패키지에 내장된 자산 순으로 처음 있는 것에서 고른다.
action은 이 선택을 다음과 같이 고정한다. PR이나 runner에 남은 값이 모델과 색인을 고르지 못한다.

- 기본(Release 입력 없음): 옵션을 주지 않고, scan 단계에서 두 환경 변수를 지우고(`unset`), `DEPBEE_CONFIG_DIR`을 이 실행이 `$RUNNER_TEMP` 아래 새로 만든 빈 폴더(`<실행 폴더>/config`)로 둔다. 그래서 depbee는 내장 자산을 쓴다. depbee는 내장 파일 넷(`model.txt`, 두 `manifest.json`, `index.json`)의 SHA-256을 코드에 고정한 값과 비교한 뒤에만 연다. 다르면 보고서 없이 오류로 끝나고 판정 단계가 실패한다.
- Release 입력 다섯 개: 받은 파일을 입력의 sha256과 비교한 폴더를 `--model-dir`, `--known-malicious-dir` 옵션으로 넘긴다. 옵션이 가장 앞이므로 다른 출처는 쓰이지 않는다. 환경 변수 제거와 설정 폴더 격리는 이때도 같다.
- 분석기(depbee-analyzer)는 action 커밋의 `pyproject.toml`이 고정한 커밋을 pip이 설치한 것을 쓴다. depbee는 설치된 분석기가 그 고정 커밋의 Git 주소에서 설치됐고 설치 뒤 바뀌지 않았는지 확인한다. 확인되면 보고서의 `provenance.feature_extractor`에 커밋과 설치 파일 해시를 적고, 확인되지 않으면 그 값은 null이며 캐시를 쓰지 않는다.
- depbee와 pip은 `python -I`로 실행한다. 현재 폴더와 `PYTHONPATH`, 사용자 site가 import 경로에 들어가지 않으므로 PR checkout 안의 `depbee`나 분석기 모듈이 대신 실행되지 않는다. 설치 단계는 PR checkout이 아니라 실행 폴더에서 돈다.

### 단계

1. Python 3.13 준비(`actions/setup-python`).
2. 입력 검사, 실행 폴더 생성(`mktemp -d "$RUNNER_TEMP/depbee.XXXXXX"`, 그 안에 빈 `config`), `pyproject.toml`에서 depbee-analyzer 고정 커밋 읽기. 입력 검사는 자산 출처(`assets`: Release 입력 다섯이면 `release`, 없으면 `bundled`)와 캐시 키에 넣을 신원(`identity`)을 step 출력으로 쓴다.
3. depbee 설치: 실행 폴더에서 `python -I -m pip install "$GITHUB_ACTION_PATH[extract]"`. 실패하면 step이 실패한다.
4. `assets`가 `release`일 때만: Release에서 `model.txt`, `manifest.json`을 HTTPS로 받고(파일당 100 MiB, 300초 상한) 입력의 sha256과 비교한다. 다르면 실패한다. depbee도 모델을 열 때 `manifest.json`의 `model_sha256`과 `model.txt`를 다시 비교한다.
5. `assets`가 `release`일 때만: `known-malicious-version` Release에서 `known-malicious-index.json`, `known-malicious-manifest.json`을 모델과 같은 curl 옵션(HTTPS만, 파일당 128 MiB, 300초 상한)으로 받아 `<실행 폴더>/known-malicious/index.json`, `manifest.json`에 두고, `index.json`을 `known-malicious-sha256`과 비교한다. 다르면 실패한다.
6. `python -I -m depbee plan --base-ref`로 바뀐 항목 수를 세어 `max-changes`를 넘으면 실패한다.
7. 캐시 복원, `python -I -m depbee scan <lockfile 폴더> --base-ref <base sha> --extract --cache-dir ... --format markdown --output report.json`, 캐시 저장. `assets`가 `release`이면 `--model-dir`, `--known-malicious-dir`이 붙는다. `assets`가 두 값 중 하나가 아니면 scan하지 않고 실패한다.
8. `report.json`을 artifact `depbee-report`로 올린다.
9. 판정: `actions.py report`가 보고서를 읽어 주석과 job summary를 쓰고 step의 성공·실패를 정한다.

기본 사용에서는 4·5단계가 돌지 않으므로 Release를 조회하거나 받지 않는다.
`depbee scan`의 종료 코드(0/1/2)는 로그에만 남긴다. 종료 코드 2는 1을 덮으므로(보류가 하나라도 있으면 2) 판정에 쓰지 않는다.
입력값은 `env:`로만 step에 넘기고 `run:` 본문에 `${{ }}`로 넣지 않는다.

### 판정 규칙

판정은 보고서 `results`의 항목별 `known_malicious.status`, `ml.status`, `status`와, 보고서가 모델과 색인의 이름을 밝혔는지로 한다(client-dev-handoff 2.3절 1번).

| 상황 | 기본 | `fail-on` |
|---|---|---|
| 기지 악성 일치(`known_malicious.status`가 `hit`) | 실패, `::error` | 항상 실패. 낮은 ML 점수가 이를 취소하지 않는다. |
| ML 위험 점수 기준 이상(`ml.status`가 `hit`) | 경고, `::warning` | `ml-hit`이면 실패, `::error` |
| 보류(`status`가 `incomplete`) | 경고, `::warning` | `incomplete`이면 실패, `::error` |
| scan 보고서에 `model_id`나 `detectors.known_malicious.list_as_of`가 없음(없는 키, null, 비었거나 공백뿐인 문자열, 문자열이 아닌 값) | 실패, `::error` | 바꿀 수 없음 |
| 입력 오류(Release 입력 일부만 지정·형식 오류, 기준 커밋 없음 포함), 모델·색인 sha256 불일치, depbee 설치 실패, 변경 수 초과, 보고서 없음·깨진 JSON·필요한 필드 없음 | 실패 | 바꿀 수 없음 |

보류는 검사를 끝내지 못한 항목이며 경고로 두더라도 통과로 바꾸지 않는다. summary와 주석은 "보류, 통과가 아님"으로 쓴다.
모델이나 색인 없이 끝난 scan은 실패다. 모델이 없으면 모든 항목이 보류(경고)로만 남고 색인이 없으면 기지 악성 일치가 나올 수 없어, 그대로 두면 아무것도 검사하지 않은 실행이 성공으로 보이기 때문이다. 이 경우에도 항목별 주석과 개수는 그대로 나온다.
`report` 입력으로 준 보고서(자기 검사)만 이 두 값 없이 판정한다. 그 summary에는 실제 검사 결과가 아니라는 줄이 붙는다.
action은 scan이 쓴 보고서만 판정한다. scan 보고서는 depbee가 실행 폴더에 새로 쓰며(`--output`은 있는 파일을 덮어쓰지 않는다), PR checkout에 있는 `report.json`은 `report` 입력을 주지 않는 한 읽지 않는다.
보고서를 만들지 못한 오류(CLI 입력 오류, 내장 자산의 해시 불일치, depbee가 연 색인의 manifest 불일치·형식 오류 등)는 `report.json`이 없으므로 판정 단계가 실패한다.
기지 악성 대조의 한계: depbee는 lockfile 항목의 이름(`name` 필드나 위치)과 버전 문자열을 대조한다. PR이 만든 lockfile에서 이름을 바꾸거나 버전에 `+build`가 아닌 표기(앞자리 0 등)를 쓰면 그 항목은 일치 대신 분석 실패·대조 실패(보류)로 끝나 기본 판정이 실패가 아니라 경고가 된다(조용히 통과하지는 않음). 엄격한 저장소는 `fail-on: incomplete`를 권장한다.
실패한 검사가 병합을 실제로 막는지는 저장소 소유자의 필수 검사(branch protection, ruleset) 설정이 정한다.
CLI 종료 코드 0/1/2의 의미는 그대로다.

### 모델 ID와 색인 기준 시점을 보는 곳

한 실행이 실제로 쓴 모델과 색인은 그 실행의 결과에서 확인한다. 값은 보고서의 원래 필드 그대로이고 action이 다시 계산하거나 고정 문구로 적지 않는다.

- job summary의 "depbee Actions 판정" 절 첫 두 줄: `모델 ID(model_id)`와 `기지 악성 색인 기준 시점(detectors.known_malicious.list_as_of)`. 그 위 depbee CLI 요약에도 "모델"과 "기지 악성 목록 ... 기준 시점" 줄이 있다.
- artifact `depbee-report`의 `report.json`: `model_id`, `threshold`, `detectors.known_malicious`(`source`, `list_as_of`, `list_sha256`), `provenance.model`(`model_sha256`, `manifest_sha256`), `provenance.feature_extractor`(분석기 커밋 등). 필드 정의는 [연결 규약](contracts.md)에 있다.
- 기본 사용에서 이 값은 `uses:`로 고정한 커밋의 depbee에 든 모델과 색인의 것이다. 커밋마다 다를 수 있어 이 문서에는 값을 적지 않는다.
- 색인은 기준 시점까지의 기록만 담는다. action은 실행 중에 색인을 갱신하지 않으므로 그 뒤에 알려진 악성 버전은 일치로 나오지 않는다. 더 새 색인은 `uses:`의 SHA를 새 릴리스 커밋으로 올리거나 Release 다섯 입력으로 준다.

### 주석, summary, artifact

- 주석은 기지 악성 일치·ML 기준 이상·보류 항목마다 하나이고, `package-lock.json`에서 그 항목의 `packages` 키(`"node_modules/@scope/name":`) 줄에 단다. 줄을 찾지 못하면 파일 단위 주석이다.
- 주석 문구는 `depbee: <패키지>@<버전> (<위치>): <이유>`이다. 패키지 유래 문자열은 CLI와 같이 출력할 수 없는 문자를 `\uXXXX`로 바꾼 뒤 workflow 명령 규칙으로 이스케이프한다. 메시지는 `%`, `\r`, `\n`을, 속성값(`file`)은 여기에 `:`, `,`까지 `%XX`로 바꾼다(actions/toolkit `command.ts`의 escapeData·escapeProperty와 같은 규칙).
- job summary(`GITHUB_STEP_SUMMARY`)에는 depbee CLI의 Markdown 출력(CLI의 Markdown 이스케이프 그대로)을 먼저 쓰고, 그 아래에 action 판정 절(모델 ID와 색인 기준 시점, 기지 악성·ML·보류 개수와 각각 실패인지 경고인지, 최상위 `exit_code`를 쓰지 않았다는 안내)을 붙인다. GitHub는 step 하나의 summary를 1 MiB로 제한한다.
- 판정 절의 모델 ID와 색인 기준 시점은 CLI와 같은 규칙의 code span으로만 넣는다(제어 문자는 `\uXXXX`, 안에 있는 어떤 백틱 묶음보다 긴 백틱). 그래서 값에 든 HTML, 링크, 제목, 줄바꿈이 해석되지 않는다. 보고서에 없는 값은 지어내지 않고 "보고서에 없음"으로 적는다.
- artifact `depbee-report`에는 `report.json` 하나가 들어 있다. 보고서가 없으면 업로드는 경고만 내고, 판정 단계가 실패한다.
- artifact 이름이 고정이라 한 workflow run에서 이 action은 한 번만 쓸 수 있다(`actions/upload-artifact` v4 이후 같은 이름의 artifact는 실패). lockfile 여러 개나 matrix는 지원하지 않는다.

### 공개되는 내용

- 결과는 그 workflow run의 summary, 주석, artifact로만 남는다. PR 댓글을 쓰지 않고 다른 곳으로 보내지 않는다. runner 밖으로 나가는 요청은 Python과 depbee·의존성 설치, npm registry에서 공개 패키지 정보·tarball 받기, GitHub의 캐시·artifact 저장뿐이고, 기본 사용에서는 Release도 받지 않는다.
- 들어가는 것: 바뀐 lockfile 항목의 패키지 이름·버전·lockfile 위치, 판정과 그 근거(추출한 feature 값, 근거 문장, 일치한 기지 악성 기록의 식별자), 모델 ID·색인 기준 시점과 해시.
- 들어가지 않는 것: 프로젝트 소스 코드, lockfile 전체, 환경 변수와 토큰, 모델 파일과 색인 본문.
- 사설 registry, Git, 파일 경로처럼 `https://registry.npmjs.org` 밖에서 오는 항목은 받지 않고 보류로 둔다. 인증 정보를 쓰지 않으므로 사설 패키지의 내용은 보고서에 없다. 그 항목의 이름·버전·위치는 lockfile에 있는 그대로 보고서와 주석에 남는다.
- summary와 artifact를 볼 수 있는 사람은 그 저장소의 workflow run을 볼 수 있는 사람이다. 공개 저장소에서는 외부 사람도 볼 수 있으므로, lockfile에 적힌 사설 패키지 이름을 감춰야 하는 공개 저장소에는 맞지 않는다.

### 캐시

- depbee 분석 캐시 폴더(`$RUNNER_TEMP/depbee-cache`)를 `actions/cache/restore`·`actions/cache/save`로 보존한다. 같은 버전 쌍을 다시 받아 추출하지 않기 위한 성능용이다.
- 키는 `depbee-<runner OS>-<신원>-<extractor 커밋>-<run id>-<run attempt>`이고, 같은 앞부분을 `restore-keys`로 쓴다. 매 실행이 새 키로 저장해 이전 항목에 새 항목이 쌓인다.
- `<신원>`은 입력 검사 단계가 정한다. Release 입력을 주면 `model-sha256` 값이고, 기본 사용에서는 `bundled-` 뒤에 action 커밋의 depbee 패키지 폴더(`src/depbee`, 내장 모델과 색인 포함, `__pycache__` 제외)에 있는 모든 파일의 경로와 내용으로 계산한 SHA-256이다. 빈 값이 되는 경우가 없으므로 모델이 다른 실행끼리 같은 키를 쓰지 않는다. 기본 사용에서는 depbee 패키지 파일이 달라진 커밋으로 `uses:`의 SHA를 바꾸면 캐시가 새로 시작한다.
- 키에 색인은 따로 넣지 않는다(캐시는 feature만 담고, 색인이 바꿀 수 있는 비교 기준 버전은 이미 캐시 항목의 키에 있다).
- 캐시는 판정의 신뢰 근거가 아니다. depbee는 캐시 항목마다 모델 입력·depbee-analyzer 설치 출처·depbee 버전·형식을 키로 확인하고 맞지 않으면 다시 추출한다.
- 범위: `pull_request` 실행이 저장한 캐시는 그 PR의 merge ref(`refs/pull/N/merge`) 범위라 같은 PR의 다음 실행과 재실행만 복원한다. 다른 PR과 기본 브랜치는 쓰지 못한다. 이 action은 `pull_request`에서만 동작하므로 기본 브랜치 캐시를 만들지 않는다. 그래서 새 PR의 첫 실행은 캐시 없이 시작한다.
- 저장 권한이 없는 실행에서는 저장만 실패하고 step과 job은 실패하지 않는다([GitHub 문서](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)). 저장소 캐시는 기본 10 GB이고 7일 동안 쓰지 않은 항목은 지워진다.

### 권한과 secret

- secret을 쓰지 않는다. 기본 사용에는 Release 다운로드도 없다. depbee 설치(공개 뒤)와 registry 다운로드는 토큰 없이 한다. `GITHUB_TOKEN`은 checkout에만 쓰이고 `contents: read`로 충분하다.
- `pull_request_target`, `continue-on-error`, `|| true`를 쓰지 않는다.

### fork·Dependabot PR

- fork에서 온 `pull_request` 실행과 Dependabot이 만든 PR의 실행은 읽기 전용 `GITHUB_TOKEN`을 받고 Actions secret을 받지 않는다(Dependabot은 Dependabot secret만). 이 action은 secret과 쓰기 권한이 필요 없으므로 같은 workflow가 조건 분기 없이 같은 방식으로 동작한다.
- 공개 저장소에서 처음 기여하는 사람의 fork PR은 쓰기 권한이 있는 maintainer가 workflow 실행을 승인해야 할 수 있다.
- PR 댓글은 쓰지 않는다. 결과는 summary, 주석, artifact로만 남긴다.

### workflow 변경 보호

`pull_request`에서는 PR 쪽의 workflow 파일이 실행된다. PR이 workflow에서 이 action을 지우거나 `uses:`의 SHA와 입력을 바꾸면 검사가 약해진다.
다음으로 막는다.

- CODEOWNERS에 `.github/workflows/`를 넣고 브랜치 보호(또는 ruleset)에서 code owner 리뷰를 필수로 한다. workflow 변경은 지정한 리뷰어의 승인이 있어야 병합된다.
- 이 job을 필수 검사로 지정한다. 실패하거나 실행되지 않은 검사는 병합을 막는다.
- 모델과 색인을 정하는 `uses:`의 SHA(Release를 쓰면 다섯 입력도)가 workflow 파일에 있으므로 같은 보호를 받는다.
- workflow 파일을 바꿀 수 있는 사람은 `report` 입력을 채우거나 이 단계를 바꿔 scan을 건너뛸 수 있다. 입력 검사는 이를 막지 못하므로, 이 job을 필수 검사로 쓸 때는 workflow 파일 변경을 위와 같이 리뷰한다. `report`로 판정한 실행은 summary에 자기 검사라고 적힌다.

### 공개 전 제한과 미검증

- depbee와 depbee-analyzer가 아직 비공개라 위 사용 예시는 다른 저장소에서 그대로 동작하지 않는다. 비공개 저장소의 action은 그 저장소가 접근을 허용한 같은 소유자의 다른 비공개 저장소에서만 쓸 수 있다([GitHub 문서](https://docs.github.com/en/actions/how-tos/reuse-automations/share-across-private-repositories)). 설치 단계도 `[extract]`가 depbee-analyzer를 git 주소와 커밋으로 받으므로 토큰 없이는 되지 않는다. action은 secret을 받지 않으므로 이 제한을 우회하는 입력은 없다.
- 두 저장소를 공개하면 workflow를 고치지 않고 위 사용 예시 그대로 동작하도록 만들었다. fork PR과 Dependabot PR도 같다.
- 모델과 기지 악성 색인을 첨부한 Release가 아직 없다. Release 다섯 입력 경로는 입력 검사와 단계 배선만 확인했고 실제 다운로드는 확인하지 않았다.
- 실제 PR에서의 설치, `depbee scan --extract`, 캐시 저장·복원, 주석 표시는 확인하지 않았다. 확인한 범위는 아래 자기 검사와 `docs/validation.md`에 있다.
- Linux runner만 고려했다. Windows·macOS runner는 확인하지 않았다(`bash`, `curl`, `sed`, `mktemp`를 쓴다).

### 자기 검사 (depbee CI `action` job)

공개 전이라 분석기 설치와 registry 다운로드를 포함한 실제 scan은 CI에서 돌릴 수 없어, 합성 자료와 설치본의 내장 자산으로 되는 범위만 검사한다.

- 판정 모듈을 직접 호출해 종료 코드를 확인한다(`docs/examples/result-contract/`의 예시 보고서, 자기 검사 판정). 실패를 기대하는 경우도 `continue-on-error` 없이 `if`로 종료 코드를 본다. 기지 악성 일치는 실패, ML 기준 이상·보류는 기본 성공이고 `fail-on`으로 실패, 보고서 없음·알 수 없는 `fail-on`·sha256 불일치는 실패다. 색인 이름이 없는 예시 보고서는 scan 보고서로 판정하면 실패하고 자기 검사로만 판정된다.
- 입력 검사를 직접 호출한다. Release 입력이 없으면 `assets=bundled`, 다섯 개면 `identity`가 `model-sha256` 값이고, 일부만 준 경우·형식이 틀린 값·기준 커밋이 없는 경우는 실패한다.
- 분석기 없이 depbee만 설치해 예시 프로젝트를 내장 자산으로 scan하고(추출이 없어 항목은 보류), 보고서의 `model_id`·모델 해시·색인 기준 시점·색인 해시가 설치본의 manifest와 같은지, 그 보고서가 scan 보고서 판정을 통과하는지 확인한다.
- `uses: ./`를 `report` 입력(위 scan의 보고서)으로 실행해 입력 검사, summary, artifact, 경고 주석의 배선을 확인한다. 이 실행의 summary에 설치본의 모델 ID와 색인 기준 시점이 나온다. `report`가 있으면 설치·다운로드·변경 수·캐시·scan 단계는 건너뛰고 Release 입력도 검사하지 않는다.
- 판정 모듈의 단위 테스트는 `tests/test_actions.py`이다(적대적 패키지 이름 이스케이프, lockfile 줄 찾기, Release 입력의 전부·전무·부분·형식 오류, 두 모드의 기준 커밋 검사, 모델 ID와 색인 기준 시점이 없는 scan 보고서의 실패와 자기 검사 호환, summary의 code span 표시, 캐시 신원 계산, 경로 입력의 링크 workspace 경계(심볼릭 링크는 POSIX, junction은 Windows에서 돎), `verify` 여러 쌍, `action.yml` 단계 순서·조건·인자를 텍스트로 확인 포함).

## CI 신뢰 경계

- PR이 수정할 수 있는 모델·특징 JSON·보고서를 판정 근거로 신뢰하지 않는다. 모델과 기지 악성 색인은 `uses:`로 고정한 커밋의 depbee에 든 것(해시를 코드에 고정) 또는 workflow의 sha256과 비교한 Release 파일만 쓴다.
- 도구/정책/모델은 보호된 참조에서 로딩한다. 대상 package.json의 script를 실행하지 않고 대상 프로젝트를 빌드하거나 설치하지 않는다.
- 환경 변수나 runner에 저장된 `depbee setup` 설정이 action의 모델과 색인을 바꾸지 못한다. scan이 모델 ID와 색인 기준 시점을 밝히지 않은 보고서를 내면 실패한다.
- action의 `lockfile`·`report` 경로는 링크의 실제 대상까지 workspace 안이어야 한다. 검사는 입력 검사 단계 한 번이며 검사와 사용 사이의 변경은 막지 않는다. `report`는 자기 검사 전용이라 일반 workflow에서는 비워 두고, workflow 파일 변경은 리뷰로 보호한다(위 "workflow 변경 보호").
- `pull_request_target`으로 외부 PR 코드를 실행하지 않는다. 토큰·secrets를 분석기에 넘기지 않는다.
- 모델 실패를 무시하는 `continue-on-error`, `|| true`를 보안 게이트에 사용하지 않는다.
- 수동 승인은 특정 버전·파일 해시·분석 요청에 묶는다. 패키지 영구 허용은 별도 논의한다.
- 신규 패키지·사설 레지스트리 등 미지원 항목은 현재 보류 대상이다. 전체 의존성 안전 보장을 주장하지 않는다.

참고: [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use),
[pull_request 이벤트](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request),
[workflow commands](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands),
[composite action 메타데이터](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax),
[npm lockfile 형식](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).

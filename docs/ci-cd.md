# 개발 CI와 GitHub Action

## 현재 포함한 개발 CI

`.github/workflows/ci.yml`의 `checks` job은 이 도구 자체의 Linux/Windows, Python 3.11/3.13 검사다.
lint·회귀 테스트·native LightGBM 합성 테스트·wheel/sdist 빌드를 수행한다.
`action` job은 아래 GitHub Action을 합성 보고서로 검사한다(자기 검사 절).
Action은 확인한 commit SHA로 고정했고 권한은 contents:read다.
의존성은 pyproject의 범위로 설치한다. 첫 환경 검증 후 팀 공통 lock/constraints를 도입한다.

## GitHub Action (`action.yml`)

저장소 루트의 `action.yml`은 pull request가 바꾼 `package-lock.json` 항목을 depbee로 검사하는 composite action이다.
대상 패키지를 설치하거나 실행하지 않는다. 탐지는 depbee CLI(`depbee scan --base-ref <PR base sha> --extract`)가 하고, action은 그 보고서를 읽어 성공·실패와 주석만 정한다(`src/depbee/actions.py`, 표준 라이브러리만 사용).

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
      - uses: 26-Capstone-Project-Team01/depbee@<태그의 commit SHA> # <태그>
        with:
          model-version: <모델이 첨부된 Release 태그>
          model-sha256: <model.txt의 sha256>
          manifest-sha256: <manifest.json의 sha256>
          # fail-on: ml-hit, incomplete
```

- `pull_request` 이벤트에서만 동작한다. 기준은 `github.event.pull_request.base.sha`이고, 이 값이 없으면(다른 이벤트) 입력 오류로 실패한다.
- checkout은 `fetch-depth: 0`으로 기준 커밋까지 받는다. depbee가 기준 lockfile을 `git cat-file`로 읽기 때문이다. 토큰은 checkout 뒤 남기지 않는다(`persist-credentials: false`).
- job `timeout-minutes`는 호출하는 workflow가 정한다(composite action은 job 시간 제한을 둘 수 없다). depbee는 변경 하나에 300초 예산을 쓰므로 `max-changes`와 함께 정한다.
- depbee 버전은 `uses:`의 ref다. action과 설치되는 depbee(`$GITHUB_ACTION_PATH`)가 같은 커밋이다. ref는 태그보다 commit SHA로 고정한다.
- 이 action을 필수 검사로 쓰면 workflow에 `paths` 필터를 두지 않는다. 필터로 건너뛴 workflow의 검사는 "Pending"으로 남아 병합을 막는다([GitHub 문서](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/collaborating-on-repositories-with-code-quality-features/troubleshooting-required-status-checks)).

### 입력

| 입력 | 기본값 | 내용 |
|---|---|---|
| `lockfile` | `package-lock.json` | 검사할 `package-lock.json`의 저장소 루트 기준 경로. 이름이 `package-lock.json`이어야 하고 workspace 안의 파일이어야 한다. |
| `fail-on` | 빈 값 | 실패로 더할 조건. `ml-hit`(ML 위험 점수 기준 이상), `incomplete`(보류). 쉼표나 공백으로 구분한다. 그 밖의 값은 입력 오류다. |
| `max-changes` | `20` | 바뀐 lockfile 항목이 이보다 많으면 검사하지 않고 실패한다. 양의 정수. |
| `model-version` | 없음(필수) | `model.txt`·`manifest.json`이 첨부된 depbee Release의 태그. |
| `model-sha256` | 없음(필수) | `model.txt`의 기대 sha256(소문자 16진수 64자). |
| `manifest-sha256` | 없음(필수) | `manifest.json`의 기대 sha256(소문자 16진수 64자). |
| `report` | 빈 값 | depbee 자체 CI의 자기 검사 전용. 비워 둔다. |

모델 세 입력은 `required: true`를 달지 않았다. GitHub는 composite action 입력의 `required`를 강제하지 않으므로, 첫 단계(`actions.py inputs`)가 값을 직접 검사해 없거나 형식이 틀리면 실패한다.
기지 악성 색인 입력은 아직 없다. depbee CLI에 색인을 넘기는 옵션이 생기면(KM-01) 모델과 같은 방식(Release 다운로드와 sha256 비교)으로 더한다.

### 단계

1. Python 3.13 준비(`actions/setup-python`).
2. 입력 검사, 임시 폴더 생성, `pyproject.toml`에서 feature-extractor 고정 커밋 읽기.
3. depbee 설치: `python -I -m pip install "$GITHUB_ACTION_PATH[extract,ml]"`. 실패하면 step이 실패한다.
4. Release에서 `model.txt`, `manifest.json`을 HTTPS로 받고(파일당 100 MiB, 300초 상한) 입력의 sha256과 비교한다. 다르면 실패한다. depbee도 모델을 열 때 `manifest.json`의 `model_sha256`과 `model.txt`를 다시 비교한다.
5. `depbee plan --base-ref`로 바뀐 항목 수를 세어 `max-changes`를 넘으면 실패한다.
6. 캐시 복원, `depbee scan . --base-ref <base sha> --extract --model-dir ... --cache-dir ... --format markdown --output report.json`, 캐시 저장.
7. `report.json`을 artifact `depbee-report`로 올린다.
8. 판정: `actions.py report`가 보고서를 읽어 주석과 job summary를 쓰고 step의 성공·실패를 정한다.

`depbee scan`의 종료 코드(0/1/2)는 로그에만 남긴다. 종료 코드 2는 1을 덮으므로(보류가 하나라도 있으면 2) 판정에 쓰지 않는다.
action의 Python 단계는 `python -I`로 실행해 PR checkout 안의 파일이 import를 가로채지 못하게 한다.
입력값은 `env:`로만 step에 넘기고 `run:` 본문에 `${{ }}`로 넣지 않는다.

### 판정 규칙

판정은 보고서 `results`의 항목별 `known_malicious.status`, `ml.status`, `status`로만 한다(client-dev-handoff 2.3절 1번).

| 상황 | 기본 | `fail-on` |
|---|---|---|
| 기지 악성 일치(`known_malicious.status`가 `hit`) | 실패, `::error` | 항상 실패. 낮은 ML 점수가 이를 취소하지 않는다. |
| ML 위험 점수 기준 이상(`ml.status`가 `hit`) | 경고, `::warning` | `ml-hit`이면 실패, `::error` |
| 보류(`status`가 `incomplete`) | 경고, `::warning` | `incomplete`이면 실패, `::error` |
| 입력 오류, 모델 sha256 불일치, depbee 설치 실패, 변경 수 초과, 보고서 없음·깨진 JSON·필요한 필드 없음 | 실패 | 바꿀 수 없음 |

보류는 검사를 끝내지 못한 항목이며 경고로 두더라도 통과로 바꾸지 않는다. summary와 주석은 "보류, 통과가 아님"으로 쓴다.
보고서를 만들지 못한 오류(CLI 입력 오류 등)는 `report.json`이 없으므로 판정 단계가 실패한다.
실패한 검사가 병합을 실제로 막는지는 저장소 소유자의 필수 검사(branch protection, ruleset) 설정이 정한다.
CLI 종료 코드 0/1/2의 의미는 그대로다.

### 주석, summary, artifact

- 주석은 기지 악성 일치·ML 기준 이상·보류 항목마다 하나이고, `package-lock.json`에서 그 항목의 `packages` 키(`"node_modules/@scope/name":`) 줄에 단다. 줄을 찾지 못하면 파일 단위 주석이다.
- 주석 문구는 `depbee: <패키지>@<버전> (<위치>): <이유>`이다. 패키지 유래 문자열은 CLI와 같이 출력할 수 없는 문자를 `\uXXXX`로 바꾼 뒤 workflow 명령 규칙으로 이스케이프한다. 메시지는 `%`, `\r`, `\n`을, 속성값(`file`)은 여기에 `:`, `,`까지 `%XX`로 바꾼다(actions/toolkit `command.ts`의 escapeData·escapeProperty와 같은 규칙).
- job summary(`GITHUB_STEP_SUMMARY`)에는 depbee CLI의 Markdown 출력(CLI의 Markdown 이스케이프 그대로)을 먼저 쓰고, 그 아래에 action 판정 절(기지 악성·ML·보류 개수와 각각 실패인지 경고인지, 최상위 `exit_code`를 쓰지 않았다는 안내)을 붙인다. GitHub는 step 하나의 summary를 1 MiB로 제한한다.
- artifact `depbee-report`에는 `report.json` 하나가 들어 있다. 보고서가 없으면 업로드는 경고만 내고, 판정 단계가 실패한다.
- artifact 이름이 고정이라 한 workflow run에서 이 action은 한 번만 쓸 수 있다(`actions/upload-artifact` v4 이후 같은 이름의 artifact는 실패). lockfile 여러 개나 matrix는 지원하지 않는다.

### 캐시

- depbee 분석 캐시 폴더(`$RUNNER_TEMP/depbee-cache`)를 `actions/cache/restore`·`actions/cache/save`로 보존한다. 같은 버전 쌍을 다시 받아 추출하지 않기 위한 성능용이다.
- 키는 `depbee-<runner OS>-<model-sha256>-<extractor 커밋>-<run id>-<run attempt>`이고, 같은 앞부분을 `restore-keys`로 쓴다. 매 실행이 새 키로 저장해 이전 항목에 새 항목이 쌓인다.
- 캐시는 판정의 신뢰 근거가 아니다. depbee는 캐시 항목마다 모델 입력·feature-extractor 설치 출처·depbee 버전·형식을 키로 확인하고 맞지 않으면 다시 추출한다.
- 범위: `pull_request` 실행이 저장한 캐시는 그 PR의 merge ref(`refs/pull/N/merge`) 범위라 같은 PR의 다음 실행과 재실행만 복원한다. 다른 PR과 기본 브랜치는 쓰지 못한다. 이 action은 `pull_request`에서만 동작하므로 기본 브랜치 캐시를 만들지 않는다. 그래서 새 PR의 첫 실행은 캐시 없이 시작한다.
- 저장 권한이 없는 실행에서는 저장만 실패하고 step과 job은 실패하지 않는다([GitHub 문서](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)). 저장소 캐시는 기본 10 GB이고 7일 동안 쓰지 않은 항목은 지워진다.

### 권한과 secret

- secret을 쓰지 않는다. depbee 설치(공개 뒤), 모델 다운로드, registry 다운로드는 모두 토큰 없이 한다. `GITHUB_TOKEN`은 checkout에만 쓰이고 `contents: read`로 충분하다.
- `pull_request_target`, `continue-on-error`, `|| true`를 쓰지 않는다.

### fork·Dependabot PR

- fork에서 온 `pull_request` 실행과 Dependabot이 만든 PR의 실행은 읽기 전용 `GITHUB_TOKEN`을 받고 Actions secret을 받지 않는다(Dependabot은 Dependabot secret만). 이 action은 secret과 쓰기 권한이 필요 없으므로 같은 방식으로 동작한다.
- 공개 저장소에서 처음 기여하는 사람의 fork PR은 쓰기 권한이 있는 maintainer가 workflow 실행을 승인해야 할 수 있다.
- PR 댓글은 쓰지 않는다. 결과는 summary, 주석, artifact로만 남긴다.

### workflow 변경 보호

`pull_request`에서는 PR 쪽의 workflow 파일이 실행된다. PR이 workflow에서 이 action을 지우거나 입력을 바꾸면 검사가 약해진다.
다음으로 막는다.

- CODEOWNERS에 `.github/workflows/`를 넣고 브랜치 보호(또는 ruleset)에서 code owner 리뷰를 필수로 한다. workflow 변경은 지정한 리뷰어의 승인이 있어야 병합된다.
- 이 job을 필수 검사로 지정한다. 실패하거나 실행되지 않은 검사는 병합을 막는다.
- 대상 저장소의 모델 sha256 입력도 workflow 파일에 있으므로 같은 보호를 받는다.

### 공개 전 제한과 미검증

- depbee와 feature-extractor가 아직 비공개라 다른 저장소에서 이 action을 실행할 수 없다. 설치 단계(`[extract]`는 feature-extractor를 git 주소와 커밋으로 받음)가 토큰 없이 되지 않는다.
- 모델을 첨부한 Release가 아직 없어 모델 입력에 기본값이 없다.
- 실제 PR에서의 설치, 모델 다운로드, `depbee scan --extract`, 캐시 저장·복원, 주석 표시는 확인하지 않았다. 확인한 범위는 아래 자기 검사와 `docs/validation.md`에 있다.
- Linux runner만 고려했다. Windows·macOS runner는 확인하지 않았다(`bash`, `curl`, `sed`, `mktemp`를 쓴다).

### 자기 검사 (depbee CI `action` job)

공개 전이라 실제 설치·다운로드는 CI에서 돌릴 수 없어, 합성 자료로 되는 범위만 검사한다.

- 판정 모듈을 직접 호출해 종료 코드를 확인한다(`docs/examples/result-contract/`의 예시 보고서). 실패를 기대하는 경우도 `continue-on-error` 없이 `if`로 종료 코드를 본다. 기지 악성 일치는 실패, ML 기준 이상·보류는 기본 성공이고 `fail-on`으로 실패, 보고서 없음·알 수 없는 `fail-on`·sha256 불일치는 실패다.
- `uses: ./`를 `report` 입력(보류 예시 보고서)으로 실행해 입력 검사, summary, artifact, 경고 주석의 배선을 확인한다. `report`가 있으면 설치·모델 다운로드·변경 수·캐시·scan 단계는 건너뛴다.
- 판정 모듈의 단위 테스트는 `tests/test_actions.py`이다(적대적 패키지 이름 이스케이프, lockfile 줄 찾기 포함).

## CI 신뢰 경계

- PR이 수정할 수 있는 모델·특징 JSON을 판정 근거로 신뢰하지 않는다. 모델은 workflow의 sha256과 비교한 Release 파일만 쓴다.
- 도구/정책/모델은 보호된 참조에서 로딩한다. 대상 package.json의 script를 실행하지 않는다.
- `pull_request_target`으로 외부 PR 코드를 실행하지 않는다. 토큰·secrets를 분석기에 넘기지 않는다.
- 모델 실패를 무시하는 `continue-on-error`, `|| true`를 보안 게이트에 사용하지 않는다.
- 수동 승인은 특정 버전·파일 해시·분석 요청에 묶는다. 패키지 영구 허용은 별도 논의한다.
- 신규 패키지·사설 레지스트리 등 미지원 항목은 현재 보류 대상이다. 전체 의존성 안전 보장을 주장하지 않는다.

참고: [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use),
[pull_request 이벤트](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request),
[workflow commands](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands),
[composite action 메타데이터](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax),
[npm lockfile 형식](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).

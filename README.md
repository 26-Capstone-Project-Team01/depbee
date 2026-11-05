# depbee

npm 프로젝트에서 바뀐 의존성 버전을 찾아, 각 버전의 변경점에서 feature를 추출하고 학습된 LightGBM 모델로 악성 업데이트 위험을 판정하는 Python CLI입니다.
이름은 dependency와 bee를 합친 것입니다.

패키지를 설치하거나 패키지 코드를 실행하지 않습니다. tarball을 받아 읽기만 합니다.
점수는 모델의 판정이며 패키지가 안전하다는 보증이 아닙니다.

## 구현 현황

| 영역      | 현재 구현 내용                                                                                    | 남은 연결·검증                          |
| --------- | ------------------------------------------------------------------------------------------------- | --------------------------------------- |
| 입력 처리 | lockfile v2/v3 비교(기준은 파일·Git 커밋), 직접·중첩 의존성 변경·추가 추출, 변경·요청 ID와 해시. lockfile 없이 registry의 버전 하나(`check`) | 추가 입력 형식                          |
| 분석      | `--extract`: feature-extractor로 설치될 버전과 그 직전 stable을 비교해 feature·근거 추출, 받은 tarball의 integrity·주소·크기·시간 검사, 추출한 feature를 실행 사이에 재사용하는 캐시와 소요 시간 | 실제 registry에서의 상한값 검증         |
| 분석 연결 | `--analysis`: 다른 분석기가 만든 JSON의 요청 ID·변경 ID·중복·상태·feature 형식 검증               |                                         |
| 모델 추론 | native LightGBM 로딩, 모델 해시·이진 분류·feature 이름/순서·자료형 검증, feature별 기여도 계산     | 검증 세트로 정한 임계값 수령            |
| 판정 조율 | feature 스키마 확인, 임계값 판정, 실패·학습 범위 밖 입력은 `incomplete` 처리                      |                                         |
| CLI 출력  | `plan`/`scan`/`check`, 한국어 텍스트·JSON·Markdown, 새 파일 저장, 종료 코드 0/1/2                 | GitHub job summary 화면 확인            |
| 테스트    | 합성 입력 회귀 테스트, 합성 native 모델 연동 테스트                                                |                                         |
| 개발 CI   | push/PR에서 Ubuntu·Windows × Python 3.11·3.13 검사·테스트·패키지 빌드                              | GitHub 서버 실행 확인                   |

웹/API, HTML 보고서, npm 설치 전 위험 변경을 차단하는 탐지 CI는 아직 구현하지 않았습니다.
현재 개발 CI에는 `ruff format --check`가 포함되지 않습니다.

## 구조

```text
src/depbee/
  cli.py                  # 인자·한국어 텍스트·JSON 출력·종료 코드
  contracts.py            # 공통 규약과 Analyzer/Predictor 인터페이스
  inputs/npm.py           # 대상 프로젝트와 기준 lockfile 비교, check의 단일 버전 요청
  inputs/git.py           # Git 커밋에서 기준 lockfile 읽기
  analysis/extractor.py   # feature-extractor 호출, 근거 정리
  analysis/baseline.py    # 비교 기준 버전(직전 stable) 선정
  analysis/cache.py       # 추출한 feature의 실행 간 캐시
  analysis/registry.py    # registry 메타데이터·tarball 다운로드와 검사, 압축 해제
  analysis/artifact.py    # 분석 결과 검증, 미리 만든 분석 JSON 연결
  inference/lightgbm.py   # 학습 완료 모델 로딩·검증·추론·기여도
  pipeline.py             # 입력→분석→추론 처리 조율
  service.py              # CLI·Actions·MCP·대시보드 공통 진입점(요청·분석기·모델 조립)
scripts/write_manifest.py # 모델 파일로 manifest.json 생성
tests/                    # 합성 자료를 이용한 회귀·모델 연동 테스트
examples/                 # 실행 가능한 명령에 사용할 가상 lockfile
docs/                     # 구조·연결 규약·CI 설계·개발 순서
models/                   # 실제 모델, Git 제외
data/                     # 실제 샘플, Git 제외
artifacts/                # 요청·분석·결과 JSON, Git 제외
.github/workflows/ci.yml  # 이 도구 자체의 검사·테스트·패키징
```

## 개발 환경

Python 3.11 이상, 로컬은 3.13을 권장합니다. PowerShell에서:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,ml,extract]"
.\.venv\Scripts\python.exe -m depbee --help
```

`extract`는 팀의 비공개 저장소 feature-extractor를 고정된 커밋으로 설치하므로 GitHub 접근 권한이 필요합니다.
feature-extractor를 함께 개발할 때는 그 저장소를 받아 `pip install -e ../feature-extractor`로 대신 설치합니다.
모델 없는 입력·계약 작업만 한다면 `ml`과 `extract`를 빼고 설치할 수 있습니다.
macOS/Linux에서는 `python3 -m venv .venv`와 `.venv/bin/python`을 사용합니다.

## 모델 준비

모델 담당자가 `Booster.save_model()`로 저장한 native 모델을 `models/<model-id>/model.txt`에 두고 manifest를 만듭니다.

```powershell
.\.venv\Scripts\python.exe scripts/write_manifest.py models/<model-id> --model-id <model-id> --threshold <검증한 임계값>
```

스크립트는 모델 파일에서 feature 이름·순서와 범주 순서를 읽고, feature 자료형(boolean·범주·결측 허용)은 분석기의 feature 스키마에서 가져옵니다.
임계값은 모델 담당자가 검증 세트로 정한 값을 넣습니다.
manifest 구조는 [연결 규약](docs/contracts.md)에 있습니다.

## 실행

```powershell
.\.venv\Scripts\python.exe -m depbee plan C:/path/to/target --base-lock C:/path/to/base-package-lock.json
.\.venv\Scripts\python.exe -m depbee scan C:/path/to/target --base-lock C:/path/to/base-package-lock.json --extract --model-dir models/<model-id>
.\.venv\Scripts\python.exe -m depbee check lodash@4.17.21 --model-dir models/<model-id>
```

비교 기준은 `--base-lock <파일>`로 주거나, 생략하면 대상 폴더가 속한 Git 저장소의 HEAD 커밋에 있는 같은 위치의 `package-lock.json`을 씁니다.
다른 커밋·브랜치·태그는 `--base-ref <ref>`로 지정하며, `--base-lock`과 함께 쓸 수 없습니다.
Git은 읽기 전용 명령(`rev-parse`, `cat-file`)만 실행하고 fetch, merge-base 계산, 작업 트리·브랜치 변경은 하지 않습니다. 원격 브랜치를 기준으로 쓰려면 미리 fetch해 둡니다.
부분 복제(partial clone) 저장소에서도 없는 객체를 원격에서 자동으로 받지 않도록 `--no-lazy-fetch`와 `GIT_NO_LAZY_FETCH=1`로 실행합니다. 기준 커밋의 lockfile이 로컬에 없으면 오류(종료 코드 2)로 끝납니다. `--base-ref`와 기본 HEAD 기준에는 Git 2.45 이상이 필요하고(`--no-lazy-fetch`가 2.45에 추가됨), 그보다 오래된 Git에서는 받는 대신 필요한 버전을 알리는 오류(종료 코드 2)로 끝납니다. `--base-lock`은 Git이 필요 없습니다.
부모 프로세스의 `GIT_DIR`, `GIT_WORK_TREE` 같은 저장소 지정 환경 변수는 Git에 넘기지 않으므로 항상 대상 폴더가 속한 저장소를 읽고, replace ref(`refs/replace/`)는 적용하지 않습니다(`--no-replace-objects`). 커밋의 부모를 바꾸는 graft(`GIT_GRAFT_FILE`, `.git/info/grafts`)도 쓰지 않도록 Git에 빈 graft 파일(`GIT_GRAFT_FILE`을 null 장치로)을 줍니다.
Git 명령에는 30초 제한과 출력 크기 상한이 있습니다. 제한을 넘으면 depbee가 직접 실행한 Git 프로세스를 종료하지만 그 하위 프로세스는 종료하지 않습니다. Windows 기본 설치의 `Git\cmd\git.exe`는 실제 Git을 하위 프로세스로 실행하는 wrapper라서, 시간 초과 오류가 실제 Git이 끝날 때까지 늦어질 수 있습니다. 현재 폴더나 상대 경로 PATH 항목에서 찾은 `git`은 실행하지 않고 오류로 처리합니다. Windows에서는 인자가 cmd.exe를 거치지 않도록 `git.exe`만 실행하고 `git.cmd`·`git.bat`은 쓰지 않습니다.

`plan`은 바뀐 버전 쌍과 `request_id`를 JSON으로 출력합니다.
`scan --extract`는 바뀌거나 새로 추가된 의존성마다 tarball을 받아 feature를 추출하고 모델로 판정합니다.
텍스트 출력은 판정별 개수를 먼저 보여 주고 위험 → 보류 → 통과 순, 같은 판정 안에서는 점수 순으로 나열합니다. `--extract`로 분석하는 동안에는 진행 상황을 표준 오류에 표시합니다.
`--format json`은 같은 결과를 lockfile 순서 그대로 JSON으로 출력하고(진행 표시 없음), `--output`은 결과를 새 파일에 저장합니다(기존 파일을 덮어쓰지 않습니다). 이미 있는 경로를 주면 다운로드나 분석을 시작하기 전에 오류(종료 코드 2)로 끝납니다.
`--format markdown`(`scan`, `check`)은 같은 결과를 GitHub job summary 등에 붙일 수 있는 한국어 Markdown(전체 판정, 결과 표, 항목별 추출된 사실과 모델 설명)으로 출력합니다. 순서는 텍스트와 같고 진행 표시는 없으며, `--output` 파일은 이때도 JSON입니다. 패키지 이름·버전·근거처럼 보고서에서 온 문자열은 모두 code span으로 감싸 HTML·링크·이미지·강조로 해석되지 않게 합니다.
오류는 표준 오류에 JSON으로 나옵니다.
tarball은 Python 임시 폴더에 풀었다가 지웁니다. 위치를 바꾸려면 `TMP`/`TEMP` 환경변수를 지정합니다.
registry 메타데이터와 tarball은 depbee가 직접 받습니다(feature-extractor는 받은 것을 읽기만 합니다). `https://registry.npmjs.org`에서만, redirect 뒤에도 그 주소에서만 받고, tarball 주소는 그 패키지·버전의 registry 경로(`/<이름>/-/<이름>-<버전>.tgz`)여야 합니다. 받은 tarball 바이트는 그 버전의 `dist.integrity`(가장 강한 해시 알고리즘, npm과 같은 방식)와 대조한 뒤에만 풉니다.
다운로드 하나는 메타데이터 128 MiB, tarball 128 MiB, 벽시계 120초를 넘으면 멈추고, 압축 해제는 풀린 크기 512 MiB와 파일 20,000개를 넘으면 멈춥니다. 하나라도 넘거나 맞지 않으면 그 항목은 분석 실패(`incomplete`, 종료 코드 2)입니다. 압축 해제와 feature 추출 자체에는 시간 상한이 없습니다. 값의 근거는 [검증 기록](docs/validation.md)에 있습니다.

`check NAME@VERSION`은 lockfile 없이 npm 공식 registry의 버전 하나를 `scan --extract`와 같은 방식(같은 release line의 직전 stable과 비교)으로 검사합니다. 설치 전에 특정 버전을 확인할 때 씁니다.
`lodash@4.17.21`이나 `@scope/name@1.0.0`처럼 정확한 이름과 버전만 받고, 범위(`^1.0.0`)·태그(`latest`)·URL·Git·파일 경로·사설 registry는 네트워크에 접근하기 전에 오류(종료 코드 2)로 거부합니다.
버전은 npm이 버전을 표시하는 build metadata 없는 형식(`1.2.3`, `1.2.3-beta.1`)만 지원합니다. `1.2.3+build.1`처럼 `+`가 붙은 버전은 SemVer 문법상 유효하지만 이 명령의 지원 범위가 아니라서 거부합니다. 숫자로만 된 pre-release 식별자의 선행 0(`1.0.0-01`)처럼 SemVer에 맞지 않는 버전도 거부합니다.
registry 메타데이터는 한 번만 받아 요청, 분석, feature 추출(feature-extractor의 snapshot)에 함께 씁니다. 그 버전이 registry에 없거나, tarball 주소가 `https://registry.npmjs.org`가 아니거나, `dist.integrity`가 없거나, 메타데이터 형식이 잘못됐으면 오류(종료 코드 2)로 끝납니다.
pre-release와 비교할 이전 stable이 없는 버전은 `scan`과 같이 `incomplete`입니다.
결과에는 "lockfile 없이 registry 정보로 검사"했다는 범위(`input_kind: "package"`)와 근거가 표시됩니다. 출력 형식, `--output`, 진행 표시(텍스트만), 종료 코드는 `scan`과 같습니다.

`scan --extract`와 `check`는 추출한 feature를 캐시 폴더(기본 `~/.cache/depbee`, `--cache-dir`로 변경)에 저장해, 같은 두 버전을 다시 비교할 때 tarball을 다시 받거나 추출하지 않습니다. registry 메타데이터는 매번 다시 받아 확인하고, 판정·점수·근거는 매번 새로 계산합니다.
캐시 키는 패키지와 비교한 두 버전, 두 버전의 registry manifest·integrity·배포 시각, feature 스키마, 설치된 feature-extractor의 출처(고정 커밋, 설치 파일 해시, Python 버전), 모델 파일과 manifest의 해시입니다. 하나라도 다르면 다시 추출합니다.
모델이 없을 때, feature-extractor가 고정 커밋 그대로 설치됐는지 확인할 수 없을 때(편집 가능 설치, 로컬 폴더 설치, 설치 후 수정), 로컬 사본(`--local-source`)으로 읽은 버전, 분석에 실패한 항목은 캐시를 쓰지 않습니다. `--no-cache`는 캐시를 읽지도 쓰지도 않습니다.
캐시한 feature는 모델이 받을 수 있는 이름과 자료형인지 다시 확인하고, 아니면 쓰지 않고 다시 추출합니다(모델이 받지 못하는 feature는 처음부터 저장하지 않습니다). 캐시 파일은 형식과 키만 검사하므로 누가 썼는지는 보증하지 못합니다. 다른 사람이나 PR이 쓸 수 있는 폴더를 캐시로 지정하지 않습니다. 캐시는 자동으로 지우지 않으므로 필요하면 폴더를 직접 지웁니다.
두 명령의 결과에는 전체 소요 시간(`elapsed_seconds`)과, 항목별로 메타데이터 조회·캐시 조회·추출에 걸린 시간(추론 제외)과 캐시 사용 여부(`cache_hit`)가 붙습니다. `--extract` 없는 `scan`과 `plan`의 출력은 바뀌지 않습니다.

`scan`과 `check`에서 `--model-dir`을 생략하면 환경 변수 `DEPBEE_MODEL_DIR`의 모델 폴더를 씁니다. `--model-dir`이 항상 우선하고, 둘 다 없거나 환경 변수가 빈 값이면 모델 없이 처리합니다(분석할 변경이 있으면 `incomplete`).
지정한 경로가 잘못되면 다른 모델로 대체하지 않고 오류(종료 코드 2)로 끝납니다. 대상 프로젝트의 설정에서는 모델 경로를 읽지 않습니다.
이 폴더의 모델은 신뢰한 입력으로 다루므로(manifest와 모델 해시만 대조합니다) 직접 준비한 신뢰할 수 있는 모델 폴더만 지정합니다.

다른 분석기가 만든 결과가 있으면 `--extract` 대신 `--analysis <분석 JSON>`을 씁니다.
registry에서 내려간 버전(예: 삭제된 악성 버전)을 시연할 때는 `--local-root <폴더>`와 `--local-source NAME@VERSION=<폴더 안의 상대 경로>`로 그 버전의 사본을 지정합니다.
사본은 lockfile integrity로 확인할 수 없어 결과의 근거에 그 사실이 표시됩니다.

예시 lockfile(`examples/`)에는 패키지 코드가 없고 URL·integrity가 가상 값이라 `--extract`로는 분석되지 않습니다.

## 동작 방식

- **비교 기준:** 모델은 "새 버전과 같은 release line의 직전 stable → 새 버전" 쌍으로 학습했습니다. 그래서 lockfile에서 1.2.0 → 1.5.3으로 바뀌어도 1.5.3을 같은 line의 직전 stable(예: 1.5.2)과 비교합니다. release line은 npm `^` 범위 단위이고(`>=1.0.0`은 major, `0.y.z`는 `0.y`), 새 line의 첫 버전이면 이전 line의 최신 stable과 비교합니다. lockfile의 이전 버전은 근거에만 표시합니다.
- **새로 추가된 의존성:** 같은 방식으로 설치될 버전과 그 직전 stable을 비교합니다.
- **학습 범위 밖 입력:** 새 버전이 pre-release이거나, 비교할 이전 stable이 없거나, 모델이 본 적 없는 범주 값이면 점수를 내지 않고 `incomplete`로 둡니다.
- **배포 시각:** 비교 기준 선정에 쓰는 registry 배포 시각이 ISO 8601 형식이 아니거나 timezone이 없으면 그 항목은 분석 실패(`incomplete`)입니다.
- **무결성:** 설치될 버전의 lockfile integrity가 registry 값과 다르면 분석 실패로 처리합니다.
- **근거와 설명:** 결과에는 추출된 사실(비교한 버전, 추가된 설치 스크립트, 새 의존성, 바뀐 JS 파일 수)과 모델 설명(점수에 크게 작용한 feature와 기여도)이 따로 나옵니다. 기여도는 LightGBM의 SHAP 값(log-odds 단위)입니다. 상위 feature 외의 기여도 합과 모델 기준값도 함께 보여 주며, 모두 더하면 점수의 log-odds가 됩니다.

| 종료 코드 | 의미                                      | 탐지 CI 처리        |
| --------- | ----------------------------------------- | ------------------- |
| 0         | 평가 대상 변경 중 미완료·위험 판정 없음   | 다음 단계 진행 가능 |
| 1         | 모델 기준 이상인 변경 존재                | 후속 설치·빌드 중단 |
| 2         | 입력 오류·분석 실패·미지원·모델 연결 문제 | 후속 단계 보류      |

변경 없음·삭제만 있는 요청도 0입니다. 프로젝트 전체가 안전하다는 뜻이 아닙니다.

## 현재 제한

- 로컬 `package-lock.json` v2/v3만 지원합니다. 기준 lockfile은 파일이나 Git 커밋에서 읽고, 저장소 하위 폴더의 단일 프로젝트는 지원하지만 npm workspaces 전체를 한 번에 비교하지는 않습니다.
- npm 공식 registry 의존성만 분석합니다. workspace/link, Git·file·사설 레지스트리 의존성, 같은 버전의 아카이브 변경은 `incomplete`입니다.
- 설치될 버전은 lockfile integrity가 registry 메타데이터의 값과 같은지 보고, 받은 tarball 바이트는 registry 메타데이터의 `dist.integrity`와 대조합니다(없으면 옛 `dist.shasum`). `check`는 대조할 lockfile이 없어 registry 값만 쓰며(registry 문서상 2017년 4월부터 기록된 값), 새 버전에 이 값이 없으면 검사하지 못합니다.
- 다운로드 시간 상한이 끝난 뒤에도 네트워크 동작 중이던 연결은 바로 끊지 못하고 버려 둡니다. 그 동작이 끝나거나(데이터 없이 최대 30초) 프로세스가 끝나면 사라집니다.
- 학습 데이터와 달리 비교 기준 후보를 OSV 악성 목록과 대조하지 않고, 새 버전 직전 24시간 안의 후보도 별도로 검증하지 않습니다.
- typosquat처럼 패키지 자체가 악성인 경우는 "업데이트 변경점"을 보는 이 모델의 범위가 아닙니다.
- `package.json`만 있는 프로젝트, yarn/pnpm, Git URL 입력은 후속 범위입니다.

## 검증

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m build
```

테스트는 네트워크와 feature-extractor 없이 돌도록 feature-extractor 호출을 가짜로 바꿔 둡니다. ML 의존성이 없으면 native LightGBM 테스트는 skip됩니다.
feature-extractor(`.[extract]`)가 설치돼 있으면 고정 커밋의 loader·extractor를 합성 tarball과 가짜 registry 응답으로 실행하는 경계 테스트도 돌고, 없으면 skip됩니다. 네트워크는 쓰지 않습니다.
테스트의 작은 모델은 직렬화·연결 검증용 합성 모델이며 실제 악성 탐지 모델이 아닙니다.

다음 작업은 [연결 규약](docs/contracts.md), [구조와 담당](docs/architecture.md), [CI/CD 연결](docs/ci-cd.md), [통합 순서](docs/development.md)를 참고합니다.

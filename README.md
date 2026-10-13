# depbee

npm 프로젝트에서 바뀐 의존성 버전을 찾아, 각 버전의 변경점에서 feature를 추출하고 학습된 LightGBM 모델로 악성 업데이트 위험을 판정하는 Python CLI입니다.
이름은 dependency와 bee를 합친 것입니다.

패키지를 설치하거나 패키지 코드를 실행하지 않습니다. tarball을 받아 읽기만 합니다.
점수는 모델의 판정이며 패키지가 안전하다는 보증이 아닙니다.

## 구현 현황

| 영역      | 현재 구현 내용                                                                                    | 남은 연결·검증                          |
| --------- | ------------------------------------------------------------------------------------------------- | --------------------------------------- |
| 입력 처리 | lockfile v2/v3 비교, 직접·중첩 의존성의 변경·추가 추출, 변경·요청 ID와 파일 해시 생성             | Git 기준 파일 자동 추출, 추가 입력 형식 |
| 분석      | `--extract`: feature-extractor로 설치될 버전과 그 직전 stable을 비교해 feature·근거 추출          | tarball 자체의 integrity 검증           |
| 분석 연결 | `--analysis`: 다른 분석기가 만든 JSON의 요청 ID·변경 ID·중복·상태·feature 형식 검증               |                                         |
| 모델 추론 | native LightGBM 로딩, 모델 해시·이진 분류·feature 이름/순서·자료형 검증, feature별 기여도 계산     | 검증 세트로 정한 임계값 수령            |
| 판정 조율 | feature 스키마 확인, 임계값 판정, 실패·학습 범위 밖 입력은 `incomplete` 처리                      |                                         |
| CLI 출력  | `plan`/`scan`, 한국어 텍스트·JSON, 새 파일 저장, 종료 코드 0/1/2                                  |                                         |
| 테스트    | 합성 입력 회귀 테스트, 합성 native 모델 연동 테스트                                                |                                         |
| 개발 CI   | push/PR에서 Ubuntu·Windows × Python 3.11·3.13 검사·테스트·패키지 빌드                              | GitHub 서버 실행 확인                   |

웹/API, HTML 보고서, npm 설치 전 위험 변경을 차단하는 탐지 CI는 아직 구현하지 않았습니다.
현재 개발 CI에는 `ruff format --check`가 포함되지 않습니다.

## 구조

```text
src/depbee/
  cli.py                  # 인자·한국어 텍스트·JSON 출력·종료 코드
  contracts.py            # 공통 규약과 Analyzer/Predictor 인터페이스
  inputs/npm.py           # 대상 프로젝트와 기준 lockfile 비교
  analysis/extractor.py   # feature-extractor 호출, 근거 정리
  analysis/baseline.py    # 비교 기준 버전(직전 stable) 선정
  analysis/artifact.py    # 분석 결과 검증, 미리 만든 분석 JSON 연결
  inference/lightgbm.py   # 학습 완료 모델 로딩·검증·추론·기여도
  pipeline.py             # 입력→분석→추론 처리 조율
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
```

`plan`은 바뀐 버전 쌍과 `request_id`를 JSON으로 출력합니다.
`scan --extract`는 바뀌거나 새로 추가된 의존성마다 tarball을 받아 feature를 추출하고 모델로 판정합니다.
텍스트 출력은 판정별 개수를 먼저 보여 주고 위험 → 보류 → 통과 순, 같은 판정 안에서는 점수 순으로 나열합니다. `--extract`로 분석하는 동안에는 진행 상황을 표준 오류에 표시합니다.
`--format json`은 같은 결과를 lockfile 순서 그대로 JSON으로 출력하고(진행 표시 없음), `--output`은 결과를 새 파일에 저장합니다(기존 파일을 덮어쓰지 않습니다).
오류는 표준 오류에 JSON으로 나옵니다.
tarball은 Python 임시 폴더에 풀었다가 지웁니다. 위치를 바꾸려면 `TMP`/`TEMP` 환경변수를 지정합니다.

다른 분석기가 만든 결과가 있으면 `--extract` 대신 `--analysis <분석 JSON>`을 씁니다.
registry에서 내려간 버전(예: 삭제된 악성 버전)을 시연할 때는 `--local-root <폴더>`와 `--local-source NAME@VERSION=<폴더 안의 상대 경로>`로 그 버전의 사본을 지정합니다.
사본은 lockfile integrity로 확인할 수 없어 결과의 근거에 그 사실이 표시됩니다.

예시 lockfile(`examples/`)에는 패키지 코드가 없고 URL·integrity가 가상 값이라 `--extract`로는 분석되지 않습니다.

## 동작 방식

- **비교 기준:** 모델은 "새 버전과 같은 release line의 직전 stable → 새 버전" 쌍으로 학습했습니다. 그래서 lockfile에서 1.2.0 → 1.5.3으로 바뀌어도 1.5.3을 같은 line의 직전 stable(예: 1.5.2)과 비교합니다. release line은 npm `^` 범위 단위이고(`>=1.0.0`은 major, `0.y.z`는 `0.y`), 새 line의 첫 버전이면 이전 line의 최신 stable과 비교합니다. lockfile의 이전 버전은 근거에만 표시합니다.
- **새로 추가된 의존성:** 같은 방식으로 설치될 버전과 그 직전 stable을 비교합니다.
- **학습 범위 밖 입력:** 새 버전이 pre-release이거나, 비교할 이전 stable이 없거나, 모델이 본 적 없는 범주 값이면 점수를 내지 않고 `incomplete`로 둡니다.
- **무결성:** 설치될 버전의 lockfile integrity가 registry 값과 다르면 분석 실패로 처리합니다.
- **근거와 설명:** 결과에는 추출된 사실(비교한 버전, 추가된 설치 스크립트, 새 의존성, 바뀐 JS 파일 수)과 모델 설명(점수에 크게 작용한 feature와 기여도)이 따로 나옵니다. 기여도는 LightGBM의 SHAP 값(log-odds 단위)입니다. 상위 feature 외의 기여도 합과 모델 기준값도 함께 보여 주며, 모두 더하면 점수의 log-odds가 됩니다.

| 종료 코드 | 의미                                      | 탐지 CI 처리        |
| --------- | ----------------------------------------- | ------------------- |
| 0         | 평가 대상 변경 중 미완료·위험 판정 없음   | 다음 단계 진행 가능 |
| 1         | 모델 기준 이상인 변경 존재                | 후속 설치·빌드 중단 |
| 2         | 입력 오류·분석 실패·미지원·모델 연결 문제 | 후속 단계 보류      |

변경 없음·삭제만 있는 요청도 0입니다. 프로젝트 전체가 안전하다는 뜻이 아닙니다.

## 현재 제한

- 로컬 `package-lock.json` v2/v3만 지원하고, 비교 기준 lockfile을 명시해야 합니다.
- npm 공식 registry 의존성만 분석합니다. workspace/link, Git·file·사설 레지스트리 의존성, 같은 버전의 아카이브 변경은 `incomplete`입니다.
- integrity는 lockfile과 registry 메타데이터를 비교합니다. 받은 tarball 자체의 해시는 아직 검증하지 않습니다.
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
테스트의 작은 모델은 직렬화·연결 검증용 합성 모델이며 실제 악성 탐지 모델이 아닙니다.

다음 작업은 [연결 규약](docs/contracts.md), [구조와 담당](docs/architecture.md), [CI/CD 연결](docs/ci-cd.md), [통합 순서](docs/development.md)를 참고합니다.

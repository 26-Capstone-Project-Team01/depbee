# npm-update-guard

npm 프로젝트의 변경된 의존성 버전을 추출하고, 팀원이 만든 정적 분석기와
학습된 LightGBM 모델을 연결하는 Python CLI입니다. 이름은 개발용 임시 이름입니다.

현재 구현된 범위는 lockfile 비교, 분석 요청 생성, 특징 JSON 검증,
LightGBM native 모델 추론 어댑터, 텍스트·JSON 출력과 종료 코드 처리입니다.
실제 분석기·학습 모델은 아직 제공되지 않았으며 탐지 성능이 검증된 제품은 아닙니다.

## 구현 현황

아래 표는 코드에 구현된 기능과 추가로 필요한 연결·검증을 구분합니다.

| 영역           | 현재 구현 내용                                                                 | 남은 연결·검증                                |
| -------------- | ------------------------------------------------------------------------------ | --------------------------------------------- |
| 입력 처리      | lockfile v2/v3 비교, 직접·중첩 의존성 변경 추출, 변경·요청 ID와 파일 해시 생성 | Git 기준 파일 자동 추출, 추가 입력 형식       |
| 분석 요청      | `plan`으로 버전 쌍과 지원 여부를 JSON 출력·저장                                | 팀원 분석기가 요청을 처리하도록 연결          |
| 분석 결과 연결 | 기존 JSON의 요청 ID·변경 ID·중복·상태·근거 형식 검증                           | 실제 정적 분석, Python 함수/CLI 자동 호출     |
| 모델 추론      | native LightGBM 로딩, 모델 해시·이진 분류·특징 이름/순서·수치 검증             | 실제 모델 수령 및 통합 검증                   |
| 판정 조율      | 특징 스키마 확인, 임계값 판정, 누락·실패 시 `incomplete` 처리                  | 실제 정상·악성·실패 사례 확인                 |
| CLI 출력       | `plan`/`scan`, 텍스트·JSON, 새 파일 저장, 종료 코드 0/1/2                      | 실제 분석기를 포함한 전체 흐름 검증           |
| 테스트         | 합성 입력 회귀 테스트와 작은 native 모델 연동 테스트 코드                      | ML 의존성 설치 후 skip 없이 전체 검사         |
| 개발 CI        | push/PR에서 Ubuntu·Windows × Python 3.11·3.13 검사·테스트·패키지 빌드          | GitHub 서버 실행 확인, 실제 탐지 CI 별도 구현 |

패키지 다운로드·압축 해제·정적 분석·특징 추출·실제 모델 학습은 현재 이 저장소에서 수행하지 않습니다.
웹/API, HTML 보고서, npm 설치 전 위험 변경을 차단하는 CI와 자동 배포도 미구현입니다.
현재 개발 CI에는 `ruff format --check`가 포함되지 않습니다.

## 구조

```text
src/npm_update_guard/
  cli.py                 # 인자·터미널·JSON 출력·종료 코드
  contracts.py           # 팀 간 규약과 Analyzer/Predictor 인터페이스
  inputs/npm.py          # 대상 프로젝트와 기준 lockfile 비교
  analysis/artifact.py   # 팀원 분석기의 JSON 결과 연결
  inference/lightgbm.py  # 학습 완료 모델 로딩·검증·추론
  pipeline.py            # 입력→분석→추론 처리 조율
tests/                   # 합성 자료를 이용한 회귀·모델 연동 테스트
examples/                # 실행 가능한 명령에 사용할 가상 lockfile
docs/                    # 구조·연결 규약·CI 설계·개발 순서
models/                  # 실제 모델, Git 제외
data/                    # 실제 샘플, Git 제외
artifacts/               # 요청·분석·결과 JSON, Git 제외
.github/workflows/ci.yml # 이 도구 자체의 검사·테스트·패키징
```

## 개발 환경

Python 3.11 이상, 로컬은 3.13을 권장합니다. PowerShell에서:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,ml]"
.\.venv\Scripts\python.exe -m npm_update_guard --help
```

활성화 스크립트나 PowerShell 실행 정책 변경 없이 실행할 수 있습니다.
macOS/Linux에서는 `python3 -m venv .venv`와 `.venv/bin/python`을 사용합니다.
모델 없는 입력·계약 작업만 한다면 ML 추가 의존성을 제외할 수 있습니다.

## 지금 실행해 보기

예시에는 패키지 코드가 없으며 URL·integrity도 가상 값입니다. 다운로드에 사용하지 마세요.

```powershell
.\.venv\Scripts\python.exe -m npm_update_guard plan examples/project --base-lock examples/baseline/package-lock.json
.\.venv\Scripts\python.exe -m npm_update_guard scan examples/project --base-lock examples/baseline/package-lock.json --format json
```

첫 명령은 변경된 버전 쌍과 `request_id`를 출력합니다.
두 번째는 모델·분석 결과가 없으므로 `incomplete`, 종료 코드 `2`가 정상적인 예상 결과입니다.
설치가 아직 안 된 환경에서는 `$env:PYTHONPATH = "$PWD/src"`를 설정한 후
`python -m npm_update_guard ...`로 입력 처리와 미완료 결과를 확인할 수 있습니다.

## 팀원 결과물을 연결한 뒤

### 모델 학습 후 받아야 할 것

| 인계 자료                          | 내용                                                                      |
| ---------------------------------- | ------------------------------------------------------------------------- |
| `models/release-001/model.txt`     | 팀원이 `Booster.save_model()`로 저장한 native LightGBM 모델               |
| `models/release-001/manifest.json` | 모델 ID·SHA-256·`objective`·양성 클래스·특징 스키마·특징 이름/순서·임계값 |
| 특징 정의·전처리 문서              | 각 특징의 의미·자료형·계산 방식·누락값 처리·전처리 버전                   |
| 학습·평가 기록                     | 데이터 범위·분할 방법·평가 지표·임계값 선정 근거·LightGBM 버전            |
| 분석 결과 또는 분석기              | 같은 특징 규약으로 새 버전 쌍을 처리하는 분석기와 요청별 결과 JSON        |

현재 런타임이 직접 읽는 모델 파일은 `model.txt`와 `manifest.json` 두 개입니다.
별도 `feature_schema.json`·`metadata.json`을 자동으로 읽는 기능은 없습니다.
manifest의 정확한 구조는 [연결 규약](docs/contracts.md)을 따릅니다.
특징 의미·전처리와 분석기 호출 방식은 아직 팀 합의가 필요합니다.

### 학습된 모델 활용 순서

1. 팀원이 특징 데이터와 정답 라벨로 모델을 학습·평가하고, 검증 세트로 임계값을 정합니다.
2. 모델과 manifest를 신뢰할 수 있는 경로로 받아 `models/release-001/`에 둡니다.
3. `plan`으로 실제 대상 프로젝트의 이전·현재 lockfile에서 분석 요청을 생성합니다.
4. 팀원 분석기가 해당 요청을 처리해 학습 때와 같은 특징·전처리를 적용한 JSON을 만듭니다.
5. `scan`에 분석 JSON과 모델 폴더를 지정합니다. CLI가 검증·추론·임계값 판정 후 결과를 출력합니다.
6. 동일 특징에 대한 팀원 측 예측과 CLI 점수를 비교하고, 정상·악성·분석 실패 사례를 확인합니다.

모델 파일만으로 패키지 소스를 판정할 수는 없습니다. 새 입력에서도 학습 때와 동일한 특징을
추출해야 합니다. 현재 어댑터는 이미 전처리된 유한한 수치 특징을 받으며 누락값을 임의로 채우지 않습니다.
아래 명령의 경로는 실제 파일로 바꿔야 합니다. 중간의 분석기 실행은 아직 자동화되지 않았습니다.

```powershell
.\.venv\Scripts\python.exe -m npm_update_guard plan C:/path/to/target --base-lock C:/path/to/base-package-lock.json --output artifacts/request-001.json
# 팀원 분석기가 이 요청을 처리해 artifacts/analysis-001.json 생성
.\.venv\Scripts\python.exe -m npm_update_guard scan C:/path/to/target --base-lock C:/path/to/base-package-lock.json --analysis artifacts/analysis-001.json --model-dir models/release-001 --output artifacts/report-001.json
```

`--output`은 기존 파일을 덮어쓰지 않습니다. 매 실행마다 새 이름을 사용합니다.
표준 출력은 선택한 형식, 오류는 표준 오류에 JSON으로 나옵니다.

| 종료 코드 | 의미                                      | 향후 탐지 CI 처리   |
| --------- | ----------------------------------------- | ------------------- |
| 0         | 평가 대상 변경 중 미완료·위험 판정 없음   | 다음 단계 진행 가능 |
| 1         | 모델 기준 이상인 변경 존재                | 후속 설치·빌드 중단 |
| 2         | 입력 오류·분석 실패·미지원·모델 연결 문제 | 후속 단계 보류      |

변경 없음·삭제만 있는 요청도 0입니다. 프로젝트 전체가 안전하다는 뜻이 아닙니다.
점수는 모델의 양성 클래스 출력이며 검증된 악성 확률로 표현하지 않습니다.
문턱값은 모델 담당자가 검증해 manifest로 전달합니다.

## 앞으로 구현·확인할 작업

아래 순서는 개발 제안이며 기한과 세부 특징은 팀 합의 후 확정합니다.

| 순서 | 작업                                            | 담당                    | 완료 기준                                                      |
| ---- | ----------------------------------------------- | ----------------------- | -------------------------------------------------------------- |
| 1    | 특징·전처리·모델·분석 결과 규약 합의            | 사용자 + 분석·모델 담당 | `docs/contracts.md`와 실제 입출력 샘플 일치                    |
| 2    | 패키지 확보·정적 분석·특징 추출, 모델 학습·평가 | 분석·모델 담당          | 분석 결과, 모델·manifest, 평가 기록 인계                       |
| 3    | 실제 JSON과 모델로 CLI 연결 검증                | 사용자 + 팀원           | 같은 특징의 예측 점수 일치, 판정과 실패 종료 코드 확인         |
| 4    | 분석기 Python 함수 또는 CLI 어댑터 구현         | 사용자                  | 요청 생성부터 분석·추론·출력까지 연결, 실패·timeout 처리       |
| 5    | 개발 환경 및 CI 검증 완료                       | 사용자                  | ML 테스트 skip 없이 검사·빌드 및 GitHub 실행 결과 기록         |
| 6    | npm 설치 전 탐지 CI 구현                        | 사용자                  | 보호된 분석기·모델 사용, 종료 코드 1/2에서 후속 설치·빌드 차단 |
| 7    | HTML 근거 보고서·정책·웹/API 등 확장            | 사용자, 팀 협의         | CLI 완료 후 필요한 기능부터 같은 pipeline 재사용               |

개발 환경 검증은 규약 합의·팀원 작업과 병행할 수 있습니다.
실제 모델·데이터·실행 결과는 각각 `models/`, `data/`, `artifacts/`에 보관하고 커밋하지 않습니다.

## 현재 제한

- 로컬 `package-lock.json` v2/v3 지원. 비교 기준 파일을 명시해야 합니다.
- 직접·중첩 의존성의 lockfile 항목을 비교하지만 코드 재귀 분석은 구현하지 않았습니다.
- 새 패키지, workspace/link, Git·file·사설 레지스트리 의존성, 같은 버전의 아카이브 변경은 미완료입니다.
- `package.json`만 있는 프로젝트, yarn/pnpm, Git URL 입력은 후속 범위입니다.
- 패키지 다운로드·압축 해제·AST/문맥 특징 추출은 팀원 분석기 담당이며 현재 이 저장소가 수행하지 않습니다.
- 학습·파인튜닝, 웹 화면, 실제 프로젝트 차단 워크플로는 아직 구현하지 않았습니다.

## 검증

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m build
```

ML 의존성이 없으면 native LightGBM 통합 테스트는 skip됩니다. 전체 검증은 `.[dev,ml]` 설치 후 수행합니다.
테스트의 작은 모델은 직렬화·연결 검증용 합성 모델이며 실제 악성 탐지 모델이 아닙니다.

다음 작업은 [연결 규약](docs/contracts.md), [구조와 담당](docs/architecture.md),
[CI/CD 연결](docs/ci-cd.md), [통합 순서](docs/development.md)를 참고합니다.

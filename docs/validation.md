# 검증 기록

## 2026-11-04: Git 시간 제한의 실제 범위(`--base-ref` 후속)

- 시간 제한이나 출력 상한을 넘으면 depbee는 직접 실행한 Git 프로세스만 종료한다. 손자 프로세스까지 정리하는 프로세스 트리 종료는 보류했다. Windows에서는 Job Object 같은 플랫폼 코드나 PID 재사용으로 확실하지 않은 종료가 필요하고, 실행하는 명령이 읽기 전용이며 lazy fetch도 꺼져 있기 때문이다(PR #6 리뷰 1차 nit 1, 2차 nit 3).
- Windows 기본 설치의 `Git\cmd\git.exe`는 실제 Git(`mingw64\bin\git.exe`)을 손자 프로세스로 실행하는 wrapper다. wrapper를 종료해도 실제 Git은 계속 돌고, 파이프를 닫는 단계가 그 프로세스가 끝날 때까지 기다리므로 시간 초과 오류가 30초보다 늦게 날 수 있다(리뷰의 모의 실험에서 2초 제한이 12.1초까지 늘어남). 메모리 상한은 그대로 지켜진다. `_run` docstring, README, 구조 문서의 시간 제한 문구를 이 범위에 맞게 고쳤다. 이 동작은 이번 작업에서 직접 재현하지 않았다.

## 2026-11-04: Windows의 git.exe 미발견 오류 문구(`--base-ref` 후속)

- PATH에 `git.cmd`만 있거나 현재 폴더에만 `git.exe`가 있을 때 Windows의 오류가 `Git executable not found on PATH`라 원인이 분명하지 않았다(PR #6 리뷰 2차 nit 2). Windows에서는 `git.exe not found on PATH (git.cmd, git.bat and the current directory are not used)`로 바꿨다. POSIX의 문구와 동작은 그대로다. 테스트 79개 통과(skip 없음), `ruff check` 통과. POSIX 문구 확인은 개발 CI(Ubuntu)에서만 실행된다.

## 2026-11-04: Git 버전 안내 판정의 언어 고정(`--base-ref` 후속)

- Git 2.45 안내는 Git의 `unknown option` 문구로 판정하는데, 이 문구는 locale에 따라 번역된다(PR #6 리뷰 2차 nit 1). Git 자식 환경에 `LC_ALL=C`를 강제한다. Git 문서(`po/README.md`)는 Git 테스트를 `LANG=C LC_ALL=C`로 실행해 번역을 고려하지 않아도 된다고 적고 있다. 부모 환경은 바꾸지 않는다.
- 동작 결정(조율자): 종료 코드 129이면서 stderr에 `unknown option`이 있을 때만 "Git 2.45 or later is required" 안내를 낸다. 129이지만 이 문구가 없으면 버전 오류로 단정하지 않고, 기존 `read_base_lock`의 Git 오류(예: `Git cannot resolve HEAD to a commit ...`)에 stderr 앞부분을 붙여 내며 CLI 종료 코드는 2다. 이유: 129는 Git의 usage 실패 전반에 쓰이는 코드이고, `--no-lazy-fetch` 문자열은 2.45 이상의 usage 출력에도 들어 있어 판정 근거가 될 수 없다.
- 테스트 79개 통과(skip 없음), `ruff check` 통과. 129, `unknown option` 없음, usage에 `--no-lazy-fetch` 있음인 음성 테스트가 버전 안내 없이 기존 Git 오류와 종료 코드 2를 확인한다. 상속 환경 회귀로 자식 `LC_ALL=C`, 부모 원래 값을 확인한다. 번역된 Git과 실제 Git 2.45 미만은 실행하지 않았다.

## 2026-11-04: Git graft 무시(`--base-ref` 후속)

- graft는 `--no-replace-objects`로 꺼지지 않는다. 부모 프로세스의 `GIT_GRAFT_FILE`이나 대상 저장소의 `.git/info/grafts`가 커밋의 부모를 바꾸면 `--base-ref HEAD~1`이 다른 커밋의 lockfile을 기준으로 읽어 실제 변경이 `changes: []`와 종료 코드 0으로 사라질 수 있었다(PR #6 리뷰 2차 minor 1). Git 자식 환경의 `GIT_GRAFT_FILE`을 null 장치(`os.devnull`)로 둔다. Git 소스(`setup.c`, `repository.c`)상 이 변수가 있으면 기본 경로 `<git dir>/info/grafts` 대신 쓰이므로 두 경로가 함께 막힌다. 부모 환경은 바꾸지 않는다.
- 테스트 78개 통과(skip 없음), `ruff check` 통과. 기존 상속 환경 회귀에 `GIT_GRAFT_FILE`을 더해 자식은 null 장치, 부모는 원래 값임을 확인한다.
- 실제 Git(2.50.1, Windows)과 합성 저장소로 `GIT_GRAFT_FILE`과 `.git/info/grafts` 두 경우를 확인했다. 새 코드의 `--base-ref HEAD~1` 출력은 같은 lockfile을 `--base-lock`으로 준 출력과 바이트 단위로 같고, 수정 전 코드(bc79c59)는 두 경우 모두 변경을 놓쳤다.

## 2026-11-04: Windows에서 git.exe만 실행(`--base-ref` 후속)

- Windows에서 `shutil.which("git")`는 PATH 앞쪽 폴더의 `git.cmd`를 `git.exe`보다 먼저 고를 수 있고, 그러면 ref 인자가 cmd.exe를 거친다(PR #6 리뷰 nit 2). 빈 자리표시 파일로 확인했다(Python 3.13.5, 실행하지 않음): 같은 PATH에서 `which("git")`는 `git.CMD`, `which("git.exe")`는 뒤 폴더의 `git.exe`를 돌려준다. Windows에서는 `git.exe`를 찾고, 결과가 `.exe`로 끝나지 않으면 실행하지 않는다. POSIX는 그대로 `git`을 찾는다.
- 테스트 78개 통과(skip 없음), `ruff check` 통과. POSIX 분기는 개발 CI(Ubuntu)에서만 실행된다.

## 2026-11-04: Git 2.45 미만에서 필요한 버전 안내(`--base-ref` 후속)

- `--no-lazy-fetch`는 Git 2.45 릴리스 노트에 처음 나온다. 그보다 오래된 Git은 알 수 없는 옵션으로 종료 코드 129를 내고, 지금까지는 `Git cannot resolve HEAD to a commit`처럼 원인을 알기 어려운 오류였다(PR #6 리뷰 minor 1). Git이 129와 `unknown option`으로 끝나면 `Git 2.45 or later is required`로 시작하는 오류를 내고 종료 코드 2는 그대로다. README와 연결 규약에 최소 Git 2.45를 적었다.
- 테스트 77개 통과(skip 없음), `ruff check` 통과. 오래된 Git의 출력은 합성 stderr로 넣었고, 실제 Git 2.45 미만은 실행하지 않았다.

## 2026-11-04: Git 자식 환경의 저장소 지정 변수 제거와 replace 객체 무시(`--base-ref` 후속)

- 부모 프로세스가 `GIT_DIR` 등을 물려주면 Git이 대상 폴더가 아닌 다른 저장소의 lockfile을 기준으로 읽어, 실제 변경이 `changes: []`와 종료 코드 0으로 사라질 수 있었다(PR #6 리뷰 major 1). Git 자식 환경에서 `GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`를 지우고, `refs/replace/`로 바뀐 객체를 읽지 않도록 `--no-replace-objects`를 붙인다. `GIT_NO_LAZY_FETCH=1` 강제는 그대로다.
- 테스트 76개 통과(skip 없음), `ruff check` 통과. 실제 `_run`과 Popen을 거쳐 Git 대신 무해한 Python 자식(상속된 `GIT_DIR`이 있으면 다른 저장소처럼 답함)을 실행해, 여섯 변수가 다른 저장소를 가리켜도 자식 환경에 남지 않고, request가 파일 입력과 같으며, 부모 환경이 바뀌지 않음을 확인했다.
- 실제 Git(2.50.1, Windows)과 합성 저장소 2개(examples lockfile만)로 확인했다. `GIT_DIR`만, 여섯 변수 모두, `refs/replace/`로 기준 blob을 바꾼 경우 모두 `plan` 출력이 같은 파일을 `--base-lock`으로 준 출력과 바이트 단위로 같다. 같은 경우를 수정 전 코드로 실행하면 `GIT_DIR`과 replace 경우에 변경이 사라졌다.

## 2026-11-04: Git 기준 읽기의 lazy fetch 차단(`--base-ref` 후속)

- 부분 복제 저장소에서 기준 커밋의 lockfile blob이 없으면 Git이 promisor remote에서 자동으로 받을 수 있었다. 모든 Git 호출에 `--no-lazy-fetch`를 붙이고 자식 환경의 `GIT_NO_LAZY_FETCH`를 부모 값과 무관하게 `1`로 둔다. 이 옵션을 모르는 Git은 알 수 없는 옵션으로 종료하므로(종료 코드 129, 현재 Git으로 다른 알 수 없는 옵션에서 확인) 받지 않고 오류가 된다.
- 테스트 75개 통과(skip 없음), `ruff check` 통과, 격리 환경 build 성공. 실제 `_run`과 Popen을 거쳐 Git 대신 무해한 Python 자식을 실행해, 부모의 `GIT_NO_LAZY_FETCH`가 없음·`0`·`false`일 때도 두 Git 자식 모두 옵션과 환경 값 `1`을 받고 request_id가 파일 입력과 같음을 확인했다. 없는 blob 오류는 CLI 종료 코드 2로 끝난다.
- 실제 Git(2.50.1, Windows) 합성 저장소의 기준 읽기와 기존 CLI 출력(9개 명령, 29개 파일)은 바이트 단위로 그대로다. 실제 부분 복제와 네트워크 fetch는 재현하지 않았다.

## 2026-11-04: 모델 경로 환경 변수(`DEPBEE_MODEL_DIR`)

- 모델 경로 우선순위는 명시한 `--model-dir`, `DEPBEE_MODEL_DIR`, 모델 없음 순이다. 변수는 import 때가 아니라 `scan_project()`를 호출할 때마다 읽는다. 테스트 73개 통과(skip 없음), `ruff check` 통과, 격리 환경 build 성공.
- 단위 테스트는 명시 경로 우선(잘못돼도 변수로 다시 시도하지 않음), 변수만 있음, 미설정과 빈 값, 공백만 있는 값과 없는 폴더의 경로 오류, 호출 사이 변수 변경, CLI 연결을 확인한다. 기존 테스트는 공통 fixture에서 변수를 지워 개발 PC 설정과 무관하게 돌고, 변수를 남기면 8개가 실패함을 확인했다.
- D04-E00과 DEV-01 합성 feature로 확인했다. 변수로 고른 모델의 text·json 출력과 `--output` 파일이 `--model-dir`로 준 출력과 바이트 단위로 같고, 잘못된 변수가 있어도 `--model-dir`을 주면 같다. 빈 값은 미설정과 같고, 공백만 있는 값과 없는 폴더는 종료 코드 2다. 변수가 없는 기존 CLI 출력(9개 명령, 29개 파일)은 바이트 단위로 같다. 탐지 성능 검증은 아니다.

## 2026-11-04: Git 기준 lockfile(`--base-ref`)

- `plan`·`scan`에 `--base-ref`를 추가했다. `--base-lock`도 `--base-ref`도 없으면 HEAD를 쓴다. 테스트 67개 통과(skip 없음), `ruff check` 통과, 격리 환경 build 성공.
- 단위 테스트는 Git을 모두 mock한다. 커밋에서 읽은 바이트가 기준 파일과 같으면 request와 request_id가 같고, 빈 ref·옵션 형태 ref, Git 없음, 현재 폴더에서 찾은 git, 저장소 아님, 없는 ref, 커밋에 lockfile 없음, 잘못된 JSON·중복 키·lockfileVersion은 오류다.
- 출력 상한, timeout, 종료 정리는 테스트 자신의 Python을 자식 프로세스로 실행해 확인했다. 끝없이 출력하는 자식은 상한을 넘는 즉시 종료되고, 출력 없이 멈춘 자식은 제한 시간에 종료되며, 두 경우 모두 프로세스가 끝나고 파이프가 닫힌다.
- `--base-lock`을 명시한 기존 CLI 출력(9개 명령, 29개 파일)은 바이트 단위로 같다.
- 실제 Git(2.50.1, Windows)으로 공백과 한글이 든 하위 폴더에 합성 저장소를 만들어 확인했다. `HEAD~1`과 annotated tag 기준의 `plan`·`scan` 출력이 같은 파일을 `--base-lock`으로 준 출력과 바이트 단위로 같고, 없는 ref, 옵션 형태 ref, 커밋하지 않은 lockfile, 저장소 밖 폴더는 종료 코드 2다. Linux·macOS의 실제 Git은 확인하지 않았다.

## 2026-10-27: 모델이 쓰는 feature만 골라 추론

- 분석기가 뽑은 feature 중 manifest `feature_names`에 있는 것만 모델에 넣는다. 남는 feature는 버리고, 모델 feature가 하나라도 없으면 지금처럼 오류(보류)다. 없는 값은 채우지 않는다.
- 테스트 48개 통과, skip 없음. `ruff check` 통과. 합성 native 모델에 feature를 더 넣어도 점수와 설명이 같고, 하나를 빼면 거부되는 것을 확인했다.
- D06-E06(package.json feature 7개, model-training main의 `models/D06_E06_package_json_only.txt`)을 `scripts/write_manifest.py`로 연결했다. 임계값 0.5는 검증 세트에서 정한 값이 아닌 임시값이다.
- 데이터 저장소 `be87ab4cf`(D06)의 `test.csv` 677행을 29개 feature 그대로 depbee 예측기에 넣은 점수가 model-training 방식(pandas category 인코딩)으로 LightGBM에서 직접 낸 점수와 모두 같다(최대 차이 0). 0.5 기준 위험은 악성 132/217, 정상 17/460으로 실험 기록(D06-E06 Test TP 132, FP 17)과 같다.
- 로컬 데모 lockfile(바뀐 패키지 8개)을 D06-E06으로 검사하면 위험 3개(@emilgroup/notification-sdk-node 1.4.1, @replayio/playwright 1.1.17, @rspack/cli 1.1.7)이고 종료 코드 1이다. D04-E00과 달리 설치 스크립트가 없는 debug 4.4.2(0.351)는 놓치고, 설치 스크립트를 추가한 어려운 정상 @replayio/playwright 1.1.17(0.608)은 위험으로 본다.

## 2026-10-14: 텍스트 출력 정리와 데모 축소

- 텍스트 출력에 판정별 개수, 위험 우선 정렬, 상위 feature 외 기여도 합과 모델 기준값, 안전 보증이 아니라는 안내를 넣고, `--extract` 텍스트 모드에 진행 표시를 추가했다. JSON 보고서는 `explanation_rest` 필드만 늘었다.
- 테스트 47개 통과, skip 없음. `ruff check` 통과.
- 상위 3개 기여도, 나머지 합, 기준값을 더한 값이 점수의 log-odds와 같음을 합성 native 모델 테스트로 확인했다.
- 데모 lockfile을 4개(위험 debug 4.4.2, 놓친 악성 @emilgroup/notification-sdk-node 1.4.1, 여러 버전을 건너뛴 어려운 정상 @replayio/playwright 1.1.17, 새로 추가된 graphql-upload 18.0.0)로 줄였다. D04-E00 점수는 8개일 때와 같다(0.997, 0.003, 0.000, 0.000).

## 2026-10-05: 내장 분석기와 실제 모델 연결

환경: Windows 11, Python 3.13.5, lightgbm 4.7.0, feature-extractor main `c24761d`(로컬 editable 설치).
모델: model-training 브랜치 `claude/great-newton-xyxx3d`의 D04-E00(데이터 npm-malware-package-pairs `4ee5c7357`), 임계값 0.5(학습 기본값, 검증 전).

### 확인 완료

- 테스트 45개 통과, skip 없음(native LightGBM 테스트 포함). `ruff check` 통과, wheel/sdist 빌드 성공.
- 추론 일치: 학습 저장소의 Test 650행을 `LightGBMPredictor`(boolean·범주·결측 변환)에 넣어 악성 22/190 탐지, 오탐 0으로 model-training의 D04-E00 결과와 같았다.
- 추출 일치: Test에서 뽑은 18쌍(무작위 정상 6, 어려운 정상 4, 악성 8)을 `ExtractorAnalyzer`로 실시간 추출했다. 18쌍 모두 비교 기준 버전, feature 29개, 점수가 학습 CSV와 같았다. 악성은 npm-malware-package-pairs main(`cb617b96f`) 체크아웃의 archive 사본을 읽었다.
- 전체 흐름: 실제 버전으로 만든 데모 lockfile(정상 4, 악성 4, 새로 추가된 의존성 1, 여러 버전을 건너뛴 업데이트 1)로 `scan --extract --local-source`를 실행해 한국어 출력, 종료 코드 1, JSON 보고서 저장을 확인했다.

### 아직 하지 못한 검증

- `ruff format --check`: `tests/test_workflow.py` 1개가 이전부터 실패한다(개발 CI에는 포함되지 않음).
- GitHub Actions 서버 실행. 저장소가 비공개라 CI에서 feature-extractor를 설치하려면 접근 권한이 필요하다. 지금 테스트는 feature-extractor 없이 돈다.
- 검증 세트로 정한 임계값, 받은 tarball 자체의 integrity 검증.

## 2026-09-16: 초기 구축

- Python 3.13 가상환경에서 표준 라이브러리 테스트 18개 통과, Python 3.14에서도 같은 결과.
- 예시 lockfile 비교와 분석 요청 JSON 생성, 분석 결과·모델 미연결 시 `incomplete` 출력.
- 미지원 출처·같은 버전 아카이브 변경 시 미완료 처리, 요청 식별자·특징 스키마 불일치와 결과 중복·누락·실패 처리.
- 기존 입력 파일을 출력으로 덮어쓰지 않는 동작.
- 당시 ML 의존성 설치에 실패해 native LightGBM 테스트 2개는 skip이었다(2026-10-05에 해소).

테스트 자료는 악성코드가 없는 합성 자료다. 테스트 통과는 탐지 성능을 뜻하지 않는다.

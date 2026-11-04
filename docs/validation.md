# 검증 기록

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

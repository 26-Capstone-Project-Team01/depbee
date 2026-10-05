# 검증 기록

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

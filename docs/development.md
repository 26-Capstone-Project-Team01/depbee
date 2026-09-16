# 다음 개발 순서

## 1. 팀원과 인계 규약 합의

- LightGBM native export와 특징 이름·순서, 악성 라벨, 판정 임계값 확인
- 특징 스키마·전처리·결측값 처리·근거 형식 결정
- 분석기 Python 함수 또는 CLI 선택, 실패·timeout 처리 결정
- 실제 버전 쌍 하나의 request → features → prediction을 공동으로 검증

## 2. 실제 통합

- 현재 JSON adapter를 팀원 함수/CLI adapter로 연결
- 특징을 바꿀 때 feature_schema와 모델 버전을 함께 갱신
- 이전·신규 아카이브의 integrity와 분석 범위 확인
- 실제 정상 후보·악성·파싱 실패 사례로 CLI 확인

## 3. 탐지 CI

- 기준 lockfile 추출과 신뢰한 도구·모델 배포 경로 설정
- GitHub Actions에서 scan을 필수 검사로 연결
- 설치 전에 분석하며, 실패·미완료를 통과시키지 않는 시연 작성

## 4. 후속 기능

- CLI 결과 JSON을 이용한 HTML 근거 보고서
- 정책 설정과 버전 단위 승인 기록
- 이후 필요성이 확인된 경우 웹 화면·API

실제 데이터 수집·모델 학습·문맥 분석 범위 결정은 해당 팀원과 진행한다.
CLI·추론 연결 작업에 학습 코드를 혼합하지 않는다.

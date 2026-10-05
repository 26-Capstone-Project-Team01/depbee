# 다음 개발 순서

## 1. 모델 인계와 통합 마무리

- 모델 담당자에게 검증 세트로 정한 임계값과 학습 기록을 받아 manifest에 반영
- feature를 바꿀 때 `depbee-features-v1` 스키마 이름, `pyproject.toml`의 feature-extractor 고정 커밋, 모델을 함께 갱신
- feature-extractor가 받은 tarball 자체의 integrity를 검증
- 학습 데이터 쪽 비교 기준 규칙이 바뀌면 `analysis/baseline.py`도 맞춘다

## 2. 탐지 CI

- 기준 lockfile 추출과 신뢰한 도구·모델 배포 경로 설정
- GitHub Actions에서 scan을 필수 검사로 연결
- 설치 전에 분석하며, 실패·미완료를 통과시키지 않는 시연 작성

## 3. 후속 기능

- CLI 결과 JSON을 이용한 HTML 근거 보고서
- 정책 설정과 버전 단위 승인 기록
- 이후 필요성이 확인된 경우 웹 화면·API

실제 데이터 수집·모델 학습·문맥 분석 범위 결정은 해당 팀원과 진행한다.
CLI·추론 연결 작업에 학습 코드를 혼합하지 않는다.

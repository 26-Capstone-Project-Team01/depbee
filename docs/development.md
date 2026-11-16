# 다음 개발 순서

## 1. 모델 인계와 통합 마무리

- 모델 담당자에게 검증 세트로 정한 임계값과 학습 기록을 받아 manifest에 반영
- feature를 바꿀 때 `depbee-features-v1` 스키마 이름, `pyproject.toml`의 feature-extractor 고정 커밋, 모델을 함께 갱신
- feature-extractor 고정 커밋을 바꿀 때는 `.[extract]`를 설치한 환경에서 loader 경계 테스트(`PinnedLoaderTests`)가 skip 없이 통과하는지 확인한다
- 학습 데이터 쪽 비교 기준 규칙이 바뀌면 `analysis/baseline.py`도 맞춘다

## 2. 탐지 CI

- 기준 lockfile 추출과 신뢰한 도구·모델 배포 경로 설정
- GitHub Actions에서 scan을 필수 검사로 연결
- 설치 전에 분석하며, 실패·미완료를 통과시키지 않는 시연 작성

## 3. 후속 기능

- 로컬 대시보드(`depbee dashboard`)의 조회·이력 화면과 프로젝트 등록은 SVC-07에서 구현했다([연결 규약](contracts.md) 7절). 다음은 대시보드에서 업데이트 확인(미리보기와 검사)과 수행(반영 게이트를 거친 lockfile 반영·`npm ci`)을 실행하는 화면이다(서비스 함수를 그대로 부르고, 실행은 POST와 같은 보안 확인으로만 받는다).
- 그 뒤 후보: Actions `report.json` 가져오기(가져온 보고서 표시, 크기·필드 검사, 반영 입력으로 쓰지 않음), 추이 그래프, 같은 변경의 모델별 점수 비교(모델 교체 뒤)
- CLI 결과 JSON을 이용한 HTML 근거 보고서
- 정책 설정과 버전 단위 승인 기록

실제 데이터 수집·모델 학습·문맥 분석 범위 결정은 해당 팀원과 진행한다.
CLI·추론 연결 작업에 학습 코드를 혼합하지 않는다.

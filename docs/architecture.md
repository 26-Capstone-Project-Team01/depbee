# 구조와 담당 경계

현재는 Python 단일 패키지를 사용한다. CLI와 LightGBM 추론을 같은 언어로 연결하고,
추후 웹·CI가 `pipeline.scan()`을 재사용하도록 한다. 저장소를 여러 서비스로 나누지 않는다.

```text
프로젝트 폴더 + 기준 lockfile
        ↓ inputs/npm.py
분석 요청 JSON (변경 버전 쌍 + 파일 해시)
        ↓ 팀원 분석기 (현재 연결 대상)
특징 JSON + 근거 + 분석 상태
        ↓ analysis/artifact.py
        ↓ inference/lightgbm.py + model.txt/manifest.json
판정 보고서 → CLI / JSON / 종료 코드 → 향후 CI 정책·UI
```

| 영역 | 담당 | 인계할 결과물 |
|---|---|---|
| 학습·평가 | 모델 담당 팀원 | native LightGBM 모델, 특징 규약, 임계값, 모델 manifest |
| 패키지 확보·정적 분석 | 분석 담당 팀원 | 요청별 특징·근거·완료 상태를 반환하는 Python 함수 또는 CLI |
| 서비스 연결 | 사용자 | 프로젝트 입력, 버전 쌍 추출, adapter, 추론, CLI, CI/CD |

현재 `ArtifactAnalyzer`는 파일을 통해 먼저 협업할 수 있는 연결부다.
팀원 함수가 정해지면 `Analyzer.analyze(request)`를 구현하고, CLI 방식이면 같은 결과를 반환하는
어댑터를 추가한다. 임의 플러그인 자동 검색이나 대상 프로젝트 설정의 명령 실행은 하지 않는다.

`package-lock`의 전체 파일 해시를 request_id에 반영한다. 다른 커밋의 분석 결과 재사용을 막지만
분석 파일 작성자의 신뢰성을 보장하지는 않는다. 배포 시 보호된 분석 작업이 결과를 생성해야 한다.

초기 CLI는 이전 lockfile을 명시적으로 받는다. 이후 Git baseline 추출, tarball 캐시,
CI PR 연결, HTML 보고서는 각 경계를 유지하며 붙인다. 전체 프로젝트 코드나 변경되지 않은
패키지를 분석했다는 뜻으로 결과를 표현하지 않는다.

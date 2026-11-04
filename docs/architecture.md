# 구조와 담당 경계

현재는 Python 단일 패키지를 사용한다. CLI와 LightGBM 추론을 같은 언어로 연결하고,
추후 웹·CI가 `pipeline.scan()`을 재사용하도록 한다. 저장소를 여러 서비스로 나누지 않는다.

```text
프로젝트 폴더 + 기준 lockfile(파일, 또는 inputs/git.py로 읽은 Git 커밋의 파일)
        ↓ inputs/npm.py
분석 요청 JSON (변경 버전 쌍 + 파일 해시)
        ↓ analysis/extractor.py (--extract): 직전 stable 선정(baseline.py) + feature-extractor
        ↓ 또는 analysis/artifact.py (--analysis): 미리 만든 분석 JSON
특징 + 근거 + 분석 상태 (artifact.validate로 같은 검사)
        ↓ inference/lightgbm.py + model.txt/manifest.json
판정 보고서 → CLI / JSON / 종료 코드 → 향후 CI 정책·UI
```

`service.py`의 `plan_project()`·`scan_project()`가 위 단계를 조립하는 공통 진입점이다. CLI와 이후 Actions·MCP·대시보드는 이 함수를 호출하고, 판정은 `pipeline.scan()`에만 둔다.

| 영역 | 담당 | 인계할 결과물 |
|---|---|---|
| 학습·평가 | 모델 담당 팀원 | native LightGBM 모델, 임계값, 학습 기록. manifest는 `scripts/write_manifest.py`로 만든다 |
| feature 추출 | 추출기 담당 팀원과 사용자 | feature-extractor의 extractor. depbee가 Python 라이브러리로 호출한다 |
| 서비스 연결 | 사용자 | 프로젝트 입력, 비교 기준 선정, 분석기 연결, 추론, CLI, CI/CD |

`ExtractorAnalyzer`는 feature-extractor의 `build_row()`를 직접 호출한다. 패키지 코드는 읽기만 하고 실행하지 않는다.
`ArtifactAnalyzer`는 다른 분석기가 파일로 넘긴 결과를 받는 연결부다.
새 분석기는 `Analyzer.analyze(request)`를 구현한다. 임의 플러그인 자동 검색이나 대상 프로젝트 설정의 명령 실행은 하지 않는다.

`package-lock`의 전체 파일 해시를 request_id에 반영한다. 다른 커밋의 분석 결과 재사용을 막지만
분석 파일 작성자의 신뢰성을 보장하지는 않는다. 배포 시 보호된 분석 작업이 결과를 생성해야 한다.

기준 lockfile은 파일로 받거나 Git 커밋(기본 HEAD)에서 읽는다. `inputs/git.py`는 PATH의 Git으로 고정된 읽기 전용 명령만 셸 없이 실행하고, 부분 복제의 자동 객체 받기(lazy fetch)를 끄고(`--no-lazy-fetch`, `GIT_NO_LAZY_FETCH=1`), 다른 저장소를 가리킬 수 있는 상속 환경 변수(`GIT_DIR` 등 6개)를 지우고 replace 객체를 쓰지 않으며(`--no-replace-objects`), 시간과 stdout·stderr 크기에 상한을 두며, 읽은 바이트를 파일 입력과 같은 JSON 검사·해시 경로(`contracts.parse_json`)로 넘긴다.
이후 tarball 캐시, CI PR 연결, HTML 보고서는 각 경계를 유지하며 붙인다. 전체 프로젝트 코드나 변경되지 않은
패키지를 분석했다는 뜻으로 결과를 표현하지 않는다.

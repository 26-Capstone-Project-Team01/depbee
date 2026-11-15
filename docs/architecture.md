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

`check_package()`(`depbee check NAME@VERSION`)는 lockfile 대신 registry 메타데이터에서 같은 형식의 요청을 만든다. 이름과 버전을 네트워크 전에 검사하고, `ExtractorAnalyzer.packument()`로 메타데이터를 한 번 받아 `inputs/npm.py`의 `build_package_request()`(새로 추가된 의존성 하나, `input_kind: "package"`)와 분석에 함께 쓴 뒤, 같은 `pipeline.scan()`으로 판정한다. registry 메타데이터와 tarball은 `analysis/registry.py`가 받는다(`https://registry.npmjs.org`만, redirect 뒤에도 검사, 크기 상한, tarball 주소 경로와 `dist.integrity` 대조, 압축 해제 크기·파일 수 상한, symbolic link는 풀지 않고 hard link는 대상 크기로 셈). 메타데이터 다운로드와 추출 단계(tarball 두 개, 압축 해제, feature 추출)는 `analysis/bounded.py`가 자식 Python 프로세스에서 실행한다. 분석하는 변경 하나는 그 변경을 시작할 때 정해지는 시간 예산 하나를 함께 쓰고(`bounded.budget()`, `ExtractorAnalyzer.analyze()`의 변경마다, `check`는 메타데이터 조회부터, 자식 단계가 없어도 적용), 예산이 끝나면 자식 프로세스를 종료하고 끝난 것을 확인한 뒤 오류를 낸다. 부모가 직접 하는 단계(호출 준비, 결과 해석, 캐시·근거 처리)는 끊지 못하므로, `run()`이 단계 사이와 결과 해석 뒤에, 분석기가 캐시용 모델 입력 검사 뒤, `cache.store`가 게시(`os.replace`) 직전, 완료 결과를 받아들이기 전에(`bounded.check()`) deadline을 다시 확인해 늦은 결과를 버린다. 부모는 자식에 함수와 인자를 pickle로 넘기고, 자식은 결과를 JSON이나 바이트로만 돌려준다(패키지 자료를 다룬 프로세스의 pickle을 읽지 않는다). 압축을 푸는 작업 폴더는 부모가 만들고 지운다. `FeatureExtractorBackend.extract()`는 feature-extractor의 `RegistrySnapshotSource` 대신 depbee의 source를 넘긴다. 이 source는 고정 loader의 공개 함수 `build_snapshot()`으로 받은 메타데이터에서 snapshot을 만들고(tarball을 받지 않는 호출), 소스 트리는 검사한 다운로드를 푼 폴더로 채운다. 그래서 feature-extractor는 registry에 접근하지 않고 old/new snapshot도 요청을 만든 문서를 쓴다(`scan --extract`도 같다). 예전의 비공개 캐시 속성(`_packument_cache`) 의존은 없다. 모델 경로 선택(`--model-dir` → `DEPBEE_MODEL_DIR` → 없음)은 `scan_project()`와 같은 함수를 쓴다.

`preview_update()`(`depbee update [이름...]`)는 `inputs/npm_cli.py`로 프로젝트의 `package.json`·`package-lock.json`만 임시 폴더에 복사해 `npm update --package-lock-only --ignore-scripts`(node와 npm-cli.js 직접 실행, 셸 없음)로 새 lockfile을 계산하고, 원본 lockfile 바이트를 기준으로 `scan_project(extract=True)`를 부른다. npm의 `--version`과 `update` 모두에 `--prefix=<임시 폴더>`·`--workspaces=false`(상위 workspace 루트 탐색 차단)와 없는 파일을 가리키는 `--git`(Git 실행 차단)을 고정하고, `overrides`와 lockfile 항목의 의존성 값도 registry 범위만 받는다. npm 실행은 `inputs/git.py`의 `_run(tree=True)`로 하위 프로세스까지 묶어(Windows는 `KILL_ON_JOB_CLOSE`를 설정한 Job Object, POSIX는 프로세스 그룹) 시간 초과·출력 상한과 정상 종료 뒤 모두 종료하고 끝난 것을 확인한다. 판정은 그대로 `pipeline.scan()`이 하고, 미리보기 메타데이터는 보고서 밖 `preview`에 둔다. 프로젝트 파일은 읽기만 한다.

| 영역 | 담당 | 인계할 결과물 |
|---|---|---|
| 학습·평가 | 모델 담당 팀원 | native LightGBM 모델, 임계값, 학습 기록. manifest는 `scripts/write_manifest.py`로 만든다 |
| feature 추출 | 추출기 담당 팀원과 사용자 | feature-extractor의 extractor. depbee가 Python 라이브러리로 호출한다 |
| 서비스 연결 | 사용자 | 프로젝트 입력, 비교 기준 선정, 분석기 연결, 추론, CLI, CI/CD |

`ExtractorAnalyzer`는 feature-extractor의 `build_row()`를 직접 호출한다. 패키지 코드는 읽기만 하고 실행하지 않는다.
`analysis/cache.py`는 추출한 feature를 실행 사이에 재사용하는 작은 JSON 파일 캐시다(키 digest가 파일 이름, 임시 파일 뒤 `os.replace`로 저장). 키는 `ExtractorAnalyzer`가 비교한 두 버전의 메타데이터, 검증한 모델의 해시(`LightGBMPredictor.identity`), 설치 출처를 확인한 feature-extractor의 식별 정보(`FeatureExtractorBackend.identity`)로 만들고, 셋 중 하나라도 없으면 캐시를 쓰지 않는다. 캐시에서 읽거나 저장할 feature는 그 모델의 입력 변환(`LightGBMPredictor.encode()`)으로 다시 확인한다. 서비스는 분석기가 잰 항목별 시간과 캐시 사용 여부를 보고서에 붙인다(`service._timed`). 판정은 그대로 `pipeline.scan()`이 한다.
`ArtifactAnalyzer`는 다른 분석기가 파일로 넘긴 결과를 받는 연결부다.
새 분석기는 `Analyzer.analyze(request)`를 구현한다. 임의 플러그인 자동 검색이나 대상 프로젝트 설정의 명령 실행은 하지 않는다.

`package-lock`의 전체 파일 해시를 request_id에 반영한다. 다른 커밋의 분석 결과 재사용을 막지만
분석 파일 작성자의 신뢰성을 보장하지는 않는다. 배포 시 보호된 분석 작업이 결과를 생성해야 한다.

기준 lockfile은 파일로 받거나 Git 커밋(기본 HEAD)에서 읽는다. `inputs/git.py`는 PATH의 Git으로 고정된 읽기 전용 명령만 셸 없이 실행하고, 부분 복제의 자동 객체 받기(lazy fetch)를 끄고(`--no-lazy-fetch`, `GIT_NO_LAZY_FETCH=1`), 다른 저장소를 가리킬 수 있는 상속 환경 변수(`GIT_DIR` 등 6개)를 지우고 replace 객체와 graft를 쓰지 않으며(`--no-replace-objects`, `GIT_GRAFT_FILE`을 null 장치로), stdout·stderr 크기에 상한을, 직접 실행한 Git 프로세스에 시간 제한을 두며(하위 프로세스는 종료하지 않는다), 읽은 바이트를 파일 입력과 같은 JSON 검사·해시 경로(`contracts.parse_json`)로 넘긴다.
이후 tarball 캐시, CI PR 연결, HTML 보고서는 각 경계를 유지하며 붙인다. 전체 프로젝트 코드나 변경되지 않은
패키지를 분석했다는 뜻으로 결과를 표현하지 않는다.

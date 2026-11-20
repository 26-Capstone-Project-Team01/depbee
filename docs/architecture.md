# 구조와 담당 경계

현재는 Python 단일 패키지를 사용한다. CLI와 LightGBM 추론을 같은 언어로 연결하고,
추후 웹·CI가 `pipeline.scan()`을 재사용하도록 한다. 저장소를 여러 서비스로 나누지 않는다.

```text
프로젝트 폴더 + 기준 lockfile(파일, 또는 inputs/git.py로 읽은 Git 커밋의 파일)
        ↓ inputs/npm.py
분석 요청 JSON (변경 버전 쌍 + 파일 해시)
        ↓ analysis/extractor.py (--extract): 직전 stable 선정(baseline.py, 색인이 있으면 기지 악성 후보 제외) + depbee-analyzer
        ↓ 또는 analysis/artifact.py (--analysis): 미리 만든 분석 JSON
특징 + 근거 + 분석 상태 (artifact.validate로 같은 검사)
        ↓ inference/lightgbm.py + model.txt/manifest.json
        ↓ known_malicious.py + index.json/manifest.json (선택): 이름·버전 대조
판정 보고서 → CLI / JSON / 종료 코드 → 향후 CI 정책·UI
```

`service.py`의 `plan_project()`·`scan_project()`가 위 단계를 조립하는 공통 진입점이다. CLI와 이후 Actions·MCP·대시보드는 이 함수를 호출하고, 판정은 `pipeline.scan()`에만 둔다.

`check_package()`(`depbee check NAME@VERSION`)는 lockfile 대신 registry 메타데이터에서 같은 형식의 요청을 만든다. 이름과 버전을 네트워크 전에 검사하고, `ExtractorAnalyzer.packument()`로 메타데이터를 한 번 받아 `inputs/npm.py`의 `build_package_request()`(새로 추가된 의존성 하나, `input_kind: "package"`)와 분석에 함께 쓴 뒤, 같은 `pipeline.scan()`으로 판정한다. registry 메타데이터와 tarball은 `analysis/registry.py`가 받는다(`https://registry.npmjs.org`만, redirect 뒤에도 검사, 크기 상한, tarball 주소 경로와 `dist.integrity` 대조, 압축 해제 크기·파일 수 상한, symbolic link는 풀지 않고 hard link는 대상 크기로 셈). 메타데이터 다운로드와 추출 단계(tarball 두 개, 압축 해제, feature 추출)는 `analysis/bounded.py`가 자식 Python 프로세스에서 실행한다. 분석하는 변경 하나는 그 변경을 시작할 때 정해지는 시간 예산 하나를 함께 쓰고(`bounded.budget()`, `ExtractorAnalyzer.analyze()`의 변경마다, `check`는 메타데이터 조회부터, 자식 단계가 없어도 적용), 예산이 끝나면 자식 프로세스를 종료하고 끝난 것을 확인한 뒤 오류를 낸다. 부모가 직접 하는 단계(호출 준비, 결과 해석, 캐시·근거 처리)는 끊지 못하므로, `run()`이 단계 사이와 결과 해석 뒤에, 분석기가 캐시용 모델 입력 검사 뒤, `cache.store`가 게시(`os.replace`) 직전, 완료 결과를 받아들이기 전에(`bounded.check()`) deadline을 다시 확인해 늦은 결과를 버린다. 부모는 자식에 함수와 인자를 pickle로 넘기고, 자식은 결과를 JSON이나 바이트로만 돌려준다(패키지 자료를 다룬 프로세스의 pickle을 읽지 않는다). 압축을 푸는 작업 폴더는 부모가 만들고 지운다. `FeatureExtractorBackend.extract()`는 depbee-analyzer의 `RegistrySnapshotSource` 대신 depbee의 source를 넘긴다. 이 source는 고정 loader의 공개 함수 `build_snapshot()`으로 받은 메타데이터에서 snapshot을 만들고(tarball을 받지 않는 호출), 소스 트리는 검사한 다운로드를 푼 폴더로 채운다. 그래서 depbee-analyzer는 registry에 접근하지 않고 old/new snapshot도 요청을 만든 문서를 쓴다(`scan --extract`도 같다). 예전의 비공개 캐시 속성(`_packument_cache`) 의존은 없다. 모델 경로 선택(`--model-dir` → `DEPBEE_MODEL_DIR` → `depbee setup`으로 저장한 폴더 → 없음, `service._asset_dir()`)은 `scan_project()`와 같은 함수를 쓴다.

`preview_update()`(`depbee update [이름...]`)는 `inputs/npm_cli.py`로 프로젝트의 `package.json`·`package-lock.json`만 임시 폴더에 복사해 `npm update --package-lock-only --ignore-scripts`(node와 npm-cli.js 직접 실행, 셸 없음, 사용자 설정의 무동작 경로를 막는 `--dry-run=false`·`--package-lock=true` 고정)로 새 lockfile을 계산하고, 원본 lockfile 바이트를 기준으로 `scan_project(extract=True)`를 부른다. npm의 `--version`과 `update` 모두에 `--prefix=<임시 폴더>`·`--workspaces=false`(상위 workspace 루트 탐색 차단)와 없는 파일을 가리키는 `--git`(Git 실행 차단)을 고정하고, `overrides`와 lockfile 항목의 의존성 값도 registry 범위만 받는다. npm 실행은 `inputs/git.py`의 `_run(tree=True)`로 하위 프로세스까지 묶어(Windows는 `KILL_ON_JOB_CLOSE`를 설정한 Job Object, POSIX는 프로세스 그룹) 시간 초과·출력 상한과 정상 종료 뒤 모두 종료하고 끝난 것을 확인한다. 판정은 그대로 `pipeline.scan()`이 하고, 미리보기 메타데이터는 보고서 밖 `preview`에 둔다. 프로젝트 파일은 읽기만 한다.

`apply_update()`(`depbee update --apply lockfile|install`)는 같은 미리보기(`_preview()`, 새 `package.json`·lockfile 바이트는 임시 폴더에서 메모리로만 나옴)를 거친 뒤 `apply_preview()`로 반영한다. 게이트는 `update_gate()`가 `report.results[]`의 항목별 필드만 읽어 정하고(기지 악성 일치는 거부, ML 기준 이상·보류·기지 악성 미확인은 한 번의 확인), 판정을 새로 만들지 않는다. 반영 직전에 `npm_cli.read_project()`와 원본·새 lockfile 해시, 새 파일의 같은 내용 검사(`npm_cli.check_files()`)를 다시 확인하고, 이력 파일 옆 `backups/`에 원본을 백업한 뒤 프로젝트 안 임시 파일과 `os.replace`로 바꾼다. 설치는 새 lockfile의 `integrity`(`npm_cli.missing_integrity()`)와 `npm ci`용 임시 폴더가 프로젝트 밖인지를 백업 전에 확인한 뒤, `npm_cli.clean_install()`이 프로젝트에서 `npm ci --ignore-scripts`를 미리보기와 같은 실행 규칙(같은 `_run(tree=True)`, 환경 정리, `--prefix`·`--workspaces=false`·없는 `--git`, 여기에 없는 `--globalconfig`와 `--package-lock-only=false`·`--dry-run=false`)으로 실행한다. 자동으로 되돌리지 않는다. 대시보드가 미리보기 결과를 들고 있다가 반영할 수 있도록 `preview_files()`는 미리보기와 새 파일 바이트를 메모리로 돌려주고 `apply_preview()`는 그것을 받는다. 규칙은 [연결 규약](contracts.md) 5.1절.

`known_malicious.py`는 기지 악성 탐지기(KM-01)다. `build_index()`가 OSV npm `all.zip`을 메모리에서 읽어 `MAL-` 기록만 담은 색인(`index.json`, `manifest.json`)을 결정적인 바이트로 만들고(`scripts/build_known_malicious_index.py`는 인자와 파일 쓰기만 하는 껍데기), `load()`가 크기·중복 키·형식·자료형·SHA-256·사본을 확인해 `contracts.KnownMaliciousDetector`인 `KnownMaliciousIndex`를 돌려준다(문제가 있으면 `GuardError`). SemVer 2.0 우선순위 비교와 OSV SEMVER 범위 평가는 표준 라이브러리로 이 모듈 안에 있고, 버전 목록과 상한 없는 범위를 함께 적은 기록의 범위 정책은 `_match_ranges()` 한 곳에 있다. 서비스는 `_predictor()` 옆의 `_known_malicious()`(`--known-malicious-dir` → `DEPBEE_KNOWN_MALICIOUS_DIR` → `depbee setup`으로 저장한 폴더 → 없음)로 색인을 한 번 읽어 `pipeline.scan(known_malicious=...)`와 `ExtractorAnalyzer(known_malicious=...)`에 같은 객체를 넘기고, 색인이 없으면 두 호출에 키워드를 넘기지 않는다. 분석기는 `select_baseline()`의 선택 콜백으로 색인의 `baseline_records()`(명시 버전과 상한 있는 범위)에 든 후보를 건너뛴다(D-16). 판정은 그대로 `pipeline.scan()`의 D-2·D-7 분기가 한다. 규칙과 형식은 [연결 규약](contracts.md) 4절.

`history.py`는 로컬 이력 저장소(표준 라이브러리 `sqlite3`)다. 서비스 함수와 `pipeline.scan()` 밖에 두어, `cli.main`의 `scan`·`update` 분기가 보고서를 출력한 뒤에만 `record()`를 부른다(그래서 `preview_update()` 안의 임시 폴더 스캔, MCP 도구, `check`, `plan`, 오류 실행은 기록되지 않는다). 대시보드도 같은 등록·조회 API를 쓴다. 보고서 값을 그대로 저장하고 판정을 다시 계산하지 않는다. `update --apply`의 반영 기록은 같은 `record()` 호출로 미리보기 실행과 함께 `applies` 표(`user_version` 2)에 들어가고, 버전 1 파일은 그 쓰기에서 올린다. 대시보드는 미리보기 실행을 먼저 `record()`로 남기고 반영 결과를 `record_apply()`로 그 실행에 더한다(같은 열 값, `_insert_apply`). 형식과 규칙은 [연결 규약](contracts.md) 6절.

`dashboard/`는 로컬 대시보드(`depbee dashboard`)다. `__init__.py`의 `serve()`가 웹 라이브러리(`web` extra: Starlette, Jinja2, uvicorn)를 쓰는 `app.py`를 지연 import하므로, extra가 없어도 다른 명령은 그대로 돈다. `app.py`는 입력 받기(등록 폼, 업데이트 확인·반영 폼, 경로 검사는 `mcp._local_path`·`_unlinked` 재사용)와 표시만 한다. 이력은 `history`의 조회·등록·기록 API로, 의존성은 `service.list_dependencies()`(`inputs/npm.py`의 `read_dependencies()`)로 읽는다. 화면에 표시할 직접 의존성이 있으면 개별 미리보기 버튼에 쓸 대상 이름을 `package.json`에서 읽는다. 모든 화면은 등록 프로젝트를 탭으로 둔 한 콘솔이고 프로젝트마다 패키지·업데이트·기록 세 화면(GET)이 있다. 화면의 업데이트 후보는 이력의 업데이트 미리보기 중 지금의 `package.json`·`package-lock.json`과 SHA-256이 같은 것에서만 읽으므로(`_update_state`), 조회는 npm을 실행하거나 네트워크를 쓰지 않고 옛 파일이나 다른 프로젝트의 결과를 현재 후보로 보이지 않는다. 종류 칸의 선언 구분은 `list_dependencies(declared=True)`가 lockfile 루트 항목에서 읽는다. 업데이트 확인은 `service.preview_files()`, 게이트 목록은 `service.update_gate()`, 반영은 `service.apply_preview()`가 하고(작업 스레드에서, 프로세스 안 잠금 하나로 한 번에 하나), 미리보기 결과와 새 파일 바이트는 프로세스 메모리(최근 10개)에만 둔다. 판정 문구와 순서는 텍스트 출력과 같은 `cli` 함수로 만든다. 탐지·판정·게이트 코드는 없다. 보안 확인(Host, 경로의 세션 `/s/<세션>/`, Origin, 응답 헤더)은 앱 전체를 감싸는 ASGI 미들웨어 `Guard` 한 곳에 있고 폼의 세션 필드는 폼 처리에서 확인한다. 템플릿과 CSS는 패키지 데이터(`templates/`, `static/`)다. 규칙은 [연결 규약](contracts.md) 7절.

`config.py`는 사용자 설정(`depbee setup`)이다. 사용자 설정 폴더(`user_dir()`: 홈 폴더 아래 `~/.config/depbee/` 또는 절대 경로의 `DEPBEE_CONFIG_DIR`)의 `config.json`에 저장한 모델·색인 폴더의 절대 경로만 두고, 임시 파일 뒤 `os.replace`로 쓴다(`write_atomic()`, 백그라운드 대시보드의 상태 파일도 같은 함수). 이 폴더는 현재 폴더, 대상 프로젝트, 이력 파일의 위치(`DEPBEE_HISTORY_DB`, 상대 경로일 수 있음)와 무관하고, 상대 경로의 `DEPBEE_CONFIG_DIR`은 `GuardError`다. 그래서 프로젝트가 가져온 `config.json`이나 제어 파일은 사용자의 것으로 읽히지 않는다. 읽기는 `service._asset_dir()` 한 곳에서 옵션과 환경 변수 다음에 하고, 손상된 파일은 설정 없음이 아니라 `GuardError`다. `service.setup_assets()`가 저장 전에 두 자산을 검사와 같은 로더(`LightGBMPredictor`, `known_malicious.load`)로 읽어 확인한다.

`dashboard/lifecycle.py`는 백그라운드 대시보드(`depbee dashboard --background`·`--status`·`--stop`)다. 표준 라이브러리만 쓴다. 시작은 분리된 자식 프로세스(`analysis/bounded.py`처럼 `python -I`에 부모의 `sys.path`를 넘김, Windows는 `CREATE_NO_WINDOW`, 그 밖은 새 세션)를 만들고, 자식은 사용자 설정 폴더의 `dashboard.lock`을 운영체제 잠금으로 잡은 채 `dashboard.serve(background=Instance)`를 부른다. `app.serve()`는 그때 주소를 출력하는 대신 `Instance.publish()`로 상태 파일에 쓰고, `Instance.control()`이 `Guard` 앞에 제어 요청(`POST /control`, 제어 값의 HMAC) 처리를 붙인다. 부모는 상태 파일의 포트(주소는 언제나 `127.0.0.1`)에 제어 요청을 보내 서버가 같은 제어 값을 가졌다는 응답을 확인한 뒤에만 주소를 돌려준다. 종료도 같은 제어 요청이고 PID로 프로세스를 끝내지 않는다. 실행 여부는 잠금으로, 남은 상태 파일이 죽은 것인지는 응답의 증명으로 판단한다.

`terminal.py`는 사람이 터미널에서 보는 표시(벌 인장, 색, 시작 화면, 다음 동작)다. 시작 화면과 `--help`의 머리말·명령 안내는 언제나 이 모듈에서 오고, 벌 인장·색·다음 동작은 표준 출력이 터미널일 때만 붙는다(`cli._emit()`). 다음 동작은 보고서의 항목 값과 `service.update_gate()`에서만 만든다. 보고서의 파이프·파일·JSON·Markdown 출력은 이 모듈이 없던 때의 바이트와 같다.

| 영역 | 담당 | 인계할 결과물 |
|---|---|---|
| 학습·평가 | 모델 담당 팀원 | native LightGBM 모델, 임계값, 학습 기록. manifest는 `scripts/write_manifest.py`로 만든다 |
| feature 추출 | 추출기 담당 팀원과 사용자 | depbee-analyzer의 extractor. depbee가 Python 라이브러리로 호출한다 |
| 서비스 연결 | 사용자 | 프로젝트 입력, 비교 기준 선정, 분석기 연결, 추론, CLI, CI/CD |

`ExtractorAnalyzer`는 depbee-analyzer의 `build_row()`를 직접 호출한다. 패키지 코드는 읽기만 하고 실행하지 않는다.
`analysis/cache.py`는 추출한 feature를 실행 사이에 재사용하는 작은 JSON 파일 캐시다(키 digest가 파일 이름, 임시 파일 뒤 `os.replace`로 저장). 키는 `ExtractorAnalyzer`가 비교한 두 버전의 메타데이터, 검증한 모델의 해시(`LightGBMPredictor.identity`), 설치 출처를 확인한 depbee-analyzer의 식별 정보(`FeatureExtractorBackend.identity`)로 만들고, 셋 중 하나라도 없으면 캐시를 쓰지 않는다. 캐시에서 읽거나 저장할 feature는 그 모델의 입력 변환(`LightGBMPredictor.encode()`)으로 다시 확인한다. 서비스는 분석기가 잰 항목별 시간과 캐시 사용 여부를 보고서에 붙인다(`service._timed`). 판정은 그대로 `pipeline.scan()`이 한다.
`ArtifactAnalyzer`는 다른 분석기가 파일로 넘긴 결과를 받는 연결부다.
새 분석기는 `Analyzer.analyze(request)`를 구현한다. 임의 플러그인 자동 검색이나 대상 프로젝트 설정의 명령 실행은 하지 않는다.

`package-lock`의 전체 파일 해시를 request_id에 반영한다. 다른 커밋의 분석 결과 재사용을 막지만
분석 파일 작성자의 신뢰성을 보장하지는 않는다. 배포 시 보호된 분석 작업이 결과를 생성해야 한다.

기준 lockfile은 파일로 받거나 Git 커밋(기본 HEAD)에서 읽는다. `inputs/git.py`는 PATH의 Git으로 고정된 읽기 전용 명령만 셸 없이 실행하고, 부분 복제의 자동 객체 받기(lazy fetch)를 끄고(`--no-lazy-fetch`, `GIT_NO_LAZY_FETCH=1`), 다른 저장소를 가리킬 수 있는 상속 환경 변수(`GIT_DIR` 등 6개)를 지우고 replace 객체와 graft를 쓰지 않으며(`--no-replace-objects`, `GIT_GRAFT_FILE`을 null 장치로), stdout·stderr 크기에 상한을, 직접 실행한 Git 프로세스에 시간 제한을 두며(하위 프로세스는 종료하지 않는다), 읽은 바이트를 파일 입력과 같은 JSON 검사·해시 경로(`contracts.parse_json`)로 넘긴다.
이후 tarball 캐시, CI PR 연결, HTML 보고서는 각 경계를 유지하며 붙인다. 전체 프로젝트 코드나 변경되지 않은
패키지를 분석했다는 뜻으로 결과를 표현하지 않는다.

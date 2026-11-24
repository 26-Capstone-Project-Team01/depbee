# 검증 기록

## 2026-11-24: 정적 규칙 결과를 공통 보고서에 연결

- 변경: pyproject가 고정한 depbee-analyzer 커밋 `917ba903`의 정적 규칙 여섯 개(규칙 묶음 `2026-11-16.1`)를 특징 추출과 같은 자식 프로세스에서, 특징 추출이 확인하고 푼 같은 두 버전에 실행해 보고서의 `rules`에 담는다([연결 규약](contracts.md) 4절 "정적 규칙"). 압축 해제 단계는 쓰지 않은 항목(링크 등)을 함께 알리고, 캐시 형식을 3으로 올려 규칙 결과를 특징과 함께 저장한다. MCP 응답에는 규칙 결과를 읽는 안내 한 줄을 더했다. 판정 규칙(D-2, D-4, D-7, 종료 코드 0/1/2, Action 판정)은 바꾸지 않았다.
- 실행 환경: Windows 11, Python 3.13.5. 테스트를 실행한 프로세스의 `depbee`는 이 브랜치의 `src`였고, `depbee_analyzer`는 고정 커밋의 Git 설치(`direct_url.json`의 커밋 `917ba903bb2e719419ad5f2daeb7d542940703d5`, depbee가 확인한 설치 파일 digest 일치)였다. 설치된 `rules/diff_scan.py`의 Git blob은 고정 커밋의 것(`acea86ce`)과 같다.
- 테스트: `python -m unittest discover -s tests` 789개 통과, 4개 skip(변경 전과 같은 Windows 전용 skip). `ruff check .` 통과. 새 `tests/test_rules.py`의 `PinnedRulesTests`는 설치된 고정 분석기의 스캐너를 실제 서비스 경로(`scan_project`, `check_package`)로 부른다. registry만 메모리에서 합성 tarball을 내주고 분석기 자신의 네트워크 호출은 실패하게 해 둔다.

고정 판정표(합성, 비실행). 비교 기준 1.0.1과 새 버전 1.1.0의 차이만 적었다. 두 검토용 적중은 알려진 정상 반례(내려받은 SVG를 검사 스크립트의 데이터 인자로 넘김, 주석 속 `eval(`와 `atob(`)이며 실행되지 않는 문자열이다.

| 새 버전의 차이 | 규칙별 결과 | 규칙 칸 | 항목·종료 코드 |
|---|---|---|---|
| 내용만 바뀐 파일 | 여섯 개 `not_hit` | `not_hit` | ML 결과 그대로 |
| 위 두 정상 반례 | `R_download_exec`·`R_diff_obfuscation` `hit`(`검토용 적중(review)`, 위치 `package.json` 행과 `lib/util.js:1`), 나머지 `not_hit` | `hit` | ML 결과 그대로(`rule_only` 또는 `both_hit`) |
| 어느 규칙도 읽지 않는 `.wasm`이 스캐너 크기 상한 초과 | 여섯 개 `not_hit` | `not_hit` | ML 결과 그대로 |
| 새 `.js`가 크기 상한 초과(두 버전에 같은 큰 `.js`도 있음) | `R_diff_obfuscation` `failed`(판정 불가, 새 파일만 이름), 나머지 `not_hit` | `failed`(`detector_failed`) | `incomplete`(`detection_failed`)·2, 점수 유지 |
| 이전 버전의 `lib/util.js`가 링크라 풀지 않았고 새 버전의 같은 파일에 난독화 단서 | `R_diff_obfuscation` `failed`(판정 불가, 새로 생긴 것인지 확정할 수 없음), `package.json`만 읽는 두 규칙 `not_hit` | `failed` | `incomplete`·2 |
| 다른 이름이나 다른 version의 `package.json`, 두 버전 모두 이름이 배열 | 여섯 개 `failed`(판정 불가) | `failed` | `incomplete`·2 |
| 스캐너 예외, 규칙 없는 응답 | 없음. `rules.detail`이 `규칙 스캔 오류(RuntimeError)` 또는 형식 오류 | `failed`(`detector_failed`) | `incomplete`·2, 특징 29개와 점수 유지 |
| 이전 stable이 없는 새 의존성, integrity 불일치 | 없음 | `not_run`(`analysis_unsupported`), `failed`(`input_failed`) | 기존 보류 이유 그대로 |
| `--analysis` 파일 | 없음 | `not_run`(`detector_not_configured`), `detectors.rules` null | ML 결과 그대로 |

같은 쌍을 캐시로 두 번 검사하면 두 번째는 tarball을 받지 않았고 규칙·특징·점수·근거가 첫 실행과 같았다. 규칙 결과가 비었거나 일부만 있거나 없는 캐시 항목은 다시 스캔했고, 스캔 오류나 읽기 오류가 있었던 결과는 저장하지 않았다.

네 진입점(같은 합성 쌍, 로컬). lockfile은 `depbee-review-only` 1.0.0 → 1.0.2, registry의 비교 기준은 1.0.1, 기준 lockfile은 Git HEAD다. registry는 메모리 스텁이고 분석의 자식 프로세스 단계는 그 스텁을 보도록 같은 프로세스에서 실행했다. 모델과 색인은 설치본 자산이고(기지 악성 시나리오만 합성 색인), 스캔 오류 시나리오만 스캐너의 `scan_pair`를 예외로 바꿨다. CLI는 `main()`, 대시보드는 앱에 폴더 등록 → 검사 버튼의 POST → 303 → 실행 화면(Starlette TestClient), MCP는 SDK의 메모리 클라이언트로 두 도구, Action은 `action.yml`과 같은 scan 인자로 만든 보고서와 Markdown을 `actions.py report`에 넘겼다.

| 시나리오 | CLI JSON(`scan`, `check`) | text·Markdown·대시보드 표시 | Action 판정 |
|---|---|---|---|
| 완료 | `not_flagged`·0, 여섯 `not_hit` | 규칙 여섯 줄 `미적중` | 통과, 주석 없음 |
| 검토용 적중 | `not_flagged`·0, `rule_only` | `검토용 적중(review)` 근거와 `package.json:5`, `lib/util.js:1` | 통과, 주석 없음 |
| 판정 불가 | `incomplete`·2(ML 기준 이상 점수 유지) | `실패 ..., 상세: 판정 불가: ...` | 기본 경고, `fail-on: incomplete`이면 실패 |
| 적중과 판정 불가 | `incomplete`·2, 규칙 칸 `적중, 실패 1개` | 두 줄이 함께 보임 | 기본 경고, `fail-on: incomplete`이면 실패 |
| 스캔 오류 | `incomplete`·2, `rules.detail` `규칙 스캔 오류(RuntimeError)` | 규칙 칸 상세에만 보이고 예외 메시지의 로컬 경로는 없음 | 기본 경고, `fail-on: incomplete`이면 실패 |
| 미실행(새 의존성) | `incomplete`·2(`no_baseline`), 규칙 `not_run` | `미실행 (분석기가 지원하지 않는 변경)` | 기본 경고, `fail-on: incomplete`이면 실패 |
| 기지 악성 일치와 판정 불가 | `flagged`·1(D-2) | 규칙 칸의 판정 불가는 그대로 | 실패(`::error`) |

모든 시나리오에서 대시보드에 저장된 보고서, MCP 응답, Action 보고서의 해당 행(비교 버전, 상태, 점수, 특징, 기지 악성, 규칙, ML, 일치 표기)이 CLI JSON과 같았고, `check`도 같은 쌍의 같은 행을 냈다. MCP 응답에는 규칙 안내가 있었고 규칙의 위치·상세가 `package_data`에도 복사됐다. 대시보드에서 규칙 탐지기 이전 보고서(`detectors.rules` null)는 `연결 안 됨`, 탐지기 필드가 없는 보고서는 `확인 안 됨`으로 보였다.

- 기존 특징·점수: 병합 커밋 `7415685`의 `src`를 `git archive`로 풀어 같은 일곱 시나리오를 CLI로 검사했다. 비교 버전, 특징 29개(키 순서 포함), 점수, 설명, 기지 악성, `ml`이 모두 같았다. 달라진 것은 `rules`와, 규칙 판정 불가나 스캔 오류인 항목의 `status`(D-7)뿐이다.
- 확인하지 못한 것: 실제 npm registry와 GitHub 호스팅 러너의 실행(CI의 lodash 확인은 규칙 여섯 개가 판정했는지까지 보도록 바꿨지만 이 기록을 쓸 때는 push 전이다), Docker 이미지 재빌드, 브라우저 렌더링, MCP stdio 자식 프로세스 경로, 실제 패키지에서 크기·링크 누락이 판정 불가를 얼마나 자주 만드는지.

## 2026-11-24: 공개 빌드 변경의 독립 검토 후속

- 계기: 아래 기록의 변경(`6fd53f5`)을 독립 검토가 다시 실행해, CI 검사가 성공으로 끝나는데 scan은 실패한 두 경우를 재현했다. 확인 스크립트가 보지 않는 해시 두 개, `core` 이미지에서 따를 수 없는 설치 안내, 아래 기록의 범위 문장도 지적했다. 다섯 건을 고쳤다. 아래 기록의 범위 문장과 호스팅 러너 항목은 `checks`가 registry에 연결하지 않는다는 점이 드러나게 바로잡았다.
- push 경로의 낡은 보고서: 이전 workflow는 scan의 종료 코드를 로그에만 남기고 workspace의 정해진 파일 `scanned-report.json`을 판정했다. 그 경로에 실제 통과 보고서를 미리 두고 registry에 닿지 못하게 한 컨테이너에서 `6fd53f5`의 action job을 push로 실행하자, scan은 `File exists`와 종료 코드 2로 끝났는데 job의 모든 단계가 통과했다. 고친 workflow는 scan의 종료 코드 0을 요구하고 보고서를 그 단계가 새로 만든 폴더에 쓴다. 같은 조건에서 scan 단계가 종료 코드 2로 실패했다. 파일만 미리 두고 registry에 닿게 한 실행은 통과했고, 판정된 보고서는 미리 둔 파일이 아니라 그 실행이 만든 것이었다. action 자신의 scan 단계와 판정 정책은 바꾸지 않았다.
- 대시보드의 보류: 이전 단계는 실행 화면에 패키지, 새 버전, 모델 ID가 있는지만 봤다. 대시보드 컨테이너에서만 registry에 닿지 못하게 하고(`--add-host`) `6fd53f5`의 단계를 실행하자 검사가 보류로 끝났는데 단계는 통과했다. 고친 단계는 기록된 실행 화면의 결과가 점수가 매겨진 `not_flagged` 하나인지 보고, 홈 볼륨에 기록된 두 실행의 보고서를 확인 스크립트로 확인한다. 같은 조건에서 `['incomplete']`로 실패했다.
- 확인 스크립트: 보고서의 `provenance.model.manifest_sha256`을 저장소 manifest 파일의 SHA-256과 비교한다. `provenance.feature_extractor.files_sha256`은 64자리 소문자 16진수여야 하고, 그 job이나 이미지에 설치된 분석기에 대해 depbee가 계산한 값과 같아야 한다. 호스팅 PR 실행의 실제 보고서에서 manifest 해시를 0으로 바꾼 사본과 설치 파일 digest를 지운 사본은 이제 실패한다. 새 단위 테스트 `tests/test_ci_report_check.py`가 받아들일 통과 보고서 세 형태와 거절할 스물한 가지를 합성 보고서로 본다.
- 분석기 설치 안내: 제품 코드의 오류 문구(`src/depbee/analysis/extractor.py`)를 바꿔, 분석기가 없을 때의 오류가 실행 환경에 맞는 방법을 적게 했다. 종료 코드와 판정은 그대로다. `core` 이미지에는 pip이 없어(`No module named pip`) 이전 안내의 명령을 실행할 수 없었다. 이제 `core` 이미지의 `check lodash@4.17.21`은 종료 코드 2와 함께 기본 이미지를 빌드하라고 안내한다. 호스트에서는 빈 venv에 wheel만 설치하고 depbee 저장소가 아닌 폴더에서 같은 명령을 실행해, 종료 코드 2와 이 depbee가 고정한 분석기 커밋을 설치하는 pip 명령을 받았다. 그 명령을 그대로 실행하자(인증을 끈 Git) 다음 실행이 통과했고 보고서에 분석기 커밋 `917ba90`과 설치 파일 digest가 적혔다. CI의 `core` 단계는 안내에 기본 이미지 빌드 명령이 있는지 보고 pip 명령이 있으면 실패한다.
- 다시 실행한 것(로컬): 고친 트리로 빌드한 두 이미지에서 docker job의 9단계가 모두 통과했고, 대시보드의 두 실행 기록이 확인 스크립트를 통과했다. action job은 Git 설정과 자격 증명이 없는 새 컨테이너에서 `pull_request`와 `push` 모두 통과했다. Windows(Python 3.13.5)의 단위 테스트는 759개를 실행해 755개 통과, 4개 건너뜀이고 `ruff check`가 통과했다.
- 확인하지 못한 것: 이 후속 커밋의 호스팅 러너 실행(이 기록을 쓸 때는 push 전이다). 아래 기록의 "확인하지 못한 것"도 그대로다.

## 2026-11-24: 공개 저장소 기준의 설치, Docker 기본 빌드, CI 실제 검사

- 범위: depbee와 depbee-analyzer가 공개 저장소가 된 뒤, 토큰 없이 되는지를 설치, 이미지 빌드, CI, Action에서 확인했다. Dockerfile에서 `analyzer` 단계(빌드 시크릿, credential helper, 미러)를 지웠다. CI의 `action`과 `docker` job은 고정한 분석기와 npm registry로 실제 버전 변경을 검사하게 바꿨고, `checks`의 네 조합은 그 분석기를 설치해 합성 입력의 단위 테스트를 돌리게 했다(registry에 연결하지 않는다). 이 기록의 변경은 제품 코드(`src/depbee`)와 `action.yml`을 바꾸지 않았다. 아래에서 "인증을 끈 Git"은 시스템·사용자 Git 설정과 credential helper를 읽지 않고 입력을 묻지 않게 한 Git이다.
- 공개 상태: 인증을 끈 Git의 `ls-remote`가 depbee, depbee-analyzer, depbee-actions-demo를 로그인 없이 읽었다. depbee 저장소에는 태그와 Release가 없다.
- Git 주소 설치: 빈 venv(Windows, Python 3.13.5)에서 [문서의 명령](usage.md#git-주소로-설치)으로 `main`의 `759cc68`을 설치했다. 휠 캐시 없이 pip이 depbee와 분석기 `917ba90`을 인증을 끈 Git으로 받았고, 설치된 분석기의 `direct_url.json`은 고정한 주소와 커밋이었다. `depbee check lodash@4.17.21`은 통과(종료 코드 0)였고 보고서에 모델 `D04-E00`, 색인 기준 시점 `2026-10-06T14:00:47Z`, 분석기 커밋 `917ba90`이 적혔다.
- wheel: 이 변경의 커밋 `479fca9`를 새로 clone해 `python -m pip wheel --no-deps`로 `depbee-0.2.1-py3-none-any.whl`을 만들고, 다른 빈 venv에 `[extract,mcp,web]`으로 설치했다(같은 인증 차단). 저장소 예시(`examples/lodash-updated`와 `examples/lodash-update`의 lockfile)에 대한 `scan --extract`와 stdio MCP `scan_lockfile`이 lodash 4.17.20 → 4.17.21을 통과로 판정했고, 두 보고서가 CI의 확인 스크립트(`.github/scripts/check_lodash_report.py`)를 통과했다.
- Docker 기본 빌드(로컬, Docker Desktop 28.3.0): `479fca9`의 새 clone에서 `docker build --no-cache`를 시크릿, 빌드 인자, 토큰 환경 변수 없이 실행해 2분 5초에 끝났다. 캐시로 표시된 것은 digest로 고정한 두 기반 이미지뿐이다. pip 단계가 분석기 `917ba90`을 받았고, 마지막 단계가 그 주소와 커밋을 출력했다. `--target core`도 빌드됐다.
- docker job의 단계(로컬): 그 두 이미지에 `ci.yml` docker job의 단계를 WSL2 Ubuntu 24.04의 `bash --noprofile --norc -e -o pipefail`로 그대로 실행했다(이미지, 컨테이너, 볼륨 이름과 포트만 바꿈). 9단계가 모두 통과했다. 실제 변경의 `scan --extract` 5.6초, MCP `scan_lockfile` 5.0초, 대시보드(컨테이너 둘, 검사만 두 번) 9.5초, `depbee update` 미리보기 5.2초였다. 미리보기에서 이미지의 npm 11.6.1이 쓴 lockfile의 SHA-256은 `examples/lodash-updated/package-lock.json`과 같았다.
- 일부러 틀리게 만든 경우: 분석기 없는 `core` 이미지를 기본 이미지 자리에 넣자 실제 변경 scan, MCP, 업데이트 미리보기 단계가 각각 실패했다. 확인 스크립트는 합성 보류 보고서, 고정 커밋을 한 글자 바꾼 `pyproject.toml`, `provenance.feature_extractor`가 null인 보고서에서 실패했다. Dockerfile을 `main`의 것(시크릿 마운트)으로 되돌린 트리에서는 `ShippedFilesTests`의 여섯 테스트 가운데 새 테스트 `test_the_image_build_can_receive_no_credential`만 실패했다.
- action job(로컬): Git 설정과 자격 증명이 없는 새 컨테이너(Dockerfile의 `base` 단계, Python 3.12.13, Git 2.47.3)에서 `ci.yml` action job과 `action.yml`의 run 단계를 그대로 실행했다. `pull_request` 경우에는 action이 `[extract]`를 설치하면서 분석기를 받았고 변경 1개를 검사해 통과로 판정했다. `push` 경우에는 직접 실행한 보고서를 `report` 입력으로 판정했다. 두 경우 모두 마지막 확인 단계를 통과했다. 다른 action을 쓰는 단계(checkout, setup-python, cache, upload-artifact)는 이 재현에서 실행하지 않았다.
- 문서의 사용 예시(로컬): [사용 예시](ci-cd.md#사용-예시)의 YAML을 그대로 workflow로 둔 합성 저장소(커밋은 lodash 4.17.20, 작업 파일은 4.17.21)와, 인증을 끈 Git으로 clone한 depbee `759cc68`의 `action.yml`로 같은 재현을 했다. 설치 69.6초, scan 7.0초, 판정은 통과였고 보고서가 확인 스크립트를 통과했다.
- 호스팅 러너: `479fca9`의 push 실행 [45291100604](https://github.com/26-Capstone-Project-Team01/depbee/actions/runs/45291100604)와 PR 실행 [45291116184](https://github.com/26-Capstone-Project-Team01/depbee/actions/runs/45291116184)에서 6개 job이 모두 성공했다. `checks`의 네 조합은 각각 757개를 실행했고 Ubuntu는 7개, Windows는 3개를 건너뛰었다(모두 OS 조건). 고정한 분석기의 loader 테스트 4개와 stdio MCP의 설치본 자산 테스트는 네 조합에서 통과했다. 이 테스트들은 합성 tarball과 가짜 registry 응답을 쓰고 네트워크에 연결하지 않는다. registry를 거친 lodash 검사는 Ubuntu의 `action`과 `docker` job에서만 돌았고, Windows 러너에서는 돌지 않았다. PR 실행의 `action` job은 `uses: ./`로 분석기를 받아 설치하고 변경 1개를 검사했다. 캐시는 없어서 새로 저장됐고 artifact가 올라갔으며, 내려받은 `report.json`이 확인 스크립트를 통과했다. push 실행의 `action` job은 직접 실행 경로였고 그 artifact도 같은 확인을 통과했다. `docker` job은 기본 이미지를 빌드해(분석기 `917ba90`) 모든 단계를 2분에 끝냈다.
- 다른 저장소의 PR: 공개 시연 저장소의 PR 두 개가 `759cc68`로 고정한 Action을 실행했다. [45290776914](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/actions/runs/45290776914)는 `ms` 2.1.1 → 2.1.3(비교 버전 2.1.2)을 통과로 판정했다. 내려받은 보고서의 점수 원값은 `8.215041385684282e-07`, 모델은 `D04-E00`, 색인 기준 시점은 `2026-10-06T14:00:47Z`, 분석기 커밋은 `917ba90`이다. [45290763429](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/actions/runs/45290763429)는 lockfile을 바꾸지 않은 PR이고 바뀐 항목 0개로 통과했다.
- 문서의 명령: Docker 안내의 [CLI로 확인](docker.md#cli로-확인) 두 줄을 Windows PowerShell 5.1.26100, PowerShell 7.6.10, Bash 5.2.21(WSL2)에서 그대로 실행했다(이미지 이름만 바꿈). 세 셸 모두 적어 둔 네 줄이 나왔고 종료 코드는 0이었다.
- 단위 테스트(로컬): Windows(Python 3.13.5)에서 757개를 실행해 753개 통과, 4개 건너뜀이다. `ruff check` 통과, sdist와 wheel 빌드 성공.
- 확인하지 못한 것: macOS와 WSL2가 아닌 Linux 호스트에서의 로컬 빌드, fork PR과 Dependabot PR, 같은 PR의 두 번째 실행에서 캐시가 복원되는지, 경고·실패 항목의 lockfile 줄 주석이 PR 화면에 놓이는 모습(위 실행은 모두 통과), Release 다섯 입력의 실제 다운로드(Release 없음), 대시보드의 업데이트 확인 화면을 브라우저로 누르는 조작(같은 서비스 함수를 CLI `depbee update` 미리보기로 실행). 이 기록과 실행 링크를 더한 마지막 문서 커밋의 호스팅 실행 결과는 이 기록에 없다.

## 2026-11-24: Docker 대시보드의 안내 문구, 이미지 CI, 별칭과 이력

- 화면: 컨테이너의 대시보드만 폴더 목록에서 `readonly` 연결 옵션과 별칭 규칙을, 프로젝트 관리에서 폴더 버튼과 직접 입력이 컨테이너에서 하는 일을, 미리보기의 설치까지 선택 아래에서 Linux용 설치를 알린다. 호스트의 화면은 안내 문단을 뺀 나머지가 컨테이너의 화면과 같다(테스트로 비교). 단위 테스트는 712개에서 714개다. Windows(Python 3.13.5)에서 714개 통과에 skip 4개, 이미지 안 Linux(Python 3.12.13)에서 714개 통과에 skip 7개다. 실제 컨테이너에서 받은 세 화면을 Edge(headless)로 1280과 390 폭에서 그려, 연결 옵션 줄이 좁은 폭에서 줄바꿈되고 설치 안내가 그 선택 바로 아래에 놓이는지 확인했다.
- CI(`docker` job): push하지 않았으므로 호스팅 러너에서는 실행하지 않았다. WSL2 Ubuntu 24.04의 `bash --noprofile --norc -e -o pipefail`로 세 단계(HEAD 기준 `plan`, 대시보드, npm)의 스크립트를 이 브랜치의 `core` 이미지에 실행해 통과했다(Docker 28.3.0, 이미지 태그와 컨테이너·볼륨 이름만 바꿈). 대시보드 단계를 세 번 이어서 실행해도 종료 직후 같은 포트로 다시 시작하는 데 실패하지 않았다. 일부러 틀리게 만든 세 경우에는 그 단계가 실패했다. Git 저장소가 아닌 폴더를 연결하면 검사만의 오류가 분석기 오류가 아니었고, 홈 볼륨을 빼면 두 번째 컨테이너에 프로젝트가 없었으며, npm 기대 버전을 바꾸면 버전 비교가 실패했다. 첫 등록이 현황판으로 이어지는 화면 변경을 담은 이미지에서도 같은 스크립트가 통과했다.
- 전체 이미지(분석기 포함, 로컬 빌드): `examples/lodash-update`를 읽기 전용으로 연결하고 [문서의 순서](docker.md#전체-이미지-확인)를 HTTP 요청으로 실행했다. 업데이트 확인은 6.6초 걸렸고(실제 npm 11.6.1과 registry), 미리보기에 `[통과] lodash@4.17.21`, 모델 `D04-E00`, 기지 악성 목록 기준 시점 `2026-10-06T14:00:47Z`, ML 위험 점수 `<0.001`이 나왔다. lockfile 반영은 "실패"와 "프로젝트 파일을 바꾸지 못함"으로 끝났고, 두 파일의 SHA-256이 그대로였으며 `node_modules`가 생기지 않았다. 쓰기 가능한 사본에서는 설치까지가 "반영함"으로 끝나 lockfile과 `node_modules/lodash`가 4.17.21이 됐다(`npm ci` 종료 코드 0).
- 별칭과 이력: 같은 볼륨에서 다른 폴더를 같은 `/projects/app`에 연결하자 등록하지 않아도 프로젝트 1로 보였다. 패키지 화면은 새 폴더의 lockfile을, 기록 화면은 이전 폴더의 실행 #1(lodash 보고서)을 보였다. 다른 별칭으로 연결하면 실행 없는 프로젝트 2가 되고 이전 프로젝트는 "폴더를 찾을 수 없음"으로 남았다. 다른 볼륨에서는 등록이 없었다.
- 셸: Windows PowerShell 5.1.26100, PowerShell 7.6.10, Bash 5.2.21(WSL2)에서 문서의 줄을 그대로 실행했다(이미지·컨테이너·볼륨 이름이 다르고 `-it` 대신 `-d`를 씀). 공백이 있는 경로, 이름이 같은 두 폴더의 서로 다른 별칭, 프로젝트 둘, 상위 폴더 연결을 `docker inspect`의 연결 정보와 컨테이너 안 `/projects` 목록으로 확인했다. 같은 문자열의 해시 8자리는 세 셸에서 같았다. 쉼표가 있는 경로는 세 셸 모두에서 `--mount`가 종료 코드 125와 `invalid field`로 거부했고, `-v "${project}:...:ro"`로는 읽기 전용으로 연결됐다(CLI `plan`도 같음). Linux에서 콜론이 있는 경로는 `-v`가 `too many colons`로 거부했고 `--mount`로 연결됐다. PowerShell 두 버전 모두 중괄호 없는 `"$project:..."`를 구문 오류로 거부했다. PowerShell 7의 `PSModulePath`를 물려받은 Windows PowerShell 5.1은 `Get-FileHash`를 찾지 못했다. 그래서 문서의 해시 줄은 모듈이 필요 없는 .NET 호출로 적었다.
- Bash의 해시 도구: 문서의 Bash 블록을 그대로 꺼내 Bash 5.2.21(WSL2, 실제 `sha256sum`과 `shasum`)과 컨테이너의 Bash 3.2.57, zsh 5.9에서 실행했다. 이름이 같은 두 폴더(`client-a/app`, `client-b/app`)의 별칭은 서로 달랐다. `sha256sum`을 뺀 PATH에서는 `shasum`으로 같은 별칭이 나왔다(두 컨테이너에는 `shasum`이 없어 `sha256sum`을 부르는 대역을 썼다). 두 도구를 모두 뺀 경우와 `sha256sum`이 빈 출력, 8자리, 63자리, 오류 문구를 낸 경우에 README 블록은 `docker`를 부르지 않았다. 안내 문서의 변수 블록은 두 변수를 지웠고, 이어서 실행한 `docker run` 명령 여섯 개는 실제 Docker에서 종료 코드 125로 끝나 컨테이너가 생기지 않았다. 도구가 없는 대화형 셸에 블록을 붙여 넣은 뒤에도 셸은 다음 명령을 받았다. 정상 도구로는 실제 Docker에서 두 폴더가 한 볼륨에 프로젝트 1과 2로 따로 등록됐다. 두 블록은 도구마다 결과를 따로 받아, 종료 코드가 0이고 출력에서 첫 공백 앞까지가 소문자 16진수 64자일 때만 쓴다. 외부 검토의 17개 사례와 추가 21개를 Bash 5.2.21에서, 그중 30개를 Bash 3.2.57과 zsh 5.9에서 실행했고 모두 기대한 결과였다. `sha256sum`이 8자리나 64자리를 출력한 뒤 실패하거나 종료 코드 0으로 65자리를 출력하면 블록은 그 출력을 버리고 `shasum`의 값으로 별칭을 만들었다. `shasum`의 결과도 쓸 수 없으면 `docker`를 부르지 않았고 전에 넣어 둔 `project`와 `alias`를 지웠다. `set -e`를 켠 Bash는 대화형 셸에서도 블록 뒤의 명령을 실행했다. `set -e`를 켠 대화형 zsh는 안내 문서 블록의 주석 줄에서 끝났다(zsh의 기본 설정은 대화형 셸의 `#` 줄을 명령으로 실행한다). 주석 줄이 없는 README 블록에서는 끝나지 않았다.
- Git 신뢰 경로와 이미지 전달: 이미지의 `safe.directory`는 `/project`, `/projects`, `/projects/*` 셋이다. 소유자가 다른 저장소의 `plan`은 `/project`, `/projects/app`, `/projects/team/app`에서 됐고 `/work`에서는 `detected dubious ownership`으로 끝났다(Docker Desktop의 Windows 경로와 WSL ext4 모두). `docker save`로 만든 파일을 `docker load`하면 같은 이미지 ID로 불러와졌다. 분석기를 뺀 이미지에서 `check`, `scan --extract`, MCP `check_package`는 분석기를 설치하라는 오류로 끝났다.
- 확인하지 못한 것: GitHub 호스팅 러너에서의 실행, macOS, WSL2가 아닌 Linux, 사람이 브라우저로 누르는 조작(HTTP 요청과 저장한 화면의 headless 렌더링으로 대신함), 화면 낭독기, `claude mcp add`에 `-v`를 쓴 등록(같은 Docker 인자를 CLI로만 확인), 쉼표와 콜론이 모두 있는 경로.

## 2026-11-21: 현재 후보를 두 파일의 해시로 찾기(이력 형식 3)

- 문제: 패키지·업데이트 화면이 그 프로젝트의 최근 업데이트 미리보기 10건을 읽은 뒤에야 해시를 비교했다. 그래서 전체 확인으로 찾은 후보가 다른 패키지 확인 10건 뒤에 사라지고 화면은 "바뀌는 항목이 없었습니다"라고 했으며, 파일을 같은 바이트로 되돌려도 그사이 다른 해시의 미리보기가 10건 쌓였으면 "파일이 바뀌었다"고 했다. 화면을 열 때마다 실행 목록 전체도 읽었다. 전체 확인 1건(후보 3개) 뒤에 다른 패키지 확인 10건을 기록한 합성 이력으로 `d95b691`에서 재현했다.
- 수정: 이력에 `previews` 표와 색인(`user_version` 3)을 더해 프로젝트와 두 해시가 같은 미리보기를 먼저 찾고(`history.list_previews`), 위치마다 그 위치를 다룬 가장 최근 확인을 쓴다. 개수 상한은 없다. 보고서 원문은 후보가 화면에 쓰이는 확인만 읽는다. "바뀌는 항목이 없었습니다"는 전체 확인이 쓰였을 때만 나오고, 이름을 지정한 확인만 있으면 일부 패키지만 확인했다고 말한다. 버전 1·2 파일은 그대로 읽고 다음 쓰기에서 올리며 이미 기록된 미리보기를 채운다.
- 단위 테스트(합성 자료만): 이 변경만 놓고 보면 `d95b691`의 574개에서 587개이고, 같은 브랜치의 다른 변경(`8f740f9`)까지 합친 전체는 598개다(둘 다 skip 3개 그대로). 이 598개는 위치 충돌 수정 전의 전체 실행 기록이고, 그 뒤 lone surrogate가 든 위치와 그 글자(`\udc80`)를 그대로 가진 위치가 한 위치로 합쳐져 후보 하나가 숨던 회귀를 고치면서(위치를 원문으로 비교하고, 저장 위치에 `\ud`가 든 확인만 한 요청에 한 번 그 보고서에서 원문 위치를 읽음) 회귀 테스트 1개를 더해 대시보드·이력 테스트 115개가 통과했다. 새 테스트는 다른 패키지 확인 12건 뒤의 전체 확인 후보, 다른 파일 상태에서 한 확인 12건 뒤 파일을 되돌린 경우, 이름 지정 확인만 있을 때의 문구, 같은 두 파일을 가진 두 프로젝트, 추가·삭제 항목과 그 뒤의 이름 지정 확인, 이력이 글자로 바꿔 저장하는 위치(lone surrogate)가 lockfile의 같은 위치로 비교되는지, GET 한 번이 읽는 보고서 수(실행 37건 중 1건, 실행 목록 전체는 읽지 않음), 버전 2 파일을 그대로 읽고 다음 쓰기에서 올리기, 실패한 올리기의 되돌림, 해시 없는 미리보기다. 차단 사유였던 두 경우의 테스트는 고치기 전 코드에서 값이 틀려 실패했고, 고친 부분을 하나씩 되돌린 변이 11개가 모두 테스트에 잡혔다. `ruff check` 통과.
- 측정(합성 프로젝트의 lockfile 항목 40개, 보고서 한 건 약 4 KB, Python 3.13.5, SQLite 3.49.1, Windows 11, Starlette TestClient로 화면마다 GET 40회의 중앙값, 고치기 전과 후를 번갈아 두 번): 기록 11건에서 패키지 화면 35~47 ms → 20~27 ms, 업데이트 화면 23~33 ms → 10~12 ms. 기록 5,011건(다른 실행 5,000건이 그 11건의 앞이나 뒤에 있음)에서 패키지 화면 73~79 ms → 19~27 ms, 업데이트 화면 62~66 ms → 10~12 ms로, 고친 뒤에는 11건일 때와 같았다. 요청당 SQLite 연결은 34개에서 7개가 됐다. 같은 파일 상태에서 전체 확인 없이 이름 지정 확인만 5,000건 쌓인 이력은 패키지 화면 82~86 ms → 62~67 ms였다(확인 한 건마다 짧은 조회 하나를 하므로 건수에 비례). 버전 2 파일을 올리는 첫 쓰기는 5,000건 이력에서 72~100 ms였다. 실제 서버(`python -m depbee dashboard --port 0`)에 HTTP로 30회씩 요청했을 때도 5,011건에서 패키지 화면 80 ms → 23 ms였고, 고치기 전에는 후보가 보이지 않았다.
- 브라우저: 프로젝트 콘솔 기록의 Chrome 158 검사에 두 장면(전체 확인 뒤 한 패키지 확인 11건, 이름 지정 확인만 있는 프로젝트의 문구)을 더해 1280×900과 390×844에서 89개 확인이 모두 통과했다. npm·Git·registry를 쓰는 세 서비스 호출은 그 기록과 같이 합성 결과로 바꿨다.
- 확인하지 못한 것: 보고서가 큰 이력(항목 수십 개)에서의 시간, 다른 OS와 SQLite 버전, 실제 npm·registry를 거친 확인. 올리기 전의 버전 2 파일은 저장된 미리보기를 하나씩 읽으므로 느리다(이름 지정 확인만 5,000건이면 패키지 화면 119~124 ms로 고치기 전보다 느리고, 다음 쓰기 뒤에는 위 수치가 된다). 기록 화면은 실행을 상한 없이 모두 보이므로 5,000건에서 170~198 ms이고 모델 정보 화면은 45~53 ms이며 이번에 바꾸지 않았다.

## 2026-11-21: 대시보드 프로젝트 콘솔(탭, 세 화면, 현재 후보, 종류)

- 구현: 모든 화면에 등록 프로젝트 탭(링크와 `aria-current`, 스크립트 없음)을 두고 프로젝트 화면을 패키지·업데이트·기록 세 GET 화면으로 나눴다. 탭 이름은 폴더 이름이고 같은 이름은 상위 폴더로 구분하며, 탭 상태는 없는 폴더, 실행 없음, 가장 최근 실행의 저장된 결과다. 업데이트 후보는 그 프로젝트의 저장된 업데이트 미리보기 중 지금의 `package.json`·`package-lock.json`과 SHA-256이 같은 것만 쓰고(위치별로 그 위치를 다룬 가장 최근 확인), 없으면 "미확인"과 확인 버튼, 옛 파일의 결과면 현재 후보가 아니라고 말한다. 패키지 화면의 종류 칸은 lockfile 루트 선언(일반·개발·선택·피어, 여러 개면 모두, alias는 선언 이름)과 중첩을 보인다(`list_dependencies(declared=True)`, 기본 반환은 그대로). 실행 중 재요청(409)과 없는 미리보기(404)는 탭이 있는 화면으로 바꿨고, 탭 아이콘을 세션 아래에서 주어 세션 없는 `/favicon.ico` 요청(403)을 없앴다. 서비스·게이트·이력 형식·`serve()`는 바꾸지 않았다. 규칙은 [연결 규약](contracts.md) 7절.
- 단위 테스트(Starlette TestClient, 가짜 서비스, 합성 자료만): 전체 497개에서 516개(skip 3개 그대로). 탭의 상태와 현재 표시, 0개·같은 이름·없는 폴더, 세 화면과 이동 경로, 전체·이름 지정 확인이 다루는 위치와 최신 확인 우선, 파일을 바꾸면 후보가 사라지고 되돌리면 다시 보이는지, 다른 프로젝트의 실행을 쓰지 않는지, 읽을 수 없는 파일, 반영한 뒤의 안내, 추가·삭제 항목, 최근 10개 상한, 후보 문자열의 이스케이프, 열려 있는 미리보기 목록, 종류 칸(여러 선언, alias, 같은 이름의 다른 위치, 선언 없는 최상위 항목), GET이 서비스를 부르지 않고 기록을 만들지 않는지를 확인한다. 후보 판별을 "저장된 미리보기는 모두 현재"로, 이름 지정 확인을 "전체를 다룸"으로 바꾼 변이에서는 해당 테스트가 실패했다.
- 브라우저: Chrome 158(headless)을 DevTools 프로토콜로 구동해 1280×900과 390×844(터치·모바일 에뮬레이션) 두 폭에서 확인했다. 화면과 서버는 제품 코드 그대로이고 npm·Git·registry를 쓰는 세 서비스 호출(`preview_files`, `apply_preview`, `scan_project`)만 합성 결과로 바꿨다. 등록 프로젝트 0개 → 폼 등록(상대 경로 거부 문구와 `aria-invalid`, 같은 이름 폴더 두 개의 탭 이름, 같은 폴더 재등록) → 5개 프로젝트의 탭 상태, 확인한 적 없는 프로젝트와 없는 폴더와 옛 파일의 결과 → 키보드만으로 Tab 순서(건너뛰기 링크, 브랜드, 모델 정보, 탭 5개, 프로젝트 관리, 화면 링크 3개, 버튼과 입력), 모든 정지점의 초점 표시, 건너뛰기, Enter로 탭 전환과 화면 전환, 이름 검색 → Enter로 전체 업데이트 확인(POST 1회) → 미리보기의 확인 항목과 확인란 → 업데이트·패키지 화면의 후보 6개와 판정, 근거 링크가 보고서의 그 항목(`:target`)을 여는지 → Space로 확인란, Enter로 반영 → 반영 뒤 안내와 기록 → 다시 연 미리보기의 404 화면 → 기지 악성 일치의 반영 불가 → 패키지 하나 확인. 화면마다 글자 대비(최소 5.76:1), 조작 요소의 접근 이름, 제목과 랜드마크, 표 머리, 인라인 스타일·스크립트 없음, 좁은 폭의 가로 넘침 없음을 계산했다. 76개 확인이 모두 통과했고, 브라우저 요청은 모두 그 서버(127.0.0.1)였으며 CSP 위반과 예상 밖 콘솔 오류가 없었다. 조회만 한 구간에서는 가짜 서비스 호출이 0회였다.
- 확인하지 못한 것: 실제 npm·registry·Git을 거친 업데이트 확인·반영의 끝단(이번 변경은 그 호출부를 바꾸지 않았고 브라우저 확인은 합성 결과를 썼다), 화면 낭독기로 실제로 듣는 확인(구조와 이름만 계산), Firefox·Safari, 프로젝트나 패키지가 아주 많을 때의 속도와 탭 줄 수, 어두운 화면 모드(밝은 화면만 있음), POSIX.

## 2026-11-20: 대시보드 Ctrl+C 종료와 등록 안내문(DEMO-02)

- 브라우저 리허설: 아래 DEMO-01 기록의 시연 환경(`d3445b0` 비편집 설치)에서 `depbee dashboard --port 0`을 띄우고 Orca 내장 브라우저로 화면을 확인했다. 시작 두 줄은 README와 같았다. 첫 화면(등록한 프로젝트 없음) → 시연 폴더 등록 → 프로젝트 화면(직접 의존성 3개, 중첩 2개, 검사만 버튼과 업데이트 확인 폼) → 업데이트 확인 11초(npm 11.6.1, 바뀐 5개, 통과 3·삭제 2, 모델 D04-E00, 기지 악성 색인 연결, 규칙 미연결, 항목별 ML 위험 점수·비교 버전·기여도 막대) → 반영 방식 lockfile(확인란 없음) 반영 1초("업데이트 반영: 반영함", lockfile sha256 변화, 이력 파일 옆 `backups/`의 백업 위치, 되돌리기 안내) → 검사만 3초(실행 #2 통과, 바뀐 5개) → 프로젝트 화면의 반영 이력 1건과 실행 기록 2건(#2 scan, #1 업데이트 미리보기).
- Ctrl+C: 대시보드를 띄운 터미널에 Ctrl+C를 한 번 보내자 1초 안에 데모 경로 프로세스가 0개가 되고 그 포트에서 리슨하는 소켓이 없었으며, 브라우저 새로고침은 빈 페이지였다(그 주소 무효). 다만 터미널에 Python `KeyboardInterrupt` traceback이 찍혔다. uvicorn 0.54.0의 `Server.capture_signals`는 정상 종료 뒤 잡아 둔 신호를 `signal.raise_signal`로 다시 올리고, 그 결과 `uvicorn.Server.run()`이 `KeyboardInterrupt`로 끝나는데 depbee가 잡지 않았다. 등록 폼 안내문이 대시보드의 검사만·업데이트 확인을 언급하지 않는 것도 이때 찾았다.
- 수정: `depbee.dashboard.app.serve()`가 uvicorn 실행에서 나온 `KeyboardInterrupt`만 잡아 stdout에 `대시보드를 종료했습니다. 위 주소는 더 이상 열리지 않습니다.` 한 줄을 쓰고 돌아가, `depbee dashboard`는 종료 코드 0으로 끝난다. 소켓은 전처럼 `finally`에서 닫는다. 다른 명령의 Ctrl+C 동작과 그 밖의 예외는 바꾸지 않았다. 프로젝트 목록의 등록 안내문과 실행 없음 문구에 프로젝트 화면의 "검사만"·"업데이트 확인"과 CLI `depbee scan`·`depbee update` 검사 기록을 적었다.
- 단위 테스트(가짜 uvicorn 서버, 합성 자료만): 전체 490개에서 492개. 가짜 `Server.run`이 `KeyboardInterrupt`를 내면 `serve(0)`와 `main(["dashboard", "--port", "0"])`이 예외 없이 종료 줄을 남기고(후자는 0을 돌려줌) 소켓이 닫히는지, `OSError`는 그대로 올라가고 종료 줄이 없는지, 두 문구가 프로젝트 목록에 나오는지 확인한다. 테스트가 `KeyboardInterrupt`를 잡아 실패로 바꾸므로, 수정 전 `app.py` 사본에 붙이면 unittest 실행이 멈추지 않고 그 테스트 하나가 실패했다(대시보드 테스트 55개 중 실패 1). `.[dev,ml]`만 있는 환경은 대시보드 테스트가 skip되어 skip 68개(새 테스트 2개 포함), 모든 extra를 설치한 환경은 skip 3개로 전과 같다.
- 확인하지 못한 것: 수정한 코드로 실제 터미널에서 보낸 Ctrl+C(가짜 서버로만 확인), 요청 처리 중이나 두 번 보낸 Ctrl+C, Ctrl+Break와 SIGTERM(바꾸지 않음), POSIX.

## 2026-11-19: 진입점별 시연 리허설(DEMO-01)

- 범위: README에 [진입점별 시연](demo.md) 절을 더하고, 그 명령을 저장소 밖 시연 환경에서 실행했다. 코드·테스트는 바꾸지 않았다(base `d3445b0`). 시연 환경은 `d3445b0`의 `git archive` 사본을 전용 venv(Python 3.13.5)에 비편집으로 `[ml,extract,mcp,web]` 설치한 것이고, 모델 D04-E00과 기지 악성 색인(OSV npm MAL, 기준 시점 2026-10-06T14:00:47Z)의 sha256을 대조했다. feature-extractor의 설치 출처(`direct_url.json`의 GitHub 주소와 고정 커밋 `c24761d`)를 확인했고 모든 `--extract` 보고서의 `provenance.feature_extractor.commit`이 이 커밋이었다. 정상 시연 프로젝트는 `lodash ^4.17.15`, `ms ^2.1.1`, `semver ^7.5.0`의 lockfile을 커밋한 Git 저장소다.
- 장면별 종료 코드(모두 기대와 같음): `plan` 0, `update` 미리보기 0, 색인 없는 `update --apply lockfile` 2(확인 필요로 반영하지 않음), 색인 연결 반영 0(반영함, 이력 파일 옆 `backups/`에 백업), 반영 뒤 `scan --extract` 0, `check` 0, pre-release로 바꾼 lockfile의 `scan --extract` 2(`out_of_training_scope`, registry 조회 전), registry가 더 이상 주지 않는 색인 버전으로 이름·버전만 바꾼 lockfile의 `--extract` 없는 `scan` 1, 로컬 사본을 읽는 악성 ML 데모 1(색인 연결·미연결 모두). 모델 없음 `check`는 `model_missing` 보류 2이고 근거가 없었으며, 색인 없는 `--extract` 없는 `scan`은 바뀐 항목이 `analysis_missing` 보류 2였다.
- 대시보드: `depbee dashboard --port 0`의 시작 두 줄 형식을 확인하고, 폼 요청으로 등록, 의존성, 업데이트 확인, 반영(확인란 없음, 색인 연결), 같은 미리보기 재전송 거부, 검사만, 실행 기록(`update_preview`, `scan`)과 반영 기록 1개, 다른 세션 403을 확인했다. 서버를 끈 뒤 남은 프로세스는 없었다. 이 PC는 WSL mirrored 네트워킹이 TCP 7765~11860을 예약해 `--port 8765` bind가 실패했고(오류 JSON, 종료 코드 2), `netstat`에는 보이지 않았다.
- MCP: SDK Client로 stdio 서버를 띄워 도구 2개, `check_package` 0(`notices` 3개), 기지 악성 일치 lockfile의 `scan_lockfile` 1(`notices` 4개, 일치 경고 포함, tarball 404라 다운로드 없음), pre-release lockfile의 `scan_lockfile` 2(보류 강조 포함)를 확인했다. 실제 Claude Code(2.1.328)도 비대화형(`claude -p`)으로 `--strict-mcp-config --mcp-config`와 함께 실행했고, 설치가 일어나지 않게 Bash·편집 도구를 금지했다. 서버가 연결되고 도구 2개가 보였으며, lodash 검사 요청은 `check_package` 0, 기지 악성 lockfile 검사 요청은 `scan_lockfile` 1이었고 에이전트가 설치를 멈추고 사용자 결정을 물었다. MCP 설정의 `env`(TMP·TEMP·USERPROFILE)가 서버에 전달되어 실제 홈 캐시가 생기지 않았다.
- README 따라 하기: 새 폴더에서 README의 npm 단계(`npm init -y`, `npm install lodash@4.17.15 ms@2.1.1 semver@7.5.0 --package-lock-only --ignore-scripts`, Git 커밋)를 그대로 실행했고 `node_modules`가 생기지 않았다. 이어 README CLI 1~7단계와 Actions 판정 재현 (a)·(b)의 첫 줄과 종료 코드가 README에 적은 것과 같았다.
- Actions 판정 재현(`action.yml` 단계를 같은 인자로 로컬 PowerShell에서 실행, 설치·Release 다운로드·캐시·artifact 단계 제외): 예시 보고서 03은 항상 실패, 02는 경고이고 `fail-on ml-hit`면 실패, 04·06은 경고이고 `fail-on incomplete`면 실패, 01·05는 통과였다. 실제 scan 보고서로 정상 업데이트는 통과, 기지 악성 일치는 실패(`::error`와 lockfile 줄 번호), pre-release 보류는 경고이고 `fail-on incomplete`면 실패, 로컬 사본의 ML 기준 이상은 경고이고 `fail-on ml-hit`면 실패였다. `--markdown` 없는 판정도 같았다. PowerShell 7.4 이상에서 `PYTHONUTF8`·`PYTHONIOENCODING` 없이 `--format markdown > summary`를 만들면 summary가 cp949로 저장되어 판정이 "보고서를 판정하지 못했습니다"(종료 코드 1)였고, `PYTHONUTF8=1`이면 정상이었다. 같은 조건에서 텍스트 출력을 파이프로 받으면 한글이 깨졌다.
- 격리: README 명령을 `--cache-dir` 없이 그대로 실행한 리허설 한 번이 실제 `~/.cache/depbee`에 정상 패키지 feature 캐시 4개를 만들었다. 시작 전에는 없던 폴더이고 안의 파일이 모두 그 실행 뒤에 생긴 것임을 확인한 뒤 지웠으며, 최종 감사에서 `~/.local/share/depbee`·`~/.cache/depbee`는 없었다. 이 일로 README의 준비 절이 이력·백업·캐시·임시 파일을 시연 전용 상태 폴더에 두게 했다. MCP 서버의 캐시는 서버 환경의 USERPROFILE로 시연 폴더 아래에 두었다. `%TEMP%`에 `depbee_*`·`feature_extractor_src_*`가 남지 않았고, 사용자 Claude Code 설정과 전역 Git 설정을 바꾸지 않았다.
- 확인하지 못한 것: 사람이 보는 브라우저 화면과 Ctrl+C 종료(위 2026-11-20 DEMO-02 기록에서 확인), 대화형 Claude Code의 `/mcp` 화면과 권한 창, 비공개 feature-extractor를 clone하는 인증 경로(pip가 휠 캐시를 재사용해 실행되지 않음), 공개·Release 뒤 실제 PR 실행, Linux·macOS.

## 2026-11-19: 대시보드 검사만 버튼(SVC-07-SCAN)

- 구현: 프로젝트 화면의 "검사만" 버튼(`POST /s/<세션>/projects/<id>/scans`)이 등록 경로에서 `service.scan_project`를 Git HEAD 기준(CLI `scan`의 기본), `extract=True`, 대시보드의 모델·캐시·기지 악성 색인 옵션으로 부르고, 성공하면 CLI와 같은 값(`base_ref` 없음, `base_lock` false)으로 scan 실행을 기록한 뒤 실행 상세로 보낸다. 기록하지 못하면 보고서를 그 자리에서 보이고 한 줄로 알린다. 업데이트 확인·반영과 같은 잠금을 써 실행 중이면 409다. 판정·점수 로직은 대시보드에 없다. 규칙은 [연결 규약](contracts.md) 7절.
- 단위 테스트(Starlette TestClient, 가짜 `scan_project`, 합성 자료만): 전체 484개에서 490개. 서비스 인자와 기록 인자, 303 위치, 기록 실패·None일 때 보고서 표시, `GuardError` 문구 이스케이프와 그 밖 예외의 고정 문구, 없는·찾을 수 없는 프로젝트, 폼 세션·Origin 403, 검사·업데이트 확인·반영이 서로 409로 막히는지. `.[dev,ml]`만 있는 환경은 대시보드 테스트가 skip되어 skip 66개, 모든 extra를 설치한 환경은 skip 3개로 전과 같다.
- 확인하지 못한 것: 실제 Git 저장소·registry·`extract`를 거친 끝단 실행과 브라우저 화면.

## 2026-11-19: Action 경로 입력의 링크 workspace 경계(SVC-06-F3)

- 구현: `actions.py inputs`의 `lockfile`·`report` 검사는 절대 경로와 `..`를 문자열로만 거부해, workspace 안의 심볼릭 링크나 Windows junction이 밖의 파일(또는 밖의 폴더를 거친 파일)을 가리켜도 통과했다(REV-SVC06-R1 F3). 이제 기존 검사 뒤에 파일과 workspace의 실제 경로(`Path.resolve()`)를 경로 구성 요소 단위로 비교해(`is_relative_to`, `/ws`와 `/ws2`를 구분하고 Windows 경로는 대소문자를 무시) 밖이면 입력 오류로 실패한다. workspace 안을 가리키는 링크는 허용한다. 검사는 입력 검사 단계 한 번이며 검사와 사용 사이의 변경은 막지 않는다. `report` 입력은 자기 검사 전용으로 유지했다.
- 단위 테스트(합성 파일만): `tests/test_actions.py` 25개에서 28개, 전체 481개에서 484개. 밖 파일 링크·밖 폴더 링크를 거친 lockfile·밖 report 링크 거부, 안쪽 링크와 링크로 가리킨 workspace 허용, 한글·공백 폴더의 링크 없는 경로 통과, Windows junction. 심볼릭 링크 테스트는 권한이 없는 Windows에서 건너뛰어 skip이 1개 늘었다(`.[dev,ml]` 60개, 모든 extra 3개). WSL Ubuntu 24.04(Python 3.12)에서는 링크 테스트가 돌아 통과했고, 수정 전 코드에서는 거부 3가지가 실패했다. junction 테스트는 이 Windows에서 돌고 수정 전 코드에서 실패한다.
- 수동 확인(`python -I src/depbee/actions.py inputs`, workspace를 현재 폴더로): 밖을 가리키는 파일 링크·폴더 링크·junction·report 링크는 종료 코드 1과 `must be inside the workspace; links must not point outside`, 안쪽 링크와 일반 경로는 종료 코드 0이었다.
- 확인하지 못한 것: GitHub runner에서의 실행, 하드 링크(링크가 아니라 같은 파일이라 이 검사로 구분하지 않음).

## 2026-11-19: MCP 응답의 기지 악성 색인 미연결 안내(MCP-KM-01)

- 구현: 색인 없이 띄운 `depbee mcp`의 성공 응답(`report.detectors.known_malicious`가 null, `detectors`가 없어도 같음)에 기지 악성 기록과 대조하지 않았으므로 통과도 알려진 악성 버전이 아니라는 확인이 아니라는 고정 안내를 강조 문구 뒤, 항상 넣는 문구 앞에 하나 넣고, 서버 지침(`instructions`)에 같은 뜻의 영어 문장을 더했다. 문구와 조건은 [연결 규약](contracts.md) 4절 끝. 판정·종료 코드·보고서·오류 응답·CLI·대시보드 출력은 바꾸지 않았다.
- 단위 테스트(합성 자료와 가짜 탐지기, 네트워크 없음): 전체 480개에서 481개. 탐지기 없음·규칙만·색인 연결에서 `notices` 전체를 순서까지 비교하고, `detectors`가 없는 보고서, 오류 응답, 지침 문장을 확인한다. `.[dev,ml]`만 있는 환경은 skip 59개, 모든 extra를 설치한 환경은 skip 2개로 전과 같다. CLI·대시보드 출력은 기존 테스트가 그대로 통과하는 것으로 확인했다.
- 수동 확인(가짜 backend·predictor·탐지기로 `mcp.check_package`의 실제 응답): 색인 없음은 종료 코드 0과 안내 포함, 가짜 색인 미적중은 종료 코드 0과 안내 없음, 적중은 종료 코드 1과 기지 악성 경고 뒤 안내 없음, 오류 응답은 오류 문구 두 개뿐이었다.
- 확인하지 못한 것: 실제 색인 폴더(로더)와 실제 MCP 클라이언트를 통한 응답 표시.

## 2026-11-18: 실제 registry 검증과 소요 시간(VAL-01)

- 목적: 정상 패키지로 실제 npm registry 메타데이터·tarball을 받아 `scan --extract`와 `check`를 실행하고, 바뀐 패키지 1·5·20개의 첫 실행과 캐시 재실행 시간을 재며, D04-E00 학습 CSV와 feature·점수가 같은지 다시 본다. 코드·테스트는 바꾸지 않았다(base `e0010c0`, depbee 0.1.0).
- 측정 환경: 이 PC(Windows 11 Home 10.0.26200, Intel Core Ultra 7 155H 16코어·22스레드, RAM 31.6 GB, NVMe SSD, Windows Defender 실시간 보호 켜짐), Python 3.13.5, LightGBM 4.7.0, numpy 2.5.4, feature-extractor 고정 커밋 `c24761d`(Git 설치). 모든 보고서의 `provenance.feature_extractor.commit`이 이 커밋이었고 캐시가 쓰였다(warm 실행의 `cache_hit`가 모두 true). 모델 D04-E00(`model_sha256` `4e3bb5a8...`, 실제 해시와 같음). 네트워크는 Wi-Fi(어댑터 링크 288 Mbps)이고 실제 회선 대역폭과 종류는 모른다. 임시 폴더·HOME·캐시는 작업 폴더 아래로 돌렸다. 그래서 다운로드·압축 해제·캐시 경로는 백신 검사 예외로 설정해 둔 폴더 아래였지만, 측정 때 예외 목록이 실제로 적용돼 있었는지는 관리자 권한이 없어 다시 확인하지 못했다. npm은 실행하지 않았다.
- 표본: D04-E00 분할의 Test 정상 쌍(`benign` 400, `hard_benign` 60)을 (패키지, 이전, 새 버전) 순으로 정렬한 뒤 `random.Random(20261118)`로 섞어 차례로 보고, 정상 14·어려운 정상 6을 채울 때까지 골랐다. 제외 규칙은 새 버전 prerelease, registry가 이전·새 버전을 제공하지 않음, 같은 패키지 이름 중복, 기지 악성 색인(OSV npm MAL, 기준 시점 2026-10-06T14:00:47Z, `a59a627f...`) `match()`가 이전·새 버전 중 하나라도 적중이었다. 앞에서 44쌍을 보았고 제외는 0건, 정상 할당이 찬 뒤 넘긴 정상 쌍이 24건이었다. N=5는 앞 5개, N=1은 앞 1개(`@vikejs/express` 0.1.0 → 0.2.0)다. 20개에는 큰 tarball을 가진 `onnxruntime-node` 1.17.0 → 1.17.3과 `puppeteer` 18.1.0 → 18.2.0이 들어 있다.
- 합성 lockfile: N마다 `package.json`과 `package-lock.json`(lockfileVersion 3, `node_modules/<이름>`에 새 버전, registry `resolved`, registry 메타데이터의 `dist.integrity`)을 만들고, 같은 꼴로 이전 버전의 기준 lockfile을 만들었다.
- 순서: N=1·5·20마다 새 캐시 폴더로 cold → 같은 캐시로 warm → `--no-cache`를 실행하고, 이 순서를 새 캐시 폴더로 한 번 더 반복했다(r1, r2). 모두 `--format json --output`으로 보고서를 남겼다. 벽시계는 프로세스 시작부터 끝까지(Python 시작과 import 포함), 보고서 시간은 최상위 `elapsed_seconds`다.

| N | 반복 | cold 벽시계 / 보고서 | warm 벽시계 / 보고서 | `--no-cache` 벽시계 / 보고서 | 추출 수 (cold / warm / no-cache) | warm `cache_hit` |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | r1 | 3.31 / 2.92초 | 1.04 / 0.84초 | 1.71 / 1.50초 | 1 / 0 / 1 | 1/1 |
| 1 | r2 | 1.54 / 1.35초 | 0.99 / 0.80초 | 1.42 / 1.23초 | 1 / 0 / 1 | 1/1 |
| 5 | r1 | 8.35 / 8.09초 | 2.26 / 2.06초 | 4.67 / 4.42초 | 5 / 0 / 5 | 5/5 |
| 5 | r2 | 5.29 / 5.05초 | 2.44 / 2.26초 | 4.93 / 4.68초 | 5 / 0 / 5 | 5/5 |
| 20 | r1 | 44.23 / 44.03초 | 8.08 / 7.83초 | 32.84 / 32.57초 | 20 / 0 / 20 | 20/20 |
| 20 | r2 | 35.84 / 35.62초 | 8.33 / 8.05초 | 35.01 / 34.70초 | 20 / 0 / 20 | 20/20 |

- 모든 실행(위 18회, 아래 `check` 3회, 색인 연결 2회와 보충 warm 6회)의 종료 코드는 0이고 모든 항목이 `not_flagged`였다. 추출 실패·보류(`incomplete`) 항목은 없었다. 같은 패키지는 모든 보고서(색인 유무, cold·warm·`--no-cache`, `check` 포함)에서 판정·점수·비교 기준·feature가 같았다.
- 항목별 `elapsed_seconds`(N=20): cold 중앙값 r1 1.55초·r2 0.95초, warm 중앙값 0.30·0.31초(최대 0.95초), `--no-cache` 중앙값 0.86·0.98초. 가장 오래 걸린 항목은 `onnxruntime-node`로 위 표(색인 없음)의 추출 때마다 11.5~11.9초였고 아래 색인 연결 cold에서는 12.8초였다. 나머지는 cold에서 0.69~2.92초였다. 변경 하나의 시간 예산 300초에 가까운 항목은 없었다. r1 cold가 r2 cold보다 느린 항목이 여러 개 있었으나 원인은 확인하지 않았다.
- `check @vikejs/express@0.2.0`(새 캐시 폴더): cold 1.48 / 1.28초, warm 0.96 / 0.77초(`cache_hit` true), `--no-cache` 1.48 / 1.30초(벽시계 / 보고서).
- 기지 악성 색인 연결(N=20, `--known-malicious-dir`, 새 캐시 폴더, 한 번): cold 39.03 / 37.46초, warm 13.69 / 12.16초. warm만 같은 캐시로 세 번 더(색인 없는 warm과 번갈아) 재면 색인 있음 9.23~10.92초, 없음 7.97~9.08초(벽시계)라 첫 13.69초는 그중 큰 값이었다. 색인 읽기는 서비스가 시간을 재기 시작한 뒤에 하므로 보고서 전체 시간에 들어간다(CLI는 경로만 넘긴다). 새 프로세스에서 import 뒤 색인만 한 번 읽은 시간은 0.53초였다. 벽시계와 보고서 시간의 차이는 색인 있음(5회) 1.4~1.6초, 없음(N=20의 r1·r2·보충 9회) 0.2~0.3초였고, 색인이 있을 때 이 차이가 커진 원인은 확인하지 않았다. 보고서 시간 중 항목 시간 밖 부분은 색인 있음(5회) 1.4~1.6초로, 색인 없는 r1 warm과 보충 warm 4회의 0.6~0.7초(r2 warm은 0.75초)보다 길었다. 이 부분에는 색인 읽기가 들어가고, 나머지 차이의 원인은 확인하지 않았다. 20개 모두 기지 악성 칸 `not_hit`이고, D-16으로 비교 기준이 바뀐 항목은 없었다(근거에 "비교 기준 후보에서 뺌" 없음). 색인 유무에 따라 `compared_version`, feature, 점수, 판정이 달라진 항목도 없었다.
- D04-E00 일치 재검사(정상 쌍만): N=20 cold 보고서 셋(색인 없음 r1·r2, 색인 있음)의 20개 항목 모두 `compared_version`이 학습 CSV의 이전 버전과 같았고, 29개 feature가 Test CSV 값과 같았다(2026-10-05 검사와 같은 규칙: bool·문자열·결측은 정확히, 숫자는 상대 1e-6·절대 1e-9). 보고서 점수와 CSV feature로 계산한 점수도 모두 같았다(절대 1e-9). 악성 쌍의 일치 검사는 이번에 다시 하지 않았다.
- 해석의 한계: 시간은 이 PC, 이 네트워크, 측정 시각의 registry·CDN 상태에 따른 값이다. 표본은 정상 20쌍이고 반복은 두 번(색인 warm은 네 번)이라 분포를 대표하지 못한다. 벽시계에는 Python 시작과 LightGBM 등의 import가 매번 들어 있다. 표본을 고를 때 같은 패키지의 메타데이터를 미리 받았으므로 첫 cold도 registry를 처음 만난 상태는 아니다. warm도 메타데이터는 매번 받으므로 네트워크 시간이 남는다.
- 확인하지 않은 것: 악성 패키지(이번 범위 밖), 크기·파일 수 상한에 가까운 실제 패키지와 시간 예산 초과, 느린 네트워크, Linux·macOS, 다른 PC, `update`·MCP·대시보드 경로의 실제 registry 실행, D-16이 실제로 비교 기준을 바꾸는 경우(이 표본에는 없었다).

## 2026-11-17: 기지 악성 탐지기(KM-01)

- 구현: OSV npm `all.zip`에서 `MAL-` 기록만 담은 색인 폴더(`index.json`, `manifest.json`)를 만드는 `scripts/build_known_malicious_index.py`와 `depbee.known_malicious`(표준 라이브러리 SemVer 2.0 비교, 정렬한 OSV SEMVER 범위, 범위 정책 함수, `0.0.1-security` 질의 제외, 로더 검사), service의 `--known-malicious-dir`·`DEPBEE_KNOWN_MALICIOUS_DIR` 연결(scan·check·update·mcp·dashboard), 비교 기준 후보 제외(D-16), GitHub Action의 색인 입력 두 개와 다운로드·sha256 확인 단계. 규칙은 [연결 규약](contracts.md) 4절.
- 단위 테스트(합성 자료만: 합성 zip, `example-*`·`@example/*` 이름, `MAL-EXAMPLE-*` ID, 가짜 backend·predictor·npm, 네트워크 없음): 전체 414개에서 468개. 새 파일 `tests/test_known_malicious.py`(생성 건수·결정적 바이트·`--as-of` 거부·덮어쓰기 거부, 로드 오류, SemVer 11절 예, 일치 규칙과 범위 정책 표, D-16 술어)와 `tests/test_known_malicious_wiring.py`(옵션→환경 변수→없음, 미설정 시 `scan()`·`ExtractorAnalyzer` 호출 불변, 한 색인 객체, hit과 낮은 점수의 위험, `--extract` 없는 scan, check·MCP 도구와 MCP 서버, 깨진 색인의 registry 조회 전 오류, 업데이트 게이트, 대시보드 옵션, D-16과 캐시 키), `tests/test_actions.py`의 색인 입력·`verify` 여러 쌍·`action.yml` 단계 확인. `.[dev,ml]`만 있는 환경은 skip 59개(`.[extract]`·`.[mcp]`·`.[web]` 미설치와 OS 전용), 모든 extra를 설치한 환경은 skip 2개(OS 전용)다.
- 실제 스냅샷 확인(네트워크 없이 2026-10-06에 받은 npm `all.zip` 217,771,875바이트, sha256 `f7eb5cec...`, 파일 수정 시각을 `--as-of 2026-10-06T14:00:47Z`로 사용, 받은 시각의 기록은 없음): 생성 23.0초, `index.json` 15,341,329바이트(sha256 `a59a627f...`), 넣은 기록 221,983건·이름 221,982개, 뺀 기록 MAL 아닌 것 7,687건·철회 331건, 기대 밖 형태 0건. 같은 zip으로 두 번 만든 `index.json`의 sha256이 같았다. 읽기(sha256·JSON·검사) 1.2~1.8초, 같은 파일을 다시 읽어 검사한 객체를 재사용할 때 0.08~0.10초. `match()`만으로 확인한 사례: 적중 16건(chalk 5.6.1·5.6.1+build, axios 0.30.4·1.14.1, debug 4.4.2, @solana/web3.js 1.95.6·1.95.7, @ctrl/tinycolor 4.1.1·4.1.2, nx 명시 버전 하나, flatmap-stream(모든 버전), @triniwiz/nativescript-pdf 1.0.0-beta.2(prerelease 경계), ng2-file-upload 8.0.2(정렬 안 된 이벤트), @dydxprotocol/perpetual 1.2.2·1.3.0(상한 없는 범위), @emilgroup/api-documentation 1.19.1), 미적중 17건(같은 패키지의 다른 버전, 철회 기록, `0.0.1-security`, GHSA에만 있는 event-stream 3.3.6·coa 2.0.3, 대소문자 다른 이름, 무관한 패키지)이 모두 기대대로였다. 범위 정책에 따라 갈리는 두 사례(@emilgroup/api-documentation 1.19.0, @ebay-business-components/marko-rum 99.9.2)는 지금 정책에서 미적중, OSV 합집합 정책에서는 적중이다. 합성 packument로 chalk 5.6.1이 비교 기준 후보에서 빠지고 5.6.0이 선택됨을 확인했다. 색인 파일과 측정 스크립트는 저장소에 두지 않았다.
- 기존 명령 출력 비교(base `542a2d9`와 HEAD의 `src`를 `git archive`로 풀어 `PYTHONPATH`로 실행, 색인을 주지 않고 `DEPBEE_KNOWN_MALICIOUS_DIR`도 지운 상태, SVC-07과 같은 명령 × 세 이력 상태): 종료 코드·stdout·stderr가 바이트 단위로 같았고, `scan`·`check`·`update`·`mcp`·`dashboard`의 도움말만 사용법 줄과 새 옵션 한 개만큼 달랐다. 최상위·`plan` 도움말은 같았다.
- 수동 확인(이 PC, 실제 `depbee scan`, `--extract` 없음, 합성 색인과 합성 lockfile, 이력 DB와 HOME을 작업 폴더 아래로): 일치한 변경 하나만 있으면 `flagged`/1이고 `reason`은 `analysis_missing` 그대로, 텍스트·Markdown 머리에 기지 악성 일치 경고와 "기지 악성 목록: OSV npm MAL, 기준 시점 ..."이 나온다. 분석하지 않은 다른 변경이 함께 있으면 전체는 `incomplete`/2이고 일치 항목은 `flagged`다. 색인 없이는 지금처럼 `detectors` null·`not_run`이고, 바꾼 `index.json`은 보고서 없이 오류(종료 코드 2)다.
- 교차 검토 R1 수정(major 2, minor 3, 모두 합성 테스트를 먼저 써서 수정 전 실패를 확인한 뒤 고침): 버전 목록이 있었지만 유효 버전이 하나도 남지 않거나 `versions`가 목록이 아닌 affected 항목을 이유(`versions_all_invalid`, `versions_not_list`)를 세어 빼서 상한 없는 범위가 켜지지 않게 함(수정 전에는 `["1.0"]`과 모든 버전 범위를 가진 기록이 임의 버전에 적중). 재사용 메모를 한 번만 읽어 비교한 항목의 객체를 돌려줌(키 비교 중 메모를 다른 색인으로 바꾸게 만든 결정적 테스트에서 수정 전에는 다른 색인을 돌려줌). 버전 숫자에 상한(16자리·2^53-1)을 두고(R2에서 major·minor·patch로 좁힘) 기록·manifest·index JSON의 긴 정수 `ValueError`를 `record_not_json`·`GuardError`로 바꿈(수정 전에는 `ValueError`가 새어 스크립트가 traceback). 암호화·지원 밖 버전·손상 스트림 zip을 `GuardError`로 바꿈(수정 전에는 `RuntimeError`·`NotImplementedError`·`zlib.error`가 샘). `zipfile.ZipFile` 생성 전에 끝 레코드(ZIP64 포함)에서 중앙 디렉터리 크기(64 MiB 상한)와 선언 항목 수를 검사함(수정 전에는 zipfile이 중앙 디렉터리 전체를 읽은 뒤 검사). 단위 테스트 468개에서 477개. 실제 스냅샷(중앙 디렉터리 15,043,787바이트, ZIP64, 선언 230,001개)으로 다시 만든 `index.json`은 sha256이 위와 같고(`a59a627f...`) 건수도 같으며 생성은 24.7초였다.
- 교차 검토 R2 수정(major 1, minor 1, 합성 테스트를 먼저 써서 수정 전 실패를 확인한 뒤 고침): R1의 숫자 상한이 prerelease에도 걸려 `1.0.0-9007199254740992`·`1.0.0-12345678901234567` 같은 유효한 버전의 적중이 `failed`가 되고 생성 때 그런 버전·경계가 빠지던 것을, npm semver처럼 major·minor·patch만 제한하고 prerelease 숫자는 정수로 바꾸지 않고 (자릿수, 문자열) 순으로 비교하게 고침(수정 전에는 큰 prerelease가 `GuardError`). 손상된 LZMA 항목의 `lzma.LZMAError`를 `GuardError`로 바꿈(수정 전에는 새어 스크립트가 traceback, 손상된 bzip2는 `OSError`라 이미 바뀜). 단위 테스트 477개에서 480개. 실제 스냅샷으로 다시 만든 `index.json`은 sha256이 위와 같고(`a59a627f...`) 건수도 같으며, prerelease가 든 버전·경계 840개 중 이 상한에 걸리는 것은 없었다.
- 확인하지 못한 것: 실제 registry·feature-extractor·모델로 색인을 연결한 `--extract`·`check`·`update`(D-16이 실제 packument에서 비교 기준을 바꾸는 경우 포함), 실제 GitHub Actions에서의 색인 다운로드(Release 없음), 소은의 고정 판정표와의 대조(명세 대기, 범위 정책은 2026-11-17에 지금 정책으로 정했고 판정표가 오면 다시 맞춘다).

## 2026-11-17: 대시보드 업데이트 확인·반영 화면과 세션 주소(SVC-07-UPDATE)

- 구현: 대시보드 세션을 쿠키에서 주소(`/s/<세션>/`)와 폼의 숨은 `session` 필드로 바꿨다(로그인 단계 없음, `Set-Cookie` 없음, `Cookie` 무시). 프로젝트 화면의 업데이트 확인(`service.preview_files`, CLI와 같은 `update_preview` 기록, 메모리 보관 최근 10개), 미리보기 화면(보고서, `service.update_gate` 목록, 반영 폼과 확인 단계), 반영(`service.apply_preview`, 미리보기를 먼저 소비, `history.record_apply`), 반영 이력 표와 실행 상세의 반영 절, `depbee dashboard --model-dir/--cache-dir/--no-cache`. 서비스(`preview_files`)와 이력(`record_apply`, `record()`와 같은 열 값)은 추가만 했다. `pipeline.py`, `contracts.py`, `mcp.py`, `actions.py`, `analysis/`, `inference/`, `inputs/`, `action.yml`, `docs/examples/`, `.github/`, `pyproject.toml`은 바꾸지 않았다. 규칙은 [연결 규약](contracts.md) 6·7절.
- 단위 테스트(합성 자료, 실제 npm·Node.js·registry·브라우저 없음, Starlette TestClient): 전체 387개에서 414개, skip 10개(`.[extract]` 미설치 4, `.[mcp]` 미설치 4, Windows에서 만들 수 없는 LF 파일 이름 1, POSIX 전용 1). `tests/test_dashboard.py` 23개에서 47개: 세션(시작 줄 형식, 접두사 없는·틀린·뒤 `/` 없는 주소와 예전 `/login`·CSS 403, 쿠키로 인증되지 않음, `Set-Cookie` 없음, 모든 링크·폼·리다이렉트의 접두사, npm 링크 `rel="noreferrer"`, 폼 세션·Origin 403, Host 400), 업데이트 확인(가짜 서비스의 성공과 기록·메모리·303, 등록 경로와 모델·캐시 옵션 전달, `GuardError` 문구 이스케이프와 `[extract]`·Node.js 안내, 그 밖 예외의 고정 문구와 무기록, 없는·찾을 수 없는 프로젝트, 실행 중 409와 그동안 열리는 조회 화면, 보관 상한, 기록 실패), 게이트 표시(기지 악성 일치는 반영 폼 없음, 확인 항목과 원인, 통과 항목은 확인란 없음, 바뀐 항목 0, `.npmrc`면 설치 비활성), 반영(확인 없음·잘못된 방식 400과 미리보기 유지·서비스 미호출, `.npmrc`와 설치 400, 성공 시 `apply_preview` 인자, 소비와 재전송 404, 기록 실패에도 결과·백업 표시, 거부·실패 표시, 예외 고정 문구, 폴더 없음, CLI 기록의 표시), 이스케이프(게이트 목록·오류 문구·백업 경로·대상 이름의 `<script>`, 따옴표, U+202E, U+200C, ESC, lone surrogate), 가짜 npm(`test_apply.ApplyFixture`)으로 실제 `apply_preview`까지 간 lockfile 반영(백업, 교체, 반영 기록, 재전송 거부). `tests/test_history.py` 2개 추가(나중에 붙인 반영 기록이 `record()`와 같은 열 값, 실행 없음 None과 DB 불변, 중복·다른 종류 `ValueError`, 버전 1 올림, 홈 없음 None), `tests/test_apply.py` 1개 추가(`preview_files`가 `preview_update`와 같은 미리보기와 새 바이트를 주고 그대로 반영됨).
- 보호를 하나씩 깨뜨린 확인(`test_dashboard`만): 확인란 검사 제거, 미리보기 소비 대신 조회, `.npmrc`와 설치 검사 제거, 세션을 앞부분만 비교, 폼 세션 검사 제거의 5가지는 모두 테스트가 실패했다. 실행 중 409 제거와 보관 상한 제거는 확인하지 못했다(첫 실행의 기다리는 잠금 변형은 테스트 안 중첩 요청과 교착해 시간 초과, 둘째 실행은 메모리 부족으로 도구가 중지).
- 작성 당시 미확인이던 두 보호의 확인(수정 1회차, 고친 커밋 `e52f307`의 전체 트리 사본, `test_dashboard`, 시간 제한 300초): 교차 검토에서 두 처리기의 409 거부를 없애면 `test_one_change_at_a_time_while_pages_stay_open`가 실패하지 않고 안쪽 요청이 끝없이 이어져 시간 초과로만 드러났다. 이 테스트가 안쪽 요청 전에 가짜 미리보기 함수를 바꾸도록 고친 뒤(단언과 제품 코드는 그대로), 409 거부 제거(바깥 요청의 잠금 해제 `RuntimeError`로 오류), 잠금을 아무것도 막지 않는 가짜로 바꾸기(409 단언 실패), 보관 상한 제거(`test_only_the_newest_previews_are_kept` 실패)가 모두 약 6초 안에 테스트 실패로 잡혔다.
- 기존 명령 출력 비교(base `276012d`와 HEAD의 `src`를 `git archive`로 풀어 `PYTHONPATH`로 실행, 같은 13개 명령과 `dashboard --help` × 세 이력 상태, 시작 DB는 base 코드로 만들어 양쪽에 사본): 최상위 `--help`의 dashboard 항목과 `dashboard --help`(usage와 새 세 옵션, argparse가 옵션 칸 너비를 넓힘)만 달랐고(의도된 변화), `update --help`를 포함한 나머지는 종료 코드·stdout·stderr가 바이트까지 같았다. 기록 수도 같았다.
- 수동 확인(이 PC, 실제 `depbee dashboard`, `DEPBEE_HISTORY_DB`·HOME을 작업 폴더 아래로, 합성 프로젝트 등록, 표준 라이브러리 HTTP 클라이언트, npm 실행 없음): 시작 줄 형식, Host 불일치·다른 포트 400, 접두사 없는 `/`·예전 `/login`·CSS·틀린 세션·뒤 `/` 없는 세션 403(본문에 경로·세션 없음), 세션을 담은 쿠키로 403, 세션 주소의 화면 4개 200과 보안 헤더·`Set-Cookie` 없음, 프로젝트 화면의 모든 링크·폼 접두사, Origin 없는·다른 POST와 틀린 폼 세션 403, 없는 미리보기 반영 404, 미리보기 경로 GET 405. 서버 표준 오류는 비었고 세션 값은 시작 줄 밖에 없었으며 로그에는 가린 형태로만 남겼다. 서버를 끈 뒤 남은 Python 프로세스가 없었다.
- 확인하지 못한 것: 실제 npm·registry·feature-extractor·모델로의 대시보드 업데이트 확인·반영과 `npm ci`(로컬 세션이 따로 확인), 실제 브라우저에서의 화면·폼 제출·주소창과 방문 기록, Ctrl+C 정상 종료, 대시보드와 CLI의 동시 반영 경합, POSIX와 Python 3.11(CI 예정).

## 2026-11-17: 프로세스 트리 시간 초과 테스트의 간헐 실패(FLAKY-01)

- 현상: `ProcessTreeTests.test_timeout_kills_the_child_and_its_grandchild`가 venv `python.exe`(래퍼) subTest에서 가끔 손자의 beat 파일이 없어 실패했다(HIST-01·SVC-07·UPD-02 검증 게이트, 모두 검증 worktree를 새로 만든 직후, CI와 base 재실행 16회는 통과).
- 원인 판단: 시작 지연이다. 실패는 "npm did not finish within 3 seconds" 단언을 통과한 뒤에 났는데, Job 배정이나 재개(`NtResumeProcess`)가 실패하면 시간 제한이 시작되기 전에 다른 GuardError가 나므로(`inputs/git.py` `_ProcessTree.__init__`) 자식은 Job 안에서 재개된 상태였다. 이 환경에서 래퍼 → 인터프리터 → 래퍼 → 인터프리터가 첫 beat를 쓰기까지 0.13~0.15초였고, 3초를 넘기려면 부하로 20배 이상 늦어져야 한다. 늦어진 원인(새 worktree 뒤의 색인·백신 검사 등)은 확인하지 못했다.
- 바꾼 방식: 테스트만 고쳤다. 제한 안에 손자가 시작하지 않은 시도는 판정 불가로 보고 3초, 10초, 15초 순으로 다시 시도하고, 시도마다 GuardError 문구와 경과 시간 상한(제한 + 12초)을 그 제한에 맞췄다. 15초에도 시작하지 않으면 실패한다. 정상일 때는 첫 시도로 끝난다.
- 손자 수명과의 관계: 합성 손자는 시작 뒤 30초에 스스로 끝난다. 시간 제한이 손자를 죽이지 못하면 손자가 물려받은 stdout 파이프 때문에 `_run`이 손자가 끝날 때까지 돌아오지 않으므로, 마지막 시도의 경과 상한(15 + 12 = 27초)과 이어지는 0.5초 정지 확인이 모두 30초 전에 끝나야 이런 회귀가 경과 시간 단언에서 실패한다. 처음 고른 25초(상한 37초)는 이 경우를 통과시켰다(교차 검토 REV-FLAKY01-R1 M1). 손자 수명 `HEARTBEAT`는 Job 테스트와 함께 쓰므로 바꾸지 않았다.
- 같은 클래스의 다른 테스트는 짧은 제한에 묶인 시작 대기가 없어 그대로 두었다(정상 종료 테스트는 부모가 beat를 기다리고 제한이 30초, Job 테스트는 beat를 20초까지 기다림, 나머지는 손자를 띄우지 않음).
- 확인(임시 스크립트, 커밋하지 않음): 손자 시작을 4초 늦춘 부모는 두 번째 시도에서 통과(27.1초), 손자를 띄우지 않는 부모는 세 시도 뒤 실패(56.2초)했다. 세 번째 시도까지 간 뒤 Job이 breakaway를 허용하고 손자가 트리를 빠져나가 30초 자연 종료까지 남게 한 결함 주입은 15초 값에서 두 subTest 모두 경과 시간 단언으로 실패(30.1초 > 27초)했고, 같은 주입을 25초 값에 넣으면 통과해 검토의 반례가 실제로 성립함을 확인했다. `ProcessTreeTests` 반복은 25초 값에서 20회, 15초 값에서 10회 모두 통과(회당 13.50~13.73초, 고치기 전 13.82초). 전체 테스트 387개 통과(skip 32), `ruff check .` 통과.
- 확인하지 못한 것: 실패가 났던 검증 worktree 생성 직후 같은 부하 상태에서의 재현, POSIX와 CI 실행.

## 2026-11-17: integrity 구분자를 ASCII로 한정(UPD-02 fix_r4)

- 재검토 R3의 M2-R3(major)를 반영했다. `valid_sri`가 Python `str.split()`으로 나눠, Python만 공백으로 보는 U+0085·U+001C~U+001F를 정상 SRI 앞에 붙인 값을 유효로 봤다. ssri는 JavaScript `trim().split(/\s+/)`(`ssri/lib/index.js` 138·379행)로 나눠 그 문자를 토큰에 남기고, 정규식에 맞지 않는 토큰을 버려 결과가 null이 되므로 npm은 대조하지 않는다(소스로 확인, 실행하지 않음).
- 이제 구분자는 ASCII 공백·탭·LF·CR(`npm_cli.SRI_SEPARATORS`)뿐이고 그 밖의 문자는 토큰에 남아 알고리즘·base64 검사에서 거부된다. 원문을 고치지 않고 검사만 하므로 npm에 넘어가는 값과 검사한 값이 같다.
- 단위 테스트 `tests/test_apply.py` 28개에서 30개: U+0085·U+001C~U+001F와 VT·FF·NBSP·U+2028·U+FEFF·U+3000·NUL을 정상 SRI의 앞·뒤·두 해시 사이(붙임과 공백 사이)에 넣은 값의 거부, ASCII 구분자로 나눈 여러 해시와 실제 형식의 sha512 허용, 앞에 붙인 다섯 문자 각각의 install 거부(`integrity_missing`)·원본 두 파일과 백업 불변·`npm ci` 미실행·같은 입력의 lockfile 반영. 전체 385개에서 387개, skip 32개(앞 기록과 같은 이유).
- 정정: fix_r3 보고의 "Python과 JavaScript 공백 정의 차이는 거부 쪽으로만 달라진다"는 틀렸다(앞에 붙인 경우 허용 쪽으로 달라졌다).
- 도움말은 바뀌지 않아 기존 명령 출력 비교는 다시 돌리지 않았다.
- 확인하지 못한 것: 실제 npm으로 이런 값을 둔 `npm ci`(로컬 세션이 다시 확인), npm 12의 ssri.

## 2026-11-16: install의 유효한 integrity와 bundled 항목(UPD-02 fix_r3)

- 재검토(REV-UPD02-R1 재검토, major 1, minor 1)와 하람 결정(2026-11-16 19:3x)을 반영했다. 규칙은 [연결 규약](contracts.md) 5.1절.
- M2: install 전 검사가 비어 있지 않은 문자열만 보아 공백이나 해시 형식이 아닌 `integrity`를 통과시켰다. npm 11.6.1 소스(실행하지 않음)에서 pacote가 lockfile 값을 ssri로 파싱하고(`pacote/lib/fetcher.js` 59-60행), ssri가 공백으로 나눠 읽지 못한 값을 버린 뒤 남은 것이 없으면 null을 돌려줘(`ssri/lib/index.js` 373-390행) 대조할 기대 해시가 사라지는 것을 확인했다. 이제 `npm_cli.valid_sri`가 값 하나하나를 `sha512`·`sha384`·`sha256`·`sha1`과 그 digest 길이의 padding 있는 base64로 확인하고(ssri보다 엄격, 하나라도 틀리면 거부), 백업·교체 전에 `integrity_missing`으로 거부한다. `sha1`은 오래된 lockfile에 있고 ssri가 대조하므로 받아들였다.
- m3: `resolved` 없는 bundled 항목을 부모 tarball로 보호된다고 보고 뺐지만, 루트 `bundleDependencies` 항목(`@npmcli/arborist/lib/node.js` 565-570행)과 부모 tarball에 없는 항목(`reify.js` 930-962·1110-1121행)은 npm이 따로 받는다. 하람 결정 2로 bundled 항목도 유효한 `integrity`가 없으면 install을 거부하고, 오류 문구에 bundled 항목 수와 lockfile만 반영해 직접 설치하라는 안내를 붙인다. `lockfile` 모드는 그대로 허용한다.
- 단위 테스트 `tests/test_apply.py` 26개에서 28개: `valid_sri`의 구분(null·빈 값·공백·해시 아님·알 수 없는 알고리즘·대문자 알고리즘·다른 알고리즘 길이·padding 없음·base64 밖 문자·`?` 옵션·정상 값 뒤의 잘못된 값은 거부, 네 알고리즘과 여러 해시·앞뒤 공백은 허용), 키 없음·null·공백·해시 아님·알 수 없는 알고리즘·잘못된 길이의 install 거부와 파일·백업 불변·`npm ci` 미실행·같은 입력의 lockfile 반영, 빈 문자열은 미리보기의 입력 검사(`inputs/npm.py`)에서 먼저 오류, 루트 `bundleDependencies` 항목과 의존 패키지 안 bundled 항목의 install 거부와 lockfile 반영. 업데이트 테스트 fixture의 `integrity`를 형식·길이가 맞는 합성 SRI로 바꿨다(실제 tarball 해시 아님). 전체 383개에서 385개, skip 32개(앞 기록과 같은 이유).
- 도움말은 바뀌지 않아 기존 명령 출력 비교는 다시 돌리지 않았다. 텍스트 출력의 거부 이유 문구(`integrity_missing`)만 바뀌었다.
- 확인하지 못한 것: 실제 npm으로 잘못된 `integrity`나 bundled 항목이 있는 lockfile의 `npm ci`(로컬 세션이 다시 확인), npm 12의 ssri.

## 2026-11-16: 미리보기 npm update의 무동작 경로(UPD-02 fix_r2)

- 발견: 로컬 세션의 실제 npm 확인(케이스 F)에서 사용자 npmrc에 `dry-run=true`가 있으면 미리보기의 `npm update --package-lock-only`가 새 lockfile을 쓰지 않고 종료 0으로 끝나, 업데이트가 있는데 바뀐 항목 0개·통과·종료 코드 0으로 보였다(UPD-01부터 있던 경로).
- npm 11.6.1 소스 확인(실행하지 않음): `dry-run`은 arborist가 저장 전에 돌아가게 하고(`reify.js` 279-281·1301-1305행), `package-lock=false`는 lockfile 저장을 건너뛴다(1534행). 미리보기 고정 인자에 `--dry-run=false`·`--package-lock=true`를 더했고 `npm ci`도 같은 값을 받는다. `global`·`location=global`은 lockfile만 계산하는 갱신에서 `ESHRINKWRAPGLOBAL`(95-99행), `npm ci`에서 `ECIGLOBAL`(`ci.js` 32-36행)로 오류가 나 조용하지 않으므로 고정하지 않았다. `save`(`update.js` 46-48행, 켜면 `package.json`도 바뀌어 `package_json_changed`로 보임), `before`, `lockfile-version`은 사용자 선택으로 남기고 연결 규약 5절에 적었다.
- 바이트가 같은 새 lockfile: arborist는 lockfile을 비교 없이 항상 다시 쓰므로(`shrinkwrap.js` 1160-1180행) 수정 시각으로 실제 쓰기를 확인할 수는 있지만 내부 구현과 시각 정밀도에 기대는 검사라 넣지 않았다. 알려진 무동작 경로를 막은 뒤의 같은 바이트는 UPD-01 확인(업데이트할 것이 없으면 바이트 그대로)과 같은 정상 결과로 본다.
- 단위 테스트: 미리보기와 `npm ci`의 정확한 argv에 새 고정값을 더했다(테스트 수 383 그대로, skip 32).
- 보호를 하나씩 깨뜨린 확인(내보낸 사본에서 20가지, 전체 테스트): 이번 2가지(`--dry-run=false` 제거, `--package-lock=true` 제거, 둘 다 미리보기와 `npm ci` argv 테스트가 실패)와 fix_r1까지의 18가지. 모두 테스트가 실패했다. 처음 돌린 `--package-lock-only=false` 제거는 바꾼 코드가 문법 오류여서 테스트가 잡은 것이 아니었고, 올바른 tuple로 다시 돌려 테스트 실패를 확인했다.
- 기존 명령 출력 비교(base `c1d2e8a`, fix_r1 스크립트, 13개 명령 × 세 이력 상태): 도움말은 이번에 바뀌지 않았고, 최상위 `--help`의 update 항목과 `update --help`만 앞과 같이 의도대로 다르며 나머지는 바이트가 같았다.
- 확인하지 못한 것: 사용자 npmrc에 `dry-run=true`·`package-lock=false`를 둔 실제 미리보기(로컬 세션이 다시 확인), `save`·`before`·`lockfile-version`을 켠 실제 동작.

## 2026-11-16: 업데이트 반영 검토 후속(UPD-02 fix_r1)

- 교차 검토 REV-UPD02-R1(major 1, minor 2, nit 1)과 하람 결정(2026-11-16 18:0x)을 반영했다. 규칙은 [연결 규약](contracts.md) 5.1절.
- M1(사용자 npm 설정으로 설치 생략): npm 11.6.1 소스로 확인했다. `npm ci`는 `dry-run`이 아니면 `node_modules` 내용을 먼저 지우고(`lib/commands/ci.js` 79-100행) 사용자 설정의 `packageLockOnly`를 그대로 넘기며(40-46행), arborist는 `dryRun`·`packageLockOnly`이면 패키지를 풀지 않고 돌아간다(`@npmcli/arborist/lib/arborist/reify.js` 279-286행). 이제 `npm ci`에 `--package-lock-only=false`·`--dry-run=false`를 고정한다(명령줄이 모든 npmrc보다 우선). `global`·`location=global`은 `npm ci`가 `ECIGLOBAL`로 실패하므로(`ci.js` 32-36행) 고정하지 않았다. 실제 npm으로 이 설정을 넣어 실행하지는 않았다.
- m1(삭제 항목): 하람 결정 1로 지금 동작(새로 설치되는 버전이 있는 항목만 확인, 삭제만 있는 반영은 확인 없이 진행, 삭제 항목도 기지 악성 일치면 거부)을 유지하고 README·연결 규약 문장을 고쳤다. 삭제만 있는 반영의 전체 경로 테스트를 더했다.
- m2(임시 폴더 위치): install은 `npm ci`용 임시 폴더를 백업·교체보다 먼저 만들고, 링크·정션을 푼 실제 경로가 프로젝트 안이면(Windows 대소문자 무시) `scratch_in_project`로 거부한다.
- n1: README 첫 문장과 최상위 `--help`의 update 설명을 기본 미리보기와 `--apply` 반영·설치에 맞게 고쳤다.
- 하람 결정 3: install은 새 lockfile에서 내려받는 항목마다 `integrity`가 있어야 한다(`integrity_missing`, 백업·교체 전). bundled 항목(`resolved` 없음)은 부모 tarball의 `integrity`로 확인되므로 제외했다.
- 검토의 2번 관찰(설치 뒤 확인은 반영한 파일만 봄): 문서대로 `package.json`과 lockfile 둘 다 확인하게 고쳤다.
- 단위 테스트 `tests/test_apply.py` 23개에서 26개: `npm ci` argv의 두 고정값, integrity 없는 항목의 install 거부와 같은 입력의 lockfile 반영(bundled 항목은 제외), `TMP`를 프로젝트 안 폴더·대문자 경로·프로젝트로 가는 정션(POSIX는 심볼릭 링크)으로 둔 install 거부와 파일·백업 불변, `npm ci`가 바꾸지 않은 `package.json`을 바꾼 경우의 실패, 삭제만 있는 반영의 확인 없는 진행. 전체 380개에서 383개, skip 32개(앞 기록과 같은 이유).
- 보호를 하나씩 깨뜨린 확인(내보낸 사본에서 19가지, 전체 테스트): 이번 보호 5가지(`--package-lock-only=false` 제거, `--dry-run=false` 제거, 프로젝트 안 임시 폴더 허용, integrity 없는 install 허용, `npm ci` 뒤 두 파일 확인 제거)와 앞 기록의 14가지. 모두 테스트가 실패했다.
- 기존 명령 출력 비교(base `c1d2e8a`, 같은 13개 명령 × 세 이력 상태): 최상위 `--help`는 update 항목 줄만, `update --help`는 usage와 새 두 옵션만 달랐고(둘 다 의도된 변화), 나머지는 바이트가 같고 기록 수도 같았다.
- 확인하지 못한 것: 사용자 npmrc에 `package-lock-only=true`·`dry-run=true`를 둔 실제 `npm ci`(소스로만 확인), POSIX의 심볼릭 링크 경우(CI 예정), 그 밖은 아래 UPD-02 기록과 같다.

## 2026-11-16: 업데이트 반영(`depbee update --apply`, UPD-02)

- 구현: `service.apply_update`·`apply_preview`·`update_gate`(미리보기 재사용, 항목별 게이트, 반영 직전 재확인, 백업, 임시 파일과 `os.replace` 교체), `inputs/npm_cli.clean_install`(`npm ci --ignore-scripts`)과 `check_files`(read_project의 내용 검사를 새 파일에도), CLI `--apply {lockfile,install}`·`--confirm-warnings`, `{preview, report, apply}` JSON과 텍스트·Markdown 반영 절, 종료 코드 규칙, 이력 `user_version` 2(`applies` 표, 버전 1 올림, `list_applies`, `get_run`의 `apply`). `pipeline.py`, `contracts.py`, `mcp.py`, `actions.py`, `analysis/`, `inference/`, `dashboard/`, `action.yml`, `docs/examples/`, `.github/`, `pyproject.toml`은 바꾸지 않았다. 규칙은 [연결 규약](contracts.md) 5.1·6절.
- npm 소스 확인(설치된 npm 11.6.1, 실행하지 않음): 설정 우선순위는 명령줄 > 환경 > 프로젝트 `.npmrc` > 사용자 > 전역 > 내장(`@npmcli/config/lib/index.js` 49-56·118-124·178-185행)이라 명령줄로 고정한 `ignore-scripts`·`git`·`prefix`·`workspaces`는 프로젝트 `.npmrc`가 바꿀 수 없지만, `registry`·인증·프록시·`cache`·`userconfig` 등은 `.npmrc` 값이 쓰인다. `registry`는 lockfile의 registry.npmjs.org tarball 주소 호스트를 바꾸고(pacote 21.0.3 `lib/fetcher.js` 87-88행, `lib/remote.js` 13-16행) 받은 바이트는 lockfile `integrity`와 대조된다(`lib/remote.js` 38행). 그래서 프로젝트 `.npmrc`가 있으면 install을 거부한다. CLI `prefix`가 있으면 전역 설정 파일 기본값이 `<prefix>/etc/npmrc`가 되어(`index.js` 296-312행) 프로젝트 파일이 전역 설정으로 읽히므로 `--globalconfig`를 depbee 임시 폴더 안의 없는 파일로 고정했다. `npm ci`는 `save: false`(`lib/commands/ci.js` 40-46행)이고 `ignore-scripts`이면 루트 script(102-124행)와 의존성 script·`binding.gyp` 빌드(`@npmcli/arborist/lib/arborist/rebuild.js` 150-166행)를 실행하지 않으며, 설치 전에 `node_modules` 내용을 지운다(88-97행).
- 단위 테스트(합성 자료, npm·Node.js·registry 실행 없음, 가짜 npm 실행기): `tests/test_apply.py` 23개. 게이트(기지 악성 `hit`은 확인을 줘도 거부, ML `hit`·보류·기지 악성 `not_run`·`failed`는 확인 없으면 파일·폴더 불변으로 거부하고 확인하면 반영, 통과 항목은 보고서 종료 코드 2여도 확인 없이 반영, 삭제 항목과 칸 없는 항목, 지금 보고서는 모든 설치 항목이 확인 대상), 재확인(미리보기 중 원본 두 파일 각각 변경, `npm-shrinkwrap.json` 생김, 새 lockfile 바이트 불일치, 새 lockfile의 registry 밖 `resolved`는 확인해도 거부, 바뀐 항목 0개는 두 방식 모두 무변경·백업 없음·`npm ci` 없음), 백업(원본 바이트, `backup.json` 값, `DEPBEE_HISTORY_DB` 옆과 빈 값일 때 홈 기준 위치, 프로젝트 안 `.env`와 무관, 백업 폴더 자리에 파일이 있거나 홈이 없으면 실패하고 프로젝트 불변), 교체(첫 번째·두 번째 `os.replace` 실패, 권한 복사 실패에서 원본 유지·이미 바꾼 파일 이름·임시 파일 없음), 설치(`npm ci`와 `--version` argv, 임시 폴더가 프로젝트 밖이고 끝나면 없음, 환경 정리, 600초·1 MiB, 종료 코드 1·시간 초과·lockfile 변경은 실패와 백업 안내이고 npm 출력 없음, 프로젝트 `.npmrc`면 install 거부·lockfile 허용, 상대 경로 거부), CLI(세 형식, `{preview, report, apply}` 키 순서, 확인 목록 문구, 종료 코드: 거부이고 보고서 1이면 1, 보고서 0이면 2, 확인 뒤 반영이면 보고서 값, 실패는 2, `--apply` 없는 `--confirm-warnings`는 npm 실행 전 2), 이력(미등록 무기록과 DB 바이트 불변, 등록 프로젝트의 실행·반영 기록과 원문 일치, 새 lockfile 내용 없음). `tests/test_history.py` 4개 추가와 버전 기대값 수정(새 DB 버전 2, 더 새 버전 예시를 3으로): 반영 기록 저장·조회, 버전 1 파일 읽기·미등록 기록이 바이트를 바꾸지 않음, 쓰기·등록 때 버전 2로 올림, 쓰기 중 실패하면 버전 1과 표가 그대로. 전체 353개에서 380개. 이 `.venv`에는 `[dev,ml]`만 있어 skip 32개(`[web]` 미설치 대시보드 22개, `.[extract]` 미설치 4개, `.[mcp]` 미설치 4개, Windows에서 만들 수 없는 LF 파일 이름 1개, POSIX 전용 1개).
- 보호를 하나씩 깨뜨린 확인(내보낸 사본에서 15가지, 새 파일 검사는 그 커밋의 `test_apply.py`만 실행): `--ignore-scripts` 제거, `--globalconfig` 제거, `.npmrc` 거부 제거, 기지 악성 거부 제거, 확인 요구 제거, 기지 악성 미확인 무시, 원본 해시 재확인 제거, 새 lockfile 해시 확인 제거, 지원 범위 재확인을 예외로, 바뀐 항목 0개에도 쓰기, 임시 파일 남김, `npm ci` 뒤 lockfile 확인 제거, 거부이고 보고서 0인 종료 코드를 0으로, 기록이 버전 1을 올리지 않음, 새 파일 지원 범위 검사 무시. 모두 테스트가 실패했다.
- 기존 명령 출력 비교(base `c1d2e8a`와 HEAD의 `src`를 `git archive`로 풀어 `PYTHONPATH`로 실행, import 위치 확인): HIST-01·SVC-07과 같은 13개 명령 × 세 이력 상태. HEAD가 버전 1 파일을 처음 쓸 때 버전 2로 올리면 base가 그 파일에 쓰지 않으므로, 시작 DB를 base 코드로 만들어 base·HEAD에 같은 사본을 따로 주었다. `update --help`만 usage 줄과 새 두 옵션 때문에 달랐고(의도된 변화, 그 밖의 줄은 같음), 최상위 `--help`를 포함한 나머지는 모두 바이트가 같았다. 기록 수도 같았고(등록한 상태에서 scan 4개가 양쪽에 하나씩), 등록하지 않은 상태의 두 DB 바이트는 그대로, 등록한 상태에서 base 사본은 버전 1, HEAD 사본은 버전 2가 됐다.
- 확인하지 못한 것: 실제 npm·registry로의 반영과 `npm ci`(로컬 세션이 따로 확인), npm 12, POSIX(프로세스 그룹, 파일 권한 복사)와 Python 3.11(CI에서 돌 예정), 실제 `.npmrc`가 있는 프로젝트의 동작(소스로만 확인), 대시보드와 CLI가 동시에 쓰는 실제 경합, 반영과 사용자 편집이 겹치는 재확인 뒤의 짧은 구간.

## 2026-11-16: 로컬 대시보드 조회·이력 화면(SVC-07)

- 구현: `depbee dashboard`(`dashboard/`, `web` extra), 의존성 목록 서비스 함수(`service.list_dependencies`, `inputs.npm.read_dependencies`), 텍스트·Markdown의 '확인 안 됨'·참고값과 규칙 일부 실패 표시(`cli.py`). `pipeline.py`, `contracts.py`, `mcp.py`, `actions.py`, `analysis/`, `inference/`, `action.yml`, `docs/examples/`, `history.py`는 바꾸지 않았다. 규칙은 [연결 규약](contracts.md) 4·7절.
- 단위 테스트(합성 자료, 실제 npm·registry·브라우저·서버 프로세스 없음, Starlette TestClient의 `base_url`은 `http://127.0.0.1:<포트>`): `tests/test_dashboard.py` 23개(교차 검토 R1 뒤 2개 추가). 예시 01~06 보고서와 새 필드를 뺀 예전 형식 보고서('확인 안 됨', 참고값), update 미리보기 실행, 점수 null, 판정 네 종류와 ML 위험 점수 순서, 기지 악성 강조, 규칙 일부 실패(`적중, 실패 1개`), 폴더·lockfile이 없거나 읽을 수 없는 프로젝트, 직접·중첩 의존성, 없는 id(SQLite 범위를 넘는 id 포함) 404, 자원에 외부 URL·스크립트 없음. 보안: Host 불일치(다른 포트, 포트 없음, `localhost`, 다른 이름, 빈 값) 400, 세션 없는 GET 403(화면·CSS), 틀린 토큰·토큰 없는 로그인 403, 토큰을 쿠키로 넣어도 403, 맞는 로그인의 303·`Location: /`·쿠키 속성(HttpOnly, SameSite=Strict, Path=/, 토큰과 다른 값), POST의 세션·CSRF·Origin(없음, 다른 포트, 다른 이름, `null`, https) 거부, 큰 본문 413, 필드 수 초과 400, JSON 본문 415, GET 등록 405, 400·403·413과 정상 응답의 보안 헤더와 서버 이름 헤더 없음, 처리하지 못한 예외(이력 조회가 경로·비밀 문자열을 담은 합성 예외를 냄)는 500에 보안 헤더 네 개와 고정 문구이고 예외 내용·로그인 토큰이 본문과 헤더에 없음, uvicorn 설정(127.0.0.1, access log·server header·proxy headers 끔, warning)과 시작 줄 형식, 잘못된 `--port` 종료 코드 2. 이스케이프: `<script>`, 따옴표, `javascript:`, U+202E, U+200C, ESC, CR, lone surrogate(U+DC80)와 Markdown 적대 문자열이 든 패키지 이름·위치·상세·근거·규칙 위치·등록 경로가 화면에서 태그·속성·보이지 않는 문자로 남지 않음(모든 문자가 출력 가능 문자). 같은 문자열을 lockfile 항목 이름과 위치로 넣은 경우는 실제 경로로 등록한 프로젝트의 의존성 표에 `cli._clean`과 HTML 이스케이프를 거친 형태로 나타나는지 먼저 확인한 뒤 같은 부재 검사를 한다(R1 m1: 처음 테스트는 등록 경로를 적대 문자열로 바꾼 채 lockfile을 검사해 의존성 표를 지나지 않았다), npm 링크 인코딩(scoped 이름, 괄호·느낌표)과 잘못된 이름의 링크 없음. 등록: 정상 등록과 같은 폴더 재등록(같은 id), 상대 경로, 없는 폴더, 파일 경로, lockfile 없음, lockfile이 폴더, 빈 값, UNC·장치 경로·`/dev/`, 예약 이름(Windows), 너무 긴 경로, 공유·장치로 가는 링크(MCP 테스트의 가짜 링크), 오류에 입력을 되싣지 않음. `web` extra 없는 환경: `depbee dashboard`가 종료 코드 2와 설치 안내, traceback 없음, `plan`은 그대로 동작.
- `tests/test_dependencies.py` 3개(직접·중첩, alias, 링크, lockfile v2·v3, 루트 항목 없음, 읽을 수 없는 lockfile 다섯 가지와 없는 파일), `tests/test_output_formats.py` 5개 추가(예전 형식 보고서의 '확인 안 됨'·참고값, 연결된 분석기의 결과 누락은 실패, 현재 보고서에는 두 문구가 없음, n4 표시, 실패 칸은 개수를 붙이지 않음). 기존 테스트는 의도된 두 변경(n4 항목의 Markdown 규칙 칸, `ml` 없는 보고서의 ML 상태)만 기대값을 고쳤다. 전체 322개에서 353개, skip은 그대로 10개(`.[extract]` 미설치 4개, `.[mcp]` 미설치로 MCP 프로토콜 4개, Windows에서 만들 수 없는 LF 파일 이름 1개, POSIX 전용 1개). 대시보드 테스트는 이 환경(starlette 1.10.0, Jinja2 3.1.6, uvicorn 0.54.0, httpx2 2.16.0)에서 skip 없이 돌았다.
- 기존 명령 출력 비교(base `b9b311e`의 `src`를 `git archive`로 풀어 `PYTHONPATH`로 실행): HIST-01과 같은 13개 명령 × 세 이력 상태에서 종료 코드·stdout·stderr를 비교했다. 최상위 `--help`만 `dashboard` 하위 명령 줄 때문에 달랐고(의도된 변화, 그 줄들만 다름), 나머지는 모두 바이트가 같았다. 지금 CLI 보고서는 새 필드가 항상 있고 규칙 탐지기가 없어 '확인 안 됨'·n4 문구가 나오지 않는다. 이력 기록 수도 base·HEAD가 같았다.
- 수동 확인(이 PC, `DEPBEE_HISTORY_DB`와 HOME을 작업 폴더 아래로): 합성 프로젝트를 등록하고 `scan`을 기록한 뒤 실제 `depbee dashboard`를 띄워 표준 라이브러리 `http.client`로 확인했다. 다른 포트·`localhost` Host 400, 세션 없는 GET 403, 틀린 토큰 403, 로그인 303과 쿠키 속성, 화면 5개 200과 보안 헤더(서버 이름 헤더 없음), CSRF 없는 POST·Origin 없는 POST 403, 세션·CSRF·Origin을 갖춘 등록 303. 이 시나리오에서 서버의 stderr는 비어 있었고(접속 기록 없음) 토큰은 시작 줄 밖 어디에도 없었다. 처리하지 못한 예외의 traceback 로그는 이 수동 확인에 들어 있지 않다. 서버는 종료 신호로 멈췄고 남은 프로세스가 없었다.
- wheel: `python -m build`로 만든 wheel에 `depbee/dashboard/templates/*.html` 6개와 `static/style.css`가 들어 있고, 메타데이터에 `web` extra가 있다.
- 교차 검토 R1(major 1, minor 2): M1(쿠키가 포트를 구분하지 않아 같은 브라우저로 연 127.0.0.1의 다른 로컬 서버가 세션 쿠키를 받아 화면을 읽고 등록 POST를 보낼 수 있음)은 하람 결정으로 코드를 바꾸지 않고 받아들인 한계로 README와 [연결 규약](contracts.md) 7절에 적었다. 이를 재현하는 테스트는 없다. m1·m2는 위 테스트로 고쳤고, 복사본이 아닌 작업 폴더에서 잠시 바꿔 본 결과 의존성 표를 그리지 않거나 autoescape를 끄거나 `_clean`을 빼면 lockfile 테스트가, 500 응답에 예외 내용을 싣거나 보안 헤더를 빼면 500 테스트가 실패했다(되돌린 뒤 통과).
- 확인하지 못한 것: 실제 브라우저에서의 화면과 쿠키·Origin 동작(M1의 쿠키 전달 포함)(브라우저 자동 실행 금지라 HTTP 클라이언트로만 확인), Ctrl+C로 끝낼 때의 정상 종료 경로(수동 확인은 프로세스 종료로 멈춤), Python 3.11과 POSIX(CI에서 돌 예정), 같은 PC의 다른 포트에서 온 실제 교차 출처 요청, 대시보드와 CLI가 동시에 쓰는 실제 경합.

## 2026-11-16: 로컬 이력 저장소(HIST-01)

- 구현: `history.py`(표준 라이브러리 `sqlite3`, 위치·등록·기록·조회), `cli.main`의 `scan`·`update` 분기에서 보고서 출력 뒤 기록. 서비스 함수, `pipeline.py`, `mcp.py`, 렌더러, 도움말은 바꾸지 않았다. 형식과 규칙은 [연결 규약](contracts.md) 6절.
- 단위 테스트 `tests/test_history.py` 18개(합성 자료, 실제 npm·registry·패키지 코드 없음): 등록·기록·조회 왕복과 최근순, 새 DB의 `user_version` 1과 application_id, 더 새 버전·depbee가 만들지 않은 SQLite(버전 0에 다른 표, 버전 1에 같은 열의 `projects` 표만 있는 파일)·SQLite가 아닌 파일에 등록·기록 모두 쓰지 않음(파일 바이트 불변), 첫 등록이 트랜잭션 중 실패하면 application_id·`user_version`·표가 모두 되돌아감, lone surrogate가 든 경로와 글자 그대로 `\udc80`이 든 경로가 다른 키·id이고 한쪽만 등록하면 다른 쪽은 기록되지 않음(`resolve()` 결과를 고정해 모든 OS에서 같은 문자열로 확인), 빈 파일은 기록하지 않고 등록만 초기화, 파일이 없으면 CLI와 조회가 파일·폴더를 만들지 않음(존재 확인 뒤 파일이 사라져도 `mode=rw`가 만들지 않음), 미등록 프로젝트 미기록(DB 바이트 불변), `check`·`plan`·오류 실행(없는 기준 lockfile, 이미 있는 `--output`, 잘못된 `check` 지정)·MCP 도구 미기록, 등록한 프로젝트의 `scan`(텍스트·JSON·Markdown)과 `update` 미리보기(가짜 npm, 시간 고정) 기록 시 stdout·stderr·종료 코드가 기록 없는 실행과 바이트 같음, 기록 실패 다섯 가지(다른 연결이 잠금, 읽기 전용 파일, 손상 파일, 더 새 버전, 다른 DB)에서 stdout·종료 코드가 같고 stderr는 고정 문구 한 줄, 판정 네 종류의 개수와 점수(null 유지), lockfile에서 온 lone surrogate(U+DC80) 위치, 경고를 모두 켠 상태에서 `ResourceWarning` 없음과 실행 뒤 DB 파일 삭제 성공(Windows), 빈 `DEPBEE_HISTORY_DB`는 홈 기준 위치, 홈 폴더를 정하지 못하면 CLI 기록만 건너뜀, 같은 폴더를 다른 경로 표기(`..`, Windows 대소문자)로 등록해도 한 프로젝트. 기존 테스트의 `Fixture`는 `DEPBEE_HISTORY_DB`를 실행 폴더 안 경로(파일 없음)로 둔다. 기존 304개의 결과는 이 변경 전후 같다. 전체 304개에서 322개, 이 환경의 skip 10개(`.[extract]` 미설치 4개, `.[mcp]` 미설치로 MCP 프로토콜 4개, Windows에서 만들 수 없는 LF 파일 이름 1개, POSIX 전용 1개).
- 보호를 하나씩 깨뜨린 확인(복사본에서): lone surrogate 변환 제거, 파일 존재 확인 제거, `mode=rwc`로 열기, 연결 닫기 제거, CLI가 `OSError`만 잡기, 실패 문구 제거, 미등록 프로젝트 확인 제거, 프로젝트 키를 되돌릴 수 없는 표시 변환으로 만들기, application_id 확인 제거, 새 DB에 application_id 설정 제거는 각각 테스트가 실패했다. 쓰기 트랜잭션 안의 버전 재확인 제거는 잡히지 않는다(읽기 확인과 쓰기 사이에 다른 프로세스가 버전을 바꾸는 경합 방어라 단위 테스트로 재현하지 않음).
- 기존 명령 출력 비교(base `5330689`의 `src`를 `git archive`로 풀어 `PYTHONPATH`로 실행, import 위치 확인): plan, scan 텍스트·JSON·Markdown, `--base-ref HEAD`(합성 Git 저장소), scan 오류, check 오류, 최상위와 plan·scan·check·update·mcp 도움말 13개의 종료 코드·stdout·stderr를 세 상태에서 비교했다. (a) 이력 파일 없음(HOME·USERPROFILE을 빈 임시 폴더로, `DEPBEE_HISTORY_DB` 없음): 모두 바이트가 같고 임시 홈에 파일이 생기지 않았다. (b) 다른 프로젝트만 등록한 이력 파일: 모두 같고 기록 수와 파일 바이트가 그대로였다. (c) 두 프로젝트를 등록: 모두 같고 scan 4개만 하나씩 기록이 늘었다. 이번 변경은 도움말을 바꾸지 않아 최상위 도움말도 같다.
- 확인하지 못한 것: Python 3.11(이 PC에는 3.13만 있음, CI에서 돌 예정), POSIX에서의 읽기 전용 파일 테스트(root로 실행하면 쓰기가 성공할 수 있음), 대시보드와 CLI가 동시에 쓰는 실제 경합, Defender가 근거 문자열이 든 DB를 탐지하는지.

## 2026-11-15: 업데이트 미리보기 재검토 후속(UPD-01 fix_r2)

- npm 버전 조회의 상위 workspace: npm은 `--version`에도 설정을 먼저 읽어 상위 workspace를 찾는다(npm 11.6.1 `lib/npm.js` 99·132-136행, `@npmcli/config/lib/index.js` 685-743행). 이제 `--version`에도 update와 같은 `--prefix`·`--workspaces=false`·`--git`을 준다. `TMP` 폴더에 `workspaces: ["*/project"]`인 `package.json`을 두고 그 아래 `demo/project`에 정상 데모 사본(이름 `depbee-demo-benign`)을 둔 뒤 `TMP`를 그 폴더로 하고 실제 `depbee update`를 실행하면, 수정 전 코드(d977b1f)는 npm `--version`이 종료 1(stderr에 "must not have multiple workspaces with the same name", `@npmcli/map-workspaces` 132-167행의 EDUPLICATEWORKSPACE)로 끝나 `Cannot read the npm version (exit code 1)`, 종료 코드 2였다. 수정 뒤에는 두 npm 호출 모두 종료 0, `depbee update` 종료 0, 바뀐 항목 5개, 새 lockfile `1c9fa3a5...`(앞의 확인과 같음)였고, 두 경우 모두 상위 `package.json`과 원본 사본의 해시가 그대로, 상위 lockfile 없음, `depbee_preview_*` 0개였다.
- Git 호스트 커밋 의존성: update 중 새로 받은 패키지가 Git 호스트 커밋(40자 sha)에 의존하면 pacote는 Git 없이 호스트 tarball을 npm 캐시 임시 폴더에 풀고, 준비용 script나 `workspaces`가 있으면 그 폴더에서 `npm install --force ... --no-package-lock-only --no-dry-run`을 실행할 수 있다(pacote 21.0.3 `lib/git.js` 43-50·152-188·193-248·297-310행, `lib/fetcher.js` 98-120행, `lib/util/npm.js` 4-13행). 하람 결정으로 막지 않는 알려진 예외로 두고 README·연결 규약·모듈 설명에 적었다. 상속된 `npm_config_ignore_scripts=true`와 `npm_config_git`으로 script와 Git이 실행되지 않는다는 판단은 소스만 읽은 것이고 실행하지 않았다.
- 파일로 읽히는 값: npm-package-arg 13.0.0 `lib/npa.js` 17행의 `/[.](?:tgz|tar.gz|tar)$/i`는 가운데 점이 아무 문자라 `x.tarXgz`도 파일로 본다(111-112행). depbee도 같은 정규식(문자열 끝, 대소문자 무관)을 쓰고, 제어 문자(C0, DEL)가 든 값도 거부한다. 직접 의존성, `overrides`, lockfile 항목에 함께 적용된다.
- 임시 폴더를 만들지 못하면 경로 없는 고정 오류(`The temporary preview folder could not be created (OSError)`)다. 원본 입력 읽기 오류는 그대로다.
- Windows Job에 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`를 설정한다(`SetInformationJobObject`, `JobObjectExtendedLimitInformation`). 구조체는 ctypes로 정의해 64비트 144바이트, `LimitFlags` 오프셋 16을 테스트로 확인했다(32비트 112바이트는 계산값, 실행하지 않음). 합성 Python 부모·손자를 Job에 넣고 `TerminateJobObject` 없이 핸들만 닫으면 둘 다 끝났다(venv와 기본 인터프리터). 설정에 실패하면 일시 정지된 자식을 죽이고 오류다. `NtResumeProcess`는 문서화되지 않은 ntdll API이고 psutil의 `Process.resume()`도 같은 함수를 쓴다(`psutil/arch/windows/proc.c`). Windows 11 64비트에서만 확인했다.
- 단위 테스트 `tests/test_update.py` 34개(3개 추가, 기존 2개 확장): 버전 조회 argv의 고정 옵션, 파일형 값과 제어 문자 12가지 거부와 허용 형태, 임시 폴더 생성 실패의 세 출력 형식, Job 플래그와 핸들 닫힘 종료, Job 설정 실패. mock 호출 표시에 환경 변수가 나오지 않게 npm 미실행 단언은 호출 수만 비교한다. 새 보호 10가지를 하나씩 깨뜨리면 9가지가 테스트 실패로 잡혔고, 남은 하나(`\Z`를 `$`로)는 제어 문자 검사가 먼저 끝 줄바꿈을 막아 결과가 같다. 전체 304개, skip 6개.
- 확인하지 못한 것: Git 호스트 커밋 의존성의 실제 준비 설치, 32비트 Windows와 다른 Windows 버전, POSIX 프로세스 그룹(CI에서 돌 예정), npm 12.

## 2026-11-15: 업데이트 미리보기 검토 후속(UPD-01 fix_r1)

- 상위 workspace(M1): npm은 가장 가까운 `package.json`을 찾은 뒤에도 위 폴더의 `workspaces`를 조사해, 임시 폴더가 그 패턴에 맞으면 그 위 폴더를 작업 폴더로 쓴다(npm 11.6.1 `@npmcli/config/lib/index.js` 702-743행). 이제 npm에 `--prefix=<임시 폴더 절대 경로>`(685-690행, CLI prefix면 탐색하지 않음)와 `--workspaces=false`(708-710행)를 준다. 정상 데모 사본을 `workspaces: ["*/project"]`인 합성 상위 폴더 아래 `depbee_preview_x/project`에 두고 실행하면, 수정 전 코드(06be78f)는 상위 폴더에 `package-lock.json`을 새로 만들고 사본의 lockfile은 그대로 두었다(depbee는 바뀐 것 0개로 보였을 것이다). 수정 뒤에는 상위 폴더에 아무 파일도 생기지 않고 사본의 lockfile만 바뀌었다(`1c9fa3a5...`, 앞의 확인과 같음). `TMP`를 같은 합성 상위 폴더로 둔 실제 `depbee update`도 종료 코드 0, 바뀐 항목 5개, 상위 `package.json` 해시 불변, 상위 lockfile 없음이었다.
- Git 실행 경로(M2): Arborist는 `overrides` 값과 lockfile 항목의 의존성 값을 새 트리를 계산할 때 다시 해석하고, Git 값이면 pacote가 `@npmcli/git`으로 Git을 실행한다(`build-ideal-tree.js` 380-392·1051-1052·1200-1215행, `edge.js` 205-228행, `pacote/lib/git.js` 102-109·292-310행). 이제 `overrides`(중첩 포함)의 값은 registry 버전·범위·태그 또는 루트 의존성 참조(`$이름`), 키의 범위 부분도 같은 기준이어야 하고, lockfile 항목의 `dependencies`·`optionalDependencies`·`peerDependencies`·`devDependencies` 값도 같은 기준이어야 한다. 직접 의존성 검사에 `..`처럼 `.`으로 시작하는 값과 `.tgz`·`.tar`로 끝나는 값(npm-package-arg가 파일로 읽음, `npa.js` 17·19·111행)을 더했다. 추가 방어로 npm에 `--git=<임시 폴더 안의 없는 파일>`을 준다. `@npmcli/git/lib/which.js` 10-13행은 이 설정을 그대로 실행 파일로 쓰고, npm은 CLI 설정을 하위 npm의 환경 변수로 넘긴다(`set-envs.js` 48-90행, 환경은 프로젝트 `.npmrc`보다 우선). 정상 데모 사본의 `ms`를 `git+https://example.invalid/ms.git`으로 바꾼 사본(지원 범위 검사는 일부러 건너뜀)에서 npm은 그 없는 파일의 ENOENT로 실패했고 `example.invalid` 이름 조회(ENOTFOUND)는 없었으며 lockfile은 그대로였다. Git 호스트의 커밋을 정확히 가리키는 의존성은 pacote가 Git 없이 그 호스트의 tarball로 받을 수 있어(`git.js` 228-260행) 이 방어 밖이다.
- 후손 프로세스(M3): npm 실행만 `_run(tree=True)`로 바꿨다. Windows는 자식을 `CREATE_SUSPENDED`로 만들어 Job Object에 넣은 뒤 `NtResumeProcess`로 시작하고, POSIX는 `start_new_session`과 `os.killpg`를 쓴다. 시간 초과·출력 상한·정상 종료 모두 남은 프로세스를 죽이고 끝난 것을 확인한 뒤 돌아오며, 10초 안에 끝나지 않으면 오류다. 처음에는 자식을 만든 뒤 Job에 넣었는데, venv의 `python.exe`처럼 곧바로 실제 프로세스를 띄우는 wrapper는 그 전에 손자를 만들어 Job 밖에 남았다(합성 테스트에서 재현). Git 호출은 바뀌지 않았다.
- 오류의 임시 경로(m4)와 안내 문구(m5): 임시 폴더 안 파일의 쓰기·읽기·파싱·검사 오류는 경로 없는 고정 문구로 바꾸고, 임시 폴더를 지우지 못하면 숨기지 않고 오류로 낸다. `.npmrc` 안내는 "프로젝트 .npmrc는 복사하지 않았습니다. 사용자·전역 npm 설정은 적용될 수 있습니다."로 고쳤다. `--prefix`를 CLI로 주면 npm은 전역 설정 파일 기본 위치도 `<prefix>/etc/npmrc`로 옮기므로(`@npmcli/config/lib/index.js` 296-303행) 기본 위치의 전역 npmrc는 이 미리보기에서 읽히지 않을 수 있다.
- 단위 테스트 `tests/test_update.py` 31개(12개 추가): argv의 `--prefix`·`--workspaces=false`·`--git` 고정, `overrides` 거부 20가지와 허용 형태, lockfile 항목 의존성 값 거부, 파일로 읽히는 값 8가지, 깨진·없는 새 lockfile과 복사 실패 오류에 임시 경로 없음(JSON·텍스트·Markdown, 모든 오류 테스트에서 `depbee_preview_` 없음 확인), 다른 경로의 오류는 유지, 임시 폴더 삭제 실패는 오류, 합성 Python 부모·손자(심장 박동 파일)로 시간 초과 뒤와 정상 종료 뒤 손자 종료(venv와 기본 인터프리터 둘 다), Job 지정을 1초 늦춰도 손자가 Job 안에 있음, 종료 확인 실패는 오류. 새 보호 14가지를 하나씩 깨뜨리면 각각 테스트가 실패했다. 전체 301개, skip 6개.
- 확인하지 못한 것: POSIX의 프로세스 그룹 종료(코드만 있고 이 PC에서 실행하지 않음, CI에서 돌 예정), 사용자·전역 npmrc가 있는 환경, Git 호스트 tarball 경로의 실제 동작, npm 12.

## 2026-11-15: 업데이트 미리보기(`depbee update`, UPD-01)

- npm 동작(client-dev 7절)을 Windows 11, node v24.11.0, npm 11.6.1에서 정상 패키지만 쓰는 데모(lodash `^4.17.15`, ms `^2.1.1`, semver `^7.5.0`, lockfile v3, OSV 2026-10-06 스냅샷에 세 이름과 중첩 의존성 lru-cache·yallist의 `MAL-` 기록 없음)의 임시 사본에서 확인했다. 모든 실행은 `node.exe npm-cli.js update --package-lock-only --ignore-scripts ...`이다.
  - `node_modules`를 만들지 않고 `package-lock.json`만 바뀌며 `package.json`은 그대로였다. 빈 npm 캐시로 실행하면 캐시에 packument 3개만 생기고 tarball(`.tgz`) 항목은 없었다.
  - 이름 없이 실행하면 범위 안 최신으로 모두 올리고(lodash 4.18.1, ms 2.1.3, semver 7.8.6, semver 7.6부터 의존성이 없어 lru-cache·yallist 삭제), `-- ms`는 ms만 올렸다. `semver ~7.5.0`으로 바꾼 사본에서는 7.8.6이 있어도 7.5.4까지만 올렸다.
  - 업데이트할 것이 없을 때 다시 실행하면 lockfile 바이트가 그대로였다(`lockfileVersion` 3 유지).
  - `--` 뒤의 없는 이름, `--save`, `-x`는 이름으로 처리돼 종료 코드 0에 아무 변화가 없었다(npm이 알리지 않으므로 depbee가 실행 전에 이름을 검사한다). `lodash@4.17.21`은 `EUPDATEARGS`, 종료 코드 1이었다.
  - `--no-audit`은 audit 요청을, `--no-update-notifier`는 npm 버전 확인 요청과 캐시 폴더 위 상태 파일을 없앴다. `--no-fund`·`--no-progress`·`--color=false`는 TTY가 아닌 이 실행에서 차이가 보이지 않았지만 출력이 사용자 설정에 따라 바뀌지 않게 둔다.
  - `--ignore-scripts` 없이 실행해야 보이는 동작은 실행하지 않고 소스로 확인했다. `npm install`(인자 없음)은 `--package-lock-only`여도 루트 `preinstall`~`postprepare`를 실행한다(`lib/commands/install.js` 150-170행, 조건에 `packageLockOnly` 없음). `npm update`에는 루트 script 실행이 없고(`lib/commands/update.js`), arborist는 `packageLockOnly`이면 패키지를 풀거나 rebuild하지 않는다(`reify.js` `[_reifyPackages]`, `[_diffTrees]`). npm 12의 의존성 script 기본 차단은 GitHub Changelog(2026-06-09)로만 확인했고 실행하지 않았다.
- 구현: `inputs/npm_cli.py`(지원 범위 검사, 이름 검사, node와 npm-cli.js 직접 실행, 환경 정리, 실행 뒤 `node_modules` 확인), `service.preview_update`, CLI `depbee update`. Git 실행기 `inputs/git.py`의 `_run`은 시간 제한·stderr 상한·이름을 인자로 받게 일반화했고 Git의 값과 오류 문구는 그대로다.
- 단위 테스트 `tests/test_update.py` 19개(npm 실행기를 가짜로 바꿈, 실제 npm·Node.js·registry를 쓰지 않음): argv(`node`, `npm-cli.js`, 고정 옵션 뒤 `--`, 이름), 환경(`npm_config_*` 대소문자 무관 제거, `NODE_OPTIONS` 제거, `npm_config_ignore_scripts=true`), 시간·출력 상한 인자, 이름 거부 24가지와 `package.json`에 없는 이름, 지원 범위 거부(Git·file·http·다른 registry·링크·resolved 없음·workspace 항목, Git·파일·alias 의존성 값, `workspaces`, `npm-shrinkwrap.json`, `package.json` 없음), `.npmrc` 미복사와 안내(텍스트·Markdown·JSON에 내용 없음), npm 실패·시간 초과·OSError·`node_modules` 생성·깨진 새 lockfile·이상한 버전 출력 → 종료 코드 2(오류에 npm 출력 없음), 모든 경우 원본 프로젝트 파일 해시 불변과 임시 폴더 삭제, preview 해시, 바뀐 것 없음 → 종료 코드 0, 보고서가 같은 lockfile의 `scan_project(extract=True)`와 시간 필드 밖에서 같음, node 탐색(`.exe` 아님, 상대 경로, 없음, `npm-cli.js` 없음), 일반화한 `_run`의 시간 제한·이름. 구현의 9가지 핵심 줄(`--`, 환경 제거, 이름 검사, 의존성 확인, `node_modules` 확인, 종료 코드 확인, `.npmrc` 미복사, workspaces 거부, ignore_scripts 강제)을 하나씩 깨뜨리면 각각 테스트가 실패했다. 전체 270개에서 289개, skip 6개(`.[extract]` 미설치 4개, Windows에서 만들 수 없는 LF 파일 이름 1개, POSIX 전용 1개).
- 수동 확인: 데모 임시 사본에서 실제 npm·registry와 D04-E00으로 `depbee update --project <사본> --model-dir models/d04-e00`을 실행했다. 이 worktree 환경에는 `.[extract]`가 없어 메인 checkout의 `.venv`(Python 3.13.5, lightgbm 4.7.0, feature-extractor 편집 가능 설치 `f9a9042`, 고정 커밋 `c24761d`가 아님)를 `PYTHONPATH`로 이 worktree의 `src`에 연결해 실행했다(그래서 provenance의 feature-extractor는 null이고 캐시를 쓰지 않음). 결과: 종료 코드 0, 바뀐 항목 5개(통과 3: lodash 4.18.1, ms 2.1.3, semver 7.8.6, 모두 ML 위험 점수 0.000, 삭제 2: lru-cache, yallist), npm 11.6.1, `package.json` 변경 없음, 새 lockfile sha256이 위 npm 확인과 같음(`1c9fa3a5...`), 전체 약 7.7초(검사 6.5초). `ms`만 지정하고 합성 `.npmrc`(설정 없음)를 둔 사본은 바뀐 항목 1개와 `.npmrc` 미적용 안내가 Markdown에 나왔다. `lodash@4.18.1`과 `package.json`에 없는 이름은 npm 실행 없이 종료 코드 2였다. 두 사본 모두 실행 전후 `package.json`·`package-lock.json` 해시가 같고 `node_modules`가 없으며 `depbee_preview_*` 임시 폴더가 남지 않았다. semver 7.8.6은 OSV 스냅샷(2026-10-06) 뒤 배포(2026-11-02)라 스냅샷으로 확인하지 못했다.
- 확인하지 못한 것: npm 12, macOS·Linux의 `npm-cli.js` 위치, 고정 커밋 feature-extractor로의 수동 실행, 사설 registry·사용자 `~/.npmrc`가 있는 환경, 반영(`apply_update`)은 설계만 했다([연결 규약](contracts.md) 5.1절).

## 2026-11-14: GitHub Action의 판정·주석·summary(SVC-06)

- `action.yml`(composite)과 판정 모듈 `src/depbee/actions.py`를 더했다. 판정은 보고서의 항목별 `known_malicious.status`, `ml.status`, `status`로만 하고 최상위 `exit_code`는 쓰지 않는다. 기지 악성 일치만 기본 실패, ML 기준 이상·보류는 기본 경고이고 `fail-on`으로 실패를 고른다. 입력 오류, sha256 불일치, 설치 실패, 변경 수 초과, 보고서 없음은 실패다. 사용법과 규칙은 `docs/ci-cd.md`에 있다.
- 단위 테스트 `tests/test_actions.py` 19개: 기지 악성 일치 실패(낮은 ML 점수로 취소되지 않음), ML·보류 기본 경고와 `fail-on` 실패, 최상위 `exit_code` 미사용, 보고서 없음·깨진 JSON·필드 누락·알 수 없는 `fail-on` 실패, 적대적 패키지 이름(줄바꿈, `%`, `::`, 제어 문자)과 속성값(`:`, `,`)의 이스케이프, lockfile 줄 찾기(scoped 이름, 중첩 `node_modules`, 못 찾으면 파일 단위, lockfile 없음), summary 순서, 입력 검사, sha256 불일치, 변경 수 상한. 전체 255개 통과, skip 8개(이 worktree `.venv`에 `[mcp]`·`[extract]`가 없어 MCP 프로토콜 4개와 고정 loader 4개), `ruff check` 통과.
- 로컬(Windows, Git Bash, Python 3.13.5)에서 확인: CI `action` job의 bash 본문을 그대로 실행해 기대 종료 코드 10가지가 모두 맞음. `report` 입력 경로의 입력 검사·판정·summary. 실제 CLI(`depbee scan examples/project --base-lock ... --format markdown --output`, 모델 없음)가 보류와 종료 코드 2를 내고, 판정은 기본 경고(성공), `fail-on incomplete`는 실패이며 주석이 `package-lock.json` 6번째 줄(`"node_modules/example-package":`)에 붙음. 보고서 경로가 없으면 실패. 기준 커밋 없이(`pull_request` 밖) 실행하면 입력 오류로 실패.
- 검토 후속(REV-SVC06-R1 F1): 입력 검사는 `\`를 `/`로 바꿔 파일을 확인했지만 셸 단계는 원래 값을 Linux `dirname`에 넘겨, `app\package-lock.json`은 루트(`.`)를 검사했고 `-app/package-lock.json`은 `dirname`이 옵션 오류로 빈 값을 내 depbee가 현재 폴더를 검사할 수 있었다(인자 안 명령 치환의 실패는 `bash -e`로 멈추지 않음). 이제 입력 검사가 `lockfile`·`report`의 `\`와 `-`로 시작하는 경로 구성 요소를 거부하고, 셸은 `dirname --` 결과를 변수에 받아 실패하거나 비면 depbee를 실행하지 않는다. 새 회귀 1개(5가지 거부, 루트와 `app/` 정상)를 수정 전 코드에 붙이면 실패 5개다. CI `action` job에 같은 입력 3가지의 기대 종료 코드를 더했다. Git Bash의 `dirname`은 `\`도 구분자로 보아 재현 A의 Linux 동작은 로컬에서 재현하지 못했다.
- 재검토 후속(F2): 이름 끝에 실제 LF가 붙은 폴더(`app<LF>/package-lock.json`)는 입력 검사를 통과했지만 `$(dirname -- ...)`가 끝의 줄바꿈을 지워 `app`이 되고, 같은 이름의 일반 폴더가 있으면 plan·scan이 그 폴더를 조용히 검사할 수 있었다. 이제 입력 검사가 `lockfile`·`report`에서 제어 문자(U+0000~U+001F, DEL)가 든 경로를 파일 확인 전에 거부한다. 새 회귀 2개 중 공통 테스트(6가지 거부)를 수정 전 코드에 붙이면 실패 6개다. LF 폴더와 일반 폴더를 함께 만드는 테스트는 Windows 파일 이름에 LF를 쓸 수 없어 POSIX에서만 돈다(CI `checks` job의 ubuntu). CI `action` job에 LF 입력 1가지의 기대 종료 코드를 더했다.
- 확인하지 못한 것: depbee 설치(feature-extractor 비공개), Release 모델 다운로드(Release 없음), `--extract` scan, 캐시 저장·복원, summary의 실제 화면, `actionlint`(설치돼 있지 않아 YAML 파싱만 함), Windows·macOS runner. GitHub runner 실행은 push 뒤 depbee CI의 `action` job(`uses: ./`, `report` 입력 자기 검사)으로 확인했다. main `d3445b0`의 CI run에서 이 job이 성공해 입력 검사, 판정, 경고 주석 명령 출력, artifact 업로드까지 runner에서 돌았다(DEMO-01 기록 참고). GitHub 화면에서 그 주석을 사람이 본 것은 아니다.

## 2026-11-07: PR #8 Revy minor 후속(pr8_round2)

- integrity가 있으면 옛 shasum으로 넘어가지 않는다(Revy minor 1). `verify`는 지원 알고리즘 값을 하나도 찾지 못하면 `dist.shasum`을 썼기 때문에, `dist.integrity`가 `md5-...`, 빈 문자열, 숫자처럼 쓸 수 없는 값이어도 sha1 shasum이 맞으면 통과했다. 이제 shasum은 `dist`에 `integrity` 키가 없을 때만 쓴다. 키가 있으면 null이어도 integrity로 보고, 문자열이어야 하며 sha512·sha384·sha256·sha1 값이 하나 이상 있어야 하며, 그중 가장 강한 알고리즘이 판정한다(지원하지 않는 알고리즘이 섞여 있으면 무시하는 것은 전과 같다). 그렇지 않으면 분석 실패다. npm(pacote 21.0.3 `lib/registry.js`)은 JavaScript 참거짓으로 판단해 빈 문자열, `false`, null도 integrity가 없다고 보고 shasum으로 넘어가지만, depbee는 이런 값도 있는 값으로 보고 실패로 둔다. 새 회귀: 맞는 shasum이 있어도 쓸 수 없는 integrity 9가지(md5, 빈 문자열, 공백, sha3, 숫자, false, 배열, 객체, null)는 거부, 지원 알고리즘 값이 있으면 shasum과 관계없이 그 값으로 판정, 키가 없을 때만 shasum으로 판정. 첫 구현(`95cd9ca`)은 null을 키가 없는 것과 같이 보아 shasum으로 넘겼고, Sol의 round 2 재리뷰가 승인 계약(존재하는 integrity는 fallback 없음) 위반으로 지적해 고쳤다. 처음 회귀 8가지를 수정 전 코드(`baf28a4`)에 붙이면 모두 통과해 실패 8개, null 경우를 `a6664e8`에 붙이면 실패 1개다.
- 거부한 URL은 오류에 scheme과 host만 쓴다(Revy minor 2). registry 밖 주소 거부(요청 주소, redirect 대상, 마지막 응답 주소)와 tarball 주소 불일치 오류가 URL 앞 200자를 그대로 넣어, 그 안의 사용자 정보·경로·query·fragment(자격 증명이나 서명 토큰이 들 수 있다)가 JSON·Markdown·텍스트 보고서의 `detail`에 남았다. urllib이 http·https·ftp가 아닌 scheme으로의 redirect를 스스로 거부할 때 내는 `HTTPError`의 문구도 대상 URL 전체를 담아 `Cannot download <주소>: <오류>`로 전해졌다. 이제 거부한 URL은 `https://evil.test (scheme and host only)`처럼 scheme과 host(포트 포함, 사용자 정보 제외)만 쓰고, 절대 URL로 읽을 수 없는 값이면 그렇다고만 쓴다. 다운로드 오류는 서버나 다른 URL에서 온 문구를 옮기지 않는다. HTTP 오류는 `HTTP 404`처럼 상태 코드만(3xx는 `HTTP 302, redirect not followed`), 그 밖에는 오류 종류와 이 컴퓨터의 OS 오류 번호·문구만 쓴다(`gaierror [Errno 11001] getaddrinfo failed`, `TimeoutError`, `BadStatusLine`). 주소를 읽을 수 없는 값(urlsplit이 거부하는 값)도 `_check_url`은 같은 거부 문구로 끝낸다.
- 첫 구현(`4031f31`)은 3xx만 상태 코드로 바꾸고 나머지 오류 문구와 URL 파싱 오류를 그대로 옮겼다. Sol의 round 2 재리뷰(R2)가 합성 표식으로 세 경로를 재현했다. (1) 서버의 상태 사유 문구(`HTTP/1.1 404 Missing <URL>`)가 `HTTP Error 404: Missing <URL>`로, (2) 잘못된 상태 줄이 `BadStatusLine`의 문구로 `detail`에 남았다(실제 http.client가 합성 응답 바이트를 해석, 실제 자식 프로세스 경유). (3) NFKC 정규화로 바뀌는 host(전각 `／` 등)가 든 메타데이터의 tarball 주소는 `urlparse`의 ValueError가 netloc 전체(사용자 정보 포함)를 담아 CLI 오류 JSON으로 나갔다. 이제 (1)(2)는 위 규칙으로, (3)은 입력 검사(`inputs/npm.py`)가 `The tarball URL of <이름>@<버전> cannot be parsed` 입력 오류(오류 JSON, 종료 코드 2, 전과 같은 분류)로 끝내며 lockfile의 `resolved`도 같다. 실제 HTTP 헤더는 ISO-8859-1로 읽히고 그 범위의 문자는 NFKC로 `/?#@:`가 되지 않아(Python 3.13.5, Unicode 15.1에서 확인) redirect의 `Location`으로는 (3)이 생기지 않는다.
- 오류 경로를 다시 확인했다. 남는 URL은 depbee가 만든 registry 주소(메타데이터 `https://registry.npmjs.org/<이름>`, tarball 경로)뿐이다. host가 정확히 `registry.npmjs.org`여야 받으므로 사용자 정보가 들어갈 수 없고, 경로는 lockfile이나 명령의 패키지 이름·버전에서 온다. lockfile과 `check`의 registry 출처 거부는 원래 URL을 쓰지 않는다. 고정 feature-extractor의 LoaderError 중 URL을 담는 것은 그 자체 다운로드 경로인데 depbee는 그 경로를 쓰지 않는다. 자식 프로세스의 오류는 같은 문구를 그대로 전한다. 압축 해제 오류(`Cannot unpack ...`)는 tarball 안의 이름 등 패키지 자료를 담을 수 있으나 URL은 아니며 이번 범위에서 바꾸지 않았다.
- 새 회귀는 합성 표식 문자열을 쓴다. 단위: 표식을 사용자 정보·경로·query·fragment에 넣은 URL 4가지를 주소 검사와 redirect handler가 거부하고, tarball 주소 9가지(같은 host의 query, scheme 없는 값, IPv6 괄호가 닫히지 않은 값, 문자열이 아닌 값 포함)가 불일치로 거부될 때 오류 문구가 정확히 scheme과 host만 담는다. 소켓 없이 실제 urllib opener와 redirect handler를 거치는 다운로드(HTTPS 연결만 대체)에서 다른 scheme과 다른 host로의 redirect가 표식 없이 거부되고, registry 안의 redirect는 따라가며 404는 `HTTP 404`다. `check` 명령: 비교 기준 tarball 주소, 새 버전 tarball 주소의 query, 다른 host로의 redirect, urllib이 거부하는 redirect 4가지에서 JSON과 Markdown 출력 모두 표식이 없고 `detail`이 정해진 문구이며 종료 코드 2다. 이 회귀를 수정 전 코드(`baf28a4`)에 붙이면 모든 경우가 표식을 내보내 실패 27개다. R2 회귀: 실제 http.client가 해석하는 합성 응답 바이트(상태 사유, 잘못된 상태 줄, 알 수 없는 protocol)와 그 밖의 전송 오류 6가지의 문구가 정확히 정해진 값이고, NFKC host는 주소 검사·redirect handler·tarball 불일치에서 거부 문구로 끝나며, `check`의 JSON·Markdown(상태 사유, 잘못된 상태 줄), 메타데이터 NFKC 주소의 오류 JSON(두 형식), lockfile NFKC 주소의 `plan`·`scan` 오류 JSON 어디에도 표식이 없다. 이 회귀를 `a6664e8`에 붙이면 실패 18개와 오류 2개다.
- 캐시 hit의 feature 키 순서를 추출 때와 같게 했다(Revy minor 3). 캐시는 항목을 `sort_keys=True`로 저장해, warm 실행의 `features`가 알파벳 순서가 되어 cold 실행의 JSON 출력과 바이트가 달랐다(값은 같았다). 이제 항목은 키 순서를 그대로 저장하고 읽으므로 feature-extractor가 낸 순서가 유지된다. 이미 있던 형식 1 항목은 정렬된 순서를 담고 있어 캐시 형식(`cache.FORMAT`)을 2로 올렸다. 형식 1 항목은 형식 검사에서 miss가 되어 다시 추출한다. 캐시 파일의 경로는 키를 정렬해 만든 해시라 이 변경과 관계없다. 새 회귀: `check`를 같은 캐시 폴더로 두 번 실행한 JSON 출력을 줄 단위 원본 그대로 비교해, 다른 줄은 `elapsed_seconds`와 `cache_hit` 줄뿐이고(`cache_hit`는 false에서 true로) `features` 블록은 바이트가 같으며 키 순서가 추출 순서와 같다. `scan --extract` 경로(서비스 함수)의 cold/warm도 키 순서가 같다. 이 회귀를 수정 전 코드(`baf28a4`)에 붙이면 실패 2개다(warm의 `features` 블록이 정렬된 순서).
- 캐시 무효화 정책(Revy minor 4). 키에 depbee 자신의 버전이 없어, depbee의 다운로드·압축 해제·feature-extractor 호출이 바뀌어도 이전 depbee가 만든 feature를 다시 썼다. 이제 키에 `depbee.__version__`(CLI `--version`과 같은 값)이 들어가 depbee 버전이 바뀌면 모든 항목이 miss다. 코드 해시나 자동 추적은 하지 않는다. 같은 버전 안에서 저장 항목이나 추출 결과를 바꾸는 변경(개발 중 커밋, 배포 전 수정)은 `cache.FORMAT`을 개발자가 직접 올려야만 무효화되며, 이를 감지하는 장치는 없다(`cache.py`의 FORMAT 주석에 같은 규칙을 적었다). feature-extractor 쪽은 전과 같이 설치 출처(고정 커밋, 설치 파일 해시, Python 버전)로 키가 바뀐다.
- 이번 PR의 이전 항목: round 1의 symbolic link 정책(`baf28a4`)은 symbolic link 권한이 없는 Windows에서 추출 결과를 바꿀 수 있는데 버전과 형식은 그대로였다. `4aa005f`와 `baf28a4`의 캐시 코드는 같고 둘 다 형식 1, depbee 버전 없는 키로 쓴다. 이번에 형식을 2로 올렸고 키에 버전이 더해져, 그 항목은 경로부터 달라 읽지 않는다. 지우지도 않는다. 실제 확인: `baf28a4` 코드로 합성 `check`를 실행해 항목을 쓴 폴더를 이 코드로 다시 쓰면 첫 실행이 miss(추출 1회)이고 이전 항목은 바이트 그대로이며, 그 뒤 `baf28a4` 코드는 자기 항목을 그대로 hit한다(합성 backend와 모델, 네트워크 없음).
- 새 회귀: hit 상태에서 depbee 버전만 바꾸거나 `cache.FORMAT`만 올리면 다시 추출하고 그다음은 hit이며, 원래 값으로 돌아오면 원래 항목이 hit이고 이전 항목은 남는다. `baf28a4`가 쓰던 그대로의 항목(형식 1, 버전 없는 키, 같은 쌍, 다른 feature 값)이 있는 폴더에서는 그 항목을 쓰지 않고 다시 추출하며 그 파일은 바뀌지 않는다. 이 회귀를 수정 전 코드에 붙이면 오류 1개(버전 값이 모듈에 없음)와 실패 2개(이전 항목을 그대로 씀)다.
- 캐시 읽기는 일반 파일만 읽는다(Revy minor 5). 캐시 읽기는 자식 프로세스가 아닌 부모에서 하는데, 항목 경로에 FIFO가 있으면 일반 `open()`이 쓰는 쪽을 기다리며 멈추고 부모도 함께 멈춘다. 이제 항목은 `O_NONBLOCK`을 더해 열고(Linux·macOS의 FIFO는 쓰는 쪽 없이 바로 열린다), 연 descriptor 자체를 `fstat`해 일반 파일이 아니면(FIFO, 장치, socket 등) 읽지 않고 miss로 둔다. 검사와 읽기가 같은 descriptor라 그 사이에 파일이 바뀌는 경우가 없고, descriptor는 모든 경우에 닫힌다(`open(opener=...)`이라 Python이 Windows의 `O_BINARY`·상속 금지 등 평소 플래그를 그대로 준다). Windows에는 `O_NONBLOCK`이 없어 여는 방식이 전과 같고, 일반 파일 검사만 더해진다. 일반 파일의 읽기는 `O_NONBLOCK`과 관계없이 동작한다.
- 남는 제한: 응답하지 않는 NFS(hard mount)나 아주 느린 디스크에서는 `open`, `fstat`, `read`와 캐시 쓰기의 `mkdir`, 임시 파일 쓰기, `os.replace` 같은 OS 동기 호출 자체가 멈출 수 있고, 이것은 부모에서 끊을 수 없다. 늦게 끝난 결과는 전과 같이 예산 확인에서 거부되지만 그 호출이 끝날 때까지 기다린다. 캐시 폴더는 로컬 디스크에 두기를 권한다.
- 새 회귀는 실제 FIFO를 만들지 않는다(고장 나면 시험이 멈추기 때문). 실제 os.open을 감싸 항목을 열 때 `O_NONBLOCK`(있는 플랫폼)과 `O_BINARY`(Windows)가 전달되는지, 연 descriptor를 FIFO·문자 장치·socket으로 알리도록 `os.fstat`을 바꾸면 내용이 정상이어도 읽지 않고 miss이며 그 descriptor가 닫혔는지, 항목 경로에 실제 디렉터리가 있으면 miss인지 본다. 이 확인은 Windows Python 3.13.5에서 실행했다(Linux·macOS의 실제 FIFO 동작은 확인하지 않았다). 이 회귀를 수정 전 코드에 붙이면 실패 4개다(비차단 열기 없음, 세 종류 모두 읽음).

## 2026-11-05: tar 링크로 압축 해제 상한을 넘던 경계(PR #8 Revy major 1)

- 리뷰가 Windows에서 symbolic link 권한이 없을 때 선언 크기 1 MiB인 tarball이 디스크에 약 53.5 MB를 쓰는 것을 재현했다. `unpack`은 member가 선언한 크기만 더했는데 링크 member의 크기는 0이고, tarfile은 링크를 만들 수 없으면 대상 member의 내용을 복사하므로 그 복사본이 상한에 들지 않았다. hard link도 `os.link`가 실패하면 같았다.
- 처리 정책과 이유, 정상 입력 영향은 아래 "registry 다운로드" 기록의 상한 절("링크 처리")에 적었다. symbolic link는 "data" filter 검사 뒤 풀지 않고, hard link는 tarfile이 복사할 대상의 크기로 센다.
- 테스트 152개 통과(skip 없음), `ruff check` 통과. 새 회귀 3개(상한 128 KiB, 합성 tarball): `os.symlink`를 실패시켜도 64 KiB 파일을 가리키는 symbolic link 8개와 순환하는 두 링크가 풀리지 않고 `os.symlink`가 불리지 않음, 폴더 밖 symbolic link는 전과 같이 거부. `os.link`를 실패시킨 hard link 복사 8개, 연쇄, 같은 이름 두 member 중 링크 앞의 큰 것이 상한을 넘으면 `RegistryError`로 거부하고 아무 파일도 쓰지 않음, 상한 안의 연쇄와 중복 이름은 `os.link`와 복사 두 경우 모두 풀리고 링크가 앞쪽 마지막 member의 내용을 가짐, 파일이 아닌 대상(symbolic link, 디렉터리, 없는 이름)의 hard link는 생략, 폴더 밖·절대 경로 hard link는 거부. `check`에서 상한을 넘는 hard link tarball은 `analysis_failed`·종료 코드 2이고 작업 폴더와 큰 파일이 남지 않음. 이 회귀만 수정 전 코드(`4aa005f`)에 붙이면 실패 5개와 오류 2개다: 링크 복사본이 풀림(symbolic link 576 KiB), hard link 거부 없음, 순환 링크에서 RecursionError, 없는 이름을 가리키는 hard link에서 KeyError(`RegistryError`가 아님), `check`는 판정까지 가서 종료 코드 1.

## 2026-11-05: 변경마다 시작하는 예산과 캐시 게시 경계(PR 전 교차 리뷰 03 M1 잔여)

- 리뷰가 두 경계를 재현했다. (A) 완료 결과 확인 뒤에 캐시용 모델 입력 검사와 `cache.store`가 실행돼, 예산 1초에 그 단계만 1.3초 늦어도 캐시 항목이 쓰이고 `passed`·종료 코드 0이었다. (B) 예산은 첫 자식 단계에서 시작했기 때문에, 같은 패키지의 두 번째 위치처럼 메타데이터와 feature를 모두 재사용하는 변경에는 deadline이 없어 늦은 캐시 읽기도 통과했다.
- 이제 예산은 변경 하나를 분석하기 시작할 때(`check`는 메타데이터 조회를 시작할 때) 바로 정해지고, 자식 단계가 있든 없든 그 변경의 부모 작업에도 적용된다. `scan --extract`의 다음 변경은 새 예산을 쓴다. 확인 지점은 자식 단계 사이와 결과 해석 뒤(아래 기록), 캐시용 모델 입력 검사 뒤(늦었으면 아무것도 쓰지 않는다), `cache.store`에서 파일을 다 쓰고 게시할 경로까지 계산한 뒤 `os.replace` 바로 앞(늦었으면 임시 파일만 지우고 게시하지 않는다), 완료 결과를 받아들이기 전(캐시 hit, 추출, `--no-cache` 모두)이다. 늦은 결과는 분석 실패(종료 코드 2)다.
- 끊을 수 없는 경계: 부모의 동기 작업과 OS의 파일 이름 바꾸기는 중간에 멈출 수 없다. 마지막 확인은 `os.replace`를 부르기 직전이고 그 사이에 다른 작업은 없다. 이 확인을 통과해 예산 안에 시작한 게시가 늦게 끝나면 이미 끝난 rename을 취소하지 않는다. 그 항목은 남고(그 feature는 예산 안에 만든 것이다) 이번 결과만 마지막 확인에서 거부한다. 예산이 지난 뒤에는 새 게시를 시작하지 않는다. 이미 있던 캐시 항목(손상된 것 포함)은 지우거나 되돌리지 않는다.
- 시계: deadline은 `time.perf_counter`(Windows에서 QueryPerformanceCounter, 단조 시계)로 재고, 보고서의 `elapsed_seconds`는 전과 같이 `time.monotonic`으로 잰다. 고정 clock 근거 실행이 바꿔 넣는 `time.monotonic`을 deadline 확인이 소비하지 않으므로 그 출력은 바뀌지 않는다(정규화 없이 원본 비교).
- 테스트 149개 통과(skip 없음), `ruff check` 통과. 새 회귀 6개는 캐시용 모델 검사 지연(항목 없음), 게시 경로 계산과 임시 파일 쓰기 지연(게시 안 함, 손상된 기존 항목과 다른 항목 그대로, 임시 파일 없음), 게시가 늦게 끝남(항목은 남고 결과는 거부, 다음 실행은 hit), 같은 패키지 두 번째 위치의 캐시 hit와 `--no-cache`(첫 위치는 통과, 두 번째는 거부), `check`가 메타데이터 조회부터 한 예산을 나눠 씀(자식 없이), 메타데이터를 실제 자식으로 받는 두 번째 위치를 본다. 이 회귀만 수정 전 코드(`8868916`)에 붙이면 실패 8개(모두 늦은 결과가 통과)다.

## 2026-11-05: 시간 예산이 지난 뒤의 결과 거부(PR 전 교차 리뷰 02 M1 잔여)

- 아래 기록의 첫 구현은 `bounded.run()`이 남은 시간을 한 번만 계산해, 부모가 호출을 pickle로 만들거나 자식을 시작하는 동안 쓴 시간을 자식 대기 시간에 다시 반영하지 않았고 결과를 해석한 뒤에도 확인하지 않았다. 리뷰가 예산 0.4초에 이 단계마다 0.7초를 더해 약 0.85초 뒤의 정상 결과가 받아들여지고, 실제 `check_package`가 `passed`·종료 코드 0을 내는 것을 재현했다. 또 메타데이터를 해석한 뒤 캐시 hit이면 다음 자식 단계가 없어 그 뒤의 부모 작업이 예산을 넘겨도 확인할 곳이 없었다.
- 이제 `run()`은 시작할 때 정한 절대 deadline(예산 안이면 그 변경의 것, 예산 밖에서 부르면 그 호출의 것) 하나를 쓰고, 시작 전, pickle 뒤, 자식 대기 직전, 결과 해석 뒤에 다시 확인한다. 이미 지났으면 자식을 시작하지 않고, 시작한 자식은 종료한 뒤, 결과는 버리고 `TimeLimitError`를 낸다. 분석기는 완료 결과를 받아들이고 캐시에 저장하기 전에 같은 deadline을 확인한다(`bounded.check()`, 캐시 hit 포함). 이 확인은 그 변경에서 자식 단계가 하나라도 시작된 뒤에만 시계를 읽는다(이후 예산은 변경을 시작할 때 정하고 별도 시계로 재도록 바꿈, 위 기록).
- 보장과 남는 한계: 자식 안의 작업(다운로드, 압축 해제, feature 추출)은 deadline에 종료된다. 부모가 직접 하는 동기 작업(pickle, 프로세스 시작, 결과 해석, 메타데이터 JSON 해석, 비교 기준·캐시·근거 처리)은 중간에 끊을 수 없어 그 작업 시간만큼 deadline을 넘길 수 있다. 다만 그렇게 늦게 끝난 결과는 받아들이지 않으므로 통과나 캐시 저장으로 바뀌지 않고 그 항목은 분석 실패(종료 코드 2)다. 추론과 보고서 작성은 예산에 들지 않는다.
- 테스트 143개 통과(skip 없음), `ruff check` 통과. 새 회귀 3개는 실제 자식 프로세스로 pickle, 프로세스 시작, 결과 해석 지연을 예산 안·밖에서 각각 넣어 오류와 자식 시작 여부·종료를 보고, 실제 `check_package`가 늦은 추출 결과를 `analysis_failed`·종료 코드 2로 끝내는지, 메타데이터 단계가 예산을 다 쓴 뒤의 캐시 hit이 거부되고 캐시 항목이 바뀌지 않는지 본다. 이 회귀만 수정 전 코드(`0b96311`)에 붙이면 실패 8개다(오류가 나지 않음 6개, 통과로 끝남 2개).

## 2026-11-05: 변경 하나의 전체 시간 예산과 작업 종료(PR 전 교차 리뷰 M1)

- 이전 구현(아래 "registry 다운로드" 기록)은 다운로드마다 120초를 따로 두고, 시간이 지나면 기다리던 쪽만 오류를 내고 작업 스레드와 연결은 그대로 두었다. 압축 해제와 feature 추출에는 시간 상한이 없었다. 교차 리뷰가 합성 재현으로 확인했다(시간 뒤에도 작업 스레드가 살아 있고, 가상 시계로 121초 걸린 압축 해제와 feature 추출도 통과).
- 이제 분석하는 변경 하나에 시간 예산 하나를 둔다. 메타데이터 다운로드, tarball 두 개 다운로드, 압축 해제, feature 추출이 그 예산을 함께 쓰고, 처음 단계가 시작될 때부터 잰다(이후 변경을 시작할 때부터로 바꿈, 위 "변경마다 시작하는 예산" 기록). `scan --extract`는 변경마다, `check`는 메타데이터 조회와 분석을 합쳐 하나다. 캐시 hit이면 메타데이터 조회만 예산을 쓴다. 이 단계들은 자식 Python 프로세스(`subprocess`, `python -I`)에서 실행하고, 예산이 끝나면 자식을 강제로 종료(Windows TerminateProcess, 그 밖 SIGKILL)한 뒤 끝난 것을 확인하고 나서 그 항목을 분석 실패(`incomplete`, 종료 코드 2)로 둔다. 그래서 자식이 하던 연결, 파일 쓰기, 계산이 함께 멈춘다. 압축을 푸는 폴더는 부모가 만들어 자식이 종료돼도 지운다. 다운로드마다 따로 두던 120초와 스레드 대기는 없앴다.
- 예산 값 300초의 근거(이 PC, Windows 11, 실시간 백신 켜짐, 합성 tarball과 설치된 고정 feature-extractor를 자식 프로세스에서 실행, 네트워크 없음): 크기 상한 안의 로컬 작업은 파일 20,000개 압축 해제 16초(feature-extractor는 소스 파일 5,000개를 넘으면 거부해 19초), JS 파일 4,998개 두 버전 10.8초, 63 MiB JS 파일 두 버전 16.7초, 작은 변경 0.29초였다. 두 버전 모두 파일 20,000개인 경우를 합쳐도 로컬 작업은 약 40초다. 나머지 약 260초는 크기 상한까지의 다운로드(메타데이터 128 MiB와 tarball 128 MiB 두 개, 합계 384 MiB)를 약 1.5 MB/s에서 받는 시간이다. 지금까지 관측한 가장 큰 경우(tarball 28.8 MB 두 개와 메타데이터 1.5 MB)는 약 0.25 MB/s에서도 들어간다. 더 짧은 예산이면 크기 상한까지의 입력은 빠른 연결에서만 분석된다. 실제 registry에서 이 값을 확인하지는 않았다.
- 자식 프로세스 비용: 아무것도 하지 않는 호출 10번의 중앙값 0.138초, 최대 0.149초. 변경 하나에 메타데이터 조회와 추출로 두 번 띄우므로 약 0.3~0.5초가 더 걸린다.
- 테스트 140개 통과(skip 없음), `ruff check` 통과. 새 `tests/test_bounded.py`는 실제 자식 프로세스로 확인한다: 결과(JSON·바이트)와 오류·비정상 종료 전달, 연결·헤더 단계에 멈춘 다운로드와 1바이트씩 오는 본문, 느린 압축 해제, 끝나지 않는 feature 추출(실제 `FeatureExtractorBackend.extract`, feature-extractor 부분만 stand-in), 두 단계가 나눠 쓰는 예산(남은 시간만 쓰고 다 쓴 뒤에는 새 프로세스를 띄우지 않음), 예산을 넘긴 `check`가 `analysis_failed`·종료 코드 2로 끝남, 설치된 고정 feature-extractor 추출을 자식에서 실행. 멈춘 경우마다 오류만이 아니라 자식이 종료됐고 작업이 남긴 heartbeat 파일이 더 이상 늘지 않으며 작업 폴더가 남지 않았음을 본다. 자식은 부모의 mock을 물려받지 않으므로 각 작업이 자식 안에서 네트워크 연결을 막고 합성 응답을 쓴다. 그 밖의 테스트는 이 경계를 같은 프로세스 안에서 실행하게 바꿔(공통 Fixture) 기존 mock과 고정 loader 테스트가 그대로 돈다.
- 확인하지 않은 것: 실제 registry와 느린 실제 네트워크에서의 종료, Linux·macOS에서의 프로세스 종료(SIGKILL 경로는 개발 CI에서만 실행), 메모리 상한(자식 프로세스의 메모리는 제한하지 않는다).

## 2026-11-05: 학습 범위 밖 결과의 캐시 제외(DEV-02e 후속)

- 분석 캐시 계획은 실패와 unsupported 결과를 캐시하지 않는다. 캐시 항목의 모델 입력 검사를 넣을 때 학습에 없던 범주 값(모델의 `OutOfScopeError`, 보고서의 `out_of_training_scope`)은 손상이 아니라고 보고 저장·재사용했는데, 이것도 모델이 점수를 내지 않는 unsupported 결과라 계획과 맞지 않았다. 이제 모델 입력 변환이 거부하는 feature는 이유와 상관없이 저장하지도, 캐시에서 쓰지도 않는다. 판정은 전과 같이 `out_of_training_scope`(`incomplete`, 종료 코드 2)다.
- 저장은 근거를 만든 뒤, 분석 결과 전체의 검사(`artifact.validate`)보다 먼저 일어난다. 그래서 모델이 쓰지 않는 feature가 JSON 값 형식을 벗어나도(리스트 등) 저장될 수 있었다(읽을 때는 miss로 거부). 이제 `cache.store`는 `cache.load`가 받아들이는 feature만 쓴다. 테스트 135개 통과.
- 테스트 134개 통과(skip 없음), `ruff check` 통과. 학습에 없던 범주를 두 번 검사하면 두 번 모두 추출하고(`cache_hit` false), 캐시 항목이 생기지 않으며, 판정은 두 번 모두 `out_of_training_scope`임을 확인한다.

## 2026-11-05: `--output` 충돌을 분석 전에 거부(PR #7 후속)

- 이미 있는 `--output` 경로는 결과를 쓸 때(`open(..., "x")`)에야 거부돼, `check`와 `scan --extract`가 registry를 읽고 추출까지 마친 뒤 오류로 끝났다(PR #7 리뷰 nit 3). 이제 `plan`·`scan`·`check` 모두 명령을 실행하기 전에 경로가 있는지 확인하고, 같은 오류 문구(`[Errno 17] File exists: ...`)와 종료 코드 2로 끝난다. 확인과 쓰기 사이에 파일이 생기는 경우는 기존처럼 쓰기 단계의 `"x"` 모드가 막는다.
- 테스트 134개 통과(skip 없음), `ruff check` 통과. 새 테스트는 text·json·markdown의 `check`에서 메타데이터 조회와 추출이 0회이고 진행 표시 없이 오류 한 줄만 나오는지, `scan --extract`에서 분석기를 만들지 않는지, 기존 파일이 그대로인지 본다. 수정 전 코드(`95cfb79`)에서는 이 테스트가 실패 3개, 오류 1개로 깨진다.

## 2026-11-05: 설치된 고정 feature-extractor의 loader 경계 테스트(PR #7 후속)

- feature-extractor가 설치된 환경에서만 도는 테스트 3개(`PinnedLoaderTests`, `skipUnless`)를 더했다(PR #7 재검증 nit 2). 실제 `FeatureExtractorBackend`와 고정 커밋 c24761d의 `build_snapshot`, `build_row`, extractor 전체, `LocalArchiveSnapshotSource`를 합성 tarball로 실행하고, depbee의 registry 접근만 가짜 응답으로 바꾸며, feature-extractor 자신의 `requests.get`은 불리면 실패하게 둔다.
- 확인하는 것: `check`와 `scan --extract` 모두 메타데이터 요청 1회와 tarball 2개만 받고 feature-extractor는 registry에 접근하지 않음, feature 29개, `installScriptAdded`가 tarball의 package.json이 아니라 확인한 registry 메타데이터에서 나옴, 바뀐 JS 수가 푼 tarball에서 나옴, 비교 기준 manifest·`dist`·`versions`·`time` 형식 오류가 tarball 요청 전에 종료 코드 2로 끝남(전에는 loader.py 100행의 `AttributeError`), 로컬 사본을 고정 `LocalArchiveSnapshotSource`로 읽음.
- 백엔드가 feature-extractor의 `RegistrySnapshotSource`로 다시 메타데이터를 받게 바꾸면 이 테스트가 실패함을 확인했다. pin을 바꿀 때 같은 회귀를 잡는다.
- 이 개발 환경(`.[dev,ml,extract]`, feature-extractor를 Git 커밋 c24761d에서 설치)에서 테스트 133개 통과, skip 없음, `ruff check` 통과. 네트워크 연결을 실패하게 바꾼 전체 실행에서도 133개가 통과했고 실제 backend는 11번 만들어졌다. `.[extract]` 없이 도는 개발 CI에서는 이 3개가 skip된다.

## 2026-11-05: 캐시 항목의 모델 입력 검사와 check의 메타데이터 시간(DEV-02e 후속)

- 캐시는 JSON 값의 형식(숫자, 문자열, bool, null, NaN·무한대 아님)만 검사해서, 모델 feature가 빠졌거나 숫자 자리에 문자열이 든 항목도 hit로 쓰였다. 그러면 다시 추출하지 않고 매번 추론 실패(`incomplete`)로 끝났다. 이제 캐시한 feature를 검증한 모델의 입력 변환(`LightGBMPredictor.encode`, 이름·순서·boolean·범주·결측 규칙)에 넣어 보고, 받지 못하면 miss로 보고 다시 추출한다. 새로 추출한 feature도 모델이 받지 못하면 저장하지 않는다. 학습에 없던 범주 값은 처음에 저장하고 다시 썼으나, 계획의 실패·unsupported 캐시 제외에 맞춰 저장하지 않게 바꿨다(위 2026-11-05 "학습 범위 밖 결과의 캐시 제외" 기록). 저장은 근거를 만든 뒤, 추론 전에 한다.
- `check`는 요청을 만들기 전에 메타데이터를 받으므로 그 시간이 결과의 `elapsed_seconds`에 빠져 있었다(연결 규약은 항목별 시간에 메타데이터 조회를 포함한다고 정한다). 이제 그 조회 시간을 결과의 값에 더한다. `scan --extract`는 분석 중에 메타데이터를 받으므로 바뀌지 않는다.
- 테스트 130개 통과(skip 없음), `ruff check` 통과. 모델 feature가 빠지거나 문자열·bool이 숫자 자리에 든 항목이 miss가 되고 다시 저장됨, 모델이 받지 못하는 새 feature는 저장되지 않음, 학습에 없던 범주의 저장·재사용(뒤에 제외로 바꿈), 고정 clock에서 `check`의 결과 시간이 메타데이터 조회와 분석 시간의 합임을 확인한다. 모델 검사를 끄거나 메타데이터 시간을 빼면 이 테스트들이 실패하는 것도 확인했다.

## 2026-11-05: registry 다운로드의 integrity, 주소, 크기·시간 상한(PR #7 후속)

- 고정 feature-extractor(c24761d)의 loader는 받은 tarball을 해시하지 않고, redirect를 제한하지 않으며, 크기·파일 수·전체 시간 상한 없이 받고 풀었다(아래 2026-11-04 기록의 제한). 이제 registry 메타데이터와 tarball은 depbee(`analysis/registry.py`)가 받고, feature-extractor에는 고정 loader의 공개 함수 `build_snapshot()`으로 만든 snapshot과 검사한 tarball을 푼 폴더만 넘긴다. feature-extractor는 registry에 접근하지 않으며, 이전 기록의 비공개 `_packument_cache` 의존도 없어졌다.
- 받은 tarball 바이트는 풀기 전에 그 버전의 `dist.integrity`와 대조한다. npm(ssri)처럼 나열된 알고리즘 중 가장 강한 것(sha512 → sha384 → sha256 → sha1)으로만 판정하고 그 알고리즘의 값 중 하나가 맞으면 통과한다. integrity가 없으면 옛 `dist.shasum`(sha1)을 쓰고, 둘 다 없으면 분석 실패다. 설치될 버전은 전과 같이 lockfile integrity가 registry 값과 같은 값을 공유해야 한다.
- 주소: 메타데이터와 tarball 모두 `https://registry.npmjs.org`에서만 받는다. redirect마다 새 주소를 검사하고 마지막 응답 주소도 다시 검사한다. tarball 주소는 비교 기준 버전도 포함해 `https://registry.npmjs.org/<이름>/-/<scope를 뺀 이름>-<버전>.tgz`와 정확히 같아야 한다.
- 상한값과 근거(코드 상수, CLI 옵션 없음). 표본은 이 작업 공간에 이미 있던 자료이고 파일 크기만 읽었다.

| 상한 | 값 | 근거 |
| --- | --- | --- |
| 메타데이터 크기 | 128 MiB | 로컬에 보관한 packument 3,146개(baseline 점검 때 받은 캐시)의 중앙값 3 KB, p99 0.43 MB, 최대 1.49 MB. 버전이 수천 개인 대형 패키지가 거의 없는 표본이라 실제 최대치를 대표하지 못해 넉넉히 잡았다. JSON을 메모리에 올리므로 최악의 메모리 사용은 이 값의 몇 배다. |
| tarball 크기 | 128 MiB | 3차 수집 때 받은 원본 tarball 119개의 최대 28.8 MB(p99 11.9 MB)의 약 4배 |
| 풀린 크기 | 512 MiB | pair archive의 버전 트리 2,334개(Git tree의 파일 크기 합)의 최대 261 MB(p99 84 MB)의 약 2배. 압축을 이 크기 넘게 풀지 않고, member가 선언한 크기의 합도 같은 상한으로 본다(링크는 표 아래 "링크 처리"). |
| 파일 수 | 20,000 | 같은 표본의 최대 9,152개(p99 2,502개)의 약 2배 |
| 다운로드 하나의 벽시계 시간(이후 변경 하나의 예산 300초로 바뀜, 위 기록) | 120초 | 관측한 최대 tarball 28.8 MB를 1 MB/s에서 약 29초에 받는다. 128 MiB tarball은 약 1.1 MB/s 이상이어야 이 안에 받는다. 소켓 동작별 30초 제한은 feature-extractor와 같다. |

- 링크 처리(PR #8 Revy major 1, 위 기록에서 추가). 선언 크기의 합은 링크가 쓰는 바이트를 세지 못했다. tarfile은 링크를 만들 수 없으면(Windows에서 symbolic link 권한이 없을 때, hard link를 지원하지 않는 파일 시스템) 대상 member를 복사한다.
  - symbolic link는 풀지 않는다. "data" filter를 먼저 적용하므로 폴더 밖이나 절대 경로를 가리키는 링크는 전과 같이 거부하고, 통과한 symbolic link만 건너뛴다. 이유: npm은 tarball의 링크를 설치하지 않는다(이 PC의 npm 11.6.1에 든 pacote 21.0.3 `lib/fetcher.js`의 tar filter가 `SymbolicLink`·`Link` 항목을 버린다). 고정 feature-extractor도 소스 파일을 모을 때 symbolic link를 건너뛴다(`core/source_files.py`의 `_walk_source_paths`). 그래서 링크를 만들 수 있는 OS에서는 feature에 쓰이지 않았고, 링크를 만들 수 없는 Windows에서만 복사본이 일반 파일로 읽혀 OS마다 feature가 달라질 수 있었다. 대상 크기를 더하는 방식은 tarfile의 symbolic link 대상 해석(아카이브 전체에서 찾기, 연쇄)을 따라 해야 하고, 서로를 가리키는 링크는 링크를 만들 수 없을 때 tarfile 자체가 RecursionError로 끝났다.
  - hard link는 대상의 크기로 센다. tarfile은 hard link의 대상을 그 링크보다 앞에 있는 member 중 경로를 정규화한 이름이 같은 마지막 것으로 찾고(`TarFile._find_link_target`), `os.link`가 실패하면 그 member를 복사한다. depbee는 링크마다 그 member의 크기를 더한다(대상이 hard link이면 그 링크가 센 크기). `os.link`가 성공해 디스크를 더 쓰지 않을 때도 같은 값을 세므로 OS와 관계없이 같은 판정이 난다. 일반 파일이나 그런 hard link가 아닌 것(symbolic link, 디렉터리, 없는 이름)을 가리키는 hard link는 풀지 않고, 폴더 밖이나 절대 경로를 가리키면 "data" filter로 거부한다. hard link는 OS와 관계없이 대상 내용을 가진 파일이 되고 feature-extractor가 일반 파일로 읽으므로 남긴다.
  - 정상 입력 영향: 링크가 없는 tarball의 처리는 그대로다. 링크가 든 tarball은 symbolic link 없는 트리로 분석하고, package.json이 symbolic link이면 패키지 루트를 찾지 못해 분석 실패다. hard link는 대상 크기만큼 상한에 더 가까워진다. 실제 registry tarball에 링크가 얼마나 있는지는 확인하지 않았다.

- 시간 범위의 구분(이 기록 당시의 구현이며, 위 "변경 하나의 전체 시간 예산" 기록에서 바꿨다):
  - 다운로드: 메타데이터 하나, tarball 하나가 각각 120초다. 요청을 스레드에서 실행하고 depbee는 최대 120초만 기다리므로 이름 조회, 연결, TLS, 헤더, redirect, 본문이 모두 이 안에 든다. 소켓 제한만으로는 데이터가 조금씩 계속 오면 이 시간이 끝나지 않는다. 스레드도 읽기(한 번에 소켓 읽기 하나인 `read1`)마다, 본문 끝에서도 시간을 확인하고 멈춘다. 시간이 지났을 때 아직 돌던 스레드는 버려 둔다. 본문을 받던 스레드는 다음 읽기에서 멈추고(읽기 하나는 데이터 없이 최대 30초), 연결·TLS·헤더 단계에서 데이터가 조금씩 계속 오면 그 단계가 끝나거나 프로세스가 끝날 때까지 남는다(이 경우의 스레드 수명은 확인하지 않았다). 한 항목은 메타데이터 하나와 tarball 두 개를 받으므로 다운로드만으로 최대 약 360초다.
  - 압축 해제: 시간 상한이 없고 크기와 파일 수 상한만 있다. 합성 측정(Windows 11, NTFS, 실시간 백신 켜짐)에서 512 MiB에 가까운 파일 하나는 1.0초, 16바이트 파일 20,000개는 16.1초 걸렸다.
  - feature 추출(feature-extractor의 extractor 실행): 시간 상한이 없다.
- 테스트 128개 통과(skip 없음), `ruff check` 통과. 모두 합성 I/O다(`_open`을 가짜 응답으로 바꿈): 다운로드 시간 상한은 합성 clock으로 본문 끝에서 시간이 지난 경우, 1바이트씩 오는 응답, 늦게 끝난 연결·redirect를 거절하고, 실제 시간 0.3초 상한으로 연결 단계와 본문 읽기에 멈춘 요청을 5초 안에 오류로 끝낸다. 그 밖에 redirect handler와 마지막 주소 재검사, 크기와 `Content-Length`, 전송 오류, integrity 알고리즘 순서와 shasum, 압축 해제의 크기·파일 수·선언 크기 상한, 경로 밖 파일과 링크 거부("data" filter), 패키지 루트 규칙, lockfile 경로와 `check`의 통합(실제 `FeatureExtractorBackend`와 depbee source, feature-extractor 부분만 stand-in)을 확인한다.
- 확인하지 않은 것: 실제 registry 접근(대형 packument, 실제 redirect, 느린 네트워크), Linux·macOS, 모든 실제 패키지의 tarball 주소 형식(옛 버전에 `http://` 주소가 남아 있으면 그 항목은 분석 실패가 된다).

## 2026-11-05: lockfile 경로의 registry 메타데이터 형식 검사(PR #7 재검증 후속)

- `scan --extract`에서 packument 자체나 `versions`가 리스트·문자열·숫자·null이거나 `time`이 리스트·문자열·숫자이면 `AttributeError`가 분석기 밖으로 나가 traceback과 종료 코드 1이 될 수 있었다(PR #7 재검증 minor 1). 이제 `ExtractorAnalyzer.packument()`가 받은 메타데이터가 객체이고 그 `versions`·`time`이 객체인지 확인하고, 아니면 `GuardError`로 그 항목을 분석 실패(`incomplete`, 종료 코드 2)로 둔다. `check`에서는 같은 검사가 요청을 만들기 전에 걸려 오류 JSON과 종료 코드 2로 끝난다(`build_package_request`와 같은 규칙). `versions`나 `time`이 아예 없을 때도 전과 같이 분석 실패이고 오류 문구만 바뀐다(전에는 "Registry no longer serves" 또는 "no publish time"). `AttributeError`를 잡는 코드는 넣지 않았다.
- 테스트 115개 통과(skip 없음), `ruff check` 통과. 새 scan 경로 회귀 테스트(subTest 12개)는 실제 `cli.main`과 FakeBackend로 종료 코드 2, 빈 stderr, `analysis_failed`, feature-extractor 미호출을 확인한다. 테스트만 수정 전 코드(`9e7f989`)에 붙이면 오류 9개(모두 `AttributeError`)와 실패 3개(다른 오류 문구)로 깨진다.
- 비교할 manifest와 `dist`의 형식 회귀에 숫자, 실수, null, bool, 빈 리스트·객체를 더했다(PR #7 재검증 nit 1). 이 형식들은 수정 전 코드에서도 통과했다(2026-11-04 기록의 검사로 이미 막혀 있었다).

## 2026-11-05: Markdown 출력(DEV-02f)

- `scan`과 `check`에 `--format markdown`을 추가했다. 테스트 114개 통과(skip 없음), `ruff check` 통과.
- 새 테스트: 파이프, 역슬래시, 개행, 백틱 묶음, HTML 태그와 주석, 링크·이미지, 강조, 자동 링크(URL, `www.`, 이메일), HTML entity, 제목 기호, 제어·방향 문자를 패키지·버전·위치·근거·상세·model_id·이유·feature 이름과 값에 넣어도, CommonMark 규칙으로 code span을 뺀 나머지 출력이 평범한 문자열일 때와 같고 표의 칸 수가 그대로임을 확인한다. code span 처리나 표의 `|` 처리, 제어 문자 처리를 끄면 이 테스트가 실패하는 것도 확인했다. 그 밖에 판정별 순서, 점수 0과 없음, 삭제·보류 항목, 빈 결과, 시간 열, check의 출처 문구, JSON과 같은 종료 코드, `--output` JSON 파일과 덮어쓰기 거부, Markdown에서 진행 표시 없음.
- 고정 clock으로 실행한 text·json 출력 12가지는 e 커밋(`84b6016`)의 출력과 바이트 단위로 같다. Markdown 출력 7가지도 같은 방식으로 기록했다.
- 확인하지 않은 것: GitHub job summary의 실제 렌더링. 위 판단은 CommonMark·GFM 명세에 따른 것이고 GitHub 화면에서 보지 않았다.

## 2026-11-05: 분석 캐시와 소요 시간(DEV-02e)

- `scan --extract`와 `check`에 추출한 feature의 실행 간 캐시(`--cache-dir`, 기본 `~/.cache/depbee`, `--no-cache`)와 소요 시간·캐시 사용 여부(`elapsed_seconds`, `cache_hit`)를 추가했다. 캐시 키와 우회 조건은 README와 연결 규약 4절에 있다. `--extract` 없는 `scan`과 `plan`에는 새 필드가 없다.
- 테스트 109개 통과(skip 없음), `ruff check` 통과. 새 테스트는 FakeBackend와 합성 메타데이터로 돈다: 같은 쌍의 cold/warm에서 추출 1회와 같은 판정·feature·근거, 요청·위치·lockfile 이전 버전이 달라도 재사용하며 근거는 현재 요청으로 다시 만듦, 모델 파일·manifest, feature-extractor 출처, integrity, 두 manifest, 배포 시각, 비교 기준 중 하나만 바뀌어도 다시 추출, `--no-cache`·모델 없음·출처 미확인·로컬 사본·`--analysis`에서 읽기와 쓰기 없음, 추출 실패는 저장하지 않고 다음 실행에서 다시 추출, 잘리거나 키·형식·feature 값(NaN, 무한대, 객체)이 틀리거나 상한을 넘는 항목은 miss, 쓰기 실패는 캐시만 건너뜀, 스레드 여러 개가 같은 항목을 동시에 쓰고 읽어도 부분 파일을 읽지 않음, 고정 clock의 항목별·전체 시간과 삭제·미지원·실패 항목의 값, 시간 값이 음수나 NaN이 되지 않음, 설치 출처 확인(고정 커밋 VCS 설치만 인정, 편집 가능·로컬 폴더·다른 커밋·다른 URL·설치 후 수정은 거부), 검증한 모델의 해시.
- 이 개발 환경에서는 `pip install -e ".[dev,ml,extract]"`가 feature-extractor를 Git 커밋 `c24761d`에서 설치했고(`direct_url.json`의 `vcs_info`), 설치 출처 확인을 통과했다.
- 합성 측정(실제 성능 아님): 고정 feature를 즉시 돌려주는 합성 backend와 D04-E00으로 `scan --extract`를 바뀐 패키지 1·5·20개에 cold, warm, `--no-cache` 순서로 실행했다. 추출 횟수는 cold 1·5·20, warm 0·0·0, `--no-cache` 1·5·20이고 메타데이터 조회는 매번 패키지 수만큼이며, 세 실행의 판정·점수·feature·근거가 같다(시간·캐시 필드를 뺀 의미 비교). 벽시계 시간은 cold 0.474·0.122·0.163초, warm 0.108·0.115·0.138초였고 첫 cold에는 LightGBM import가 들어 있다. 추출이 즉시 끝나는 합성 backend라 이 값은 depbee 자체의 처리 시간이며 실제 npm 다운로드·추출 시간이나 캐시로 줄어드는 시간이 아니다.
- 고정 clock으로 `check`와 `scan --extract`를 subprocess에서 12가지 실행한 출력(cold/warm, `--no-cache`, 모델 없음, pre-release, 잘못된 배포 시각, `--output`)은 두 번 실행해 바이트 단위로 같다.
- 확인하지 않은 것: 실제 registry에서의 추출 시간과 캐시 효과, 여러 OS 파일시스템에서의 동시 쓰기·내구성(Windows NTFS에서 스레드로만 확인), 캐시 폴더의 크기 증가(자동 정리 없음).

## 2026-11-04: 비교할 manifest의 사전 검사, 다운로드 상한 없음(PR #7 리뷰 후속)

- 비교 기준 버전의 manifest가 문자열이거나 그 `dist`가 리스트이면, 고정 feature-extractor(c24761d) `loader.py` 100행이 형식 검사 없이 `dist.tarball`을 읽다가 `AttributeError`를 냈다. 이 예외는 분석 실패로 바뀌지 않아 traceback과 종료 코드 1(위험 판정과 같은 코드)로 끝났다(PR #7 리뷰 minor 1). 아래 기록의 "비교한 두 버전의 manifest가 객체가 아니면 분석 실패"는 FakeBackend 기준이었고, 실제 loader를 거치면 비교 기준 쪽은 지켜지지 않았다.
- 이제 `backend.extract()`를 부르기 전에 비교 기준과 새 버전의 manifest, 각 `dist`가 객체인지 확인하고, 아니면 그 항목을 분석 실패(`incomplete`, 종료 코드 2)로 둔다. `scan --extract`에서 새 버전의 integrity를 읽던 곳의 같은 예외도 이 검사로 막힌다. 로컬 사본으로 읽는 새 버전은 registry manifest를 쓰지 않으므로 검사하지 않는다. `dist`가 아예 없을 때는 전에도 분석 실패였고 오류 문구만 바뀐다. 정상 메타데이터의 출력은 같다.
- 테스트 96개 통과(skip 없음), `ruff check` 통과. 새 회귀는 두 가지다. check 경로에서는 실제 `FeatureExtractorBackend.extract`와 c24761d `loader.py` 55-56, 100행처럼 `dist.tarball`을 읽는 stand-in source로, 문자열 manifest와 리스트 `dist`가 JSON `incomplete`, 종료 코드 2로 끝나고 feature-extractor를 부르지 않는지 본다. lockfile 경로에서는 비교 기준과 새 버전 각각의 같은 경우가 extract 전에 실패하는지 본다. 테스트만 수정 전 코드(66e3527)에 붙이면 새 회귀가 실패 2개, 오류 4개로 깨지고, 오류는 모두 그 `AttributeError`다.
- 고정 c24761d의 `errors.py`, `loader.py`(`build_snapshot`, `get_publish_time`, `_download_and_extract_tarball`), `sources.py`, `pipeline.py`(`build_row`) 원문을 그대로 실행하고 registry 조회, `requests.get`(다운로드 차단), 임시 폴더 생성만 합성으로 바꿔 확인했다. 수정 전 코드는 두 경우 모두 `loader.py` 100행의 `AttributeError` traceback과 종료 코드 1로 끝났고, 수정 후에는 tarball 요청 없이 종료 코드 2였다. 정상 메타데이터는 두 코드 모두 비교 기준 tarball 요청까지 가서 합성 차단으로 분석 실패가 됐다. 실제 registry 접근, tarball 다운로드, 압축 해제, feature-extractor 설치는 하지 않았다.
- 제한(이번에 고치지 않음): 고정 feature-extractor의 다운로드에는 packument·tarball 크기, 압축 해제 크기, 멤버 수, 전체 시간의 상한이 없다. `loader.py`의 `timeout=30`은 연결과 읽기에 각각 걸리는 소켓 단위 제한으로, 그 시간 동안 받은 바이트가 없을 때만 끝나므로 전체 다운로드 시간의 상한이 아니다(requests 문서). PR #7 리뷰는 65 KB tgz 안의 64 MiB 파일이 그대로 풀리는 것을 확인했다고 보고했다. 이번 작업에서 대용량 실험은 다시 하지 않았다. `check`는 임의의 패키지 이름을 받으므로 `scan --extract`보다 이 노출이 크다.

## 2026-11-04: check 교차 리뷰 후속(메타데이터 재사용, 버전 검사, 배포 시각)

- 아래 기록의 "메타데이터를 한 번 받는다"는 FakeBackend 기준이었다. 실제 `FeatureExtractorBackend.extract()`는 빈 `RegistrySnapshotSource`를 새로 만들어 registry를 다시 조회했고, old/new snapshot이 요청을 만들 때 검증한 문서와 다른 문서를 쓸 수 있었다(PR 전 교차 리뷰 차단 1). 이제 받은 메타데이터를 그 source의 캐시에 넣어 old/new snapshot도 같은 문서를 쓴다. 고정 feature-extractor(c24761d)에는 공개 API가 없어 캐시 속성(`_packument_cache`)에 의존하며, 속성이 없으면 다시 조회하지 않고 분석 실패로 둔다. `scan --extract`도 패키지당 조회가 한 번으로 줄었다.
- 숫자로만 된 pre-release 식별자의 선행 0(`1.0.0-01`, `1.0.0-alpha.01`)을 네트워크 전에 거부한다(차단 2). `1.0.0-0`, `1.0.0-01a`는 그대로 받는다. build metadata(`+...`)는 SemVer 문법상 유효하지만 이 명령의 지원 범위가 아니라는 점을 README, `--help`, 오류 문구, 연결 규약에 맞췄다(권장 4). registry 저장 규칙 전체를 검증한 것은 아니다.
- 비교 기준 선정의 배포 시각이 ISO 8601이 아니거나 timezone이 없으면 TypeError로 CLI가 종료 코드 1로 끝나던 것을, 그 항목의 분석 실패(`incomplete`, 종료 코드 2)로 바꿨다(차단 3). 서로 다른 timezone offset은 시각대로 비교한다. 정상 메타데이터의 출력은 같다.
- 테스트 94개 통과(skip 없음), `ruff check` 통과. 새 회귀는 고친 전 코드(530133a)에서 실패한다. 고정 feature-extractor의 `RegistrySnapshotSource`·`build_row` 소스를 그대로 실행하고 조회와 snapshot 생성만 합성으로 바꾼 확인에서, 고친 뒤에는 조회 1회와 old/new의 같은 문서 사용을, 고치기 전에는 조회 2회를 확인했다. 실제 registry 접근, tarball 다운로드, 추출은 하지 않았다. 기존 CLI 출력(9개 명령, 29개 파일)은 바이트 단위로 같다.

## 2026-11-04: lockfile 없는 단일 패키지 검사(`check NAME@VERSION`)

- `depbee check NAME@VERSION`을 추가했다. 이름과 버전은 네트워크 접근 전에 검사하고(scope가 있거나 없는 registry 이름, 정확한 semver), registry 메타데이터를 한 번 받아 요청(`input_kind: "package"`, 새로 추가된 의존성 하나, lockfile 해시 없음)과 분석에 함께 쓴 뒤 `scan --extract`와 같은 분석기와 판정으로 처리한다. 그 버전의 manifest 이름·버전, `https://registry.npmjs.org` tarball, `dist.integrity` 중 하나라도 맞지 않거나 메타데이터를 읽지 못하면 오류(종료 코드 2)다. 텍스트·JSON 보고서의 범위와 근거에 lockfile 없이 registry 정보로 검사했다고 표시한다. lockfile 보고서의 필드·scope·텍스트는 그대로다.
- 분석기는 비교한 두 버전의 manifest와 `scripts`·`dependencies`·`optionalDependencies`가 객체가 아니면(빈 값 제외) 예외로 끝내지 않고 그 항목을 분석 실패(`incomplete`)로 둔다. `scan --extract`에도 같이 적용된다.
- 테스트 91개 통과(skip 없음), `ruff check` 통과. 새 테스트 12개는 feature-extractor를 FakeBackend로 바꿔 네트워크와 패키지 코드 없이 돈다: 네트워크 전 이름·버전 거부, NAME@VERSION 분리, 요청 형식과 request_id 반복 일치, 잘못된 메타데이터 14가지, 메타데이터 읽기 실패, 임계값 경계와 메타데이터 한 번 조회, 결과별 텍스트의 출처 표시, JSON `--output`과 덮어쓰기 거부, 모델 경로 우선순위, 비교 버전의 잘못된 메타데이터, 합성 native 모델.
- D04-E00과 DEV-01 합성 feature, 합성 registry 응답으로 `cli.main`을 subprocess에서 14가지 실행해 출력 바이트를 기록했다(위험, 통과, 모델 없음, 환경 변수 모델, pre-release, 비교 기준 없음, integrity 없음, 버전 범위, 메타데이터 읽기 실패, scoped 이름, 출력 파일 덮어쓰기 거부, URL 이름 등). 두 번 실행한 결과가 바이트 단위로 같다(기존 출력 파일 경로가 들어간 오류 메시지 1개는 실행 폴더 이름만 다름). 실제 registry 접근과 실제 추출은 하지 않았고 탐지 성능 검증도 아니다. 기존 CLI 출력(9개 명령, 29개 파일)은 바이트 단위로 같다.

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

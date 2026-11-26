# 사용 참고서

설치본에 든 기본 자산과 사용자 지정, 명령별 옵션, 업데이트 반영 조건과 백업·복구, 이력 보관 방식, MCP 설정을 설명합니다. 처음 실행하는 명령은 [빠른 시작](../README.md), 네 진입점을 순서대로 실행하는 예시는 [진입점별 시연](demo.md)에 있습니다.

분석기는 Python 배포와 실행 명령에서 `depbee-analyzer`, import에서 `depbee_analyzer`를 사용합니다. 이전 배포명은 `feature-extractor`, import는 `feature_extractor`였습니다. 새 환경에서는 depbee의 `[extract]` 옵션이 지정한 커밋을 설치합니다. 저장된 결과와 이력에서 분석기의 출처를 읽을 때는 기존 JSON 키 `provenance.feature_extractor`를 사용합니다.

## 기본 자산

depbee 설치본에는 ML 모델과 기지 악성 색인이 들어 있습니다. 옵션, 환경 변수, 저장한 설정이 모두 없으면 `scan`, `check`, `update`, `dashboard`, `mcp`가 이 자산을 씁니다. 파일을 복사하거나 내려받거나 `depbee setup`을 먼저 실행할 필요가 없습니다.

| 자산 | 식별 | 설치된 depbee 패키지 안 위치 |
| --- | --- | --- |
| ML 모델 | 모델 ID `D04-E00` | `assets/model/model.txt`, `assets/model/manifest.json` |
| 기지 악성 색인 | 기준 시점 `2026-10-06T14:00:47Z` (OSV npm `MAL-` 기록) | `assets/index/index.json`, `assets/index/manifest.json` |

- 우선순위: 명령의 옵션(`--model-dir`, `--known-malicious-dir`), 환경 변수(`DEPBEE_MODEL_DIR`, `DEPBEE_KNOWN_MALICIOUS_DIR`, 빈 값은 없는 것으로 봄), [`depbee setup`으로 저장한 설정](#자산-폴더-설정-depbee-setup), 설치본 순입니다. 앞의 셋은 설치본 대신 다른 모델이나 색인을 쓰려는 사용자의 선택입니다.
- 사용자가 지정한 폴더(옵션, 환경 변수, 저장한 설정)가 없거나 읽을 수 없거나 SHA-256·형식이 맞지 않으면 설치본으로 대체하지 않고 오류(종료 코드 2)로 끝납니다. 손상된 지정이 말없이 다른 모델이나 색인으로 바뀌지 않게 하기 위해서입니다.
- 저장한 설정에 한쪽 자산만 있을 때(다른 쪽을 "연결 안 됨"으로 저장한 경우) 그 자산에 설치본을 쓰는지는 아직 확정되지 않았습니다. 그런 설정을 쓰고 있다면 아래 [결과 재현에 남길 값](#결과-재현에-남길-값)으로 실제로 쓰인 자산을 확인하거나, `depbee setup --clear`로 저장한 설정을 지워 설치본을 씁니다.
- 색인은 기준 시점까지의 기록만 담습니다. depbee는 실행 중에 자산을 내려받거나 갱신하지 않으므로 그 뒤에 올라온 기록은 설치본 색인에 없습니다. 더 새로운 색인이 필요하면 [색인 만들기](#색인-만들기)로 만들어 지정합니다.
- 대상 프로젝트 폴더나 현재 폴더에서는 모델·색인·설정을 찾지 않습니다.

### 결과 재현에 남길 값

같은 결과를 다시 만들거나 보고서를 인용할 때는 "기본 자산"이라고만 적지 않고, JSON 보고서의 아래 값과 depbee의 고정 버전·커밋을 함께 남깁니다. 경로는 MCP 응답과 `update`의 JSON 기준이고, `scan`·`check`의 `--format json`과 `--output` 파일에서는 앞의 `report.` 없이 최상위에 있습니다.

| 값 | 뜻 |
| --- | --- |
| `report.model_id` | 판정에 쓴 모델 ID |
| `report.provenance.model.model_sha256`, `report.provenance.model.manifest_sha256` | 그 모델 파일과 manifest의 SHA-256 |
| `report.detectors.known_malicious.list_as_of` | 대조한 기지 악성 목록의 기준 시점 |
| `report.detectors.known_malicious.list_sha256` | 그 색인(`index.json`)의 SHA-256 |
| depbee 버전과 소스 커밋 | 설치한 depbee의 버전(`python -m pip show depbee`)과 설치에 쓴 소스의 커밋 |

feature를 추출한 실행이라면 `report.provenance.feature_extractor.commit`(depbee-analyzer 커밋)도 함께 남깁니다. `report.detectors.known_malicious`가 null인 보고서는 기지 악성 기록과 대조하지 않은 결과입니다.

## 모델 준비

설치본 모델 대신 다른 모델을 쓸 때만 필요합니다. 모델 담당자가 `Booster.save_model()`로 저장한 native 모델을 `models/<model-id>/model.txt`에 두고 manifest를 만듭니다. CLI와 Actions에서 읽는 `model.txt`는 최대 100 MiB(104,857,600바이트)입니다.

```powershell
python scripts/write_manifest.py models/<model-id> --model-id <model-id> --threshold <검증한 임계값>
```

스크립트는 모델 파일에서 feature 이름·순서와 범주 순서를 읽고, feature 자료형(boolean·범주·결측 허용)은 분석기의 feature 스키마에서 가져옵니다.
임계값은 모델 담당자가 검증 세트로 정한 값을 넣습니다.
manifest 구조는 [연결 규약](contracts.md)에 있습니다.

## 자산 폴더 설정 (`depbee setup`)

선택 사항입니다. [설치본 자산](#기본-자산) 대신 직접 준비한 모델 폴더와 기지 악성 색인 폴더를 계속 쓰려면 한 번 저장해 둡니다. 저장하면 `scan`, `check`, `update`, `dashboard`, `mcp`가 옵션과 환경 변수 다음으로 이 폴더를 쓰고, 저장하지 않으면 설치본 자산을 씁니다. 자산 폴더 하나 아래에 두 폴더를 다음 이름으로 둡니다.

```text
<자산 폴더>/
  model/   model.txt, manifest.json     (모델 준비 절의 결과)
  index/   index.json, manifest.json    (색인 만들기 절의 결과)
```

```powershell
depbee setup C:\depbee-assets    # 저장. macOS/Linux 예: depbee setup /opt/depbee-assets
depbee setup                     # 저장된 설정 보기
depbee setup --clear             # 저장된 설정 지우기
```

- 저장할 때 `model`과 `index`를 검사에서 쓰는 방식 그대로 읽어 확인합니다(모델 파일과 manifest의 SHA-256 대조와 LightGBM 로딩, 색인과 manifest의 SHA-256 대조와 형식 검사). 하나라도 읽지 못하면 아무것도 저장하지 않고 오류(종료 코드 2)로 끝나며, 전에 저장한 설정은 그대로 둡니다.
- `model`이나 `index` 폴더가 없으면 그 자산은 "연결 안 됨"으로 저장합니다. 둘 다 없으면 오류입니다. 그 이름이 폴더가 아닌 것(일반 파일, 대상이 없어진 링크나 정션)으로 있으면 "연결 안 됨"으로 보지 않고 오류(종료 코드 2)로 끝나며, 전에 저장한 설정은 그대로 둡니다. 망가진 자산 폴더를 다시 저장하다가 기존 색인 연결이 말없이 빠지는 것을 막기 위해서입니다. 나중에 빠진 폴더를 채웠다면 `depbee setup <자산 폴더>`를 다시 실행합니다. 같은 폴더 안의 파일만 바꿨다면 다시 저장할 필요가 없습니다. 한쪽만 저장한 설정에서 저장하지 않은 자산에 설치본을 쓰는지는 아직 확정되지 않았습니다([기본 자산](#기본-자산)).
- depbee는 자산을 내려받지 않고 찾아다니지도 않습니다. 사용자가 이름을 준 폴더만 저장하며, 대상 프로젝트 폴더나 현재 폴더에서 모델·색인·설정 파일을 찾지 않습니다. 직접 만들었거나 SHA-256을 확인한 폴더만 저장합니다.
- 우선순위: 명령의 옵션, 환경 변수(`DEPBEE_MODEL_DIR`, `DEPBEE_KNOWN_MALICIOUS_DIR`, 빈 값은 없는 것으로 봄), 저장된 설정, 설치본 순입니다. 옵션, 환경 변수, 저장된 설정이 모두 없으면 설치본 자산을 씁니다. `depbee setup`은 환경 변수가 저장한 값보다 먼저 쓰이고 있으면 그 사실을 함께 보여 줍니다.
- 저장된 폴더가 나중에 없어지거나 내용이 맞지 않게 되면 "자산 없음"이나 설치본으로 바꾸지 않고 오류(종료 코드 2)로 끝납니다. 옵션이나 환경 변수로 준 폴더와 같은 규칙입니다.
- 설정 파일은 사용자 설정 폴더의 `config.json`입니다. 사용자 설정 폴더는 기본이 홈 폴더 아래 `~/.config/depbee/`(Windows도 홈 폴더 기준)이고, 환경 변수 `DEPBEE_CONFIG_DIR`(실행할 때마다 읽고 빈 값은 없는 것으로 봄)로 바꿀 수 있습니다. 이 변수에는 절대 경로만 줄 수 있습니다. 상대 경로는 실행한 자리의 폴더로 읽지 않고 오류(종료 코드 2)로 끝납니다. 파일에는 자산 폴더와 두 폴더의 절대 경로만 들어 있습니다.
- 현재 폴더, 대상 프로젝트, 이력 파일의 위치(`DEPBEE_HISTORY_DB`)는 사용자 설정 폴더를 바꾸지 못합니다. `DEPBEE_HISTORY_DB`는 상대 경로일 수 있어 그 폴더가 프로젝트 폴더가 될 수 있기 때문입니다. 그래서 받은 저장소 안에 `config.json`이나 `model`·`index` 폴더가 들어 있어도 쓰이지 않습니다.
- 시연이나 시험처럼 평소 설정과 분리해야 하는 환경은 이력의 `DEPBEE_HISTORY_DB`와 별도로 `DEPBEE_CONFIG_DIR`을 그 환경 전용 폴더의 절대 경로로 지정합니다. 지정하지 않으면 그 환경의 명령도 홈 폴더의 설정을 읽습니다. MCP 서버처럼 홈 폴더(`USERPROFILE`, `HOME`)를 통째로 옮긴 프로세스는 옮긴 홈 아래의 `.config/depbee/`를 씁니다.
- 사용자 설정 폴더는 본인 계정만 쓰는 폴더여야 합니다. 이 폴더의 `config.json`을 바꿀 수 있는 사람은 depbee가 신뢰하는 모델과 색인을 바꿀 수 있고, [백그라운드 대시보드](#백그라운드-실행)의 `dashboard.json`을 읽을 수 있는 사람은 그 대시보드를 쓸 수 있습니다. 폴더가 없으면 depbee가 본인 전용(권한 0700)으로 만듭니다. Windows에서는 Python 3.12.4 이상이 이 값을 폴더 소유자, SYSTEM, Administrators만 허용하는 접근 목록으로 바꾸고 폴더 안에 생기는 파일이 그 목록을 물려받습니다. 그보다 오래된 Python과 관리자 권한으로 실행한 터미널에서는 새 폴더가 상위 폴더의 권한을 물려받습니다(관리자 권한으로 만든 폴더는 소유자가 Administrators 그룹이 되므로, 소유자 전용으로 만들면 같은 사용자의 일반 터미널에서 그 폴더가 열리지 않을 수 있어서입니다). 기본 위치는 홈 폴더 아래라 어느 경우에도 계정 프로필의 권한 안에 있습니다.
- 이미 있는 폴더는 권한을 바꾸지 않고 그대로 씁니다. Windows에서 그 폴더의 접근 목록이 `Users`, `Authenticated Users`, `Everyone` 같은 그룹을 허용하면(홈 폴더 밖이나 공유 드라이브에 직접 만든 폴더가 대개 그렇고, 그 안의 파일도 같은 권한을 물려받음) 터미널에서 실행한 `depbee setup`과 `depbee dashboard --background`가 표준 오류에 주의 한 줄을 씁니다. 파이프나 파일로 받는 출력과 종료 코드는 그대로입니다. 주의가 보이면 `DEPBEE_CONFIG_DIR`을 지워 기본 폴더를 쓰거나, 아직 없는 경로를 지정해 depbee가 본인 전용 폴더를 만들게 합니다. 그 폴더를 계속 쓰려면 폴더 속성의 보안 설정에서 그 그룹의 권한을 빼되 본인 계정의 권한은 남겨 둡니다. 여러 계정이 일부러 같이 쓰는 폴더를 지정했다면, 그 계정들이 서로의 대시보드를 열고 신뢰하는 자산 경로를 바꿀 수 있다는 뜻입니다. depbee는 이를 막지 않고 알리기만 합니다. macOS·Linux에서는 depbee가 이 폴더에 만드는 파일이 폴더 권한과 관계없이 소유자 전용(0600)이라 이 주의가 없습니다.
- 설정은 같은 폴더의 임시 파일에 쓴 뒤 `os.replace`로 바꾸므로 쓰다가 실패해도 이전 파일이 남습니다. 설정 파일이 손상됐거나 depbee가 쓴 형식이 아니면(JSON 오류, 상대 경로 등) 설정이 없는 것으로 넘기지 않고 오류(종료 코드 2)로 끝납니다. `depbee setup <자산 폴더>`로 다시 저장하거나 `depbee setup --clear`로 지웁니다.
- 오래 떠 있는 `mcp`와 `dashboard`도 호출마다 설정을 읽으므로, 서버를 띄운 뒤에 저장한 설정도 다음 검사부터 쓰입니다. 검사 한 번(명령 한 번, MCP 도구 호출 한 번, 대시보드의 확인 한 번)은 저장된 설정을 한 번만 읽습니다. 그래서 검사 도중에 `depbee setup`으로 설정을 바꿔도 그 검사의 모델과 색인은 같은 저장본의 것이고, 한 보고서에 이전 모델과 새 색인이 섞이지 않습니다.
- `depbee setup <자산 폴더>`는 저장을 마치면 에이전트에 등록할 명령(Claude Code, Codex)을 실행 파일의 절대 경로와 함께 출력합니다([에이전트에 등록하기](#에이전트에-등록하기)). 이 명령은 지금 실행한 depbee가 그 Python에 설치된 사본일 때만 나옵니다(wheel 설치와 편집 가능 설치 모두 해당). 설치하지 않은 소스 폴더를 `PYTHONPATH`나 현재 폴더로 실행했거나 같은 Python에 다른 사본이 설치돼 있으면, 그 Python 옆의 `depbee` 실행 파일은 다른 사본을 띄우거나 다른 폴더에서는 실행되지 않습니다. 그때는 등록 명령 대신 에이전트가 쓸 Python 환경에 이 버전을 설치한 뒤 그 환경의 depbee로 `depbee setup <자산 폴더>`를 다시 실행하라는 안내가 나옵니다. 설정 저장은 두 경우 모두 끝난 상태입니다.

## 실행

```powershell
depbee plan C:/path/to/target --base-lock C:/path/to/base-package-lock.json
depbee scan C:/path/to/target --base-lock C:/path/to/base-package-lock.json --extract
depbee check lodash@4.17.21
depbee check lodash@4.17.21 --model-dir models/<model-id>    # 선택: 직접 준비한 모델로 한 번만
```

비교 기준은 `--base-lock <파일>`로 주거나, 생략하면 대상 폴더가 속한 Git 저장소의 HEAD 커밋에 있는 같은 위치의 `package-lock.json`을 씁니다.
다른 커밋·브랜치·태그는 `--base-ref <ref>`로 지정하며, `--base-lock`과 함께 쓸 수 없습니다.
Git은 읽기 전용 명령(`rev-parse`, `cat-file`)만 실행하고 fetch, merge-base 계산, 작업 트리·브랜치 변경은 하지 않습니다. 원격 브랜치를 기준으로 쓰려면 미리 fetch해 둡니다.
부분 복제(partial clone) 저장소에서도 없는 객체를 원격에서 자동으로 받지 않도록 `--no-lazy-fetch`와 `GIT_NO_LAZY_FETCH=1`로 실행합니다. 기준 커밋의 lockfile이 로컬에 없으면 오류(종료 코드 2)로 끝납니다. `--base-ref`와 기본 HEAD 기준에는 Git 2.45 이상이 필요하고(`--no-lazy-fetch`가 2.45에 추가됨), 그보다 오래된 Git에서는 받는 대신 필요한 버전을 알리는 오류(종료 코드 2)로 끝납니다. `--base-lock`은 Git이 필요 없습니다.
부모 프로세스의 `GIT_DIR`, `GIT_WORK_TREE` 같은 저장소 지정 환경 변수는 Git에 넘기지 않으므로 항상 대상 폴더가 속한 저장소를 읽고, replace ref(`refs/replace/`)는 적용하지 않습니다(`--no-replace-objects`). 커밋의 부모를 바꾸는 graft(`GIT_GRAFT_FILE`, `.git/info/grafts`)도 쓰지 않도록 Git에 빈 graft 파일(`GIT_GRAFT_FILE`을 null 장치로)을 줍니다.
Git 명령에는 30초 제한과 출력 크기 상한이 있습니다. 제한을 넘으면 depbee가 직접 실행한 Git 프로세스를 종료하지만 그 하위 프로세스는 종료하지 않습니다. Windows 기본 설치의 `Git\cmd\git.exe`는 실제 Git을 하위 프로세스로 실행하는 wrapper라서, 시간 초과 오류가 실제 Git이 끝날 때까지 늦어질 수 있습니다. 현재 폴더나 상대 경로 PATH 항목에서 찾은 `git`은 실행하지 않고 오류로 처리합니다. Windows에서는 인자가 cmd.exe를 거치지 않도록 `git.exe`만 실행하고 `git.cmd`·`git.bat`은 쓰지 않습니다.

`plan`은 바뀐 버전 쌍과 `request_id`를 JSON으로 출력합니다.
`scan --extract`는 바뀌거나 새로 추가된 의존성마다 tarball을 받아 feature를 추출하고 모델로 판정합니다.
텍스트 출력은 판정별 개수를 먼저 보여 주고 위험 → 보류 → 통과 → 삭제 순, 같은 판정 안에서는 ML 위험 점수가 높은 순으로 나열합니다. 완료하지 못한 항목(보류)이 있으면 통과가 아니라는 문장을 개수 아래에 따로 적습니다. 점수는 "ML 위험 점수"로 표시하며 악성 확률이 아닙니다. 점수 뒤에는 판정 기준 이상인지 미만인지를, 점수가 없으면 모델을 실행하지 않았는지(미실행) 실행하려다 실패했는지(실패)를 적습니다. 위험 항목에는 "대안(안전 보증 아님)"으로 업데이트면 lockfile의 이전 버전, 새 의존성이나 `check`면 비교 기준 버전을 한 줄 보여 줍니다. depbee가 그 버전을 검사한 것은 아니며 JSON 결과에는 이 줄이 없습니다. `--extract`로 분석하는 동안에는 진행 상황을 표준 오류에 표시합니다.
ML 위험 점수는 소수 셋째 자리까지 적되, 정확히 0이면 `0`, 0보다 크고 0.001보다 작으면 `<0.001`로 적습니다. 반올림한 값이 판정 기준 점수의 반대편에 놓이거나 기준과 같아 보이는 경우, 그리고 기준 점수가 0.001보다 작아 `<0.001`만으로는 기준 이상인지 알 수 없는 경우에는 저장된 값을 줄이지 않고 그대로 적습니다. 판정 기준 점수는 지수 표기 없이 전체 자릿수로 적고, 보고서에 없으면 "기록 없음"으로 적습니다. 적은 점수가 저장된 값과 다르면(반올림했거나 `<0.001`로 적은 경우) 항목 상세에 "점수 원값"으로 JSON과 같은 값을 함께 적습니다. 대시보드의 실행 상세와 후보 근거는 점수가 있는 항목마다 원값을 화면의 글자로 보입니다. 이 표시는 텍스트, Markdown, 대시보드, 업데이트 반영 목록, GitHub Action 주석에 똑같이 적용되며 JSON의 `score`와 `threshold`, 판정과 종료 코드는 바꾸지 않습니다.
`--format json`은 같은 결과를 lockfile 순서 그대로 JSON으로 출력하고(진행 표시 없음), `--output`은 결과를 새 파일에 저장합니다(기존 파일을 덮어쓰지 않습니다). 이미 있는 경로를 주면 다운로드나 분석을 시작하기 전에 오류(종료 코드 2)로 끝납니다. 경로 중간에 폴더가 아닌 파일이 있을 때도 같습니다(예: `package.json/report.json`). 아직 없는 폴더는 depbee가 만듭니다.
`--format markdown`(`scan`, `check`)은 같은 결과를 GitHub job summary 등에 붙일 수 있는 한국어 Markdown(전체 판정, 결과 표, 위험 항목의 대안 버전과 그 위치, 항목별 추출된 사실과 모델 설명)으로 출력합니다. 판정·이유·종료 코드와 표시 내용은 텍스트·JSON과 같습니다. 순서는 텍스트와 같고 진행 표시는 없으며, `--output` 파일은 이때도 JSON입니다. 패키지 이름·버전·근거처럼 보고서에서 온 문자열은 모두 code span으로 감싸 HTML·링크·이미지·강조로 해석되지 않게 합니다.
오류는 표준 오류에 JSON으로 나옵니다.
tarball은 Python 임시 폴더에 풀었다가 지웁니다. 위치를 바꾸려면 `TMP`/`TEMP` 환경변수를 지정합니다.
registry 메타데이터와 tarball은 depbee가 직접 받습니다(depbee-analyzer는 받은 것을 읽기만 합니다). `https://registry.npmjs.org`에서만, redirect 뒤에도 그 주소에서만 받고, tarball 주소는 그 패키지·버전의 registry 경로(`/<이름>/-/<이름>-<버전>.tgz`)여야 합니다. 거부한 주소는 오류에 scheme과 host만 적고 다운로드 오류는 HTTP 상태 코드나 오류 종류만 적어, 주소나 서버 응답에 든 자격 증명·토큰이 보고서에 옮겨지지 않습니다. 받은 tarball 바이트는 그 버전의 `dist.integrity`(가장 강한 해시 알고리즘, npm과 같은 방식)와 대조한 뒤에만 풉니다.
다운로드는 메타데이터 128 MiB, tarball 128 MiB를 넘으면 멈추고, 압축 해제는 풀린 크기 512 MiB와 파일 20,000개를 넘으면 멈춥니다. tarball 안의 symbolic link는 풀지 않고(npm도 설치하지 않습니다), hard link는 가리키는 파일의 크기로 셉니다.
분석하는 변경 하나(메타데이터 조회, tarball 두 개 다운로드, 압축 해제, feature 추출, 그 결과와 캐시의 처리)에는 그 변경을 분석하기 시작할 때부터 재는 시간 예산 300초가 있습니다(`check`는 메타데이터 조회부터). 같은 패키지가 여러 위치에 있어 메타데이터나 캐시를 재사용하는 변경도 따로 예산을 씁니다. 이 작업들은 별도의 Python 프로세스에서 실행되고, 예산이 끝나면 그 프로세스를 강제로 종료해 진행 중이던 연결과 파일 작업도 함께 멈춥니다. depbee 자신이 하는 짧은 작업(호출 준비, 프로세스 시작, 결과와 메타데이터 해석, 캐시 읽기·검사·쓰기, 근거 정리)은 중간에 끊지 못해 예산을 그만큼 넘길 수 있지만, 예산이 지난 뒤 끝난 결과는 쓰지 않고 새 캐시 항목도 게시하지 않습니다. 예산 안에 시작한 캐시 파일 게시(파일 이름 바꾸기)가 늦게 끝나면 그 항목은 남지만(예산 안에 만든 feature입니다) 이번 결과는 쓰지 않습니다. 이미 있던 캐시 항목은 지우거나 되돌리지 않습니다. 하나라도 넘거나 맞지 않으면 그 항목은 분석 실패(`incomplete`, 종료 코드 2)입니다. 값의 근거는 [검증 기록](validation.md)에 있습니다.

`check NAME@VERSION`은 lockfile 없이 npm 공식 registry의 버전 하나를 `scan --extract`와 같은 방식(같은 release line의 직전 stable과 비교)으로 검사합니다. 설치 전에 특정 버전을 확인할 때 씁니다.
`lodash@4.17.21`이나 `@scope/name@1.0.0`처럼 정확한 이름과 버전만 받고, 범위(`^1.0.0`)·태그(`latest`)·URL·Git·파일 경로·사설 registry는 네트워크에 접근하기 전에 오류(종료 코드 2)로 거부합니다.
버전은 npm이 버전을 표시하는 build metadata 없는 형식(`1.2.3`, `1.2.3-beta.1`)만 지원합니다. `1.2.3+build.1`처럼 `+`가 붙은 버전은 SemVer 문법상 유효하지만 이 명령의 지원 범위가 아니라서 거부합니다. 숫자로만 된 pre-release 식별자의 선행 0(`1.0.0-01`)처럼 SemVer에 맞지 않는 버전도 거부합니다.
registry 메타데이터는 한 번만 받아 요청, 분석, feature 추출(depbee-analyzer의 snapshot)에 함께 씁니다. 그 버전이 registry에 없거나, tarball 주소가 `https://registry.npmjs.org`가 아니거나, `dist.integrity`가 없거나, 메타데이터 형식이 잘못됐으면 오류(종료 코드 2)로 끝납니다.
pre-release와 비교할 이전 stable이 없는 버전은 `scan`과 같이 `incomplete`입니다.
결과에는 "lockfile 없이 registry 정보로 검사"했다는 범위(`input_kind: "package"`)와 근거가 표시됩니다. 출력 형식, `--output`, 진행 표시(텍스트만), 종료 코드는 `scan`과 같습니다.

`scan --extract`와 `check`는 추출한 feature를 캐시 폴더(기본 `~/.cache/depbee`, `--cache-dir`로 변경)에 저장해, 같은 두 버전을 다시 비교할 때 tarball을 다시 받거나 추출하지 않습니다. registry 메타데이터는 매번 다시 받아 확인하고, 판정·점수·근거는 매번 새로 계산합니다.
캐시 키는 패키지와 비교한 두 버전, 두 버전의 registry manifest·integrity·배포 시각, feature 스키마, depbee 버전과 캐시 형식 번호, 설치된 depbee-analyzer의 출처(고정 커밋, 설치 파일 해시, Python 버전), 모델 파일과 manifest의 해시입니다. 하나라도 다르면 다시 추출합니다. depbee 코드는 해시하지 않으므로, 버전을 올리지 않고 추출 결과를 바꾸는 변경은 개발자가 캐시 형식 번호를 올려야 이전 항목을 쓰지 않습니다([검증 기록](validation.md)).
모델이 없을 때, depbee-analyzer가 고정 커밋 그대로 설치됐는지 확인할 수 없을 때(편집 가능 설치, 로컬 폴더 설치, 설치 후 수정), 로컬 사본(`--local-source`)으로 읽은 버전, 분석에 실패한 항목은 캐시를 쓰지 않습니다. `--no-cache`는 캐시를 읽지도 쓰지도 않습니다.
캐시한 feature는 모델이 점수를 낼 수 있는 이름과 자료형인지 다시 확인하고, 아니면 쓰지 않고 다시 추출합니다. 모델이 받지 못하거나 학습에 없던 범주 값이라 점수를 내지 않는 feature는 처음부터 저장하지 않습니다. 캐시 항목은 일반 파일일 때만 읽고(FIFO·장치 파일은 기다리지 않고 건너뜀), 형식과 키만 검사하므로 누가 썼는지는 보증하지 못합니다. 다른 사람이나 PR이 쓸 수 있는 폴더를 캐시로 지정하지 않습니다. 캐시는 자동으로 지우지 않으므로 필요하면 폴더를 직접 지웁니다.
두 명령의 결과에는 전체 소요 시간(`elapsed_seconds`)과, 항목별로 메타데이터 조회·캐시 조회·추출에 걸린 시간(추론 제외)과 캐시 사용 여부(`cache_hit`)가 붙습니다. `--extract` 없는 `scan`과 `plan`의 출력에는 이 시간 필드가 없습니다.
`scan`·`check`의 JSON 결과에는 출처(`provenance`)도 있습니다. 확인한 모델 파일·manifest의 SHA-256과, 설치된 depbee-analyzer의 고정 커밋·설치 파일 해시·Python 버전이며, 모델이 없거나 depbee-analyzer로 추출하지 않았거나 설치 출처를 확인하지 못하면 해당 값은 null입니다.
JSON 결과에는 기지 악성·규칙 탐지기 칸(`detectors`, 항목별 `known_malicious`·`rules`)과 ML 경로만의 상태(`ml`), 규칙/ML 일치 여부(`rule_ml_agreement`)도 있습니다. 기지 악성 목록은 기본으로 [설치본 색인](#기본-자산)이 연결되고, `--known-malicious-dir`(또는 `DEPBEE_KNOWN_MALICIOUS_DIR`)로 다른 색인을 지정할 수 있습니다([기지 악성 탐지기](#기지-악성-탐지기)). 규칙 탐지기는 depbee-analyzer로 추출하는 실행(`scan --extract`, `check`, `update`, `mcp`, `dashboard`)에 연결되며, 고정한 depbee-analyzer의 정적 규칙 여섯 개를 특징 추출에 쓴 같은 두 버전에서 실행합니다. 규칙 적중은 강도(검토용 적중, 강한 정적 근거)와 근거, 파일·행으로 보이고 판정과 종료 코드를 바꾸지 않습니다. 규칙별 `실패`의 상세가 `판정 불가`로 시작하면 그 규칙이 읽는 파일이 크기 제한·링크 등으로 빠졌거나 분석기가 판정을 유보한 것이고, 규칙 칸의 상세가 `규칙 스캔 오류`이면 스캔 자체가 실패한 것입니다. 둘 다 미적중이 아니며, 그 항목은 기지 악성 기록과 일치하면 위험이고 아니면 보류입니다(ML 경로가 이미 보류였으면 원래 이유가 남습니다). 연결되지 않은 탐지기는 "연결 안 됨"(`not_run`)으로 나오고 판정에 쓰이지 않습니다. 연결된 탐지기가 하나도 없는 보고서는 판정과 종료 코드가 모델 결과만으로 정해집니다. 텍스트·Markdown 출력도 개수 아래에 연결되지 않은 탐지기를 "연결 안 됨(미실행)"으로, 연결된 기지 악성 목록은 출처와 기준 시점으로 한 번 적습니다. 탐지기가 연결된 보고서라면 텍스트·Markdown은 기지 악성 기록 일치를 맨 위에 경고로 강조하고(낮은 ML 위험 점수는 이 경고를 취소하지 않음), 항목마다 기지 악성(일치·미적중·미실행·실패)과 규칙(적중·미적중·미실행·실패, 규칙별 근거와 위치) 결과, 그리고 판정에 쓰지 않는 규칙/ML 일치 표시를 따로 보여 줍니다. 규칙 중 일부가 적중하고 일부가 실패한 항목은 규칙 칸에 "적중, 실패 N개"로 함께 보입니다. 이 필드들이 없는 예전 보고서는 탐지기 칸을 "확인 안 됨"으로 보이고(미적중으로 읽지 않음), ML 상태는 판정과 이유에서 구한 값에 "참고값"을 붙여 보입니다. 필드 정의는 [연결 규약](contracts.md) 4절에 있습니다.

`scan`과 `check`에서 `--model-dir`을 생략하면 환경 변수 `DEPBEE_MODEL_DIR`의 모델 폴더를, 그것도 없거나 빈 값이면 [`depbee setup`으로 저장한 모델 폴더](#자산-폴더-설정-depbee-setup)를 씁니다. `--model-dir`이 항상 우선하고, 옵션, 환경 변수, 저장한 설정이 모두 없으면 [설치본 모델](#기본-자산)을 씁니다.
지정한 경로가 잘못되면 설치본이나 다른 모델로 대체하지 않고 오류(종료 코드 2)로 끝납니다. 대상 프로젝트의 설정에서는 모델 경로를 읽지 않습니다.
지정한 폴더의 모델은 신뢰한 입력으로 다루므로(manifest와 모델 해시만 대조합니다) 직접 준비한 신뢰할 수 있는 모델 폴더만 지정합니다.

다른 분석기가 만든 결과가 있으면 `--extract` 대신 `--analysis <분석 JSON>`을 씁니다.
registry에서 내려간 버전(예: 삭제된 악성 버전)을 시연할 때는 `--local-root <폴더>`와 `--local-source NAME@VERSION=<폴더 안의 상대 경로>`로 그 버전의 사본을 지정합니다.
사본은 lockfile integrity로 확인할 수 없어 결과의 근거에 그 사실이 표시됩니다.

예시 lockfile(`examples/`)에는 패키지 코드가 없고 URL·integrity가 가상 값이라 `--extract`로는 분석되지 않습니다.

### 터미널에서 보는 화면

사람이 터미널에서 직접 실행할 때만 붙는 표시가 있습니다. 표준 출력이 터미널이 아니면(파이프, 파일로 보내기, 다른 프로그램이 받는 출력) 붙지 않으므로, 텍스트 출력을 읽는 스크립트와 `--format json`·`--format markdown`·`--output` 파일, MCP, GitHub Action의 결과는 전과 같습니다. 판정, 이유, 종료 코드는 어느 경우에도 같습니다.

- 시작 화면: 인수 없이 `depbee`를 실행하면 벌 인장과 버전, 자주 쓰는 명령 여섯 개, 종료 코드의 뜻을 보여 줍니다. 검사한 것이 없으므로 종료 코드는 전과 같이 2입니다(통과로 읽히지 않게). `depbee --help`는 같은 머리말과 명령 안내에 argparse의 명령 목록을 더한 것이고 종료 코드 0입니다. 명령 안내는 화면 폭에 맞춰 명령과 설명을 한 줄에 두거나, 좁으면 설명을 명령 아래 줄에 둡니다. 표준 출력이 터미널이 아니면 벌 인장 대신 `depbee <버전>` 한 줄로 시작합니다.
- 벌 인장: ASCII 문자만 쓴 세 줄 그림(시작 화면, `--help`)과 한 줄 표시 `-(||||)o`(텍스트 결과의 첫 줄 앞)입니다. 콘솔 코드 페이지나 글꼴과 관계없이 보입니다.
- 색: 전체 판정과 항목 머리의 `[위험]`은 빨강, `[보류]`는 노랑, `[통과]`는 초록, 기지 악성 일치 경고는 빨강, 보류 안내는 노랑입니다. 색은 이미 글자로 적힌 판정을 다시 표시할 뿐이라 색이 없어도 빠지는 정보가 없습니다. 환경 변수 `NO_COLOR`가 있거나(빈 값 제외) `TERM=dumb`이거나, Windows 콘솔이 ANSI 색(가상 터미널 모드)을 받지 않으면 색 없이 같은 글자만 나옵니다. 벌 인장과 다음 동작은 색과 관계없이 나옵니다.
- 다음 동작: `scan`, `check`, `update`의 텍스트 결과 끝에 지금 할 일을 급한 순서로 적습니다. 기지 악성 기록과 일치한 항목은 설치하지 말 것, ML 위험 점수가 기준 이상인 항목은 근거를 검토할 것, 보류는 통과가 아니며 원인이 모델 없음이면 `depbee setup`이나 `--model-dir`, 분석 없음이면 `--extract`로 다시 실행할 것, 기지 악성 목록이 연결되지 않았으면 그 사실과 연결 방법, 위험·보류가 없으면 검사한 버전 그대로 설치할 것을 안내합니다(삭제된 의존성만 있어 설치할 버전이 없는 결과에는 이 설치 안내를 붙이지 않음). `update` 미리보기에는 반영 방법(`--apply lockfile`, `--apply install`)과, 반영할 때 확인이 필요한 항목 수와 `--confirm-warnings`가 필요하다는 것을 적습니다. 기지 악성 일치가 있으면 반영할 수 없다고 적습니다. 이 안내는 보고서의 항목별 값과 반영 게이트(`update --apply`가 쓰는 것과 같은 함수)에서만 만들며 판정을 바꾸지 않습니다. 긴 문장은 화면 폭에 맞춰 띄어쓰기에서 줄을 바꿉니다.
- `plan`은 표준 출력에 JSON만 내보냅니다. 터미널에서 실행했을 때만 바뀐 의존성 수와 검사 명령 안내 한 줄을 표준 오류에 씁니다.
- 한글 도움말과 화면이 인코딩할 수 없는 문자 때문에 중단되지 않도록, depbee는 표준 출력에 쓸 수 없는 문자를 `\uXXXX` 꼴로 바꿔 씁니다(보고서 출력이 전부터 쓰던 방식).

## 기지 악성 탐지기

depbee는 바뀐 의존성의 정확한 이름·버전을 공개 악성 기록 목록과 대조합니다. 기본으로 [설치본 색인](#기본-자산)(기준 시점 `2026-10-06T14:00:47Z`)을 쓰고, `--known-malicious-dir <색인 폴더>`로 직접 만든 색인을 지정할 수 있습니다. 목록은 OSV(공개 취약점·악성 기록 DB)의 npm `MAL-` 기록(OpenSSF Malicious Packages, Apache-2.0)을 한 시점에 통째로 받은 스냅샷으로 만든 색인입니다. 실행 중에는 OSV에 묻지 않으므로 같은 색인이면 같은 결과가 나옵니다.

```powershell
depbee scan C:/path/to/target --extract                                     # 설치본 색인과 대조
depbee check lodash@4.17.21 --known-malicious-dir models/known-malicious    # 선택: 직접 만든 색인과 대조
```

- 대조 대상: `MAL-` 기록만 씁니다. GHSA·CVE 같은 일반 취약점 기록은 넣지 않으므로, GHSA에만 있는 과거 탈취 사건(예: `event-stream` 3.3.6)은 잡지 못합니다. 철회(`withdrawn`)된 기록은 쓰지 않고, 스냅샷을 받은 시점 이후에 올라온 기록은 없습니다.
- 미적중(`not_hit`)은 "이 목록에 없다"는 뜻일 뿐 안전 판정이 아닙니다.
- 일치 규칙: 이름은 대소문자까지 정확히 같아야 하고(scoped 포함, 정규화하지 않음), 버전은 SemVer 2.0 우선순위로 비교합니다(build metadata `+...`는 무시). 기록의 버전 목록에 있으면 `listed_version`, 범위(`introduced`·`fixed`·`last_affected`, 기록 순서가 아니라 버전 순으로 평가) 안이면 `affected_range`입니다. build를 뗀 버전이 엄격한 SemVer가 아니면(앞자리 0 등) 그 항목의 대조는 실패(`failed`, 보류)입니다.
- 범위 정책: 버전 목록이 있는 기록은 그 목록과 상한 있는 범위(`fixed`·`last_affected`로 닫힌 구간)만 적중으로 봅니다. 상한 없는 범위(모든 버전, "X 이상")는 버전 목록이 없는 기록에서만 씁니다. 그래서 목록과 "모든 버전" 범위를 함께 적은 기록에서 목록 밖 버전은 미적중입니다.
- npm 보안 대체 버전 `0.0.1-security`는 기록이 무엇이든 적중으로 보지 않습니다. 같은 기록의 다른 버전은 그대로 적중합니다.
- 판정: 일치하면 ML 점수와 관계없이 그 항목은 위험(`flagged`, 종료 코드 1)이고 낮은 점수는 이 경고를 취소하지 않습니다. 분석하지 않는 `--extract` 없는 `scan`도 이름·버전을 대조합니다.
- 비교 기준 후보 제외: 색인이 연결된 실행에서는 기록의 명시 버전이나 상한 있는 범위에 든 버전을 비교 기준 후보에서 빼고 다음 후보와 비교하며, 근거에 "비교 기준 후보에서 뺌: <버전> (기지 악성 기록 <ID>)"를 더합니다. 모든 버전·"X 이상" 범위와 철회 기록은 이 제외에 쓰지 않습니다. 후보가 모두 빠지면 비교 기준 없음(`no_baseline`, 보류)입니다. 그래서 색인 유무에 따라 비교 버전·feature·점수가 달라질 수 있습니다. `--analysis`로 준 분석 결과에는 적용되지 않습니다.
- 옵션과 환경 변수: `scan`, `check`, `update`, `mcp`, `dashboard`가 같은 옵션을 받습니다. 생략하면 환경 변수 `DEPBEE_KNOWN_MALICIOUS_DIR`(호출마다 읽음)의 폴더를, 그것도 없거나 빈 값이면 [`depbee setup`으로 저장한 색인 폴더](#자산-폴더-설정-depbee-setup)를 씁니다. 옵션, 환경 변수, 저장한 설정이 모두 없으면 [설치본 색인](#기본-자산)을 씁니다. 대상 프로젝트의 설정에서는 읽지 않습니다. 색인이 연결되지 않은 보고서(`detectors.known_malicious`가 null, 항목은 "연결 안 됨")는 상태와 종료 코드가 ML 경로로만 정해집니다.
- 지정한 색인 폴더가 없거나, 읽을 수 없거나, `index.json`의 SHA-256이 `manifest.json`의 `index_sha256`과 다르거나, 형식·자료형·목록 시점이 어긋나면 "색인 없음"이나 설치본 색인으로 바꾸지 않고 보고서 없이 오류(종료 코드 2)로 끝납니다. `scan`·`check`는 registry를 조회하기 전에, `update`는 모델처럼 npm 미리보기 뒤 새 lockfile을 검사할 때 읽습니다. 이 폴더의 색인은 신뢰한 입력으로 다루므로 직접 만들었거나 SHA-256을 확인한 색인만 지정합니다.
- 보고서의 `detectors.known_malicious`에는 출처(`source`: `OSV npm MAL`), 목록 시점(`list_as_of`), `index.json`의 SHA-256(`list_sha256`)이 남습니다.

### 색인 만들기

설치본 색인보다 새로운 기록이 필요하거나 색인을 직접 만들어 쓸 때만 필요합니다. OSV npm 전체 덤프 `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip`을 받고, 받은 UTC 시각을 `--as-of`(ISO 8601, `Z`로 끝남)로 넘깁니다.

```powershell
python scripts/build_known_malicious_index.py C:/path/to/all.zip models/known-malicious --as-of 2026-10-06T14:00:47Z
```

- 결과는 폴더 하나(`index.json`, `manifest.json`)이고 이미 있는 파일은 덮어쓰지 않습니다. 같은 zip과 같은 `--as-of`면 바이트까지 같은 `index.json`이 나옵니다.
- zip은 메모리에서 읽고 풀어 쓰지 않습니다. `MAL-*.json`만 쓰고, 그 밖의 파일, 철회 기록, SEMVER가 아닌 범위·`limit` 이벤트·SemVer가 아닌 버전(npm semver처럼 major·minor·patch는 2^53-1 이하, prerelease 숫자는 길이 상한 없이 수치 순서로 비교) 같은 기대 밖 형태는 조용히 버리지 않고 이유별 건수로 `index.json` 머리와 스크립트 출력에 남깁니다. 버전 목록이 있었는데 쓸 수 있는 버전이 하나도 없으면 그 항목은 "목록 없는 기록"으로 바꾸지 않고 뺍니다.
- 중앙 디렉터리가 64 MiB를 넘거나 항목이 200만 개를 넘는 zip, 압축 해제 합계가 4 GiB를 넘는 zip, 암호화·지원 밖·손상된 zip은 읽기 전에 또는 읽는 중에 오류로 끝납니다(traceback 없이 오류 문구와 0이 아닌 종료 코드).
- 2026-10 스냅샷 기준 `index.json`은 약 15 MB이고, 만드는 데 약 23초, 읽고 검사하는 데 1~2초가 걸립니다. 오래 떠 있는 `mcp`·`dashboard`는 같은 파일이면(경로, 크기, 수정 시각, 두 파일의 SHA-256) 검사한 색인을 다시 씁니다.
- 색인 형식은 [연결 규약](contracts.md) 4절에 있습니다.

## 업데이트 미리보기 (`depbee update`)

`depbee update`는 npm이 지금 프로젝트에 `npm update`를 하면 바뀔 lockfile을 임시 폴더에서 계산하고, 그 변경을 `scan --extract`와 같은 방식으로 검사합니다. 미리보기만 하며 프로젝트의 파일은 아무것도 바꾸지 않습니다. 검사한 결과를 프로젝트에 반영하려면 `--apply`를 줍니다([업데이트 반영](#업데이트-반영-depbee-update---apply)).

```powershell
depbee update --project C:/path/to/target
depbee update lodash semver --project C:/path/to/target --format markdown
```

- Node.js와 npm(Node.js에 함께 설치된 것), 분석용 `extract`가 필요합니다. `--project`를 생략하면 현재 폴더입니다. `--format`, `--output`, `--model-dir`, `--known-malicious-dir`, `--cache-dir`/`--no-cache`는 `scan`과 같습니다.
- 대상은 `package.json`의 `dependencies`·`devDependencies`·`optionalDependencies`에 있는 패키지 이름만 받습니다(`lodash`, `@scope/name`). 버전이나 범위(`lodash@4.17.21`, `^4`)는 받지 않고, 이름을 주지 않으면 전체를 미리봅니다. npm `update`라서 `package.json`에 적힌 범위 안에서만 올립니다. `-`·`.`·`_`로 시작하는 이름, ASCII가 아닌 문자, 공백, `:`, `\`, `%&|^<>"`가 든 이름, 214자를 넘는 이름, `package.json`에 없는 이름은 npm을 실행하기 전에 오류(종료 코드 2)로 끝납니다.
- 임시 폴더(Python 임시 폴더 아래 `depbee_preview_*`, `TMP`/`TEMP`를 따름)에 `package.json`과 `package-lock.json`만 복사하고, 그 안에서 `npm update --package-lock-only --ignore-scripts --no-audit --no-fund --no-update-notifier --no-progress --color=false --loglevel=warn --dry-run=false --package-lock=true --prefix=<임시 폴더> --workspaces=false --git=<없는 파일> -- <이름...>`을 실행합니다. `--dry-run=false`·`--package-lock=true`는 사용자·전역 npm 설정의 `dry-run=true`나 `package-lock=false`가 npm이 새 lockfile을 쓰지 않고 성공으로 끝나게 만들어(업데이트가 있는데 바뀐 항목 0개로 보임) 고정합니다. 그 전에 npm 버전을 읽는 `--version`에도 `--prefix`·`--workspaces=false`·`--git`을 같이 줍니다(npm은 `--version`에도 설정을 읽으며 상위 workspace를 찾습니다). 패키지를 설치하거나 lifecycle script를 실행하지 않습니다. registry 의존성만 있는 정상 데모에서는 npm이 tarball을 받지 않고 registry 메타데이터만 읽었습니다(npm 11.6.1에서 확인, [검증 기록](validation.md)). `--prefix`와 `--workspaces=false`는 npm이 임시 폴더 위의 workspace 루트를 찾아 그 폴더의 lockfile을 쓰지 않게 합니다. `--git`은 npm이 실행할 Git 프로그램을 없는 파일로 정해, 새로 받은 패키지 정보가 Git 의존성을 가져와도 Git이 실행되지 않고 npm이 실패(종료 코드 2)하게 합니다. Git 호스트(GitHub 등)의 커밋을 40자 sha로 정확히 가리키는 의존성은 알려진 예외로, 막지 않습니다. update 중 registry에서 새로 받은 패키지가 그런 의존성을 가지면 npm 11.6.1은 Git 없이 그 호스트에서 커밋의 tarball을 받아 npm 캐시의 임시 폴더(`_cacache/tmp/git-clone*`)에 풀고, 그 패키지에 준비용 script(`prepare`, `build`, `install` 등)나 `workspaces`가 있으면 그 폴더에서 준비용 설치(`npm install --force ... --no-package-lock-only --no-dry-run`)를 실행할 수 있습니다(pacote 21.0.3 `lib/git.js` 43-50·152-188·193-248·297-310행, `lib/fetcher.js` 98-120행, `lib/util/npm.js` 4-13행). 이 설치는 원본 프로젝트나 depbee 임시 폴더와 무관하고, 상속된 `npm_config_ignore_scripts=true`와 `npm_config_git` 때문에 lifecycle script와 Git은 실행되지 않는다고 소스로 판단하지만 실행으로 확인하지 않았습니다. npm 11에는 이를 끄는 설정이 없고, npm 12는 Git 의존성을 `--allow-git` 없이는 막습니다(GitHub Changelog 2026-06-09, 실행하지 않음). 끝나면 npm과 npm이 띄운 프로세스가 모두 끝난 것을 확인한 뒤 임시 폴더를 지우고, 지우지 못하면 오류(종료 코드 2)입니다.
- 새 lockfile은 지금 `package-lock.json`과 비교해 `scan --extract`와 같은 판정·근거·종료 코드로 보여 줍니다. 텍스트·Markdown은 앞에 미리보기 요약(대상, npm 버전, `package.json` 변경 여부, 바뀐 항목 수, 안내)을 붙이고, JSON(`--format json`, `--output`)은 `{"preview": {...}, "report": <scan 보고서>}`입니다([연결 규약](contracts.md) 5절).
- 프로젝트의 `.npmrc`는 복사하지 않습니다. 있으면 "프로젝트 .npmrc는 복사하지 않았습니다. 사용자·전역 npm 설정은 적용될 수 있습니다."라고 안내합니다. 사용자 설정 파일(`~/.npmrc`)은 npm이 평소처럼 읽으므로 그 안의 registry·scope별 registry 설정이 미리보기에 쓰일 수 있고, depbee는 그 내용을 읽거나 출력하지 않습니다. 명령줄로 고정한 값(위 인자)은 사용자 설정이 바꿀 수 없습니다. 고정하지 않아 사용자 설정이 남는 것 중 결과에 영향을 주는 것은 `save`(켜면 npm이 `package.json`의 범위도 고쳐 미리보기에 `package.json` 바뀜으로 보이고 반영 때 함께 씀), `before`(그 시각 이전 버전으로만 올림), `lockfile-version`(lockfile 형식)입니다. `global`·`location=global`은 lockfile만 계산하는 갱신에서 npm이 오류로 끝나므로 미리보기도 오류(종료 코드 2)입니다. 부모 프로세스의 `npm_config_*` 환경 변수와 `NODE_OPTIONS`는 npm에 넘기지 않고 `npm_config_ignore_scripts=true`를 넣습니다.
- npm은 Windows에서 `npm.cmd`·`npm.ps1`이 아니라 PATH에서 찾은 `node.exe`(절대 경로)와 그 옆 `node_modules\npm\bin\npm-cli.js`로 셸 없이 실행합니다(cmd.exe의 인자 재해석을 피함). macOS·Linux에서는 `node` 위치 기준 `../lib/node_modules/npm/bin/npm-cli.js`를 씁니다. 찾지 못하면 오류입니다.
- npm 실행에는 호출마다 120초 제한과 출력 상한(stdout 1 MiB, stderr 64 KiB)이 있고, 실패·시간 초과·`node_modules` 생성·읽을 수 없는 새 lockfile은 판정 없는 오류(종료 코드 2)입니다. 시간 초과나 출력 상한에 걸리면 npm이 띄운 하위 프로세스까지 함께 종료합니다(Windows는 Job Object, macOS·Linux는 프로세스 그룹). Windows의 Job에는 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`를 설정해 depbee가 강제로 끝나 Job 핸들이 닫혀도 남은 프로세스가 종료됩니다. npm은 일시 정지 상태로 만들어 Job에 넣은 뒤 `ntdll`의 `NtResumeProcess`로 시작합니다. 이 함수는 Microsoft가 문서화하지 않은 API이며 psutil의 `Process.resume()`도 같은 함수를 씁니다(`psutil/arch/windows/proc.c`). Windows 11 64비트에서만 확인했고 32비트·다른 Windows 버전은 확인하지 않았습니다. macOS·Linux의 프로세스 그룹은 새 세션을 만든 후손까지 묶지 못합니다. npm 출력에는 주소나 토큰이 있을 수 있어 오류에 옮기지 않고 종료 코드만 적습니다. 임시 폴더를 만들거나 지우지 못한 오류와 그 안 파일에 관한 오류도 그 경로를 적지 않습니다.
- 지원하지 않는 프로젝트(npm을 실행하기 전에 오류, 종료 코드 2): `npm-shrinkwrap.json`이 있음, `package.json`에 `workspaces`가 있음, `package.json` 의존성이 registry 버전·범위·태그가 아님(Git·파일·URL·`npm:` alias처럼 `:`·`/`·`\`가 든 값, `..`처럼 `.`으로 시작하는 값, npm-package-arg가 파일로 읽는 `.tgz`·`.tar.gz`·`.tar`로 끝나는 값(대소문자 무관, npm 정규식의 가운데 점은 아무 문자라 `x.tarXgz`도 포함), 제어 문자가 든 값), `overrides`(중첩 포함)의 값이나 키의 범위가 같은 기준을 벗어남(값은 루트 의존성을 가리키는 `$이름`도 허용), lockfile v2/v3가 아님, lockfile에 링크·workspace 항목, `https://registry.npmjs.org/` 밖의 `resolved`(Git, file, 사설 registry 등), registry 범위가 아닌 항목별 의존성 값이 있음.

## 업데이트 반영 (`depbee update --apply`)

`depbee update`에 `--apply`를 주면 같은 명령 안에서 미리보기와 검사를 마친 뒤, 아래 확인을 모두 통과할 때만 이번 실행에서 검사한 lockfile을 프로젝트에 반영합니다. 미리보기 결과를 따로 보관하지 않습니다.

```powershell
depbee update --project C:/path/to/target --apply lockfile
depbee update lodash --project C:/path/to/target --apply install --confirm-warnings
```

- `--apply lockfile`: 검사한 `package-lock.json`을 프로젝트에 씁니다(npm이 `package.json`도 바꿨다면 함께). `node_modules`는 건드리지 않습니다.
- `--apply install`: lockfile을 반영한 뒤 프로젝트에서 `npm ci --ignore-scripts`를 실행합니다. `npm ci`는 기존 `node_modules`의 내용을 지우고 lockfile 그대로 다시 설치합니다.
- 반영 게이트: 최상위 종료 코드가 아니라 항목별 판정으로 정합니다.
  - 기지 악성 기록 일치(`known_malicious.status`가 `hit`)가 하나라도 있으면 반영·설치하지 않습니다. 확인 옵션으로도 바꿀 수 없습니다.
  - 새로 설치되는 버전이 있는 항목 중 ML 위험 점수 기준 이상(`ml.status`가 `hit`), 보류(`incomplete`), 기지 악성 목록과 대조하지 못한 항목(`known_malicious.status`가 `not_run`이나 `failed`)이 있으면 그 목록(판정, 이유, ML 위험 점수, 탐지기 상태)을 보여 주고 반영하지 않습니다. 목록을 검토한 뒤 `--confirm-warnings`를 함께 주면 한 번의 확인으로 모두 진행하고, 확인한 사실과 항목을 결과와 이력에 남깁니다.
  - 삭제 항목은 설치되는 것이 없어 확인 대상이 아닙니다. 그래서 삭제만 있는 반영은 확인 없이 진행합니다. 다만 삭제 항목도 기지 악성 기록과 일치하면 위와 같이 거부합니다.
  - 기지 악성 목록과 대조하지 못한 실행(보고서의 `detectors.known_malicious`가 null)에서는 새로 설치되는 모든 버전이 미확인이므로, 새로 설치되는 버전이 있는 반영마다 `--confirm-warnings`가 필요합니다. 기본으로 연결되는 설치본 색인이나 지정한 색인과 대조하면 미적중(`not_hit`)인 항목은 미확인 원인에서 빠집니다.
  - `--confirm-warnings`는 `--apply`와 함께만 받습니다. 없이 주면 npm을 실행하기 전에 오류(종료 코드 2)입니다.
- 반영 직전 재확인: 프로젝트를 미리보기와 같은 지원 범위 검사로 다시 읽고, `package.json`·`package-lock.json`의 SHA-256이 미리보기 때와 같고 쓸 lockfile의 SHA-256이 검사한 새 lockfile과 같을 때만 반영합니다. npm이 계산한 새 `package.json`·`package-lock.json`도 같은 지원 범위 검사(registry 밖 `resolved` 거부 등)를 통과해야 합니다. 하나라도 어긋나면 아무것도 바꾸지 않습니다.
- `--apply install`의 추가 조건(어긋나면 아무것도 바꾸지 않고 거부): 새 lockfile의 모든 `node_modules/` 항목마다 npm이 받은 바이트와 대조할 수 있는 유효한 `integrity`(ASCII 공백·탭·LF·CR로만 나눈 값 하나하나가 `sha512`·`sha384`·`sha256`·`sha1` 중 하나와 그 길이에 맞는 base64 digest이고, 그 밖의 문자는 어디에 있든 거부)가 있어야 합니다. 비었거나 공백뿐이거나 해시 형식이 아닌 값은 npm이 대조 없이 받으므로 거부합니다. bundled 항목(`inBundle`)도 예외가 아닙니다. 루트의 `bundleDependencies` 항목이나 부모 tarball에 없는 항목은 npm이 따로 받기 때문입니다. 그래서 `bundleDependencies`를 쓰는 프로젝트는 대개 install이 거부되며, `--apply lockfile`로 반영한 뒤 직접 설치하세요. `--apply lockfile`은 `integrity`가 없거나 유효하지 않아도 반영합니다. 또 아래 `npm ci`용 임시 폴더를 백업·교체보다 먼저 만들어, 링크·정션을 푼 실제 경로가 프로젝트 안이면(Windows는 대소문자 무시, 예: `TMP`·`TEMP`가 프로젝트 안 폴더) 거부합니다.
- `--apply install`과 `node_modules`: 프로젝트의 `node_modules`가 없거나 프로젝트 자신의 폴더일 때만 설치합니다. `npm ci`가 그 폴더의 내용을 지우기 때문입니다. `node_modules`가 링크(symlink, junction)이거나 파일이면 백업과 파일 교체보다 먼저 거부하고 아무것도 바꾸지 않습니다. `--apply lockfile`로 반영한 뒤 직접 설치하세요. npm을 시작하기 직전에도 다시 확인합니다. 그 사이에 링크로 바뀌었으면 npm을 실행하지 않고 설치 실패(종료 코드 2)로 끝납니다. 대시보드의 설치까지도 같습니다.
- 바뀐 항목이 없으면 아무것도 쓰지 않고(백업도 만들지 않음) `npm ci`도 실행하지 않습니다.
- 백업: 프로젝트 파일을 바꾸기 전에 원본 `package.json`·`package-lock.json`과 설명 파일 `backup.json`(프로젝트 경로, 원본·새 SHA-256, 시각, 방식)을 이력 파일 옆 `backups/<UTC 시각>-<무작위 8자>/`에 씁니다. 기본은 `~/.local/share/depbee/backups/`이고, `DEPBEE_HISTORY_DB`를 지정했으면 그 파일이 있는 폴더의 `backups/`입니다. 위치는 대상 프로젝트의 파일로 바꿀 수 없습니다. 백업을 쓰지 못하거나 홈 폴더를 정하지 못하면 반영하지 않고 실패(종료 코드 2)입니다. 백업은 자동으로 지우지 않습니다.
- 되돌리기: depbee는 자동으로 되돌리지 않습니다. 반영 중 실패(예: lockfile을 바꾼 뒤 `npm ci` 실패)는 오류로 알리고 백업 위치와 되돌리는 방법을 보여 줍니다. 되돌리려면 백업 폴더의 두 파일을 프로젝트에 복사하고, 설치한 `node_modules`도 되돌리려면 그 뒤 `npm ci --ignore-scripts`를 실행합니다.
- 파일 교체: 바뀐 파일을 모두 프로젝트 폴더 안 임시 파일(`.package-lock.json.<무작위>.depbee` 등)에 쓴 뒤 `os.replace`로 하나씩 바꿉니다. 실패하면 남은 임시 파일을 지우고, 이미 바꾼 파일이 있으면 그 이름을 오류에 적습니다.
- 설치 스크립트는 실행하지 않습니다. `npm ci`는 항상 `--ignore-scripts`로 실행하고 설치 스크립트를 실행하는 옵션은 없습니다. 설치 스크립트가 필요한 패키지(네이티브 모듈 빌드 등)는 직접 검토한 뒤 `npm rebuild`를 실행합니다.
- `npm ci` 실행 규칙: 미리보기와 같이 `node.exe`와 `npm-cli.js`를 셸 없이 실행하고, `npm_config_*`·`NODE_OPTIONS`를 넘기지 않으며 `npm_config_ignore_scripts=true`를 넣습니다. 인자는 `ci --ignore-scripts --no-audit --no-fund --no-update-notifier --no-progress --color=false --loglevel=warn --dry-run=false --package-lock=true --package-lock-only=false --prefix=<프로젝트> --workspaces=false --git=<없는 파일> --globalconfig=<없는 파일>`이고, 두 없는 파일은 depbee가 만든 임시 폴더(Python 임시 폴더 아래 `depbee_install_*`, 프로젝트 밖인지 확인, 끝나면 지움) 안의 경로입니다. `--package-lock-only=false`·`--dry-run=false`는 사용자 npm 설정에 그 값이 켜져 있어도 `npm ci`가 `node_modules`를 비운 뒤 설치를 건너뛰고 성공으로 끝나지 않게 합니다. `--package-lock=true`는 미리보기와 같은 고정값입니다(`npm ci`는 스스로 lockfile을 씀). 사용자 설정의 `omit`·`include`(그리고 `NODE_ENV=production`)는 일부 패키지를 설치하지 않게 할 수 있고, `global`·`location=global`이면 `npm ci`가 오류로 끝나 설치 실패(종료 코드 2)입니다. npm은 `--prefix`를 받으면 `<프로젝트>/etc/npmrc`를 전역 설정 파일로 읽으므로 `--globalconfig`로 막습니다. 그래서 이 설치에서는 기본 위치의 전역 npmrc도 읽지 않습니다. 시간 제한은 600초(모든 tarball을 받아 풀기 때문에 미리보기의 120초보다 깁니다), 출력 상한은 stdout·stderr 각 1 MiB이고, 넘으면 npm과 하위 프로세스를 함께 종료합니다. npm 출력은 오류에 옮기지 않습니다. 끝난 뒤 `package.json`·`package-lock.json`이 반영한 그대로인지 확인합니다.
- 프로젝트 `.npmrc`와 install: 미리보기는 임시 폴더에서 돌아 프로젝트 `.npmrc`를 읽지 않지만 `npm ci`는 프로젝트 폴더에서 돌아 읽습니다. depbee가 명령줄로 고정한 설정(`ignore-scripts`, `git`, `prefix`, `workspaces`, `globalconfig`, `audit` 등)은 `.npmrc`보다 우선하지만 `registry`, scope별 registry, 인증, 프록시·인증서, 캐시 위치, `userconfig` 같은 설정은 `.npmrc` 값이 쓰입니다. 그래서 프로젝트에 `.npmrc`가 있으면 `--apply install`은 아무것도 바꾸지 않고 거부합니다. `--apply lockfile`로 반영한 뒤 `.npmrc`를 직접 검토하고 `npm ci --ignore-scripts`로 설치합니다. 사용자 `~/.npmrc`는 미리보기와 같이 npm이 읽습니다.
- 출력: 텍스트·Markdown은 미리보기 요약과 검사 결과 뒤에 반영 결과(반영했는지, 방식, 거부·실패 이유, 거부한 항목과 확인이 필요한 항목, 바꾼 파일과 SHA-256, 백업 위치, npm 버전과 `npm ci` 종료 코드, 안내)를 붙입니다. 이때 미리보기 요약의 "미리보기만 했고 프로젝트 파일은 아무것도 바꾸지 않았습니다." 안내는 빠집니다. JSON(`--format json`, `--output`)은 `{"preview": {...}, "report": <scan 보고서>, "apply": {...}}`입니다([연결 규약](contracts.md) 5절).
- 종료 코드: 0/1/2의 뜻은 그대로이고 보고서의 종료 코드를 씁니다. 반영을 요청했는데 반영하지 않았고(게이트 거부, 확인 없음, 프로젝트 `.npmrc`, 재확인 불일치, install의 유효한 `integrity` 없음, 링크나 파일인 `node_modules`, 프로젝트 안 임시 폴더) 보고서 값이 0이면 2(요청한 동작을 끝내지 못함)입니다. 백업·교체·`npm ci` 중 실패는 2입니다. 확인하고 반영했어도 보고서가 1(위험)이나 2(보류)면 그 값입니다. 미리보기 단계의 입력·지원 범위·npm 오류는 반영 없이 지금처럼 판정 없는 오류(표준 오류의 error JSON, 종료 코드 2)입니다. `--output` 파일을 쓰지 못하면(검사하는 동안 같은 이름의 파일이 생긴 경우 등) 반영 결과는 그대로 출력하고 이력에도 남긴 뒤, 표준 오류에 안내 한 줄과 그 파일의 error JSON을 쓰고 2로 끝납니다. 이때도 있는 파일은 덮어쓰지 않으며, 프로젝트가 바뀌었는지는 출력된 반영 결과와 백업 위치로 확인합니다.
- 이력: 등록한 프로젝트면 업데이트 미리보기 실행 기록과 함께 반영 기록을 남깁니다([로컬 이력 저장소](#로컬-이력-저장소)).

## 로컬 이력 저장소

depbee는 [대시보드](#로컬-대시보드-depbee-dashboard)에 등록한 프로젝트의 검사 결과를 이 PC의 SQLite 파일 하나에 기록합니다. 대시보드와 CLI가 같은 파일을 씁니다. 등록은 대시보드 화면이나 Python API(`depbee.history.register_project`)로 합니다. 이 파일은 등록할 때만 만들어집니다. `scan`·`update`는 파일이 없으면 아무것도 만들지 않고, 파일이 있으면 그 프로젝트가 등록돼 있는지 확인하려고 읽으며, 등록하지 않은 프로젝트의 결과는 쓰지 않습니다(그 읽기가 실패하면 아래의 고정 문구가 나올 수 있습니다).

- 기록하는 것: 등록한 프로젝트의 `scan`(`depbee scan <프로젝트>`)과 `update` 미리보기(`--project`, 기본은 현재 폴더) 결과입니다. 보고서를 출력한 뒤 보고서 원문, 미리보기 요약(`preview`), 실행 시각(UTC), depbee 버전, 기준 지정(`--base-ref` 값, `--base-lock` 사용 여부), 판정별 개수와 항목별 판정·점수를 남깁니다. 판정·이유·종료 코드는 보고서 값 그대로이고 다시 계산하지 않습니다. 미리보기가 계산한 새 lockfile 내용은 저장하지 않습니다(해시만 미리보기 요약에 있습니다).
- `update --apply`는 같은 미리보기 실행 기록에 반영 기록 하나를 더합니다(대시보드는 미리보기를 기록한 뒤 반영할 때 그 실행에 더함): 방식, 결과(반영함·바뀐 항목 없음·거부·실패), 거부·실패 이유, 확인 여부와 확인한 항목, 원본·새 SHA-256, 백업 위치, npm 버전과 `npm ci` 종료 코드, 반영 결과 원문(`apply`). 새 lockfile 내용은 여기에도 저장하지 않습니다.
- 기록하지 않는 것: 이력 파일이 없을 때(만들지 않음), 등록하지 않은 프로젝트, `check`, `plan`, 오류로 끝난 실행, MCP 도구. GitHub 호스팅 러너처럼 이력 파일이 없는 환경에서는 GitHub Action의 `scan`도 기록되지 않습니다. 다만 이력 파일이 있는 PC에서 그 체크아웃 폴더를 등록해 둔 자기 호스팅 러너라면, 그 `scan`도 등록한 프로젝트의 실행으로 기록됩니다.
- 출력: 기록해도 stdout, stderr, 종료 코드는 기록하지 않을 때와 같습니다. 기록에 실패하면(잠금 대기 초과, 손상된 파일, 더 새 depbee가 만든 파일, depbee가 만들지 않은 파일, 쓰기 권한 없음 등) stdout과 종료 코드는 그대로 두고 표준 오류에 경로나 패키지 이름이 없는 고정 문구 한 줄만 씁니다.
- 위치: 환경 변수 `DEPBEE_HISTORY_DB`(파일 경로, 실행할 때마다 읽고 빈 값은 없는 것으로 봄)가 있으면 그 파일, 없으면 `~/.local/share/depbee/history.sqlite3`입니다(Windows도 홈 폴더 기준). 대상 프로젝트의 파일로는 위치를 바꿀 수 없습니다. `DEPBEE_HISTORY_DB` 없이 홈 폴더를 정하지 못하면 `scan`·`update`는 기록만 건너뛰고(출력 없음), 등록·조회 API는 오류(`RuntimeError`)를 냅니다.
- 이 파일은 SQLite 헤더의 application_id로 depbee 이력임을 표시합니다. 그 표시가 없는 파일(다른 프로그램의 SQLite 파일 등)에는 쓰지 않습니다.
- 이력 형식 버전은 3입니다. 버전 2는 반영 기록 표를, 버전 3은 업데이트 미리보기마다 그 미리보기를 만든 `package.json`·`package-lock.json`의 SHA-256과 대상 이름을 담는 표와 색인을 더했습니다. 이전 depbee가 만든 버전 1·2 파일은 그대로 읽고, 처음 쓸 때 같은 트랜잭션에서 버전 3으로 올리며 이미 기록된 미리보기도 새 표에 채웁니다(기록 5,000건 파일에서 0.1초 안팎). 올리기 전에도 대시보드의 후보는 똑같이 보이지만, 저장된 미리보기를 하나씩 읽어 찾으므로 기록이 많으면 화면이 느리게 열립니다. 올린 뒤에는 이전 depbee가 이 파일을 "더 새 depbee가 만든 파일"로 보고 쓰지 않으며(기록 실패 문구), 이전 depbee의 대시보드도 이 파일을 읽지 못합니다.
- 프로젝트는 절대 경로로 구분합니다(Windows에서는 대소문자 무시). 폴더를 옮기면 다른 프로젝트이고, 폴더가 사라져도 기록은 지우지 않습니다.
- 이전 Docker 설치에서 등록한 프로젝트의 이력은 기존 볼륨에 컨테이너 경로로 저장돼 있습니다. 이전 이력이 필요하면 해당 볼륨을 보관하고, 호스트 대시보드에서는 실제 프로젝트 폴더를 새로 등록합니다.
- 내용: 이력에는 검사한 패키지의 이름·버전과 근거 문자열(예: 추가된 설치 스크립트 명령의 앞부분)이 그대로 들어갑니다. 악성 사례를 검사한 기록에는 그 문자열이 남으므로, 다른 사람이 쓸 수 있는 폴더나 동기화 폴더에 두지 않습니다. 이 파일의 내용은 표시용 기록이며 다른 검사나 반영의 입력으로 쓰지 않습니다.
- 지우기: 자동으로 지우지 않습니다. 이력을 없애려면 그 파일을 지웁니다(쓰는 동안에만 옆에 `-journal` 파일이 생깁니다).

## 로컬 대시보드 (`depbee dashboard`)

프로젝트에서 설치 버전과 업데이트 후보를 나란히 보고 후보를 선택하면 같은 화면에 그 항목의 검사 근거가 열립니다. 검색한 이름과 의존성 종류를 유지한 채 다른 후보를 비교할 수 있습니다. 실행 번호로 전체 보고서를 열고, **기록**에서 최근 10회까지 실행별 최고 ML 위험 점수와 사용 모델을 확인합니다. 점수를 산출한 항목이 없는 실행은 ‘점수 없음’으로 표시합니다. [대시보드 디자인 지침](dashboard-design.md)

등록한 프로젝트와 위 이력을 브라우저에서 보고, 커밋하지 않은 lockfile 변경을 검사하거나 업데이트를 확인(미리보기와 검사)하고 반영하는 로컬 웹 화면입니다. 이 PC의 `127.0.0.1`에서만 열립니다. Starlette, Jinja2, uvicorn(`web` extra)이 필요하고, 검사만에는 `depbee scan --extract`와 같이 Git과 `extract`가, 업데이트 확인에는 `depbee update`와 같이 Node.js와 npm, `extract`가 필요합니다.

```powershell
python -m pip install ".[web,extract]"
depbee dashboard                       # 빈 포트를 OS가 고름
depbee dashboard --port 8765           # 포트 지정
depbee dashboard --background          # 백그라운드로 실행 (아래 백그라운드 실행)
```

- `--model-dir`, `--known-malicious-dir`, `--cache-dir`/`--no-cache`는 검사만과 업데이트 확인에 쓰며 뜻은 `depbee scan`·`depbee update`와 같습니다. 모델과 색인은 지정하지 않으면 환경 변수, `depbee setup`으로 저장한 설정, 설치본 순으로 쓰므로([기본 자산](#기본-자산)) 평소에는 두 옵션이 필요 없습니다.
- 시작하면 표준 출력에 세션 주소와 종료 방법(Ctrl+C)이 나옵니다. 등록한 프로젝트가 없으면 시작 주소는 **프로젝트 추가** 버튼 하나만 있는 화면이고, 누르면 이 PC의 폴더 선택 창이 열립니다. 창을 닫으면 같은 화면으로 돌아오고, 창을 열 수 없거나 고른 폴더가 거부되면 경로를 직접 적을 수 있는 프로젝트 관리 화면이 열립니다. 첫 프로젝트가 등록되면 현황판이 열리고 그 프로젝트가 아직 검사하지 않은 미검사 상태로 보입니다. 그 뒤에 프로젝트 관리에서 등록하는 프로젝트는 등록하면 그 프로젝트의 패키지 화면이 열립니다. 등록한 프로젝트가 하나라도 있으면 시작 주소는 현황판입니다. 현황판 위쪽의 차트는 프로젝트가 최근 검사 상태별로 몇 개인지 보여 줍니다. 상태는 위험, 보류, 통과, 미검사이고 해당하는 프로젝트가 있을 때만 파일 바뀜과 폴더 없음이 더해지며, 프로젝트 하나가 육각 셀 하나입니다. 그 아래 표에는 프로젝트마다 가장 최근 실행(검사 또는 업데이트 미리보기)의 상태, 건수, 시각, 보고서와 가장 최근 반영 시도의 결과, 이유(거부와 실패 포함), 보고서가 나옵니다. 마지막으로 성공한 반영은 따로 적습니다(최근 시도가 성공이면 그 시도, 없으면 "없음"). "파일 바뀜"은 가장 최근 실행이 업데이트 미리보기인데 지금의 `package.json`·`package-lock.json`이 그 미리보기를 만든 파일도, 그 미리보기를 반영해 남긴 파일도 아닌 경우입니다. 검사(scan) 기록에는 파일 해시가 없어 이 구분을 하지 않습니다. 이 주소를 브라우저에 붙여 넣어 엽니다. 브라우저를 자동으로 열지 않습니다. Ctrl+C로 끄면 `대시보드를 종료했습니다. 위 주소는 더 이상 열리지 않습니다.` 한 줄을 남기고 종료 코드 0으로 끝납니다. `web` extra 없이 실행하면 설치 안내와 함께 종료 코드 2로 끝나고, 다른 명령은 이 extra 없이 그대로 동작합니다.
- 화면은 운영체제의 밝게·어둡게 설정을 따릅니다. 레일 맨 위의 **화면** 버튼을 누를 때마다 시스템 설정, 밝게, 어둡게 순서로 바뀌고 같은 화면으로 돌아옵니다. 고른 테마는 depbee 설정 폴더(`DEPBEE_CONFIG_DIR`, 없으면 `~/.config/depbee`)의 `dashboard-theme.json`에 남아 대시보드를 다시 시작해도 유지됩니다. 판정은 색과 글자에 더해 육각 안의 기호(위험 ×, 보류 !, 통과 ✓, 미확인 ?, 실패 −, 파일 바뀜 =, 폴더 없음 /)로 표시합니다.
- **프로젝트 관리**에서 폴더를 등록하고, 각 폴더의 상태와 최근 실행 요약을 확인합니다. **프로젝트 폴더 선택**으로 이 PC의 폴더를 고르거나 절대 경로를 직접 적어 등록합니다. 파일을 올리는 업로드는 없고, 대시보드는 등록한 폴더의 파일을 그 자리에서 읽습니다. 등록은 `package-lock.json` 일반 파일이 있는 로컬 폴더의 절대 경로만 받습니다. 상대 경로, 네트워크 공유(`\\server\share`), 장치 경로(`\\.\`, `\\?\`), Windows 예약 이름(`CON`, `NUL` 등), 공유·장치로 가는 링크는 거부합니다. 같은 폴더를 다시 등록하면 처음 등록을 그대로 씁니다.
- 공통 메뉴(현황판, 프로젝트 관리, 모델 정보)가 레일 위쪽에 있고 그 아래에 프로젝트 링크가 한 줄씩 있습니다. 순서는 폴더 없음, 위험, 보류, 알 수 없음(최근 실행의 결과를 읽을 수 없음), 미검사, 통과이고(같은 상태끼리는 등록 순서) 목록 위에 "조치 필요" 수를 0이어도 적습니다. 좁은 화면에서는 현재 프로젝트만 표시하며 현황판에서 다른 프로젝트를 고릅니다. 한 줄에는 판정 표시, 이름, 최근 실행의 위험·보류 수가 보이고, 이름에 마우스를 올리면 등록 경로 전체가 나옵니다. 화면 낭독기는 상태도 읽습니다. 상태는 등록 폴더가 없으면 "폴더를 찾을 수 없음", 실행이 없으면 "실행 기록 없음", 그 밖에는 가장 최근 실행의 저장된 결과("최근 실행 위험", "최근 실행 보류", "최근 실행 통과")이며 새로 판정한 값이 아닙니다. 이름은 폴더 이름이고, 폴더 이름이 같은 프로젝트가 있으면 서로 구분될 때까지 상위 폴더 이름을 앞에 붙입니다(예: `team-a/app`, `team-b/app`). 지금 보는 프로젝트의 탭은 실행 상세나 미리보기처럼 그 프로젝트 아래의 화면에서도 선택된 채로 있습니다. 스크립트 없이 링크로만 동작하며 키보드 Tab과 Enter로 전환합니다.
- 프로젝트의 세 화면: 머리 한 줄에 이름, 최근 실행 상태, 줄인 경로(`…`과 끝 세 단계, 마우스를 올리면 전체)와 **업데이트 후보 확인**, **검사만** 버튼이 있고, 그 아래 **패키지**, **업데이트**, **기록** 링크로 오갑니다. 링크에는 lockfile 항목, 지금 파일 기준 후보, 저장된 실행 수가 붙습니다. 설명 문단은 `?` 버튼을 누르면 열리고, 뜻이 갈리는 안전 문장은 늘 보입니다. 등록 폴더가 없으면 세 화면 모두 그 사실과 갈 곳(옮긴 폴더는 프로젝트 관리에서 새로 등록, 지난 기록은 기록 화면)을 알리고 실행 버튼을 보이지 않습니다.
- 패키지 화면: 지금 `package-lock.json`에서 읽은 패키지마다 한 줄입니다. 이름과 종류 꼬리표, 그 아래 설치 위치, 버전(후보가 있으면 "1.1.0 → 1.2.0"), 반영 여부이고, 행 어디를 눌러도 그 후보의 검사 근거가 열립니다. 이름으로 검색하거나 직접·중첩으로 거를 수 있고, 검색 줄 위의 **전체**, **후보**, **미확인**, **후보 없음** 탭이 함께 적용됩니다. 탭의 수는 지금 검색과 종류가 남긴 행 가운데 그 상태의 수입니다. 지금 파일로 확인한 적이 없으면 모든 행이 미확인이라 "후보 0 · 미확인 N"이고, 확인했는데 후보가 없으면 "후보 없음"으로 구분합니다. 행이 없는 탭은 누를 수 없고, 주소가 가리키는 탭에 행이 없으면 전체를 보입니다. 패키지는 npm을 실행하지 않고 `scan`과 같은 lockfile 검사를 거쳐 읽습니다. 종류의 "직접"은 lockfile 루트 항목의 `dependencies`·`devDependencies`·`optionalDependencies`·`peerDependencies`에 선언된 이름이고, 그 뒤에 선언된 곳을 일반·개발·선택·피어로 적습니다(여러 곳에 선언됐으면 모두). 선언은 설치 위치(`node_modules/<선언 이름>`)로 찾습니다. 그래서 다른 이름(alias)으로 선언한 패키지는 "선언 이름"을 함께 보이고, 선언된 패키지와 이름이 같아도 다른 패키지 아래에 설치된 사본은 "중첩"입니다. 선언 값(범위, `npm:` 등)은 읽거나 해석하지 않습니다. 루트에 선언되지 않은 나머지는 "중첩"입니다.
- 업데이트 후보(패키지·업데이트 화면 공통): 후보는 이 프로젝트의 저장된 업데이트 미리보기 중, 그 미리보기를 만든 `package.json`·`package-lock.json`의 SHA-256이 지금 두 파일과 같은 것만 씁니다(대시보드의 업데이트 확인과 CLI `depbee update`가 남긴 기록 모두). 파일이 바뀌기 전의 결과와 다른 프로젝트의 결과는 현재 후보로 보이지 않습니다. 화면을 여는 것(GET)은 두 파일과 이력만 읽고 npm 실행이나 네트워크 검사를 하지 않습니다. 후보를 고르면 검사 근거가 그 후보의 반영 여부(반영 가능, 확인 필요, 반영 거부)와 이유를 판정 카드로 먼저 보이고, 기지 악성 색인, 정적 규칙, ML 점수(점수와 0~1 게이지, 판정 기준 눈금)의 결과를 세 칸으로 보인 뒤, 상세 근거(각 탐지기의 목록과 메모, ML 위험 점수, 점수 원값, 판정 기준 점수, 모델, 추출된 사실, 저장된 판정)를 보입니다. 반영 여부는 업데이트 반영 기준(`depbee update --apply`와 같은 게이트)을 그 후보 하나에 적용한 결과입니다. 기지 악성 색인 일치는 ML 위험 점수가 낮아도 반영 거부이고, 실제 반영은 미리보기 전체 결과로 정합니다. 패키지 화면의 행은 후보가 있으면 버전 칸에 후보 버전을, 반영 여부 칸에 그 결과를 보이고(보고서의 그 항목은 검사 근거의 "보고서에서 전체 근거 보기"로 갑니다), 확인이 다룬 위치인데 바뀌지 않았으면 "후보 없음"을, 확인한 적이 없으면 "미확인"이나 **후보 확인** 버튼(`package.json`에서 업데이트 대상으로 지정할 수 있는 직접 의존성)을 보입니다. 전체 확인은 모든 위치를, 이름을 지정한 확인은 바뀌는 위치와 지정한 이름의 위치만 다룬 것으로 보며, 같은 위치를 여러 확인이 다뤘으면 가장 최근 것을 씁니다. 후보 표시는 볼 때의 registry 상태가 아니라 그 확인 시각의 결과이므로 확인 시각을 함께 보입니다.
  - 찾는 범위: 확인의 개수나 순서로 자르지 않고, 이 프로젝트의 기록 중 두 파일의 SHA-256이 지금과 같은 확인을 모두 찾습니다. 그 뒤에 다른 패키지를 확인한 기록이나 다른 파일 상태에서 만든 기록이 몇 건이 쌓여도 전체 확인의 후보는 그대로 보이고, 파일을 고쳤다가 같은 내용으로 되돌리면 그 내용으로 했던 확인이 다시 현재 후보가 됩니다. 가장 최근 전체 확인보다 오래된 확인은 쓰지 않습니다.
  - 근거가 부족할 때: "바뀌는 항목이 없었습니다"는 전체 확인에서 바뀌는 항목이 없었을 때만 나옵니다. 이름을 지정한 확인만 있으면 화면은 일부 패키지만 확인했다고 말하고, 그 확인이 다루지 않은 항목은 "미확인"입니다.
  - 읽는 양: 화면을 열 때 이력에서는 해시가 같은 확인의 짧은 행(실행 번호, 시각, 대상, 결과 위치)과 후보가 화면에 보이는 확인의 보고서만 읽습니다. 기록이 5,000건 넘게 쌓인 합성 이력에서도 여는 시간은 기록이 11건일 때와 같았습니다([검증 기록](validation.md)). 같은 파일 상태에서 전체 확인 없이 이름을 지정한 확인만 수천 건 쌓인 경우에만 후보 찾기가 그 건수에 비례해 느려집니다. 이와 따로, 머리의 **기록** 링크에 붙는 실행 수는 이 프로젝트의 실행을 이력의 색인에서 세므로 프로젝트의 기록 수에 비례하지만, 보고서는 읽지 않습니다.
- 업데이트 화면: 현재 후보를 반영 여부로 묶은 목록(반영 거부 → 확인 필요 → 반영 가능 → 삭제. 행은 패키지와 위치, 현재 → 후보, 저장된 판정과 이유 한 줄, ML 위험 점수, 근거 열기이고, 탐지기별 상태·추출된 사실·보고서와 npm 페이지 링크는 근거 열기의 검사 근거에 있음)과 그 확인에 쓴 실행(어느 위치에서든 가장 최근인 확인과 전체 확인만, 최근순), 패키지 지정 확인, 열려 있는 미리보기(이 대시보드 프로세스가 들고 있어 반영할 수 있는 미리보기. 그 뒤 파일이 바뀌었으면 반영이 거부된다고 알림)입니다. 전체 확인과 검사만은 머리의 버튼이고, 패키지 지정 확인은 머리 아래 동작 줄의 접힌 "지정한 패키지 확인"입니다. 현재 후보가 없으면 그 이유(확인한 적 없음, 마지막 확인 뒤 파일이 바뀜, 그 결과를 이미 반영함, 파일을 읽을 수 없음)를 말합니다. 릴리스 노트와 변경 내역 원문은 depbee가 수집하지 않으므로 보이지 않고, 검사 근거는 두 배포본을 비교해 추출한 사실입니다.
- 기록 화면: 업데이트 반영 이력(시각, 방식, 결과, 이유, 확인 여부, 백업 위치, `npm ci` 종료 코드, 연결된 미리보기 실행)과 실행 기록(상한 없이 모두, 최근순, 실행 번호가 그 보고서의 링크), 최근 10회의 실행별 최고 ML 위험 점수(판정 기준선이 있는 점 그래프와 표. 실행이 하나면 표만)입니다. 반영 이력에는 CLI `update --apply`가 남긴 기록도 함께 보입니다.
- 실행 상세: 맨 위 요약 띠에 결과와 상태별 수, 그 아래 한 줄에 모델·기준 점수·기지 악성 목록·규칙·종료 코드가 있고, 항목은 텍스트 출력과 같은 순서(위험 → 보류 → 통과 → 삭제, 같은 판정 안에서는 ML 위험 점수 순)와 문구의 카드로, 기지 악성 일치와 보류를 강조하고 항목마다 판정, ML 위험 점수, 비교 버전, 이유, 대안(안전 보증 아님), 탐지기 칸, 추출된 사실, 모델 설명(기여도 막대)을 나눠 보여 줍니다. update 미리보기 기록은 미리보기 요약을 위에, 반영 기록이 있으면 반영 절을 아래에 보입니다. npm 페이지 링크는 `https://www.npmjs.com/package/`와 인코딩한 패키지 이름으로만 만들고(`rel="noreferrer"`), 보고서·lockfile·registry에서 온 주소로는 링크를 만들지 않습니다. 실행 상세, 미리보기, 반영 결과, 오류 화면 위에는 프로젝트와 그 화면(기록 또는 업데이트)으로 돌아가는 이동 경로가 있습니다.
- 접근성과 좁은 화면: 색만으로 상태를 알리지 않고 판정을 글자로 함께 적으며 '통과'에는 안심을 뜻하는 색을 쓰지 않습니다. 본문으로 건너뛰는 링크, 탭과 화면 링크의 현재 위치 표시(`aria-current`), 표의 행·열 머리, 키보드 초점 표시가 있습니다. 좁은 화면에서는 패키지와 후보 표가 행 단위 묶음으로 바뀌고 기록 표는 표 안에서 가로로 넘깁니다. 시각은 저장된 UTC 값을 분 단위로 보입니다.
- 모델 정보: 저장된 실행의 보고서에 있는 모델 ID, 판정 기준 점수, 모델·manifest 해시, 분석기와 depbee-analyzer 정보만 보입니다. 학습 데이터 버전과 공격 유형별 탐지율은 보고서에 출처가 없어 보이지 않습니다.
- 판정·이유·종료 코드·탐지기 상태는 저장된 보고서 값 그대로이며 다시 계산하지 않습니다. 모든 화면에 "'통과'는 모델의 판정일 뿐 패키지가 안전하다는 보증이 아닙니다."를 둡니다.

검사만, 업데이트 확인과 반영:

- 검사만: 프로젝트 머리의 "검사만" 버튼은 등록한 경로에서 `depbee scan <프로젝트> --extract`와 같이 커밋하지 않은 `package-lock.json` 변경을 Git HEAD의 lockfile과 비교해 바뀐 버전의 추출을 언제나 요청하고, 모델이 있으면 ML 위험 점수를 계산합니다(바뀐 것이 없으면 바뀐 항목 없음). 모델이 없으면 점수 없이 보류합니다. 삭제·지원하지 않는 변경·추출 실패 항목도 점수가 없을 수 있습니다. 설치나 파일 변경은 없습니다. 실행 전에 등록 때와 같은 경로 검사를 하고, 성공하면 CLI의 `scan`과 같은 값(비교 기준 옵션 없음)으로 이력에 기록한 뒤 그 실행 상세로 이동합니다. 기록하지 못하면 검사 결과를 그 자리에서 보이고 기록하지 못했다는 한 줄을 더합니다. Git 저장소가 아니거나 HEAD에 lockfile이 없을 때, `extract`가 없을 때 등은 기록하지 않고 오류 화면에 depbee의 오류 문구를 보입니다(그 밖의 예외는 고정 문구). 다른 비교 기준(Git ref, 이전 lockfile 파일)은 CLI로 검사합니다.
- 업데이트 확인: 프로젝트 머리의 **업데이트 후보 확인**(이미 전체를 확인했으면 **업데이트 후보 다시 확인**)을 누르면 `package.json` 범위 안의 전체를, 업데이트 화면에 패키지 이름을 공백으로 나눠 적고 **지정한 패키지 확인**을 누르면 그 이름들을, 패키지 화면의 **후보 확인**은 그 행의 이름 하나를 확인합니다. 이름 규칙과 미리보기 방식(임시 사본, `npm update --package-lock-only --ignore-scripts`, 지원 범위)은 `depbee update`와 같고, 프로젝트 경로는 폼에서 받지 않고 등록한 경로를 씁니다(실행 전에 등록 때와 같은 경로 검사). 성공하면 CLI와 같이 업데이트 미리보기 실행으로 이력에 기록합니다. 업데이트·기록 화면에서 보낸 확인은 미리보기 화면으로 이동합니다. 패키지 화면에서 보낸 확인은 같은 검색과 종류의 패키지 목록으로 돌아와 그 확인이 돌려준 후보 가운데 목록에 보이는 첫 후보를 열고 거기에 초점을 둡니다. 이때 탭은 전체로 돌아갑니다(미확인 탭에서 보낸 확인은 그 행을 미확인에서 빼기 때문입니다). 후보가 열리지 않으면 주소에는 보낸 탭이 남고, 그 탭에 남은 행이 없으면 화면에는 전체가 보입니다. 지금 검색과 필터로 보이는 후보가 없으면 상태 문장이 그렇다고 알리고, 전에 열려 있던 후보는 그대로 둡니다. 이 경로는 아무것도 반영하지 않으며, 반영하려면 검사 근거의 **이 확인의 미리보기 열기**로 미리보기 화면에 갑니다. 기록하지 못하면 화면에 한 줄로 알리고 미리보기는 그대로 쓸 수 있습니다(그때는 반영해도 반영 기록이 남지 않습니다). 입력·지원 범위·npm 오류, Node.js나 `extract`가 없을 때는 기록하지 않고 오류 화면에 depbee의 오류 문구를 보입니다(그 밖의 예외는 고정 문구).
- 미리보기 화면: 미리보기 요약, 검사 결과(실행 상세와 같은 화면), 반영 게이트 결과(`depbee update --apply`와 같은 서비스 함수로 계산)와 반영 폼입니다.
  - 기지 악성 기록 일치(`known_malicious.status`가 `hit`)가 하나라도 있으면 반영 폼이 없고 거부 이유와 항목을 보입니다. 확인으로도 바꿀 수 없습니다.
  - 새로 설치되는 버전이 있는 항목 중 ML 위험 점수 기준 이상, 보류, 기지 악성 목록과 대조하지 못한 항목이 있으면 그 목록(판정, 원인, ML 위험 점수)을 보이고, "위 N개 항목을 검토했고 진행합니다" 확인란을 선택해야 반영합니다(한 번의 명시적 확인, CLI의 `--confirm-warnings`와 같은 뜻). 기지 악성 목록과 대조하지 못한 미리보기에서는 새로 설치되는 버전이 있는 반영마다 이 확인이 필요하고, 설치본 색인이나 지정한 색인과 대조한 미리보기에서는 미적중 항목이 이 목록의 미확인 원인에서 빠집니다.
  - 바뀐 항목이 없으면 반영 폼이 없습니다.
  - 방식은 lockfile 반영과 설치까지(`npm ci --ignore-scripts`) 중 하나입니다. 미리보기 때 프로젝트 `.npmrc`가 있었으면 설치까지는 고를 수 없고, lockfile만 반영한 뒤 `.npmrc`를 직접 검토하고 설치하라고 안내합니다. 설치까지는 새 lockfile의 모든 항목에 유효한 `integrity`가 있어야 합니다(없으면 서비스가 거부).
- 반영: 확인이 필요한데 확인란이 없거나, `.npmrc`가 있었는데 설치까지를 고르면 아무것도 실행하지 않고 미리보기를 그대로 둔 채 안내와 함께 미리보기 화면을 다시 보입니다. 그 밖에는 미리보기를 메모리에서 먼저 꺼내 지운 뒤 `depbee update --apply`와 같은 반영(`service.apply_preview`)을 등록 경로에 실행합니다: 원본·새 lockfile 해시 재확인, 원본 백업, 파일 교체, 설치까지면 `npm ci --ignore-scripts`. 그래서 한 미리보기로는 반영을 한 번만 시도하고, 새로고침이나 폼 재전송은 "미리보기가 없음"으로 거부됩니다. 거부·실패여도 같은 미리보기로 다시 시도할 수 없고 업데이트 확인을 다시 해야 합니다.
- 결과 화면: 결과(반영함, 바뀐 항목 없음, 반영하지 않음, 실패), 방식, 이유, 오류, 확인한 항목, 바꾼 파일과 SHA-256, 백업 위치, npm 버전과 `npm ci` 종료 코드, 안내(설치 스크립트 미실행, 되돌리는 방법)입니다. 미리보기 실행이 이력에 있으면 그 실행에 반영 기록을 더합니다. 반영 기록을 남기지 못해도 결과와 백업 위치는 그대로 보이고 기록하지 못했다는 한 줄을 더합니다.
- 백업·되돌리기: `depbee update --apply`와 같습니다. 바꾸기 전에 원본 두 파일을 이력 파일 옆 `backups/`에 백업하고, 자동으로 되돌리지 않습니다. 되돌리려면 백업 폴더의 두 파일을 프로젝트에 복사하고, 설치한 `node_modules`도 되돌리려면 그 뒤 `npm ci --ignore-scripts`를 실행합니다.
- 한 번에 한 작업: 검사만, 업데이트 확인, 반영은 대시보드 프로세스에서 한 번에 하나만 실행합니다(요청 안에서 끝날 때까지 기다림). 누른 버튼은 실행 중임을 글자로 알리고("후보 확인 중…", "검사 중…", "반영 중…", 폴더 선택은 "폴더 선택 창을 확인하세요…") 그동안 그 화면의 실행 버튼은 요청을 다시 보내지 않습니다. 스크립트를 끈 브라우저나 다른 탭에서 실행 중에 또 보내면 409와 고정 문구로 거부합니다(프로젝트 탭이 있는 화면이라 먼저 보낸 작업의 결과를 보러 갈 수 있습니다). 조회 화면은 그동안에도 열립니다. CLI와 대시보드가 같은 프로젝트를 동시에 반영하는 것은 막지 않습니다(반영 직전의 해시 재확인이 미리보기 뒤 바뀐 파일을 거부합니다).
- 미리보기 보관: 미리보기 결과(새 `package.json`·lockfile 바이트 포함)는 대시보드 프로세스 메모리에만 있고 파일이나 이력에 쓰지 않습니다. 최근 10개까지 두고 넘으면 가장 오래된 것부터 지우며, 대시보드를 끄거나 다시 시작하면 모두 사라집니다.

보안 동작:

- `127.0.0.1`에만 바인딩하고 다른 주소로 여는 옵션은 없습니다. 모든 요청의 Host 헤더가 `127.0.0.1:<포트>`와 정확히 같아야 합니다(DNS rebinding 방지, 다르면 400).
- 세션: 실행할 때마다 무작위 세션 값을 만들어 시작 주소에 넣습니다. 모든 화면·폼·CSS는 `/s/<세션>/` 아래에 있고, 이 접두사가 없거나 세션이 다르면 조회를 포함한 모든 요청을 고정 문구 403으로 거부합니다. 같은 PC의 다른 프로세스·계정도 `127.0.0.1`에 접속할 수 있기 때문입니다. 쿠키는 쓰지 않습니다(응답에 `Set-Cookie`가 없고 요청의 `Cookie`는 무시). 로그인 단계도 없습니다. 쿠키를 없애면 로그인 단계가 세션을 넘길 곳이 주소뿐이라 따로 두어도 보호가 늘지 않습니다.
- 알려진 한계(받아들인 위험): 세션 값이 주소에 있으므로 브라우저 주소창과 방문 기록에 남고, 시작 줄이나 그 주소를 볼 수 있는 사람은 대시보드가 도는 동안 화면을 보고 검사, 업데이트 확인·반영을 할 수 있습니다. 주소를 다른 사람에게 보이지 않게 하고, 쓰지 않을 때는 대시보드를 끕니다. 대시보드를 끄면 그 주소는 무효가 됩니다(다음 실행은 새 세션). 예전 쿠키 방식의 한계(같은 브라우저로 연 127.0.0.1의 다른 포트 서버가 세션 쿠키를 받음)는 쿠키를 없애 사라졌습니다.
- 상태를 바꾸는 요청은 POST만 받습니다(프로젝트 등록, 검사만, 업데이트 확인, 반영, 화면 테마 저장). GET은 npm을 실행하거나 상태를 바꾸지 않습니다. POST는 `Origin: http://127.0.0.1:<포트>`이고 폼의 숨은 세션 값이 맞아야 하며, 브라우저가 `Sec-Fetch-Site`를 보냈으면 `same-origin`이나 `none`이어야 합니다(하나라도 아니면 403). 본문은 16 KiB, 폼 필드는 4개, 경로·대상 이름 칸은 각각 1024자까지 받습니다.
- 모든 응답에 `Content-Security-Policy`(외부 자원·인라인 스크립트·`eval`·프레임 금지), `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`(다른 사이트로 가는 요청에 세션이 든 주소를 보내지 않음), `Cache-Control: no-store`를 붙입니다. 화면은 패키지 안의 템플릿, CSS, 글꼴 두 개(Noto Sans KR과 JetBrains Mono의 일부, SIL OFL 1.1)와 스크립트 파일 하나(`/s/<세션>/static/app.js`)만 쓰고 외부 CDN·글꼴·스크립트가 없습니다. 그 스크립트는 요청을 보내지 않고, 실행 중인 버튼 표시와 중복 전송 방지, 확인 뒤 첫 후보로의 초점 이동만 합니다. 스크립트를 꺼도 모든 폼과 링크가 그대로 동작합니다.
- 접속 기록(access log)을 남기지 않고, 프록시 헤더를 믿지 않으며, 서버 이름 헤더를 보내지 않습니다. 세션 값은 시작 줄 밖(로그, 오류 문구)에 쓰지 않습니다. 오류 화면에는 입력 경로나 예외 내용을 싣지 않습니다(depbee가 정한 검사·업데이트 확인 오류 문구는 예외, 처리하지 못한 예외는 고정 문구의 500). 다만 처리하지 못한 예외는 uvicorn이 서버를 띄운 터미널의 표준 오류에 traceback으로 남길 수 있습니다.
- 패키지 이름·위치·근거·경로·오류 문구 등 보고서와 lockfile, 이력, 서비스에서 온 문자열은 텍스트 출력처럼 제어·양방향·영폭 문자를 `\uXXXX`로 바꾼 뒤 HTML 이스케이프합니다.
- npm은 서비스 함수를 통해서만 실행됩니다(미리보기는 임시 사본, 설치는 반영 뒤 프로젝트에서 `npm ci --ignore-scripts`).

### 백그라운드 실행

터미널을 차지하지 않고 대시보드를 띄워 두는 방법입니다. 화면과 보안 동작은 위와 같고, 시작·확인·종료 방식만 다릅니다.

```powershell
depbee dashboard --background    # 시작하고 주소 출력. 옵션(--port, --model-dir 등)은 위와 같음
depbee dashboard --status        # 실행 중인 주소와 PID, 시작 시각
depbee dashboard --stop          # 종료
```

- 시작: `--background`는 창 없는 별도 프로세스로 대시보드를 띄우고, 그 서버가 실제로 응답하는 것을 확인한 뒤에만 주소를 출력하고 종료 코드 0으로 돌아옵니다. 첫 줄은 포그라운드 실행과 같은 세션 주소이고 둘째 줄은 안내입니다. 시작한 터미널을 닫거나 그 터미널의 프로세스를 종료해도 대시보드는 계속 실행됩니다. Windows에서는 콘솔 창이 뜨지 않습니다(대시보드가 실행하는 git·npm도 창을 띄우지 않음). macOS·Linux에서는 새 세션으로 분리합니다.
- 이미 실행 중이면 새로 띄우지 않고 실행 중인 주소와 "이미 백그라운드에서 실행 중"이라는 안내를 출력합니다(종료 코드 0). 이때 준 `--port` 같은 옵션은 쓰이지 않습니다. 옵션을 바꾸려면 `--stop` 뒤에 다시 시작합니다. 여러 터미널에서 동시에 시작해도 하나만 뜨고 모두 같은 주소를 받습니다.
- 준비되지 않으면 주소를 출력하지 않습니다. 포트를 쓸 수 없거나 `web` extra가 없는 등 시작에 실패하면 그 오류를, 30초 안에 응답하지 않으면 시간 초과를 표준 오류의 error JSON으로 알리고 종료 코드 2로 끝납니다. 시간 초과일 때는 방금 띄운 프로세스를 종료해 반쯤 뜬 서버를 남기지 않습니다.
- 확인: `--status`는 실행 중이면 주소와 PID·시작 시각(UTC)을 출력합니다. 실행 중이 아니면 그렇게 알리고 종료 코드 0입니다. 프로세스는 있는데 응답하지 않으면(시작 중이거나, 하던 작업을 마치고 종료하는 중) 그렇게 알리고 종료 코드 2입니다.
- 종료: `--stop`은 서버에 종료를 요청하고 프로세스가 끝난 것을 확인한 뒤 돌아옵니다. 서버는 Ctrl+C 때와 같이 스스로 정상 종료합니다. 실행 중이 아니면 "실행 중인 백그라운드 대시보드가 없습니다"라고 알리고 종료 코드 0입니다(여러 번 실행해도 같음). 진행 중인 검사나 반영이 있으면 서버는 그 작업을 마친 뒤 끝나므로, 15초 안에 끝나지 않으면 그 사실을 오류(종료 코드 2)로 알립니다. 그 사이 새 접속은 받지 않으며 `--status`로 다시 확인합니다. `--stop`이 기다리는 것은 종료 요청을 받은 그 서버입니다. 그 서버가 끝난 직후 다른 터미널에서 새 대시보드를 시작했더라도 `--stop`은 새 서버를 기다리거나 건드리지 않고 종료 완료로 돌아옵니다.
- depbee는 PID로 프로세스를 강제 종료하지 않습니다. 종료 요청은 `127.0.0.1`의 해당 포트로만 보내고, 시작할 때 만든 무작위 제어 값으로 서명합니다(HMAC-SHA256, 값 자체는 보내지 않음). 서버도 같은 값으로 서명한 응답을 돌려주므로, 죽은 대시보드의 포트를 다른 프로그램이 쓰고 있어도 실행 중으로 착각하거나 그 프로그램에 종료를 시키지 않습니다. 제어 값이 맞지 않는 요청은 세션 없는 다른 요청과 똑같이 403입니다. 예외는 하나로, `--background`가 방금 직접 띄운 프로세스가 30초 안에 준비되지 않을 때 그 프로세스만 종료합니다.
- 상태 파일: 사용자 설정 폴더([자산 폴더 설정](#자산-폴더-설정-depbee-setup)의 `config.json`과 같은 폴더, 기본 `~/.config/depbee/`, 바꾸려면 절대 경로의 `DEPBEE_CONFIG_DIR`)에 `dashboard.lock`, `dashboard.json`, `dashboard.log`를 둡니다. 사용자 설정 폴더마다 백그라운드 대시보드는 하나입니다. 실행 여부는 서버 프로세스가 살아 있는 동안 잡고 있는 `dashboard.lock`의 운영체제 잠금으로 판단하므로, 프로세스가 강제 종료되거나 PC가 꺼져도 잠금은 저절로 풀립니다. 그렇게 남은 `dashboard.json`은 다음 `--status`·`--stop`·`--background`가 죽은 것으로 알아보고 지우거나 새로 씁니다. 남은 파일은 잠금을 잡은 채로만 지우고 서버도 잠금을 잡은 뒤에만 자기 파일을 쓰므로, 남은 파일의 정리와 새 시작이 겹쳐도 새 서버의 `dashboard.json`은 지워지지 않습니다.
- `--status`와 `--stop`은 사용자 설정 폴더의 파일만 봅니다. 현재 폴더, 프로젝트 폴더, 이력 파일(`DEPBEE_HISTORY_DB`) 옆에 같은 이름의 파일이 있어도 읽지 않고, 그 파일이 가리키는 포트로 아무 요청도 보내지 않으며, 그 파일을 지우지도 않습니다. `DEPBEE_CONFIG_DIR`이 상대 경로면 어떤 파일도 건드리기 전에 오류(종료 코드 2)로 끝납니다.
- `dashboard.json`에는 세션 주소와 제어 값이 들어 있습니다. 이 파일을 읽을 수 있는 사람은 대시보드를 쓸 수 있으므로 사용자 설정 폴더를 다른 사람이 읽을 수 있는 곳에 두지 않습니다. macOS·Linux에서는 이 파일을 소유자만 읽고 쓰게(0600) 만들고, Windows에서는 파일이 사용자 설정 폴더의 접근 목록을 물려받습니다. depbee가 만든 폴더는 본인 전용이고, 이미 있던 폴더가 다른 계정에 열려 있으면 터미널에서 실행한 `--background`가 주소와 안내 다음에 표준 오류로 주의 한 줄을 씁니다([자산 폴더 설정](#자산-폴더-설정-depbee-setup)의 폴더 권한 항목). 서버가 정상 종료하면 이 파일을 지웁니다. 세션 주소와 제어 값은 명령줄 인자나 `dashboard.log`에 쓰지 않습니다.
- `dashboard.log`에는 서버의 표준 오류(uvicorn 경고, 처리하지 못한 예외의 traceback)가 들어가고 시작할 때마다 비웁니다. traceback에는 경로나 패키지 문자열이 들어갈 수 있습니다.
- 백그라운드 서버는 사용자 설정 폴더를 작업 폴더로 삼으므로 시작한 프로젝트 폴더를 붙잡지 않습니다. 상대 경로로 준 옵션과 상대 경로일 수 있는 환경 변수(`DEPBEE_HISTORY_DB`, `DEPBEE_MODEL_DIR`, `DEPBEE_KNOWN_MALICIOUS_DIR`)는 시작한 폴더 기준의 절대 경로로 바꿔 넘기므로, 이력과 자산은 포그라운드로 띄웠을 때와 같은 파일을 씁니다.
- 포그라운드 `depbee dashboard`는 전과 같이 상태 파일을 쓰지 않고 Ctrl+C로 끕니다. `--status`·`--stop`은 백그라운드로 띄운 것만 다룹니다.
- 확인한 환경과 한계: Windows 11과 Linux(WSL2의 Ubuntu 24.04)에서 실제 프로세스로 시작·확인·중복 시작·동시 시작·종료·재시작, 강제 종료된 서버가 남긴 상태의 정리를 확인했습니다. 터미널이 사라진 뒤의 유지는 Windows에서 콘솔 창 닫기와 프로세스 트리 종료로, Linux에서 터미널 끊김(SIGHUP)으로 확인했습니다. macOS는 Linux와 같은 코드 경로(새 세션, `flock` 잠금)를 쓰지만 실행해 확인하지 않았습니다. 로그아웃하면 운영체제가 사용자 프로세스를 끝낼 수 있고, 로그인이나 재부팅 뒤에 자동으로 다시 시작하지 않습니다.

지금 할 수 없는 것: 파일 업로드(프로젝트나 lockfile을 올려 등록·검사), 대시보드에서 `check` 실행, 검사만의 다른 비교 기준(Git ref, 이전 lockfile 파일) 선택(CLI로 실행하면 등록한 프로젝트의 `scan`은 기록됨), 등록 해제와 이력 삭제, GitHub Actions `report.json` 가져오기, 판정 건수의 추이 그래프(기록 화면의 실행별 최고 ML 점수 그래프는 있음), 의심 코드 위치와 과거 캠페인 정보.

## MCP 진입점 (검사 전용)

에이전트가 패키지를 설치하기 전에 depbee 검사를 부를 수 있도록 stdio MCP 서버를 둡니다. 공식 MCP Python SDK 2.x(`mcp` extra)가 필요하고, 분석에는 `extract`도 필요합니다. MCP 클라이언트에는 아래 실행 명령을 stdio 서버로 등록합니다.

```powershell
python -m pip install ".[mcp,extract]"
depbee mcp                         # 등록할 서버 명령은 이것뿐
```

서버 명령에 모델·색인 경로를 넣지 않습니다. 경로가 없고 환경 변수와 저장된 설정도 없으면 [설치본 자산](#기본-자산)을 씁니다. 다른 모델이나 색인을 쓰는 것은 선택이며, `depbee mcp --model-dir "<모델 폴더>" --known-malicious-dir "<색인 폴더>"`처럼 절대 경로를 주거나 서버 환경에 `DEPBEE_MODEL_DIR`·`DEPBEE_KNOWN_MALICIOUS_DIR`를 두거나 [자산 폴더를 저장](#자산-폴더-설정-depbee-setup)합니다. 옵션, 환경 변수, 저장된 설정, 설치본 순으로 쓰고, 바꾸지 않을 자산은 옵션과 값을 함께 생략합니다. 빈 값을 인자로 주면 입력 오류입니다.

`python -m depbee`는 현재 폴더를 import 경로 맨 앞에 넣으므로, MCP 클라이언트가 신뢰할 수 없는 작업 폴더에서 서버를 띄울 수 있으면 위처럼 콘솔 스크립트(`depbee mcp`)나 `python -P -m depbee mcp`로 등록합니다.

- 도구는 두 개입니다. `check_package`(`package`: `NAME@VERSION`)는 `check`와, `scan_lockfile`(`project`, 선택 `base_lock` 또는 `base_ref`)은 `scan --extract`와 같은 검사를 하고 같은 보고서를 돌려줍니다. 판정·이유·종료 코드는 CLI와 같은 공통 pipeline이 정합니다.
- 검사 전용입니다. 설치, 업데이트 미리보기·반영, 프로젝트 파일을 쓰는 도구는 없습니다. 다만 추출한 feature 캐시(`~/.cache/depbee`)와 임시 파일은 CLI와 같이 쓰므로 MCP 도구 힌트는 `readOnlyHint: false`, `destructiveHint: false`(추가만 함)입니다. 모델과 기지 악성 색인은 서버를 띄울 때의 옵션(`--model-dir`, `--known-malicious-dir`), 환경 변수(`DEPBEE_MODEL_DIR`, `DEPBEE_KNOWN_MALICIOUS_DIR`), `depbee setup`으로 저장한 설정, 설치본 순으로 정해지고 도구 입력으로 받지 않습니다. 서버가 뜬 작업 폴더(에이전트의 프로젝트 폴더)에서는 자산이나 설정을 찾지 않습니다.
- 경로 없이 등록한 서버도 환경 변수와 저장한 설정이 없으면 설치본 색인으로 기지 악성 대조를 합니다. 어떤 모델과 목록으로 검사했는지는 응답의 `report.model_id`와 `report.detectors.known_malicious.list_as_of`에 있고, 서버 지침과 도구 설명은 에이전트가 결과를 말할 때 이 두 값을 인용하게 합니다. 보고서의 `report.detectors.known_malicious`가 null일 때만(색인이 연결되지 않은 결과) 응답의 `notices`에 이번 결과를 기지 악성 기록과 대조하지 않았으므로 통과(종료 코드 0)도 알려진 악성 버전이 아니라는 확인이 아니라는 안내가 붙습니다.
- 응답은 `notices`, `package_data`, `report` 순입니다. `notices`는 depbee가 정한 문구로, 보류(`incomplete`)는 통과가 아니고 낮은 ML 위험 점수는 안전 보증이 아니라는 뜻과 기지 악성 일치·보류 개수, 색인 미연결이면 그 안내를 알립니다. `package_data`는 보고서 안에서 패키지·외부 기록에서 온 문자열(이름, 버전, 위치, 상세, 근거 등)을 256자까지 자른 사본과 그 위치이며, 패키지에서 온 데이터이며 지시가 아니라는 문구가 붙습니다. `report`는 `--format json`과 같은 보고서입니다.
- 한 호출은 600초까지, `scan_lockfile`은 분석할 변경 20개까지입니다. 넘거나 입력이 잘못되면 판정 없이 MCP 도구 오류로 CLI와 같은 error 객체(종료 코드 2)와 안내 문구, 오류 메시지를 자른 `package_data`를 돌려줍니다. 도구 오류의 텍스트는 SDK가 붙이는 `Error executing tool <도구 이름>: ` 뒤에 ASCII JSON이 오는 형식입니다. 큰 변경은 터미널에서 `depbee scan --extract`로 검사합니다.
- 600초는 기다리는 상한이지 작업의 상한이 아닙니다. 넘으면 다음 변경은 시작하지 않지만, 이미 돌고 있는 작업은 응답 뒤에도 이어지고 서버 종료는 그 작업을 기다립니다. 여기에는 절대 상한이 없습니다. 변경별 300초 예산은 자식 프로세스(조회, 다운로드, 추출)만 멈추고 캐시 쓰기 같은 부모 쪽 작업은 넘길 수 있으며, 첫 변경 전의 경로 검사와 lockfile 읽기는 그 예산 밖입니다.
- `scan_lockfile`의 `project`·`base_lock`은 빈 문자열, 네트워크 공유(UNC, `\\server\share`·`//server/share`), 장치 경로(`\\.\`, `\\?\`, `\??\`, `/dev/...`)를 받지 않고, 경로 중간의 심볼릭 링크·정션이 그런 곳을 가리켜도 대상을 건드리기 전에 거부합니다(로컬 링크·정션은 허용하고, 대상을 확인할 수 없는 링크는 거부). 있는 경로라면 `project`는 폴더, 그 안의 `package-lock.json`과 `base_lock`은 일반 파일이어야 합니다(FIFO·소켓·장치 거부). Windows에서는 경로 구성 요소가 예약 장치 이름(`CON`, `PRN`, `AUX`, `NUL`, `COM0`~`COM9`, `LPT0`~`LPT9` 등, 대소문자와 확장자 무관)이면 경로가 있든 없든 거부합니다. 이 검사는 MCP 입력에만 있고 CLI 동작은 그대로입니다.
- SDK 없이 `depbee mcp`를 실행하면 설치 안내와 함께 종료 코드 2로 끝납니다. depbee의 다른 명령은 SDK 없이 동작합니다.

### 에이전트에 등록하기

depbee를 설치한 뒤 에이전트에 `depbee mcp`를 등록하는 한 단계입니다. 모델·색인 경로나 `depbee setup`은 필요 없고, 환경 변수나 저장한 설정으로 바꾸지 않았다면 등록한 서버는 [설치본 자산](#기본-자산)을 씁니다. 아래에서 `<depbee 폴더>`는 절대 경로로 바꿉니다. 에이전트가 서버를 띄우는 작업 폴더는 depbee 폴더가 아닐 수 있으므로 실행 파일은 절대 경로로 적습니다.

| 환경 | 등록 |
| --- | --- |
| PowerShell, Claude Code | `claude mcp add --scope user depbee -- "<depbee 폴더>\.venv\Scripts\depbee.exe" mcp` |
| PowerShell, Codex | `codex mcp add depbee -- "<depbee 폴더>\.venv\Scripts\depbee.exe" mcp` |
| Bash·Zsh, Claude Code | `claude mcp add --scope user depbee -- "<depbee 폴더>/.venv/bin/depbee" mcp` |
| Bash·Zsh, Codex | `codex mcp add depbee -- "<depbee 폴더>/.venv/bin/depbee" mcp` |

설치본 대신 직접 준비한 모델이나 색인으로 등록하는 것은 선택입니다. `mcp` 뒤에 `--model-dir "<모델 폴더>" --known-malicious-dir "<색인 폴더>"`를 붙이거나(절대 경로, [색인 만들기](#색인-만들기)) `depbee setup <자산 폴더>`로 저장해 둡니다. 옵션은 저장된 설정보다 우선합니다. `depbee setup <자산 폴더>`는 저장을 마치면 지금 설치된 depbee 실행 파일의 절대 경로를 넣은 Claude Code·Codex 등록 명령을 출력합니다(설치하지 않은 소스 폴더에서 실행했다면 명령 대신 설치 안내가 나옵니다).

**Claude Code:** `claude mcp add`로 stdio 서버를 등록합니다. `--` 뒤의 명령과 인자는 그대로 서버 실행에 쓰입니다.

```powershell
claude mcp add --scope user depbee -- "<depbee 폴더>\.venv\Scripts\depbee.exe" mcp
```

`--scope`는 `local`(기본값, 현재 프로젝트에서 나만 사용), `project`(프로젝트 루트의 `.mcp.json`에 저장해 저장소로 공유, 처음 쓸 때 사용 승인을 물음), `user`(내 모든 프로젝트)입니다. 위 명령의 경로는 내 PC의 경로이므로 `local`이나 `user`를 권장합니다. `claude mcp list`로 등록 상태를 확인합니다.

**Codex:** `codex mcp add`로 등록하거나 `~/.codex/config.toml`(신뢰한 프로젝트라면 프로젝트의 `.codex/config.toml`)에 `[mcp_servers.<이름>]` 표를 직접 씁니다. Codex의 도구 호출 기본 제한은 60초라 depbee 검사(최대 600초)가 끝나기 전에 끊길 수 있으므로 `tool_timeout_sec`를 600보다 크게 둡니다.

```powershell
codex mcp add depbee -- "<depbee 폴더>\.venv\Scripts\depbee.exe" mcp
```

```toml
[mcp_servers.depbee]
command = '<depbee 폴더>\.venv\Scripts\depbee.exe'
args = ["mcp"]
tool_timeout_sec = 660
```

TOML의 작은따옴표 문자열은 역슬래시를 그대로 둡니다. macOS·Linux에서는 `<depbee 폴더>/.venv/bin/depbee`를 씁니다.

### 에이전트 지침 예시: 설치·업데이트 전에 먼저 검사

MCP는 에이전트가 도구를 부를 때만 효과가 있습니다. 프로젝트의 에이전트 지침 파일(`CLAUDE.md`, `AGENTS.md`)에 붙여 넣을 블록은 README의 [에이전트 지침](../README.md#에이전트-지침)에 있습니다. 블록의 규칙은 아래 동작에 맞춘 것입니다.

- `check_package`는 정확한 버전 하나를 그 직전 stable과 비교하며 그 패키지의 의존성은 검사하지 않습니다. 범위(`^1.0.0`)와 태그(`latest`)는 거부합니다([실행](#실행)). 그래서 프로젝트에 넣는 변경은 전이 의존성까지 담은 lockfile로 `scan_lockfile`이 검사합니다.
- `--ignore-scripts` 없이 `npm install`을 실행하면 `--package-lock-only`여도 프로젝트의 `preinstall`·`postinstall`·`prepare` 등이 실행될 수 있습니다. 그래서 검사 전 준비에는 항상 `--ignore-scripts`를 붙입니다. `--package-lock-only`는 `node_modules`를 설치하지 않을 뿐, 새 직접 의존성은 기본 설정(`save`)대로 `package.json`에도 저장합니다.
- `scan_lockfile`의 기준은 `base_lock`, `base_ref`, 둘 다 없으면 Git HEAD의 lockfile이고, `base_lock`과 `base_ref`는 함께 줄 수 없습니다. 변경을 커밋한 뒤 HEAD를 기준으로 검사하면 바뀐 항목이 0개라 종료 코드 0이 나오므로, 블록은 `report.results`에 바꾼 패키지가 들어 있는지도 확인하게 합니다. HEAD에 lockfile이 없으면 오류(종료 코드 2)이고, 이전 lockfile이 전혀 없는 새 프로젝트에는 비교할 기준이 없으므로 블록은 사용자에게 묻게 합니다.
- `scan_lockfile`은 한 호출에 분석 대상 변경([연결 규약](contracts.md)의 `analyzable`이 true인 추가·업데이트) 20개까지 분석합니다. 삭제(`removed`)와 Git·파일·사설 registry 의존성처럼 분석 대상이 아닌 변경은 이 수에 들지 않고 보고서에는 그대로 들어갑니다. 분석 대상이 20개를 넘거나 입력이 잘못되면 보고서 없이 도구 오류(`error.exit_code` 2)를 돌려줍니다. 도구 오류는 판정이 아니므로 블록은 멈추게 합니다([MCP 진입점](#mcp-진입점-검사-전용)).
- `npm ci`는 lockfile을 바꾸지 않고 그대로 설치하며, `package.json`과 lockfile이 맞지 않으면 lockfile을 고치지 않고 오류로 끝납니다. 그래서 검사한 것과 다른 버전이 들어오지 않습니다. 블록은 설치를 `depbee guard ci`에 맡깁니다. MCP 결과는 나중에 npm이 읽을 바이트와 묶여 있지 않으므로, depbee가 설치할 바로 그 파일을 다시 검사해 통과할 때만 [반영 설치](#업데이트-반영-depbee-update---apply)와 같은 `npm ci --ignore-scripts`를 실행합니다([설치 가드](claude-guard.md#depbee-guard-ci)).
- 이 블록은 에이전트가 따르기로 한 지침일 뿐 실행을 막지 않습니다. 실제로 막는 방법은 README의 [에이전트 지침](../README.md#에이전트-지침) 아래에 있습니다.

## 동작 방식

- **비교 기준:** 모델은 "새 버전과 같은 release line의 직전 stable → 새 버전" 쌍으로 학습했습니다. 그래서 lockfile에서 1.2.0 → 1.5.3으로 바뀌어도 1.5.3을 같은 line의 직전 stable(예: 1.5.2)과 비교합니다. release line은 npm `^` 범위 단위이고(`>=1.0.0`은 major, `0.y.z`는 `0.y`), 새 line의 첫 버전이면 이전 line의 최신 stable과 비교합니다. lockfile의 이전 버전은 근거에만 표시합니다.
- **새로 추가된 의존성:** 같은 방식으로 설치될 버전과 그 직전 stable을 비교합니다.
- **학습 범위 밖 입력:** 새 버전이 pre-release이거나, 비교할 이전 stable이 없거나, 모델이 본 적 없는 범주 값이면 점수를 내지 않고 `incomplete`로 둡니다.
- **배포 시각:** 비교 기준 선정에 쓰는 registry 배포 시각이 ISO 8601 형식이 아니거나 timezone이 없으면 그 항목은 분석 실패(`incomplete`)입니다.
- **무결성:** 설치될 버전의 lockfile integrity가 registry 값과 다르면 분석 실패로 처리합니다.
- **근거와 설명:** 결과에는 추출된 사실(비교한 버전, 추가된 설치 스크립트, 새 의존성, 바뀐 JS 파일 수)과 모델 설명(점수에 크게 작용한 feature와 기여도)이 따로 나옵니다. 기여도는 LightGBM의 SHAP 값(log-odds 단위)입니다. 상위 feature 외의 기여도 합과 모델 기준값도 함께 보여 주며, 모두 더하면 점수의 log-odds가 됩니다.

| 종료 코드 | 의미                                      | 탐지 CI 처리        |
| --------- | ----------------------------------------- | ------------------- |
| 0         | 평가 대상 변경 중 미완료·위험 판정 없음   | 다음 단계 진행 가능 |
| 1         | ML 기준 이상 또는 기지 악성 일치 변경 존재 | 후속 설치·빌드 중단 |
| 2         | 입력 오류·분석 실패·미지원·모델 연결 문제 | 후속 단계 보류      |

변경 없음·삭제만 있는 요청도 0입니다. 프로젝트 전체가 안전하다는 뜻이 아닙니다.
기지 악성·규칙 탐지기가 연결되면 기지 악성 기록과 일치한 변경은 모델 점수와 관계없이 1, 연결된 탐지기가 실패한 변경은 2로 처리합니다(둘이 겹치면 1). 기지 악성 목록은 기본으로 설치본 색인이 연결되며 `--known-malicious-dir`로 다른 색인을 지정할 수 있습니다. 규칙 탐지기는 추출 실행에 연결되며, 규칙 적중은 종료 코드를 바꾸지 않고 규칙 판정 불가와 규칙 스캔 오류는 2입니다. 연결된 탐지기가 없는 실행은 모델 결과로만 정해집니다. 여러 항목 중 하나라도 미완료면 전체는 2입니다.
`update --apply`가 반영하지 못했을 때의 종료 코드는 [업데이트 반영](#업데이트-반영-depbee-update---apply)에 있습니다.

## 현재 제한

- 로컬 `package-lock.json` v2/v3만 지원합니다. 기준 lockfile은 파일이나 Git 커밋에서 읽고, 저장소 하위 폴더의 단일 프로젝트는 지원하지만 npm workspaces 전체를 한 번에 비교하지는 않습니다.
- npm 공식 registry 의존성만 분석합니다. workspace/link, Git·file·사설 레지스트리 의존성, 같은 버전의 아카이브 변경은 `incomplete`입니다.
- 설치될 버전은 lockfile integrity가 registry 메타데이터의 값과 같은지 보고, 받은 tarball 바이트는 registry 메타데이터의 `dist.integrity`와 대조합니다(`integrity` 키가 없을 때만 옛 `dist.shasum`, 키가 있는데 null이거나 쓸 수 있는 해시가 없으면 분석 실패). `check`는 대조할 lockfile이 없어 registry 값만 쓰며(registry 문서상 2017년 4월부터 기록된 값), 새 버전에 이 값이 없으면 검사하지 못합니다.
- 시간 예산을 넘긴 작업은 그 프로세스를 종료해 멈추므로 결과는 남기지 않습니다. 메타데이터 조회와 추출마다 Python 프로세스를 하나씩 새로 띄우므로 변경 하나에 약 0.3~0.5초가 더 걸립니다(합성 측정).
- 비교 기준 후보는 기지 악성 색인을 연결했을 때만 OSV `MAL-` 기록(명시 버전과 상한 있는 범위)과 대조하고, 학습 데이터처럼 모든 버전 기록이나 학습 archive의 악성 버전으로는 빼지 않습니다. 새 버전 직전 24시간 안의 후보도 별도로 검증하지 않습니다.
- typosquat처럼 패키지 자체가 악성인 경우는 "업데이트 변경점"을 보는 모델의 범위가 아닙니다. 그런 패키지가 OSV `MAL-` 기록에 있으면 기지 악성 탐지기로만 잡힙니다.
- 기지 악성 대조는 색인을 만든 스냅샷 시점까지의 `MAL-` 기록만 봅니다(설치본 색인은 `2026-10-06T14:00:47Z`까지). GHSA에만 있는 과거 사건과 그 뒤에 올라온 기록은 잡지 못하고, 미적중은 안전 판정이 아닙니다.
- `check`는 registry가 그 버전을 제공할 때만 검사 요청을 만들므로 registry에서 내려간 악성 버전은 기지 악성 기록에 있어도 오류(종료 코드 2)입니다. lockfile `scan`은 lockfile의 이름·버전을 그대로 대조하므로 이런 버전도 적중합니다.
- `package.json`만 있는 프로젝트, yarn/pnpm, Git URL 입력은 후속 범위입니다.
- `update --apply`와 대시보드의 반영은 검사한 lockfile 반영과 `npm ci --ignore-scripts` 설치만 합니다. 설치 스크립트 실행, 자동 되돌리기, 새 의존성 추가(`depbee add`), 대안 버전 고정은 없습니다.
- `update`는 `npm:` alias 의존성(`"lodash4": "npm:lodash@^4"`)이 있는 프로젝트를 지원하지 않습니다. Git·파일·URL 의존성과 같은 기준(`:`가 든 값)으로 거부합니다.

## 구조

```text
src/depbee/
  assets/                 # 설치본에 포함된 기본 자산: model/(model.txt, manifest.json), index/(index.json, manifest.json)
  cli.py                  # 인자·한국어 텍스트·JSON 출력·종료 코드
  terminal.py             # 터미널에서만 붙는 표시: 벌 인장, 색, 시작 화면, 다음 동작
  config.py               # 사용자 설정(depbee setup): 저장한 모델·색인 폴더, 원자적 파일 쓰기
  contracts.py            # 공통 규약과 Analyzer/Predictor 인터페이스
  inputs/npm.py           # 대상 프로젝트와 기준 lockfile 비교, check의 단일 버전 요청
  inputs/git.py           # Git 커밋에서 기준 lockfile 읽기
  inputs/npm_cli.py       # update의 프로젝트 검사와 npm 실행(미리보기의 lockfile 계산, 반영의 npm ci)
  analysis/extractor.py   # depbee-analyzer 호출, 근거 정리
  analysis/baseline.py    # 비교 기준 버전(직전 stable) 선정
  analysis/cache.py       # 추출한 feature의 실행 간 캐시
  analysis/registry.py    # registry 메타데이터·tarball 다운로드와 검사, 압축 해제
  analysis/artifact.py    # 분석 결과 검증, 미리 만든 분석 JSON 연결
  inference/lightgbm.py   # 학습 완료 모델 로딩·검증·추론·기여도
  known_malicious.py      # 기지 악성 색인 생성·검증·대조(OSV npm MAL)
  pipeline.py             # 입력→분석→추론 처리 조율
  service.py              # CLI·Actions·MCP·대시보드 공통 진입점(요청·분석기·모델 조립)
  mcp.py                  # 검사 전용 MCP 진입점(check_package, scan_lockfile)
  guard.py                # Claude Code 설치 가드 훅(PreToolUse)과 그 설정 파일 편집(depbee guard)
  history.py              # 로컬 이력 저장소(SQLite): 프로젝트 등록, 보고서 기록·조회
  dashboard/              # 로컬 대시보드(depbee dashboard): app.py, templates/, static/
  dashboard/lifecycle.py  # 백그라운드 대시보드의 시작·상태·종료(잠금, 상태 파일, 제어 요청)
scripts/write_manifest.py # 모델 파일로 manifest.json 생성
scripts/build_known_malicious_index.py # OSV npm all.zip으로 기지 악성 색인 폴더 생성
tests/                    # 합성 자료를 이용한 회귀·모델 연동 테스트
examples/                 # 실행 가능한 명령에 사용할 lockfile: 합성 예시와 lodash 4.17.20 → 4.17.21의 실제 변경
docs/                     # 구조·연결 규약·CI 설계·개발 순서
models/                   # 직접 준비한 모델·색인을 두는 폴더(선택), Git 제외
data/                     # 실제 샘플, Git 제외
artifacts/                # 요청·분석·결과 JSON, Git 제외
.github/workflows/ci.yml  # 이 도구 자체의 검사·테스트·패키징, Action의 실제 검사
.github/scripts/          # CI가 실제 검사의 보고서를 확인하는 스크립트
```

## 개발 환경

소스와 가상환경을 [설치와 준비](../README.md#설치와-준비)에 따라 준비합니다. 개발용으로는 저장소 루트에서 편집 가능 설치를 사용합니다.

```sh
python -m pip install -e ".[dev,extract,mcp,web]"
depbee --help
```

`extract`는 팀의 공개 저장소 depbee-analyzer를 고정된 커밋으로 설치합니다. pip이 Git으로 받으므로 Git이 필요하고 로그인이나 토큰은 필요 없습니다.
depbee-analyzer를 함께 개발할 때는 그 저장소를 받아 `pip install -e ../depbee-analyzer`로 대신 설치합니다.
ML 추론(LightGBM)은 기본 설치에 들어 있고 `ml`은 이전 명령과의 호환용으로 남긴 이름입니다. 추출이 필요 없는 입력·계약 작업만 한다면 `extract`를 빼고 설치할 수 있습니다.
분석기 없이 설치한 depbee에서 `check`나 `scan --extract`처럼 추출이 필요한 명령을 실행하면 오류(종료 코드 2)로 끝나고, 그 오류에 이 depbee가 고정한 분석기 커밋을 설치하는 pip 명령이 적혀 있습니다. 명령은 그 depbee를 실행한 Python을 경로로 지정합니다. 그래서 어느 폴더에서 실행해도 되고, 가상환경을 활성화하지 않았거나 PATH의 `python`이 다른 환경의 것이어도 depbee가 설치된 환경에 설치됩니다.

Windows에서는 PowerShell 형식(`& '<Python 경로>' -m pip install '<분석기>'`)으로, macOS/Linux에서는 셸 형식(`<Python 경로> -m pip install '<분석기>'`, 경로는 필요할 때 작은따옴표로 감쌈)으로 나옵니다. Windows에서 Python 경로에 `[`, `]`, 백틱이 있으면 PowerShell의 명령 찾기(`&`, `Get-Command`, `Start-Process`)가 그 경로를 와일드카드로 읽어 다른 Python을 실행할 수 있으므로, 경로를 그대로 Windows의 프로세스 실행 API(`System.Diagnostics.ProcessStartInfo`)에 넘기는 더 긴 PowerShell 명령으로 나옵니다. 이 명령도 pip을 명령을 입력한 폴더에서 실행하므로 소스 checkout의 `.[extract]`가 그대로 동작합니다. 그 파일이 없거나 pip이 실패하면 그 줄이 오류로 끝나며, PowerShell 창과 현재 위치, 변수, `$ErrorActionPreference`는 그대로입니다. 어느 형식이든 아래처럼 오류 JSON을 디코딩해 나온 명령 전체를 복사해 실행하고, 이 문서의 형식을 보고 직접 다시 쓰지 않습니다.

오류는 stderr의 JSON 한 줄(`{"status": "error", "exit_code": 2, "error": "..."}`)이고, 명령은 `error` 값 안에서 Windows는 `in PowerShell:` 뒤, macOS/Linux는 콜론 뒤부터 맨 끝 괄호(import 오류) 앞까지입니다. 이 줄은 역슬래시, 큰따옴표, 비ASCII 문자와 제어 문자를 이스케이프한 JSON이므로 줄에 보이는 글자를 복사하지 말고 디코딩한 `error` 값에서 명령을 복사합니다. 디코딩할 때는 오류를 낸 것과 같은 depbee 실행 파일로 같은 명령을 다시 실행합니다. 가상환경을 활성화하지 않고 그 안의 depbee를 직접 실행했다면 PATH의 `depbee`는 다른 환경의 것이거나 없을 수 있으므로 그 경로를 그대로 씁니다. 예를 들어 PowerShell에서는 `(.\.venv\Scripts\depbee.exe check ms@2.1.3 2>&1 | ConvertFrom-Json).error`, macOS/Linux에서는 `.venv/bin/depbee check ms@2.1.3 2>&1 >/dev/null | .venv/bin/python -c 'import json, sys; print(json.load(sys.stdin)["error"])'`입니다. PowerShell에서 `[`나 `]`가 든 폴더로 이동할 때는 그냥 `cd`가 이름을 와일드카드로 읽어 다른 폴더로 갈 수 있으므로 `cd -LiteralPath '<폴더>'`를 씁니다. 디코딩한 명령에서 경로의 작은따옴표가 PowerShell에서는 `''`, `’’`처럼 두 번씩, macOS/Linux에서는 `'"'"'`로 적혀 있는 것은 셸이 원래 글자 하나로 읽는 표기이므로 고치지 않고 그대로 실행합니다.

### Git 주소로 설치

소스를 따로 받지 않고 pip에 저장소 주소와 커밋을 주어 설치할 수 있습니다. depbee는 PyPI에 올리지 않았습니다. `pip install depbee`처럼 이름만 주는 설치는 이 프로젝트를 설치하지 않습니다.

```sh
python -m pip install "depbee[extract,mcp,web] @ git+https://github.com/26-Capstone-Project-Team01/depbee@759cc6880452b178566fe0d3294dadaf1a249d2c"
```

`@` 뒤는 설치할 커밋의 전체 SHA입니다. 예시는 depbee `main`에 있는 커밋(depbee 0.2.1)이고, 다른 커밋을 설치하려면 그 SHA로 바꿉니다. 저장소에 태그와 Release는 없습니다. pip은 depbee와 분석기 두 저장소를 로그인 없이 받습니다.

### wheel 만들기와 설치

저장소 루트에서 다음 명령을 실행하면 `dist/`에 현재 버전의 wheel이 생깁니다.

```sh
python -m pip wheel --no-deps --wheel-dir dist .
```

wheel로 depbee를 실행할 수 있습니다. 모델 manifest나 색인을 직접 생성할 때는 소스 저장소의 `scripts/`를 사용합니다. Python 3.11 이상의 가상환경을 만들고 활성화한 뒤 wheel이 있는 폴더에서 하나를 골라 실행합니다. 파일 이름은 받은 버전에 맞춥니다.

```sh
python -m pip install ./depbee-0.2.1-py3-none-any.whl                     # 기본 CLI와 plan
python -m pip install "./depbee-0.2.1-py3-none-any.whl[extract,mcp,web]"  # ML 분석과 네 진입점
```

빈 가상환경에서 설치하면 Windows에는 `.venv\Scripts\depbee.exe`, macOS/Linux에는 `.venv/bin/depbee`가 생깁니다. 활성화한 터미널에서 `depbee --help`로 설치를 확인합니다. wheel에는 Python 코드, 대시보드 템플릿·스타일, [기본 모델과 기지 악성 색인](#기본-자산)이 들어갑니다. 분석기는 `extract` 옵션으로 따로 설치합니다. `extract` 옵션은 설치할 때 고정된 분석기 커밋을 공개 저장소에서 Git으로 받으므로 Git과 네트워크가 필요하고 로그인은 필요 없습니다. 사용한 분석기 커밋은 보고서의 `provenance.feature_extractor.commit`에서 확인합니다.

같은 버전 번호의 시험 wheel을 교체할 때는 새 가상환경을 사용하거나 `python -m pip install --force-reinstall`에 사용할 wheel 경로와 extra를 지정합니다.

PowerShell에서 가상환경 활성화가 제한되면 활성화하지 않고 `.\.venv\Scripts\python.exe -m pip install ".[extract,mcp,web]"`과 `.\.venv\Scripts\depbee.exe --help`를 직접 실행할 수 있습니다. 가상환경 활성화 없이 계속 사용하려면 Python 3.11 이상의 `pipx` 환경에서 `pipx install ".[extract,mcp,web]"`로 설치합니다. `pipx ensurepath`를 한 번 실행하고 새 터미널에서 `depbee --help`를 확인합니다. Windows의 `depbee.exe`와 macOS/Linux의 `depbee`는 Python 환경의 실행 명령입니다. depbee는 공개 저장소의 소스로만 배포합니다. PyPI 패키지, GitHub Release, Python 없이 실행하는 독립 바이너리는 제공하지 않습니다.

## 검증

```powershell
python -m unittest discover -s tests -v
python -m ruff check .
python -m build
```

`python -m ruff format --check .`는 개발 CI 밖의 별도 서식 점검입니다. 기존 파일에 서식 차이가 남을 수 있습니다.

테스트는 네트워크와 depbee-analyzer 없이 돌도록 depbee-analyzer 호출을 가짜로 바꿔 둡니다. ML 의존성이 없으면 native LightGBM 테스트는 skip됩니다.
depbee-analyzer(`.[extract]`)가 설치돼 있으면 고정 커밋의 loader·extractor를 합성 tarball과 가짜 registry 응답으로 실행하는 경계 테스트도 돌고, 없으면 skip됩니다. 네트워크는 쓰지 않습니다.
MCP SDK(`.[mcp]`)가 없으면 MCP 프로토콜 경로(메모리 내 클라이언트, stdio 하위 프로세스) 테스트만 skip되고, 도구 함수와 CLI 동등성 테스트는 그대로 돕니다. `.[web]`이나 `httpx2`(`[dev]`에 포함)가 없으면 대시보드 화면·보안 테스트가 skip되고, extra 없는 환경의 안내 테스트는 그대로 돕니다. CI는 `[extract]`, `[mcp]`, `[web]`을 모두 설치하므로 extra가 없어서 건너뛰는 테스트가 없습니다. 경로 없이 띄운 stdio MCP 서버의 보고서가 설치본 모델 ID와 색인 기준 시점을 싣는지 보는 테스트는 실제 모델·색인·분석기를 쓰므로 `extract`가 설치된 환경에서만 돕니다.
테스트의 작은 모델은 직렬화·연결 검증용 합성 모델이며 실제 악성 탐지 모델이 아닙니다.

다음 작업은 [연결 규약](contracts.md), [구조와 담당](architecture.md), [CI/CD 연결](ci-cd.md), [통합 순서](development.md)를 참고합니다.

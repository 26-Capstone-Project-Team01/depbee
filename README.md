# depbee

depbee는 npm 패키지를 설치하기 전에 버전 변경을 검사합니다. 공개 악성 기록에 등록된 이름·버전인지 확인하고, 새 버전과 이전 배포본의 차이로 계산한 ML 위험 점수와 근거를 보여 줍니다. 검사는 패키지 코드를 실행하지 않습니다. 낮은 점수만으로 안전을 보증할 수는 없습니다.

진입점은 네 가지입니다. [CLI](#cli)와 [로컬 대시보드](#로컬-대시보드)로 자기 프로젝트를 검사하고 업데이트를 관리합니다. [MCP](#mcp)는 AI 에이전트의 설치 전 검사에, [GitHub Actions](#github-actions)는 PR의 lockfile 변경 검사에 씁니다. 통과·경고·실패가 PR에 어떻게 나타나는지는 합성 정책 [공개 시연](#공개-시연)에서 바로 볼 수 있습니다.

## 설치와 준비

Python 3.11 이상이 필요합니다. 저장소 접근 권한이 있다면 소스를 받아 가상환경에 설치합니다.

```sh
git clone https://github.com/26-Capstone-Project-Team01/depbee.git
cd depbee
```

**Windows PowerShell** (Python 3.13 예시)

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install ".[extract,mcp,web]"
depbee --help
```

**macOS/Linux** (Bash 또는 Zsh)

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ".[extract,mcp,web]"
depbee --help
```

가상환경을 활성화하면 어느 프로젝트에서든 `depbee`를 실행할 수 있습니다. 패키지에서 특징을 추출하는 `extract` 설치에는 비공개 분석기 저장소 접근 권한이 필요합니다. [분석기 저장소](https://github.com/26-Capstone-Project-Team01/depbee-analyzer) · [wheel과 pipx 설치](docs/usage.md#wheel-만들기와-설치)

**설치 직후 `depbee check lodash@4.17.21`로 첫 검사를 실행하세요.** wheel에는 모델 `D04-E00`과 `2026-10-06T14:00:47Z` 기준 OSV npm 색인이 들어 있습니다. `depbee setup`으로 현재 자산을 확인할 수 있고, 매 보고서에 실제 검사에 쓴 모델과 색인이 기록됩니다. [기본 자산 변경](docs/usage.md#기본-자산) · [결과 재현에 남길 값](docs/usage.md#결과-재현에-남길-값)

호스트에 Python과 Node.js를 설치하지 않고 쓰려면 로컬 Docker 이미지 하나로 CLI 검사, stdio MCP, 대시보드를 실행합니다. [Docker로 실행](#docker로-실행)

## CLI

아래 예시는 Git에 `package-lock.json`(v2 또는 v3)을 커밋한 npm 프로젝트 폴더에서 실행합니다. 기본 비교 기준은 Git HEAD이며 Git 2.45 이상이 필요합니다. 기준 파일을 직접 지정하려면 `--base-lock <파일>`을 사용합니다.

```powershell
depbee plan .                  # 바뀐 의존성 목록만 출력
depbee scan . --extract         # lockfile 변경 검사
depbee check lodash@4.17.21     # lockfile 없이 정확한 버전 하나 검사
depbee update                  # npm 업데이트 미리보기 (Node.js와 npm 필요)
```

검사 종료 코드는 `0` 통과, `1` 위험, `2` 보류 또는 오류입니다. 결과를 파일에 남기려면 `depbee scan . --extract --format json --output report.json`을 사용합니다(`report.json`은 새 파일이어야 합니다).

인수 없이 `depbee`만 실행하면 벌 인장과 자주 쓰는 명령을 모은 시작 화면이 나옵니다. 검사한 것이 없으므로 이때의 종료 코드는 2입니다. 터미널에서 직접 실행한 텍스트 결과에는 판정의 색과 마지막의 **다음 동작** 안내가 붙습니다. 파이프나 파일로 보낸 출력, JSON, Markdown은 전과 같습니다. [터미널에서 보는 화면](docs/usage.md#터미널에서-보는-화면)

미리보기를 검토한 뒤 `depbee update --apply lockfile`로 변경을 반영하거나 `depbee update --apply install`로 설치까지 진행할 수 있습니다. 설치에는 `npm ci --ignore-scripts`를 사용합니다. 기지 악성 일치는 반영을 거부하고, ML 기준 이상·보류·기지 악성 미확인은 추가 확인을 요구합니다. [반영 조건과 백업·복구](docs/usage.md#업데이트-반영-depbee-update---apply)

## 로컬 대시보드

```powershell
depbee dashboard                # 이 터미널에서 실행, Ctrl+C로 종료
depbee dashboard --background   # 백그라운드로 실행하고 주소 출력 (터미널을 닫아도 유지)
depbee dashboard --status       # 실행 중인 백그라운드 대시보드의 주소 다시 보기
depbee dashboard --stop         # 백그라운드 대시보드 종료
```

`--background`는 서버가 실제로 응답한 뒤에 주소를 출력하고, 이미 실행 중이면 새로 띄우지 않고 그 주소를 보여 줍니다. `--stop`으로 끄면 그 주소는 만료됩니다. [백그라운드 실행](docs/usage.md#백그라운드-실행)

터미널에 출력된 개인용 `127.0.0.1` 주소를 엽니다. 처음에는 화면에 하나뿐인 **프로젝트 추가** 버튼으로 npm 프로젝트를 등록합니다. 다음부터는 **프로젝트 현황판**에서 프로젝트별 최근 검사 상태와 최근 반영 시도를 비교합니다. 프로젝트를 열면 **패키지**에서 버전·설치 위치·종류와 후보 근거를, **업데이트**에서 미리보기와 반영을, **기록**에서 점수 이력과 보고서를 볼 수 있습니다.

**전체 업데이트 확인**이나 직접 의존성 하나의 **후보 확인**으로 npm이 제안한 변경을 미리 보고, 검사 근거를 검토한 뒤 lockfile 반영이나 설치를 선택합니다. **검사만**은 현재 lockfile과 Git HEAD의 차이를 검사합니다. 화면을 여는 것만으로는 npm을 실행하거나 네트워크로 검사하지 않습니다. 업데이트 후보는 지금의 `package.json`·`package-lock.json`으로 확인한 결과만 보이고, 그렇지 않으면 미확인으로 표시합니다. [화면별 설명](docs/usage.md#로컬-대시보드-depbee-dashboard)

## MCP

에이전트가 설치 전에 검사하게 하려면 depbee를 stdio 서버로 등록합니다. 등록 명령은 `depbee mcp`뿐이고 모델·색인 경로를 넣지 않습니다. 환경 변수나 저장한 설정으로 바꾸지 않았다면, 경로를 주지 않은 서버는 [설치본의 모델과 색인](#설치와-준비)을 씁니다.

```sh
claude mcp add --scope user depbee -- "<depbee 실행 파일의 절대 경로>" mcp   # Claude Code
codex mcp add depbee -- "<depbee 실행 파일의 절대 경로>" mcp                # Codex
```

쓰는 에이전트의 줄만 실행하고 `claude mcp list`나 `codex mcp list`로 확인합니다. `check_package`는 정확한 이름@버전 하나를, `scan_lockfile`은 프로젝트의 lockfile 변경을 검사합니다. 두 도구는 검사 결과를 반환하고 설치·업데이트는 에이전트가 수행합니다. 응답은 안내 문구(`notices`)와 보고서 원문(`report`)을 함께 담고, `report.model_id`와 `report.detectors.known_malicious.list_as_of`가 검사에 쓴 모델과 색인 기준 시점입니다. 서버 지침은 에이전트가 결과를 말할 때 이 두 값을 인용하게 합니다.

PowerShell과 Bash의 등록 명령, Codex 설정, 직접 준비한 모델·색인으로 등록하는 방법은 [에이전트에 등록하기](docs/usage.md#에이전트에-등록하기)에 있습니다. 에이전트가 설치 전에 도구를 부르게 하려면 프로젝트의 지침 파일에 [에이전트 지침 예시](docs/usage.md#에이전트-지침-예시-설치업데이트-전에-먼저-검사)를 복사해 넣습니다.

## GitHub Actions

PR에서 lockfile 변경을 검사하려면 예시 workflow를 대상 저장소의 `.github/workflows/depbee.yml`에 둡니다. `pull_request`의 기준 커밋과 비교하며, 검사 결과는 Checks의 요약, lockfile 줄 주석, `depbee-report` 아티팩트에서 확인합니다. Action은 고정한 커밋의 설치본에 든 모델과 색인을 기본으로 쓰고, Release 태그와 SHA-256은 다른 모델이나 색인으로 바꿀 때만 지정합니다. [복사할 전체 workflow와 입력](docs/ci-cd.md#사용-예시)

기지 악성 일치는 `fail-on`과 관계없이 항상 실패합니다. ML 기준 이상과 보류는 기본 경고이며 `fail-on: ml-hit, incomplete`로 실패 조건에 추가할 수 있습니다. 입력이나 검증 오류도 실패합니다. 병합을 막으려면 저장소의 필수 검사로 지정합니다.

### 공개 시연

통과, 경고, 실패가 PR에서 어떻게 보이는지는 공개 저장소 [depbee-actions-demo](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo)의 열린 PR 세 개에서 볼 수 있습니다.

| 장면 | PR | Check | lockfile 줄 주석 |
| --- | --- | --- | --- |
| 정상 버전 변경 | [#1](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/pull/1) | 성공 | 없음 |
| 사전 배포 버전 보류 | [#2](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/pull/2) | 성공 | 경고 1개 |
| 가상 목록 일치 | [#3](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/pull/3) | 실패 | 오류 1개 |

세 장면을 한 번에 실행한 기록은 [Actions run 44781575143](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/actions/runs/44781575143)입니다. 가상 목록 일치 장면의 실패가 기대 결과이므로 이 실행은 전체가 실패로 표시됩니다.

이 시연은 합성 정책 시연입니다. 시연 저장소의 fixture 게이트가 합성 lockfile의 이름과 버전을 가상 목록과 비교해, 일치는 실패이고 보류는 경고라는 정책이 PR에 어떻게 나타나는지 보여 줍니다. depbee 제품은 실행되지 않으며 Check의 성공과 실패는 보안 판정이 아닙니다. [장면별 확인 방법](docs/demo.md#github-actions)

### 실제 제품 검사의 조건

외부 저장소의 PR에서 depbee Action이 실제로 검사하려면 depbee와, 설치 단계에서 사용하는 depbee-analyzer가 모두 공개돼야 합니다. Action은 전체 커밋 SHA로 고정하고, 모델과 색인은 그 커밋의 설치본에 포함된 것을 기본으로 씁니다. Release 태그와 SHA-256은 다른 모델이나 색인을 명시해 바꿀 때만 씁니다. 두 저장소의 공개가 아직 허용되지 않았으므로, secret 없이 도는 공개 저장소에서의 실제 제품 검사 시연은 실행하지 않았습니다. 공개 전에도 depbee 저장소 루트에서 아래 명령으로 기지 악성 일치 예시의 실패 판정(종료 코드 1)을 확인할 수 있습니다.

```powershell
python -I src/depbee/actions.py report docs/examples/result-contract/03-known-malicious-low-ml.json --lockfile examples/project/package-lock.json
```

## Docker로 실행

호스트에 Python과 Node.js가 없어도 depbee 저장소에서 빌드한 로컬 이미지 `depbee:local`로 대시보드, CLI 검사, stdio MCP를 실행합니다. 빌드에는 비공개 저장소의 읽기 권한이 필요합니다. [이미지 빌드](docs/docker.md#이미지-빌드)

대시보드는 검사할 npm 프로젝트 폴더에서 아래 블록 하나로 시작합니다. 프로젝트는 읽기 전용으로 연결하고, 포트는 호스트의 `127.0.0.1`에만 게시하며, 등록과 기록은 `depbee-home` 볼륨에 남깁니다.

**PowerShell**

```powershell
$project = (Get-Location).Path
$hash = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($project)), 0, 4).Replace('-', '').ToLower()
$alias = "$(Split-Path -Leaf $project)-$hash"
docker run --rm -it -p 127.0.0.1:5757:5757 --mount "type=bind,source=$project,target=/projects/$alias,readonly" --mount type=volume,source=depbee-home,target=/home/depbee depbee:local dashboard
```

**Bash**

```sh
project="$PWD"
hash="$({ printf '%s' "$project" | sha256sum || printf '%s' "$project" | shasum -a 256; } 2>/dev/null)"
if [[ "$hash" =~ ^[0-9a-f]{64} ]]; then
    alias="$(basename "$project")-${hash:0:8}"
    docker run --rm -it -p 127.0.0.1:5757:5757 --mount "type=bind,source=$project,target=/projects/$alias,readonly" --mount type=volume,source=depbee-home,target=/home/depbee depbee:local dashboard
else
    echo 'sha256sum과 shasum으로 경로 해시를 만들지 못해 컨테이너를 시작하지 않았습니다. docs/docker.md의 "별칭을 직접 정합니다"를 따르세요.' >&2
fi
```

출력된 `http://127.0.0.1:5757/s/...` 주소를 브라우저에서 열어 연결한 폴더를 등록하고, Ctrl+C로 종료합니다. 읽기 전용 연결에서는 조회, 검사만, 업데이트 확인까지 할 수 있습니다.

이력은 프로젝트를 컨테이너 경로(`/projects/<별칭>`)로 구분합니다. 같은 볼륨에서 다른 프로젝트를 이미 쓴 별칭에 연결하면 이전 프로젝트의 기록이 그 프로젝트의 기록으로 보입니다. 위의 `$alias`는 폴더 이름에 절대 경로의 해시를 붙여 폴더마다 다른 별칭을 만듭니다. Bash 블록은 `sha256sum`을 쓰고 없으면 `shasum`을 쓰며, 온전한 해시를 얻지 못하면 컨테이너를 시작하지 않습니다. 그때는 별칭을 직접 정합니다. [프로젝트 별칭과 이력](docs/docker.md#프로젝트-별칭과-이력)

[CLI 검사](docs/docker.md#cli-검사) · [MCP 등록](docs/docker.md#claude-code에-stdio-mcp-서버-등록) · [프로젝트 여러 개](docs/docker.md#프로젝트-여러-개) · [쉼표가 있는 경로](docs/docker.md#쉼표가-있는-경로) · [읽기 전용 연결과 반영](docs/docker.md#읽기-전용-연결과-반영) · [포트](docs/docker.md#포트) · [종료](docs/docker.md#종료)

## 참고 문서

[네 진입점 시연](docs/demo.md) · [상세 사용법과 지원 범위](docs/usage.md) · [Docker로 실행하기](docs/docker.md) · [결과 필드와 연결 규약](docs/contracts.md) · [구조](docs/architecture.md) · [검증 기록](docs/validation.md) · [공개 Actions 시연 저장소](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo)

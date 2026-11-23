# Docker로 실행하기

depbee 소스에서 직접 빌드한 로컬 이미지로 CLI 검사(`plan`, `scan`, `check`), stdio MCP 서버, [대시보드](#대시보드)를 실행합니다. 모델과 기지 악성 색인, 대시보드의 업데이트 확인에 쓰는 Node.js 24.11.0과 npm 11.6.1은 이미지에 들어 있습니다. [설치본의 기본 자산](usage.md#기본-자산) · [호스트 설치](../README.md#설치와-준비)

Linux 컨테이너와 BuildKit이 필요합니다. Windows에서는 Docker Desktop과 PowerShell, Linux에서는 Docker Engine과 Bash를 사용합니다.

## 이미지 빌드

이미지는 depbee 소스에서 직접 빌드합니다. depbee와 분석기(depbee-analyzer) 저장소는 비공개이고, 공개 레지스트리에서 받는 이미지는 없습니다. 준비 방법은 가진 권한에 따라 다릅니다.

| 가진 것 | 준비 방법 | 실행할 수 있는 것 |
| --- | --- | --- |
| 두 저장소의 읽기 권한 | 아래 명령으로 기본 이미지를 빌드합니다. | 이 문서의 모든 기능 |
| depbee 소스만 | 토큰 없이 `docker build --target core -t depbee:local .`로 분석기를 뺀 이미지를 빌드합니다. | `plan`, `--extract` 없는 `scan`, 대시보드의 등록과 조회 |
| 권한이 있는 사람이 빌드한 이미지 파일 | [빌드한 이미지 전달](#빌드한-이미지-전달)의 `docker load`로 불러옵니다. | 그 이미지와 같음 |

분석기를 뺀 이미지에서 `check`, `scan --extract`, MCP의 두 도구, 대시보드의 **검사만**과 **업데이트 확인**은 분석기를 설치하라는 오류로 끝납니다. CLI의 종료 코드는 2입니다.

기본 이미지는 depbee 저장소 루트에서 빌드합니다. 비공개 분석기의 고정 커밋을 받으려면 해당 저장소의 `Contents` 읽기 권한이 있는 GitHub 토큰이 필요합니다. 아래 명령은 현재 셸에 `GH_TOKEN`이 없을 때만 입력을 받습니다. [분석기 저장소](https://github.com/26-Capstone-Project-Team01/depbee-analyzer)

**PowerShell**

```powershell
if (-not $env:GH_TOKEN) { $env:GH_TOKEN = [System.Net.NetworkCredential]::new('', (Read-Host 'GH_TOKEN' -AsSecureString)).Password }
```

**Bash**

```sh
[ -n "${GH_TOKEN:-}" ] || read -rs -p 'GH_TOKEN: ' GH_TOKEN
export GH_TOKEN
```

두 셸에서 같은 명령으로 이미지를 빌드하고 버전을 확인합니다.

```sh
# depbee 저장소 루트에서 실행
docker build --secret id=gh_token,env=GH_TOKEN -t depbee:local .
docker run --rm depbee:local --version
```

토큰은 빌드 중 비공개 분석기를 받는 단계에만 전달합니다. 빌드 후 `docker run`에는 자격 증명이 필요 없습니다. [Docker 빌드 시크릿](https://docs.docker.com/build/building/secrets/)

### 빌드한 이미지 전달

기본 이미지에는 비공개 분석기의 코드가 들어 있습니다. 두 저장소를 볼 권한이 있는 사람에게만 전달하고 공개 레지스트리에 올리지 않습니다. 이미지는 파일로 저장해 전달합니다. 받은 PC에서는 빌드와 토큰 없이 실행합니다.

```sh
docker save -o depbee-local.tar depbee:local    # 빌드한 PC에서 실행
docker load -i depbee-local.tar                 # 받은 PC에서 실행
docker run --rm depbee:local --version
```

## CLI 검사

이제 검사할 npm 프로젝트 폴더로 이동합니다. 다음은 `package-lock.json`이 Git에 커밋된 일반 clone의 예입니다. 별도의 Git worktree나 Git 이력이 없는 폴더에서는 [비교 기준 lockfile](#비교-기준-lockfile)을 지정합니다.

**PowerShell**

```powershell
# 검사할 npm 프로젝트 루트에서 실행
$project = (Get-Location).Path
```

**Bash**

```sh
# 검사할 npm 프로젝트 루트에서 실행
project="$PWD"
```

이미지의 진입점이 `depbee`이므로 `depbee:local` 뒤에 `depbee`의 인자를 그대로 적습니다.

```sh
# 네트워크 없이 실행
docker run --rm --network none --mount "type=bind,source=$project,target=/project,readonly" depbee:local plan /project
docker run --rm --network none --mount "type=bind,source=$project,target=/project,readonly" depbee:local scan /project

# registry 접근이 필요한 검사
docker run --rm depbee:local check lodash@4.17.21
docker run --rm --mount "type=bind,source=$project,target=/project,readonly" depbee:local scan /project --extract
```

프로젝트는 컨테이너의 `/project`에 읽기 전용으로 연결합니다. `plan`은 버전 변경 목록을 출력하고 `scan`은 기본 색인으로 대조합니다. `--extract` 없는 `scan`에서 ML 분석이 필요한 변경은 보류로 표시될 수 있습니다. `check`와 `scan --extract`는 정적 분석용 메타데이터와 tarball을 받기 위해 npm registry로 HTTPS 연결이 필요합니다. 패키지 이름과 버전만 검사하는 `check`에는 마운트가 필요 없습니다. [Docker bind mount](https://docs.docker.com/engine/storage/bind-mounts/)

Linux에서 이미지의 기본 사용자(`10001:10001`)는 마운트한 디렉터리를 통과하고 lockfile을 읽을 수 있어야 합니다. Git HEAD와 비교하려면 `.git` 아래 디렉터리와 Git 객체에도 같은 접근 권한이 필요합니다. 프로젝트 소유자만 접근할 수 있는 폴더(0700)나 파일(0600)은 일반 Linux Docker에서 소유자 계정의 Bash로 `docker run` 뒤에 `--user "$(id -u):$(id -g)" -e HOME=/tmp`를 추가해 검사할 수 있습니다. Docker가 사용자 ID를 재매핑하는 환경에서는 컨테이너에서 읽을 수 있는 사본과 `--base-lock`을 사용하세요.

## 비교 기준 lockfile

기본 비교 대상은 Git HEAD에 커밋한 `package-lock.json`입니다. 연결한 폴더는 소유자가 컨테이너 사용자와 다르므로, 이미지의 Git은 아래 위치의 저장소만 읽습니다(`safe.directory`).

| 컨테이너 경로 | 연결하는 곳 |
| --- | --- |
| `/project` | CLI 검사와 MCP |
| `/projects`, `/projects` 아래의 모든 폴더 | 대시보드 |

다른 경로에 연결한 저장소에서는 Git이 `detected dubious ownership` 오류를 내고 HEAD 기준 검사가 종료 코드 2로 끝납니다. CLI 검사에는 직접 관리하는 저장소 루트를 `/project`에 연결하세요. npm 프로젝트가 저장소의 하위 폴더라면 저장소 루트를 마운트하고 `plan /project/<하위 폴더>`처럼 실행합니다.

별도의 Git worktree는 `.git` 파일이 컨테이너 밖을 가리킬 수 있습니다. 호스트에서 이전 lockfile을 아래의 빈 파일 이름으로 내보낸 뒤 `--base-lock`으로 전달합니다. Git 이력이 없다면 보관한 이전 lockfile을 같은 위치에 둡니다.

**PowerShell**

```powershell
# 검사할 npm 프로젝트 루트에서 실행
cmd /c "git show HEAD:./package-lock.json > previous-package-lock.json"
```

**Bash**

```sh
# 검사할 npm 프로젝트 루트에서 실행
git show HEAD:./package-lock.json > previous-package-lock.json
```

```sh
docker run --rm --network none --mount "type=bind,source=$project,target=/project,readonly" depbee:local scan /project --base-lock /project/previous-package-lock.json
```

`previous-package-lock.json`에는 비교할 이전 내용을 저장하세요. 현재 lockfile과 내용이 같으면 변경도 없습니다.

## Claude Code에 stdio MCP 서버 등록

MCP 도구를 쓸 npm 프로젝트의 checkout 루트에서 등록합니다. 그 폴더의 경로를 변수에 담습니다.

**PowerShell**

```powershell
# MCP 도구를 쓸 npm 프로젝트 루트에서 실행
$project = (Get-Location).Path
```

**Bash**

```sh
# MCP 도구를 쓸 npm 프로젝트 루트에서 실행
project="$PWD"
```

두 셸에서 같은 명령으로 등록합니다.

```sh
claude mcp add --transport stdio --scope local depbee '--' docker run --rm -i --mount "type=bind,source=$project,target=/project,readonly" depbee:local mcp
claude mcp list
```

`--scope local`은 이 프로젝트에서 본인만 쓰는 등록입니다. 셸이 등록 시점에 `$project`를 호스트 절대 경로로 바꾸고 Docker가 그 폴더를 `/project`에 연결합니다. 프로젝트를 옮기기 전에 기존 프로젝트 폴더에서 `claude mcp remove depbee --scope local`로 등록을 지우고, 옮긴 뒤에는 새 프로젝트 폴더에서 `$project`를 다시 정의하고 위 명령으로 등록합니다. `-i`로 표준 입력을 유지하고 TTY(`-t`)와 포트 게시 없이 실행합니다. [Claude Code의 stdio 서버 등록](https://code.claude.com/docs/en/mcp)

도구에는 컨테이너 안의 경로를 넘깁니다.

| 도구 | 인자 | 값 |
| --- | --- | --- |
| `check_package` | `package` | 정확한 `NAME@VERSION`. 예시는 `lodash@4.17.21` |
| `scan_lockfile` | `project` | `/project` |
| `scan_lockfile` | `base_lock` (선택) | `/project` 아래의 이전 lockfile. 예시는 `/project/previous-package-lock.json` |
| `scan_lockfile` | `base_ref` (선택) | 기준으로 쓸 Git 커밋, 브랜치, 태그. `base_lock`과 함께 쓸 수 없음 |

패키지 하나만 검사하면 마운트 없이 `docker run --rm -i depbee:local mcp`를 등록할 수 있습니다. `--rm`으로 실행한 컨테이너의 이력과 캐시는 종료 시 사라집니다. 보고서를 호스트에 남기려면 `--format json`으로 출력해 저장합니다. [에이전트 지침 예시](usage.md#에이전트-지침-예시-설치업데이트-전에-먼저-검사)

## 대시보드

같은 이미지로 [로컬 대시보드](usage.md#로컬-대시보드-depbee-dashboard)를 실행합니다. 컨테이너는 이 터미널에서 실행되고, 브라우저는 호스트에서 엽니다. 대시보드에서 볼 npm 프로젝트 폴더로 이동해 폴더 경로와 그 프로젝트의 별칭을 변수에 담습니다.

**PowerShell**

```powershell
# 대시보드에서 볼 npm 프로젝트 루트에서 실행
$project = (Get-Location).Path
$hash = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($project)), 0, 4).Replace('-', '').ToLower()
$alias = "$(Split-Path -Leaf $project)-$hash"
```

**Bash**

```sh
# 대시보드에서 볼 npm 프로젝트 루트에서 실행
project="$PWD"
hash="$(printf '%s' "$project" | sha256sum | cut -c1-8)"
alias="$(basename "$project")-$hash"
```

별칭은 컨테이너 안에서 이 프로젝트를 가리키는 이름입니다. 폴더 이름에 폴더 절대 경로의 SHA-256 앞 8자리를 붙여 만듭니다(예: `shop-api-1a2b3c4d`). 같은 폴더에서는 늘 같은 별칭이 나오고, 이름이 같은 다른 폴더에서는 다른 별칭이 나옵니다. [프로젝트 별칭과 이력](#프로젝트-별칭과-이력)

두 셸에서 같은 명령으로 시작합니다.

```sh
docker run --rm -it -p 127.0.0.1:5757:5757 --mount "type=bind,source=$project,target=/projects/$alias,readonly" --mount type=volume,source=depbee-home,target=/home/depbee depbee:local dashboard
```

터미널에 이번 실행의 주소가 출력됩니다. 이 주소를 호스트의 브라우저에 붙여 넣습니다. 브라우저를 자동으로 열지 않습니다.

```text
http://127.0.0.1:5757/s/<이번 실행의 세션 값>/
이 주소를 호스트의 브라우저에서 여세요. 컨테이너의 5757번 포트를 호스트의 127.0.0.1에만 같은 번호로 게시해야 열립니다(docker run -p 127.0.0.1:5757:5757). 종료하려면 Ctrl+C를 누르거나 docker stop을 실행하세요.
```

| 옵션 | 하는 일 |
| --- | --- |
| `-p 127.0.0.1:5757:5757` | 컨테이너의 5757번 포트를 호스트의 `127.0.0.1`에만 게시합니다. [포트](#포트) |
| `--mount type=bind,...,target=/projects/<별칭>` | 프로젝트 폴더를 컨테이너의 `/projects` 아래에 그 프로젝트의 별칭으로 연결합니다. [프로젝트 폴더 연결과 등록](#프로젝트-폴더-연결과-등록) |
| `readonly` | 컨테이너가 프로젝트 파일을 바꾸지 못하게 합니다. [읽기 전용 연결과 반영](#읽기-전용-연결과-반영) |
| `--mount type=volume,source=depbee-home,...` | 이력과 캐시를 Docker 볼륨에 남깁니다. [이력 보관](#이력-보관) |
| `-it` | Ctrl+C로 종료할 수 있게 터미널을 연결합니다. [종료](#종료) |

### 프로젝트 폴더 연결과 등록

컨테이너의 대시보드는 `/projects` 아래에 연결한 폴더만 프로젝트로 등록합니다. 호스트의 폴더 선택 창을 열지 않고, 컨테이너의 다른 경로나 연결하지 않은 호스트 폴더는 보이지 않습니다. 이미지에 설정된 환경 변수 `DEPBEE_CONTAINER_PROJECTS=/projects`가 이 동작을 켭니다. 호스트에 설치한 depbee에는 이 변수가 없으므로 전과 같이 폴더 선택 창을 엽니다.

1. 첫 화면에서 **프로젝트 추가**를 누릅니다. 등록한 프로젝트가 이미 있으면 **프로젝트 관리**의 **프로젝트 폴더 선택**을 누릅니다.
2. `/projects` 아래의 폴더 목록이 열립니다. `package-lock.json`이 있는 폴더에는 "npm 프로젝트" 표시와 **등록** 버튼이 있습니다. 폴더 이름을 누르면 그 안의 폴더를 엽니다.
3. **등록**을 누릅니다. 첫 프로젝트를 등록하면 현황판이 열리고 그 프로젝트가 미검사 상태로 보입니다. 그 뒤에 등록하는 프로젝트는 그 프로젝트의 화면이 열립니다. 등록은 검사를 실행하지 않습니다.

숨김 폴더, `node_modules`, 링크는 목록에 표시하지 않습니다. 목록 아래와 프로젝트 관리에 있는 **폴더 경로 직접 입력**에도 `/projects` 아래의 컨테이너 경로만 적을 수 있습니다(예: `/projects/my-app`). 목록 맨 아래의 링크는 폴더 선택을 누른 곳으로 돌아갑니다. 등록한 프로젝트가 없으면 첫 화면, 있으면 프로젝트 관리입니다. `..`이나 링크로 `/projects` 밖을 가리키는 폴더와 `package-lock.json`은 등록을 거부합니다. 이력에 남아 있더라도 `/projects` 밖의 폴더는 "폴더를 찾을 수 없음"으로 표시하고 검사, 업데이트 확인, 반영을 실행하지 않습니다.

**검사만**은 Git HEAD의 lockfile과 비교합니다. npm 프로젝트가 저장소의 하위 폴더이면 저장소 루트를 `/projects/<별칭>`에 연결하고, 목록에서 하위 폴더를 열어 등록합니다. 이미지의 Git은 `/project`, `/projects`와 그 아래 폴더만 `safe.directory`로 둡니다. 별도의 Git worktree처럼 `.git`이 연결한 폴더 밖을 가리키면 **검사만**은 오류 화면으로 끝납니다. **업데이트 확인**은 Git 없이 동작합니다.

### 프로젝트 별칭과 이력

이력은 프로젝트를 컨테이너 경로(`/projects/<별칭>`)로 구분합니다. 한 이력 볼륨 안에서는 이 경로가 곧 그 프로젝트입니다. 호스트의 어느 폴더를 연결했는지는 이력에 남지 않습니다.

- 같은 프로젝트는 매번 같은 별칭에 연결합니다. 별칭이 바뀌면 새 프로젝트로 등록되고, 이전 별칭의 프로젝트는 "폴더를 찾을 수 없음" 상태로 기록과 함께 남습니다.
- 다른 프로젝트를 이미 쓴 별칭에 연결하지 않습니다. 같은 볼륨에서 그렇게 연결하면 등록하지 않아도 이전 프로젝트로 보이고, 이전 프로젝트의 검사, 미리보기, 반영 기록이 새 프로젝트의 기록으로 나옵니다.

[대시보드](#대시보드)의 `$alias`는 폴더의 절대 경로로 만들므로 이름이 같은 다른 폴더와 겹치지 않습니다. 폴더를 옮기면 별칭이 달라집니다. 같은 폴더도 다른 셸에서 다른 표기의 경로로 실행하면 별칭이 달라집니다(예: PowerShell의 `C:\work\app`과 WSL의 `/mnt/c/work/app`). 그럴 때는 아래 두 방법 중 하나를 씁니다.

**별칭을 직접 정합니다.** 프로젝트마다 다른 이름을 하나 정해 계속 씁니다. `$alias`를 만드는 줄만 바꿉니다.

```powershell
$alias = 'shop-api'    # PowerShell
```

```sh
alias='shop-api'       # Bash
```

**이력 볼륨을 나눕니다.** 볼륨마다 등록, 기록, 백업, 캐시가 따로 있습니다. 기록이 섞이면 안 되는 프로젝트 묶음마다 볼륨 이름을 다르게 줍니다.

```sh
docker run --rm -it -p 127.0.0.1:5757:5757 --mount "type=bind,source=$project,target=/projects/$alias,readonly" --mount type=volume,source=depbee-home-client-a,target=/home/depbee depbee:local dashboard
```

한 별칭에 이미 섞인 기록은 프로젝트별로 나눌 수 없습니다. 그 볼륨을 지우고 다시 등록합니다. [이력 보관](#이력-보관)

### 프로젝트 여러 개

**한 폴더 아래에 모여 있을 때.** 그 상위 폴더에서 [대시보드](#대시보드)의 변수와 명령을 그대로 실행합니다. 상위 폴더가 `/projects/<별칭>`에 연결됩니다. 폴더 목록에서 그 폴더를 열고 프로젝트마다 **등록**을 누릅니다.

**폴더가 흩어져 있을 때.** 프로젝트마다 `--mount`를 하나씩 적고 별칭을 직접 정합니다. 아래 블록에서 경로 두 줄을 고친 뒤 실행합니다.

**PowerShell**

```powershell
$api = 'C:\work\shop-api'
$web = 'D:\client\shop-web'
docker run --rm -it -p 127.0.0.1:5757:5757 --mount "type=bind,source=$api,target=/projects/shop-api,readonly" --mount "type=bind,source=$web,target=/projects/shop-web,readonly" --mount type=volume,source=depbee-home,target=/home/depbee depbee:local dashboard
```

**Bash**

```sh
api="$HOME/work/shop-api"
web="$HOME/client/shop-web"
docker run --rm -it -p 127.0.0.1:5757:5757 --mount "type=bind,source=$api,target=/projects/shop-api,readonly" --mount "type=bind,source=$web,target=/projects/shop-web,readonly" --mount type=volume,source=depbee-home,target=/home/depbee depbee:local dashboard
```

상위 폴더를 `/projects`에 바로 연결하지 않습니다. 그렇게 하면 그 아래의 폴더 이름이 곧 별칭이 됩니다. 나중에 다른 상위 폴더를 같은 볼륨에 연결하면 이름이 같은 프로젝트끼리 기록이 섞입니다.

### 쉼표가 있는 경로

`--mount`는 쉼표로 항목을 나눕니다. 호스트 경로나 별칭에 쉼표(`,`)가 있으면 컨테이너를 만들기 전에 `invalid field ... must be a key=value pair` 오류로 끝납니다. 그런 폴더는 `--volume`(`-v`)으로 연결합니다. 연결하는 내용은 같고 `:ro`가 읽기 전용입니다.

```sh
docker run --rm -it -p 127.0.0.1:5757:5757 -v "${project}:/projects/${alias}:ro" --mount type=volume,source=depbee-home,target=/home/depbee depbee:local dashboard
```

- 이 명령은 PowerShell과 Bash에서 같습니다. 변수 이름은 중괄호로 감쌉니다. PowerShell은 중괄호 없는 `"$project:..."`를 구문 오류로 거부합니다.
- CLI 검사와 MCP 등록에서는 `--mount "type=bind,source=$project,target=/project,readonly"`를 `-v "${project}:/project:ro"`로 바꿉니다.
- `-v`는 콜론(`:`)으로 항목을 나눕니다. Linux에서 경로에 콜론이 있는 폴더는 `--mount`로 연결합니다. 쉼표와 콜론이 모두 있는 경로는 이 문서의 명령으로 연결할 수 없습니다. 폴더 이름을 바꾸거나 다른 위치의 사본을 연결합니다.
- 반영하려면 `:ro`를 뺍니다.

### 읽기 전용 연결과 반영

위 예시는 프로젝트를 `readonly`로 연결합니다. 이 상태에서 할 수 있는 일과 없는 일은 다음과 같습니다.

| 동작 | `readonly` 연결 | 쓰기 가능한 연결 |
| --- | --- | --- |
| 패키지, 기록, 보고서 조회 | 가능 | 가능 |
| 검사만 | 가능 | 가능 |
| 업데이트 확인(미리보기와 검사) | 가능 | 가능 |
| lockfile 반영 | 실패로 기록, 파일은 그대로 | 가능 |
| 설치까지 | 실패로 기록, 파일은 그대로 | 가능 (아래 주의) |

`readonly` 연결에서 반영하면 결과 화면에 "실패"와 이유 "프로젝트 파일을 바꾸지 못함"이 나오고, 프로젝트 파일은 바뀌지 않습니다.

반영하려면 대시보드를 종료하고 그 프로젝트의 `--mount`에서 `,readonly`를 뺀 뒤 다시 시작합니다. 미리보기는 대시보드 프로세스의 메모리에만 있으므로 다시 시작한 뒤 업데이트 확인부터 다시 합니다.

**설치까지**는 컨테이너의 Linux용 npm이 연결한 호스트 폴더의 `node_modules`를 지우고 Linux용으로 다시 설치합니다. 호스트가 Windows나 macOS이면 **lockfile 반영**만 사용하고, 호스트에서 `npm ci --ignore-scripts`로 설치하세요. 컨테이너의 미리보기 화면은 **설치까지** 선택 바로 아래에 같은 안내를 보여 줍니다.

### 컨테이너가 하는 일

| 동작 | 프로젝트 폴더 | npm | 네트워크 |
| --- | --- | --- | --- |
| 화면 조회 | 읽기 | 실행 안 함 | 없음 |
| 검사만 | 읽기(`.git` 포함) | 실행 안 함 | npm registry에서 메타데이터와 tarball 받기 |
| 업데이트 확인 | 읽기. `package.json`과 `package-lock.json`만 컨테이너의 임시 폴더로 복사 | 임시 사본에서 `npm update --package-lock-only --ignore-scripts` | npm registry |
| lockfile 반영 | `package-lock.json` 교체(npm이 바꿨다면 `package.json`도) | 실행 안 함 | 없음 |
| 설치까지 | 위 교체 뒤 `node_modules`를 지우고 다시 설치 | 프로젝트 폴더에서 `npm ci --ignore-scripts` | npm registry |

- 프로젝트의 코드와 설치 스크립트는 실행하지 않습니다. npm은 항상 `--ignore-scripts`로 실행하고, 내려받은 패키지는 실행 없이 정적으로 분석합니다.
- 반영 조건은 호스트의 대시보드와 같습니다. 기지 악성 일치는 거부하고, ML 기준 이상·보류·미확인 항목은 화면에서 확인해야 진행합니다. [업데이트 반영](usage.md#업데이트-반영-depbee-update---apply)
- 프로젝트 밖에 쓰는 것은 `depbee-home` 볼륨의 이력, 백업, 캐시와 컨테이너의 임시 폴더뿐입니다.
- 컨테이너는 root가 아닌 사용자(`10001:10001`)로 실행됩니다.

### 이력 보관

`--mount type=volume,source=depbee-home,target=/home/depbee`는 컨테이너 사용자의 홈 폴더를 Docker 볼륨 `depbee-home`에 둡니다. 이 볼륨에 다음이 남아 다음 실행에서도 보입니다.

| 내용 | 볼륨 안의 위치 |
| --- | --- |
| 등록한 프로젝트, 검사·미리보기·반영 기록 | `.local/share/depbee/history.sqlite3` |
| 반영 전 원본 파일의 백업 | `.local/share/depbee/backups/` |
| 추출한 특징의 캐시 | `.cache/depbee/` |
| npm 캐시 | `.npm/` |

이 옵션을 빼면 `--rm` 때문에 컨테이너를 종료할 때 등록과 기록이 모두 사라집니다. 볼륨 이름(`source=`)을 바꾸면 다른 이력을 씁니다([프로젝트 별칭과 이력](#프로젝트-별칭과-이력)). 반영 결과 화면의 백업 위치는 컨테이너 경로입니다. 백업을 호스트로 꺼내려면 볼륨을 연결한 컨테이너를 실행하지 않고 만들어 복사합니다.

```sh
docker create --name depbee-backups --mount type=volume,source=depbee-home,target=/home/depbee depbee:local
docker cp depbee-backups:/home/depbee/.local/share/depbee/backups ./depbee-backups
docker rm depbee-backups
```

이력을 모두 지우려면 대시보드를 종료한 뒤 `docker volume rm depbee-home`을 실행합니다.

### 포트

컨테이너 안의 대시보드는 컨테이너의 모든 인터페이스에서 5757번 포트를 엽니다. 호스트에서 어디까지 열리는지는 `-p`가 정합니다.

- `-p`의 맨 앞에 `127.0.0.1:`을 반드시 적습니다. 빼면 Docker가 호스트의 모든 네트워크 주소에 포트를 엽니다. 같은 이유로 `--network host`로 실행하지 않습니다.
- 호스트 포트와 컨테이너 포트는 같은 번호여야 합니다. 대시보드는 출력한 주소 `127.0.0.1:<포트>`로 온 요청만 받으므로 번호가 다르면 "잘못된 Host 헤더입니다."로 거부합니다.
- 5757번을 다른 프로그램이 쓰고 있으면 세 곳을 같은 번호로 바꿉니다.

```sh
docker run --rm -it -p 127.0.0.1:8123:8123 --mount "type=bind,source=$project,target=/projects/$alias,readonly" --mount type=volume,source=depbee-home,target=/home/depbee depbee:local dashboard --port 8123
```

주소에는 실행할 때마다 새로 만드는 세션 값이 들어 있고, 이 값이 없는 요청은 모두 거부합니다. 주소를 다른 사람에게 보이지 않게 하세요. `localhost`가 아니라 출력된 `127.0.0.1` 주소 그대로 엽니다. [보안 동작](usage.md#로컬-대시보드-depbee-dashboard)

### 종료

대시보드를 실행한 터미널에서 Ctrl+C를 누릅니다. `대시보드를 종료했습니다. 위 주소는 더 이상 열리지 않습니다.`가 출력되고 `--rm`이 컨테이너를 지웁니다. 다음 실행은 새 주소를 출력합니다.

터미널을 차지하지 않게 하려면 `-it` 대신 `-d --name depbee-dashboard`로 시작합니다. 주소는 로그에서 확인하고 `docker stop`으로 종료합니다. 컨테이너에서는 `--background`, `--status`, `--stop`을 쓰지 않습니다.

```sh
docker run --rm -d --name depbee-dashboard -p 127.0.0.1:5757:5757 --mount "type=bind,source=$project,target=/projects/$alias,readonly" --mount type=volume,source=depbee-home,target=/home/depbee depbee:local dashboard
docker logs depbee-dashboard
docker stop depbee-dashboard
```

`docker stop`은 10초 안에 끝나지 않은 컨테이너를 강제로 종료합니다. 검사나 반영이 실행 중이면 끝난 뒤 종료하세요.

### Linux 파일 권한

Windows의 Docker Desktop에서는 기본 사용자로 반영까지 동작하므로 아래 설정이 필요 없습니다. Linux의 Docker Engine에서는 컨테이너의 기본 사용자(`10001:10001`)가 호스트 파일의 소유자가 아닙니다.

- 조회, 검사만, 업데이트 확인에는 프로젝트 폴더와 `.git`을 다른 사용자가 읽을 수 있어야 합니다. [CLI 검사](#cli-검사)의 권한 안내와 같습니다.
- 반영에는 프로젝트 폴더에 쓸 수 있어야 합니다. 프로젝트 소유자로 실행하려면 `--user`를 더하고, 그 사용자가 쓸 수 있는 호스트 폴더를 볼륨 대신 홈으로 연결합니다.

```sh
mkdir -p "$HOME/.depbee-docker"
docker run --rm -it --user "$(id -u):$(id -g)" -p 127.0.0.1:5757:5757 --mount "type=bind,source=$project,target=/projects/$alias" --mount "type=bind,source=$HOME/.depbee-docker,target=/home/depbee" depbee:local dashboard
```

## 전체 이미지 확인

기본 이미지의 실제 업데이트 확인은 비공개 분석기와 npm registry가 필요해 저장소의 CI가 실행하지 않습니다. 이미지를 빌드한 PC에서 아래의 정상 예시로 확인합니다. [CI가 확인하는 범위](ci-cd.md#docker-이미지-검사-depbee-ci-docker-job)

예시 프로젝트 `examples/lodash-update`는 `package.json`이 lodash 4.17.21을 요구하고 lockfile은 아직 4.17.20인 상태입니다. 프로젝트는 읽기 전용으로 연결하고, 이력은 확인용 볼륨에 따로 둡니다.

**PowerShell**

```powershell
# depbee 저장소 루트에서 실행
$example = Join-Path (Get-Location).Path 'examples\lodash-update'
```

**Bash**

```sh
# depbee 저장소 루트에서 실행
example="$PWD/examples/lodash-update"
```

두 셸에서 같은 명령으로 시작하고 주소를 확인합니다.

```sh
docker run --rm -d --name depbee-verify -p 127.0.0.1:5757:5757 --mount "type=bind,source=$example,target=/projects/lodash-update,readonly" --mount type=volume,source=depbee-verify-home,target=/home/depbee depbee:local dashboard
docker logs depbee-verify
```

1. 출력된 주소를 열고 [프로젝트 폴더 연결과 등록](#프로젝트-폴더-연결과-등록)의 순서로 `lodash-update`를 등록합니다. 그 프로젝트의 패키지 화면에 lodash 4.17.20이 보입니다.
2. 그 프로젝트의 **업데이트** 화면에서 **전체 업데이트 확인**을 누릅니다. 미리보기에 lodash 4.17.21이 통과로 나옵니다. 모델은 `D04-E00`이고 기지 악성 목록의 기준 시점은 `2026-10-06T14:00:47Z`입니다.
3. 미리보기의 **설치까지** 선택 바로 아래에 Linux용 설치 안내가 있는지 봅니다.
4. **lockfile 반영**을 고르고 **반영**을 누릅니다. 결과는 "실패"이고 이유는 "프로젝트 파일을 바꾸지 못함"입니다. `git status`로 `examples/lodash-update`의 두 파일이 그대로인지 확인합니다.

확인이 끝나면 컨테이너와 확인용 볼륨을 지웁니다.

```sh
docker stop depbee-verify
docker volume rm depbee-verify-home
```

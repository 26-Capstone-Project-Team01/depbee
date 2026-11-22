# Docker로 실행하기

depbee 소스에서 직접 빌드한 로컬 이미지로 CLI 검사(`plan`, `scan`, `check`)와 stdio MCP 서버를 실행합니다. 모델과 기지 악성 색인은 이미지에 들어 있습니다. 대시보드와 `depbee update`의 npm 미리보기·반영·설치는 호스트에 설치한 depbee로 실행합니다. [설치본의 기본 자산](usage.md#기본-자산) · [호스트 설치](../README.md#설치와-준비)

Linux 컨테이너와 BuildKit이 필요합니다. Windows에서는 Docker Desktop과 PowerShell, Linux에서는 Docker Engine과 Bash를 사용합니다.

## 이미지 빌드

depbee 저장소 루트에서 빌드합니다. 비공개 분석기의 고정 커밋을 받으려면 해당 저장소의 `Contents` 읽기 권한이 있는 GitHub 토큰이 필요합니다. 아래 명령은 현재 셸에 `GH_TOKEN`이 없을 때만 입력을 받습니다. [분석기 저장소](https://github.com/26-Capstone-Project-Team01/depbee-analyzer)

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

기본 비교 대상은 Git HEAD에 커밋한 `package-lock.json`입니다. 이미지의 Git은 소유자가 다른 마운트를 읽을 수 있도록 `/project` 한 곳만 `safe.directory`로 설정합니다. 직접 관리하는 저장소 루트를 이 위치에 연결하세요. npm 프로젝트가 저장소의 하위 폴더라면 저장소 루트를 마운트하고 `plan /project/<하위 폴더>`처럼 실행합니다.

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

MCP 도구를 쓸 npm 프로젝트의 checkout 루트에서 등록합니다. [CLI 검사](#cli-검사)처럼 그 폴더에서 `$project`를 먼저 정의합니다.

```sh
# MCP 도구를 쓸 npm 프로젝트 루트에서 $project를 정의한 뒤 실행
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

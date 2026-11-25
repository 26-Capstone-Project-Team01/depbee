# Claude Code 설치 가드 (선택)

Claude Code가 Bash·PowerShell 도구로 실행하려는 npm 설치·업데이트를 실행 전에 확인하는 `PreToolUse` 훅입니다. 검사 없는 설치는 거부하고 다음에 실행할 명령을 알려 줍니다. 설치는 depbee가 같은 lockfile을 Git HEAD 기준으로 다시 검사한 뒤 통과할 때만 `npm ci --ignore-scripts`로 실행합니다. 켜지 않으면 depbee는 Claude Code 설정을 읽거나 바꾸지 않습니다.

이 가드는 Claude Code가 도구로 내는 npm 명령의 흔한 형태를 걸러 에이전트가 검사를 건너뛰지 않게 하는 장치입니다. 셸이나 운영체제 전체의 보안 경계, npm 또는 Claude Code의 샌드박스가 아닙니다. 파일을 쓸 수 있는 에이전트는 설정 파일도 고칠 수 있고, 스크립트 안의 npm 실행은 보이지 않습니다([한계](#한계)).

## 흐름

사용자가 "lodash를 추가해 줘"라고 하면 다음 순서로 진행됩니다.

1. Claude가 `npm install lodash`를 실행하려 하면 훅이 실행 전에 거부하고 아래 2~4단계의 명령을 알려 줍니다.
2. Claude가 `npm install lodash@4.17.21 --package-lock-only --ignore-scripts`를 실행합니다. `node_modules`를 설치하지 않고 설치 스크립트도 실행하지 않으며 `package.json`·`package-lock.json`만 바꾸므로 훅은 막지 않습니다. 실행 여부는 평소처럼 Claude Code의 권한 확인이 정합니다.
3. (선택) Claude가 depbee MCP의 `scan_lockfile`로 Git HEAD 대비 변경을 검사해 결과를 사용자에게 보여 줍니다.
4. Claude가 거부 메시지에 적힌 `depbee guard ci` 명령을 실행합니다. depbee가 같은 파일을 다시 검사하고, 모든 항목이 확인 없이 통과할 때만 그 파일 그대로 `npm ci --ignore-scripts`를 실행합니다. 위험·보류·오류면 설치하지 않고, Claude는 판정과 이유를 사용자에게 보여 준 뒤 결정을 기다립니다.

거부 메시지는 Claude에게 전달되며 다음과 같은 형태입니다(경로는 예시).

```text
depbee 설치 가드가 이 명령을 실행 전에 막았습니다. npm install: --package-lock-only와 --ignore-scripts가 함께 있어야 합니다. 설치·업데이트는 아래 순서로만 진행합니다.
1. node_modules 없이 package.json·package-lock.json 변경안만 만듭니다: npm install lodash --package-lock-only --ignore-scripts
2. (선택) depbee MCP scan_lockfile로 Git HEAD 대비 변경을 검사해 결과를 사용자에게 보여 줍니다.
3. 설치는 depbee가 같은 파일을 Git HEAD 기준으로 다시 검사한 뒤 통과할 때만 npm ci --ignore-scripts로 실행합니다: 'C:\Users\me\depbee\.venv\Scripts\python.exe' -I -m depbee guard ci 'C:\work\shop-api'
...
```

PowerShell 도구에서는 3단계 명령이 `& 'C:\...\python.exe' -I -m depbee guard ci 'C:\work\shop-api'`처럼 호출 연산자를 붙인 형태로 나옵니다. Claude Code는 이 이유를 `PreToolUse:Bash hook error:`(PowerShell 도구는 `PreToolUse:PowerShell`) 뒤에 붙인 도구 결과로 Claude에게 전달하며, 이름과 달리 훅 오류가 아니라 거부 결정입니다.

"개발 환경을 구성해 줘"처럼 방금 받은 저장소를 설치하려는 경우, Claude의 `npm ci`나 `npm install`은 거부되고 `depbee guard ci`로 안내됩니다. lockfile이 Git HEAD와 같으면 depbee가 검사한 변경이 없으므로 설치하지 않고 "변경 0건은 통과가 아닙니다"라고 알립니다. 이미 커밋된 의존성을 그대로 설치할지는 사용자가 정하고, 정했으면 사용자가 Claude Code 밖의 터미널에서 직접 `npm ci --ignore-scripts`를 실행합니다. Git HEAD에 `package-lock.json`이 없는 새 프로젝트는 비교 기준이 없어 오류로 끝납니다. 의존성을 넣기 전 상태(빈 의존성의 `package.json`과 lockfile)를 사용자가 먼저 커밋하면 그 뒤에 추가한 의존성이 모두 검사 대상이 됩니다.

## 켜기, 확인, 끄기

필요한 것은 Claude Code 2.1.295 이상(`onFailure` 지원), `.[extract]`를 설치한 depbee, Git, 그리고 설치까지 하려면 Node.js와 npm입니다. depbee를 설치한 가상환경의 `depbee`로 실행합니다. 훅에는 그 가상환경 Python의 절대 경로가 들어가므로, 실행 중인 depbee가 Claude Code가 쓸 설치본이어야 합니다.

훅을 넣을 설정 파일을 직접 고릅니다.

| 파일 | 적용 범위 |
| --- | --- |
| 프로젝트의 `.claude/settings.local.json` (권장) | 그 프로젝트에서 연 Claude Code. 저장소에 커밋하지 않는 개인 설정 |
| `~/.claude/settings.json` | 이 사용자의 모든 프로젝트. Orca가 넣은 훅 항목은 그대로 둡니다 |
| 별도 파일 (예: `C:\Users\me\depbee-guard.json`) | `claude --settings <파일>`로 시작한 세션만 |

**PowerShell** (프로젝트 폴더에서)

```powershell
depbee guard enable .claude\settings.local.json
depbee guard status .claude\settings.local.json
depbee guard disable .claude\settings.local.json
```

**Bash**

```sh
depbee guard enable .claude/settings.local.json
depbee guard status .claude/settings.local.json
depbee guard disable .claude/settings.local.json
```

`enable`은 쓰기 전에 넣을 명령을 Claude Code와 같은 방식(셸 없이 명령과 인자를 직접 실행, 이벤트 JSON을 stdin으로 전달)으로 새 빈 임시 폴더에서 세 번 실행해, 검사 없는 설치는 거부하고 조회 명령은 그대로 두는지 확인합니다. 실행하는 것은 지금 실행한 depbee의 Python으로 만든 아래 항목뿐이고 설정 파일에 적힌 명령은 실행하지 않습니다. 통과해야만 파일을 씁니다. 파일이 없으면 만들고, 있으면 다른 설정과 다른 훅(Orca 훅 포함)을 그대로 둔 채 아래 그룹 하나만 `hooks.PreToolUse` 끝에 더합니다. 지금 depbee의 Python으로 아래와 똑같이 쓴 항목만 가드의 것으로 보고 바꾸거나 지웁니다. 실행 파일 경로는 그 Python의 경로와 글자가 같아야 하며(Windows는 대소문자와 `/`·`\` 차이만 같게 봄), `.`이나 `..`가 든 경로나 상대 경로는 같은 파일로 이어지는 것처럼 보여도 가드의 것으로 보지 않습니다. POSIX에서는 링크 뒤의 `..`가 링크 대상의 부모로 가므로 다른 프로그램일 수 있기 때문입니다. 인자와 필드가 같아도 실행 파일이 다른 항목(다른 경로의 depbee 설치본, 같은 인자를 받는 사용자 프로그램)과 필드를 더하거나 값을 바꾼 항목은 누구의 것인지 확신할 수 없으므로 그대로 두고 "주의"로 알립니다. 다른 설치본의 항목이 남아 있으면 그 Python이 없어졌을 때 모든 셸 명령을 막을 수 있으니 확인해 직접 지웁니다. 엄격한 JSON 객체가 아니거나 `hooks`·`hooks.PreToolUse`의 형식이 다르면 아무것도 바꾸지 않고, 읽지 못하는 형태의 그룹은 그대로 둡니다.

바꾸기 전 파일은 프로젝트가 아니라 사용자 설정 폴더(`~/.config/depbee`, 또는 `DEPBEE_CONFIG_DIR`)의 `guard-backups/<UTC 시각>-<난수>/original/`에 원래 이름으로 남기고, `original/` 옆의 `backup.json`에 원래 경로와 SHA-256을 적습니다. 설정 파일 이름이 `backup.json`이어도 겹치지 않습니다. 출력에 백업 위치와 되돌리는 방법이 나옵니다. 폴더는 depbee가 처음 만들 때 사용자 전용이고(POSIX 0700, Windows는 Python 3.12.4 이상에서 소유자·SYSTEM·Administrators만 접근) 백업 파일은 0600이라 원래 파일보다 넓게 읽히지 않으며, 프로젝트의 Git에 들어가지 않습니다. 이미 있던 사용자 설정 폴더를 다른 계정이 열 수 있으면 터미널에 경고가 나옵니다. 새 내용은 같은 폴더의 임시 파일에 쓴 뒤 교체하므로 중간에 실패해도 원래 파일이 남고, 교체한 파일은 원래 파일의 권한 비트를 그대로 가집니다. Windows에서 교체한 파일은 폴더의 접근 권한을 물려받으므로, 원래 파일에 폴더에서 물려받지 않은 자기 접근 규칙이 있거나 상속이 꺼져 있으면(또는 그 목록을 읽지 못하면) 무엇도 쓰기 전에 거부하고 직접 고치라고 안내합니다. 교체를 시도할 때마다 직전에 파일을 다시 읽어(Windows에서 다른 프로세스가 파일을 잠깐 열고 있으면 다시 시도), 그 사이 Claude Code·Orca·편집기가 파일을 바꿨으면 교체하지 않고 오류로 끝납니다. 그 확인과 교체 사이의 아주 짧은 순간에 다른 프로그램이 쓴 내용은 알아채지 못합니다. 설정 파일이 심볼릭 링크이거나 링크·junction이 든 경로면 링크가 가리키는 실제 파일을 고치고 링크는 그대로 둡니다(대상이 없는 링크는 거부). 하드 링크가 둘 이상인 파일은 교체하면 다른 이름이 옛 내용으로 남으므로 거부합니다. JSON은 두 칸 들여쓰기로 다시 쓰므로 원래 파일의 공백 배치는 달라질 수 있습니다.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "C:\\Users\\me\\depbee\\.venv\\Scripts\\python.exe",
            "args": ["-I", "-m", "depbee.guard", "hook"],
            "timeout": 30,
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

`command`와 `args`를 나눈 형식(exec form)은 셸을 거치지 않으므로 경로의 공백·한글·따옴표를 따로 인용하지 않아도 됩니다. `-I`는 `PYTHONPATH`, 사용자 site 폴더, 현재 폴더를 import 경로에서 빼서 프로젝트에 놓인 다른 `depbee` 폴더가 대신 실행되지 않게 합니다. `matcher`가 `Bash|PowerShell`이므로 Git Bash가 없어 PowerShell 도구만 있는 Windows에서도 동작합니다.

`status`는 설정 파일을 먼저 읽기만 해서 확인합니다. 가드 항목이 위 형태 그대로이고, 그 Python이 지금 실행한 depbee의 것이며, 그룹 조건이 `matcher` `Bash|PowerShell` 하나뿐이고, `disableAllHooks`가 true가 아니어야 합니다. `depbee.guard`를 가리키지만 다른 Python, 추가 인자, 다른 `timeout`·`onFailure`, `if`·`shell`·`async` 같은 필드, 셸 문자열 형식처럼 다른 항목이 있으면 그 내용을 보여 주고 아무것도 실행하지 않은 채 종료 코드 2로 끝납니다. `enable`은 지금 depbee의 항목만 쓰거나 바꾸고 이런 항목은 바꾸지도 지우지도 않으므로, 이 depbee로 다시 켜려면 `depbee guard enable`을 실행하고 보여 준 항목은 직접 확인해 고치거나 지우라고 안내합니다. 모두 맞으면 `enable`과 같은 자가 시험을 지금 depbee의 항목으로 실행하고, 통과할 때만 종료 코드 0입니다. 다른 설정 파일(사용자·관리 설정)의 `disableAllHooks`는 보지 않으므로 Claude Code의 `/hooks`로도 확인합니다. `disable`은 위 형태 그대로인 depbee 가드 항목만 지우고, 그 때문에 비는 그룹이 `matcher`와 `hooks`만 가진 그룹이면 그 그룹도 지웁니다. 다른 필드가 있는 그룹은 빈 `hooks`로 남깁니다. Claude Code는 설정 파일 변경을 다시 읽으므로 실행 중인 세션에도 반영되며 `/hooks`에서 확인할 수 있습니다. 대화형 세션에서는 신뢰하기로 한 폴더에서만 훅이 실행됩니다. 켠 뒤 Claude Code에 "npm install lodash를 실행해 줘"라고 하면 거부 메시지가 나오는지로 동작을 확인합니다.

에이전트가 `depbee guard enable`·`disable`을 실행하면 훅이 거부합니다. 가드를 켜고 끄는 일은 사용자가 Claude Code 밖의 터미널에서 합니다.

### 권한

훅은 허가(`allow`)를 내보내지 않습니다. 거부하거나 아무것도 출력하지 않으며, 아무것도 출력하지 않은 명령은 평소의 권한 규칙과 확인 창을 그대로 거칩니다. 따라서 가드를 켜도 셸 권한이 넓어지지 않습니다. lockfile 변경 준비나 `depbee guard ci`를 매번 묻지 않게 하려면 사용자가 확인 창에서 직접 허용하거나 권한 규칙을 추가합니다. 훅 설정이 깨지면 권한 규칙만 남으므로([오류가 나면](#오류가-나면-claude-code에서-일어나는-일)), `Bash(npm install *)`처럼 넓은 규칙보다 `depbee guard ci` 명령처럼 좁은 규칙을 권합니다.

## 훅이 판정하는 명령

훅은 명령 문자열을 `;`, `&&`, `||`, `|`, `&`, 줄바꿈, 괄호·중괄호, `<`·`>`로 나눈 각 부분의 첫 단어를 봅니다. Bash는 POSIX 따옴표와 역슬래시, PowerShell은 작은따옴표·큰따옴표와 백틱으로 단어를 나눕니다. `npm`, `npm.cmd`, `C:\...\npm.cmd`, `node ...\npm-cli.js`, `npx`는 모두 같은 npm·npx로 봅니다.

| 명령 | 결과 |
| --- | --- |
| npm이 아닌 명령, npm 단어가 데이터로만 나오는 명령(`grep "npm install" docs`, `git commit -m "... npm ci ..."`) | 통과 |
| 조회·스크립트 명령: `npm view`, `npm ls`, `npm outdated`, `npm audit`(fix 제외), `npm run`, `npm test`, `npm config get`, `npm pkg get`, `npm init -y`, `npm -v` 등 | 통과 |
| lockfile만 바꾸는 `npm install`·`update`·`uninstall`·`audit fix`: `--package-lock-only`와 `--ignore-scripts`가 모두 켜져 있고, 그 밖의 옵션은 저장 옵션(`-D`, `-E` 등), `--legacy-peer-deps`, `--no-audit`, `--no-fund`, `--prefix`뿐이며, 패키지 인자가 registry 이름(버전·범위·태그 가능)이고, 프로젝트에 `.npmrc`가 없을 때 | 통과 |
| 위 조건이 하나라도 빠진 설치·업데이트·제거: `npm install`, `npm i x`, `-g`, Git·URL·파일·별칭 인자, 환경 변수나 `sudo` 같은 명령을 앞에 붙인 실행 | 거부, 위 [흐름](#흐름)의 명령 안내 |
| `npm ci`·`install-test`·`install-ci-test`와 그 별칭 | 거부, `depbee guard ci` 안내 |
| `npx`, `npm exec`, `npm init <초기화 도구>`, `npm create` | 거부. 설치된 도구는 `npm run`이나 `node_modules/.bin`으로 실행 |
| `npm rebuild`, `link`, `dedupe`, `prune`, npm이 받아 주는 약어(`npm insta`, `npm upd` 등)와 그 밖의 npm 명령 | 거부 |
| npm·npx 단어가 든 다른 셸 실행(`bash -c`, `sh`로 파이프, `eval`, `cmd /c`, `powershell -Command`, `Invoke-Expression`, `Start-Process`), 변수를 명령으로 쓴 경우(`$NPM install`, `& $npm`), 옵션이 붙은 감싼 명령(`sudo -u x npm ...`, `env -u X npm ...`), 백틱 명령 치환, 닫히지 않은 따옴표, npm 명령 앞의 모르는 옵션 | 거부(판정 불가) |
| `depbee update ... --confirm-warnings`(약어 포함) | 거부. 확인은 사용자가 직접 합니다 |
| depbee 환경 변수(`DEPBEE_`)를 바꾼 명령의 `depbee guard ci`, `depbee guard enable`·`disable` | 거부 |
| 그 밖의 depbee 명령(`depbee guard ci`, `depbee update --apply install` 등) | 통과 |

판정할 수 없는 형태는 통과시키지 않고 거부하며, npm을 다른 명령 없이 직접 실행하라고 안내합니다. 안내에 적는 프로젝트 폴더는 npm이 실제로 쓰는 폴더입니다: `--prefix`·`-C`가 있으면 그 폴더, 없으면 작업 폴더와 그 위에서 가장 가까운 `package.json`이나 `node_modules`가 있는 폴더(lockfile 변경 준비의 `.npmrc` 확인도 그 폴더에서 합니다). 명령에서 폴더를 알 수 없으면(변수, PowerShell 작은따옴표 안의 `''`처럼 문자열에서 정확히 되살릴 수 없는 경우) 경로 대신 자리 표시를 둡니다. 반대로 단어 하나로 모든 것을 막지도 않습니다. npm 단어가 따옴표 안의 데이터로만 나오는 명령은 그대로 둡니다.

## `depbee guard ci`

```powershell
depbee guard ci C:\work\shop-api
depbee guard ci C:\work\shop-api --format json
```

프로젝트의 `package-lock.json`을 Git HEAD의 lockfile과 비교해 바뀐 항목을 지금 검사하고, 모든 항목이 통과할 때만 그 파일 그대로 `npm ci --ignore-scripts`로 설치합니다. 모델·기지 악성 색인·캐시·비교 기준을 고르는 옵션은 없습니다. 모델과 색인은 다른 depbee 명령과 같은 순서(환경 변수, `depbee setup`으로 저장한 폴더, 동봉 기본값)로 정하고, 기준은 언제나 Git HEAD입니다. 종료 코드는 설치했을 때만 0이고, 위험으로 거부하면 1, 보류·오류·변경 0건·도중 변경·설치 실패는 2입니다.

### 왜 설치 직전에 다시 검사하는가

MCP의 `scan_lockfile` 결과는 에이전트가 읽는 보고서입니다. 그 결과는 나중에 npm이 읽을 바이트, 그 프로젝트, 그 시점과 묶여 있지 않습니다. 검사 뒤 파일이 바뀌거나, 다른 프로젝트나 예전 결과를 잘못 쓰거나, Docker MCP처럼 다른 경로를 본 결과를 근거로 설치할 수 있습니다. 그래서 depbee는 승인 파일이나 영수증을 만들지 않고, 설치하는 depbee 프로세스가 설치할 바로 그 바이트를 직접 검사해 결론을 냅니다. MCP 검사는 사용자에게 결과를 먼저 보여 주는 단계로 남습니다.

### 네트워크와 캐시

다시 검사할 때 바뀐 패키지마다 npm registry 메타데이터를 한 번 새로 받고, 설치를 정하는 데에도 그 한 번의 응답만 씁니다. 패키지 tarball은 depbee의 특징 캐시(`~/.cache/depbee`)에 없을 때만 받습니다. 캐시 항목의 키는 모델 해시, 분석기 커밋, 두 버전과 그 integrity이므로, 같은 사용자의 네이티브 MCP나 CLI가 같은 모델로 먼저 검사했다면 대부분 내려받지 않습니다. Docker로 실행한 MCP의 캐시는 컨테이너 볼륨에 있어 공유되지 않으므로 그때는 다시 내려받습니다. 캐시는 속도를 위한 것이고, 판정은 매번 모델과 기지 악성 색인으로 새로 계산합니다.

### 설치하는 조건과 순서

1. 프로젝트 경로를 실제 경로(링크와 junction을 푼 경로) 하나로 정하고 끝까지 그 경로만 씁니다. 검사 도중 링크가 같은 파일을 가진 다른 폴더를 가리키게 바뀌어도 설치는 검사한 폴더에서 하고, `npm ci` 직전에 그 경로가 다시 링크를 지나게 되었으면 시작하지 않습니다. 같은 프로젝트의 다른 `depbee guard ci`가 실행 중이면 기다리지 않고 거부합니다. 잠금은 이력 파일 옆 `locks/` 폴더의 파일에 거는 운영체제 잠금이라 프로세스가 끝나면 풀립니다.
2. 검사 전에 거부합니다: `depbee update`가 지원하지 않는 프로젝트(workspaces, `npm-shrinkwrap.json`, registry 밖 의존성 등), 프로젝트 `.npmrc`, 프로젝트 자신의 폴더가 아닌 `node_modules`, 유효한 integrity가 없는 lockfile 항목, 이름이 null이거나 버전이 없거나 `01.2.3`처럼 SemVer 형식에 맞지 않는 버전을 적은 항목처럼 registry 이름·버전으로 읽을 수 없는 항목과, `1.2.3+build`처럼 SemVer로는 유효하지만 빌드 메타데이터가 붙어 이 가드가 지원하지 않는 버전의 항목(옆의 정상 항목도 내려받지 않고, npm과 네트워크를 쓰지 않은 채 오류 JSON, 종료 코드 2). 트리 어디에든 번들(`package.json`이나 lockfile 항목의 `bundleDependencies`·`bundledDependencies`, `inBundle` 항목)이나 자기 `npm-shrinkwrap.json`을 가진 패키지(`hasShrinkwrap`)가 있어도 거부합니다. npm은 그 부분을 다른 패키지의 tarball이나 그 안의 shrinkwrap에서 가져오므로, lockfile 항목의 tarball과 digest를 묶는 이 명령의 검사가 닿지 않기 때문입니다. npm이 lockfile에 적는 이 표시만 보고, npm의 처리 방식을 따로 흉내 내지 않습니다.
3. `package.json`·`package-lock.json`을 읽어 해시를 남기고, Git HEAD와 비교한 변경 목록을 만듭니다. 분석할 변경이 20개를 넘으면 내려받기 전에 멈춥니다(MCP와 같은 상한).
4. `depbee scan --extract`와 같은 검사를 엄격 모드로 합니다. 분석기는 바뀐 버전마다 registry 메타데이터를 한 번 받아 그 응답의 `dist`로 분석하는데, 엄격 모드에서는 그 `dist`와 lockfile 항목을 비교해 `resolved`와 `dist.tarball`이 모두 registry의 그 버전 tarball 주소(`https://registry.npmjs.org/<이름>/-/<이름>-<버전>.tgz`)이고 `integrity`와 `dist.integrity`가 같은 sha512 값 하나일 때만 분석합니다. 내려받은 tarball은 바로 그 `dist`로 확인하고(`registry.verify`), 특징 캐시를 쓸 때도 같은 비교를 먼저 하므로 캐시 적중이 이 조건을 건너뛰지 않습니다. 조건이 어긋나면 그 항목은 보류가 되어 설치하지 않습니다. `npm ci`는 lockfile의 `resolved`에서 받아 lockfile의 `integrity`로 확인하므로, 이 비교로 npm이 받아들일 바이트가 분석한 tarball의 sha512에 묶입니다. 나중에 registry에 다시 묻지 않으므로 그 사이 바뀐 응답이 설치를 허락하는 일은 없습니다. 검사가 읽은 lockfile과 HEAD가 3단계와 다르면(요청 ID 비교) 설치하지 않습니다.
5. 보고서가 3단계의 변경 목록과 정확히 맞는지(항목마다 행 하나, 같은 위치·버전·삭제 여부) 확인하고, 맞지 않으면 오류로 멈춥니다. 바뀐 항목이 없거나 삭제만 있으면 depbee가 검사한 설치 항목이 없으므로 npm을 실행하지 않습니다. 설치하려면 추가·업데이트가 하나 이상 있고 그 모두가 실제로 분석돼 ML 위험 점수가 있고, ML 기준 미만이며 기지 악성 목록과 대조해 일치가 없어야 합니다(보고서 종료 코드 0). 그다음 `depbee update --apply install`과 같은 반영 게이트를 확인 없이 적용합니다. 기지 악성 일치는 거부, ML 기준 이상·보류·기지 악성 미확인도 거부이며, 경고를 확인하고 진행하는 옵션은 없습니다. 이 조건은 `depbee guard ci`에만 적용되고, 대시보드와 `depbee update --apply`의 반영 규칙은 그대로입니다.
6. 사용자 npm 설정이 다른 registry를 쓰게 해 `npm ci`가 받는 주소가 바뀌어도, `npm ci`는 lockfile의 같은 sha512로 확인하므로 다른 바이트는 설치되지 않습니다.
7. 두 파일을 다시 읽어 해시를 비교하고, npm 버전을 확인한 뒤 `npm ci`를 시작하기 바로 전에 두 파일, `.npmrc`, Git HEAD 기준 변경 목록, `node_modules`가 프로젝트 자신의 폴더인지를 한 번 더 확인합니다. 하나라도 다르면 `npm ci`를 시작하지 않습니다.
8. `npm ci --ignore-scripts`는 `depbee update --apply install`과 같은 고정 옵션으로 실행합니다(설치 스크립트 미실행, Git 실행 파일과 전역 설정을 없는 경로로 고정, `npm_config_*`·`NODE_OPTIONS` 환경 변수 제거, 시간·출력 상한). 끝난 뒤 두 파일이 그대로인지 확인합니다.

depbee는 프로젝트 파일을 쓰지 않습니다. 반영 경로를 그대로 쓰므로 설치 전에 두 파일의 사본이 이력 파일 옆 `backups/`에 남습니다. 7단계의 마지막 확인 뒤 npm이 파일을 읽기까지의 사이에 다른 프로세스가 파일을 쓰는 것은 막지 못합니다. 그런 변경은 8단계의 확인이나 npm ci 자신의 `package.json`·lockfile 일치 확인에서 실패로 드러날 수 있지만, 설치가 이미 진행된 뒤일 수 있습니다. 같은 프로젝트에서 사람이나 다른 도구가 동시에 파일을 고치지 않게 합니다. `--format json`의 `apply.npm_ci_started`는 7단계를 마치고 `npm ci`를 시작했는지를 알립니다. npm 프로세스를 만들지 못했거나, Windows에서 npm을 묶을 작업 객체(Job)를 준비하지 못해 멈춘 채 만든 프로세스를 실행 전에 정리했으면 시작하지 않은 것으로 봅니다. 시작한 뒤 실패하거나 시간이 다 되면 `node_modules`는 중간 상태일 수 있고 두 파일은 그대로이며, 출력도 그렇게 안내합니다. 시작 전에 멈췄으면 설치하지 않았다고 안내합니다. 원인을 확인한 뒤 다시 실행하면 처음부터 다시 검사합니다.

## 설치 허가로 쓰지 않는 것

설치를 정하는 근거는 `depbee guard ci`가 그 자리에서 낸 판정뿐입니다. 다음은 설치 허가가 되지 않습니다.

- 검사 없는 설치 명령, `check_package` 한 건의 결과(그 패키지의 의존성을 검사하지 않음)
- MCP `scan_lockfile`의 어떤 결과, 프로젝트 안의 보고서 JSON, 에이전트나 모델이 적은 문장
- 변경 0건, 삭제만 있는 변경, 위험(1), 보류(2), 도구 오류, 기지 악성 미확인, 변경 목록과 맞지 않는 보고서
- 검사 뒤 바뀐 파일의 예전 결과, 다른 프로젝트나 다른 기준의 결과
- 특징 캐시, 대시보드 이력 같은 저장된 데이터

비교 기준은 Git HEAD입니다. 에이전트가 검사 전에 lockfile을 커밋하면 그 커밋의 의존성은 비교에서 빠집니다(커밋한 내용이 곧 HEAD라 변경 0건이면 설치하지 않습니다). 에이전트의 `git commit`을 허용하지 않거나, 의존성을 바꾼 커밋을 사람이 검토하는 것을 권합니다. 팀 기준의 HEAD 검토에는 [GitHub Actions](ci-cd.md#github-action-actionyml)를 필수 검사로 씁니다.

## 오류가 나면 Claude Code에서 일어나는 일

| 상황 | Claude Code의 동작 |
| --- | --- |
| 훅이 거부(종료 코드 0, `permissionDecision: "deny"`) | 그 명령을 실행하지 않고 거부 이유를 Claude에게 전달 |
| 훅이 이의 없음(종료 코드 0, 출력 없음) | 평소 권한 규칙과 확인 창으로 진행. 훅이 허가하지 않음 |
| 훅 입력을 읽지 못하거나 내부 오류(종료 코드 2) | 그 명령을 막고 stderr를 이유로 전달. `onFailure`와 관계없이 막힘 |
| Python 경로가 없거나 시작하지 못함, 30초 시간 초과, 그 밖의 종료 코드 | `onFailure: "block"`이므로 막힘. 이때 모든 Bash·PowerShell 명령이 막히므로 [복구](#복구)를 따릅니다 |
| 설정 파일이 JSON으로 읽히지 않거나 스키마에 맞지 않음 | Claude Code는 그 파일 전체(훅과 권한 규칙 포함)를 적용하지 않고 오류 창이나 `-p`의 stderr로 알림. 가드가 꺼진 상태이며 `claude doctor`로 확인 |
| 폴더를 아직 신뢰하지 않음(대화형) | 신뢰할 때까지 설정 파일의 훅을 실행하지 않음 |
| `disableAllHooks`, `claude --safe-mode`, `claude --bare` | 훅이 실행되지 않음(가드 꺼짐) |
| Claude Code 2.1.295 미만 | `onFailure`를 지원하지 않아, 훅을 시작하지 못하면 명령이 그대로 실행될 수 있음. 보호를 보장하지 않습니다 |

훅 자신의 오류는 모두 종료 코드 2로 끝나므로, 입력이나 예외 때문에 명령이 실수로 통과되지 않습니다.

## 복구

모든 셸 명령이 막혔다면(예: depbee 가상환경을 지우거나 옮김) Claude Code 안의 셸 도구로는 고칠 수 없습니다. Claude Code 밖의 터미널에서 다음 중 하나를 합니다.

1. `depbee guard status <설정 파일>`로 원인을 보고 `depbee guard disable <설정 파일>`로 끕니다. `disable`은 그것을 실행한 depbee의 Python으로 쓴 항목만 지우므로, 항목을 쓴 이전 환경이 남아 있으면 그 환경의 depbee로 실행합니다. depbee를 다른 경로에 다시 설치했을 때 새 설치본의 `enable`은 이전 경로의 항목을 바꾸거나 지우지 않고 "주의"로 알린 채 새 항목을 더하므로, 이전 항목이 남아 있으면 그 Python이 없는 동안 셸 명령이 계속 막힙니다. 이전 환경이 있으면 먼저 그 환경에서 `disable`하고, 없으면 2번처럼 이전 항목만 직접 지운 뒤 새 설치본으로 `depbee guard enable <설정 파일>`과 `depbee guard status <설정 파일>`을 실행합니다.
2. depbee를 실행할 수 없으면 Claude Code 밖의 편집기로 설정 파일을 열어 자신의 가드 항목만 지웁니다. 지울 항목은 `hooks.PreToolUse` 그룹의 `hooks` 목록에 든 항목 하나로, `command`가 예전 depbee의 Python 경로이고 나머지가 [위 형태](#켜기-확인-끄기) 그대로(`"type": "command"`, `"args": ["-I", "-m", "depbee.guard", "hook"]`, `"timeout": 30`, `"onFailure": "block"`, 다른 필드 없음)인지 전체를 대조합니다. `args`가 같아도 `command`가 다르거나 필드가 다른 항목은 다른 설치본이나 사용자 프로그램일 수 있으니 확인한 뒤에만 지웁니다. 같은 그룹의 다른 훅과 그룹의 다른 필드는 그대로 두며, 그 항목을 지워 `hooks`가 비고 그룹에 `matcher`와 `hooks`만 있을 때만 그룹째 지웁니다. 또는 `enable`이 사용자 설정 폴더의 `guard-backups/<시각>-<난수>/original/`에 남긴 백업(그 옆 `backup.json`에 원래 경로와 SHA-256)으로 되돌립니다. 쓸 백업은 열어 보아 고장 난 이전 가드 항목이 실제로 빠져 있고 사용자의 다른 설정이 보존된 것을 직접 확인한 것만 고릅니다. 새 위치에서 `enable`하기 직전의 백업에는 고장 난 이전 항목이 남아 있을 수 있습니다. 백업 원본과 `backup.json`은 고치지 않고 백업은 설정 파일 경로에 복사해서만 씁니다. 백업 뒤에 더하거나 바꾼 설정(권한 규칙, 다른 훅, Orca가 바꾼 항목 등)을 유지해야 하면 백업을 별도 작업 사본으로 복사해 지금 파일과 비교·병합하고 그 결과만 설정 파일로 씁니다. 그런 백업이 없으면 위의 항목 단위 수동 복구만 씁니다.
3. 그 세션에서만 끄려면 `claude --safe-mode`(훅을 포함한 사용자 지정 설정 전체 끔)나 `claude --settings '{"disableAllHooks": true}'`(Orca 훅을 포함한 모든 훅 끔)로 시작합니다.

## Docker로 실행한 MCP와 함께 쓸 때

훅과 `depbee guard ci`는 Claude Code가 도는 호스트에서 실행되므로 호스트에 설치한 depbee가 필요합니다. Docker의 MCP는 프로젝트를 `/projects/<별칭>`으로 읽기 전용 연결해 검사하므로 경로가 다르고, 그 결과나 캐시를 호스트의 가드와 공유하지 않습니다. 이 구성에서도 MCP 결과는 사용자에게 보여 주는 용도이고, 설치는 호스트의 `depbee guard ci`가 호스트 경로의 파일을 직접 검사해 정합니다. 읽기 전용 연결의 컨테이너는 설치를 하지 않습니다.

## 한계

- 명령 문자열의 흔한 형태만 판정합니다. 스크립트 파일, 셸 별칭과 함수, `package.json` 스크립트 안의 npm 실행(`npm run setup`이 내부에서 `npm install`을 실행하는 경우), 변수로 조립하거나 인코딩한 명령, yarn·pnpm·bun은 보지 못합니다. 사용자의 터미널, IDE 작업, 다른 에이전트가 실행하는 명령에는 적용되지 않습니다.
- lockfile 변경 준비(2단계)는 에이전트의 npm이 프로젝트에서 실행합니다. 설치 스크립트는 실행하지 않지만 사용자 npm 설정을 읽고, registry 패키지가 Git 커밋에 의존하면 npm이 그 tarball을 받아 준비할 수 있습니다([알려진 예외](usage.md#업데이트-미리보기-depbee-update)). 프로젝트 `.npmrc`가 있으면 훅이 이 단계를 거부합니다.
- 통과는 모델과 목록의 판정일 뿐 패키지가 안전하다는 보증이 아닙니다. 검사 범위는 Git HEAD 대비 바뀐 항목뿐입니다.
- `depbee guard ci`는 바뀐 항목의 `integrity`가 sha512 값 하나이고 분석이 받은 registry 메타데이터의 `dist.integrity`도 같은 값 하나일 때만 설치합니다. sha1만 있는 오래된 배포본처럼 이 조건을 맞출 수 없는 패키지는 검사(`depbee scan`, MCP)는 되지만 이 명령으로는 보류되어 설치되지 않으며, 사용자가 판단해 직접 설치합니다. 번들이나 자기 shrinkwrap을 가진 패키지가 트리에 있는 프로젝트도 이 명령으로는 설치하지 않습니다. 이 조건들은 이 명령에만 있고 일반 검사의 결과, 보고서 형식, 캐시 키는 그대로입니다.
- Windows PowerShell 5.1은 `&` 뒤의 경로를 와일드카드로 찾습니다. depbee 설치 경로에 `[`나 `]`가 있으면 거부 메시지의 PowerShell 명령 대신 Bash 도구를 쓰거나 대괄호 없는 경로에 설치합니다.

# 진입점별 시연

지금 구현으로 네 진입점(CLI, 로컬 대시보드, MCP, GitHub Actions)을 한 PC에서 차례로 보여 주는 절차입니다. 단계마다 명령과 기대하는 첫 줄·종료 코드만 적고, 옵션·보안·반영 게이트·되돌리기는 각 절을 따릅니다. 점수와 개수는 모델과 registry 상태에 따라 달라지므로 적지 않습니다. `<depbee 폴더>`, `<시연 폴더>`, `<시연 상태 폴더>`, `<모델 폴더>`, `<색인 폴더>`는 절대 경로로 바꿉니다. 경로가 든 인자는 공백이 있어도 되도록 큰따옴표로 감쌌습니다.

### 준비

| 진입점 | extra | Git | Node.js·npm | 모델 | 기지 악성 색인 | 네트워크 |
| --- | --- | --- | --- | --- | --- | --- |
| `plan` | 없음 | `--base-lock`이면 불필요 | 불필요 | 불필요 | 불필요 | 불필요 |
| `--extract` 없는 `scan` | 없음 | 기본 HEAD 기준이면 2.45 이상 | 불필요 | 불필요 | 일치를 보려면 필요 | 불필요 |
| `scan --extract`, `check` | `ml`, `extract` | `scan`의 기본 HEAD 기준이면 2.45 이상 | 불필요 | 필요 | 권장 | registry |
| `update` 미리보기·반영 | `ml`, `extract` | 불필요 | 필요 | 필요 | 권장(없으면 반영마다 확인 필요) | registry |
| 대시보드 | `web`, `ml`, `extract` | 검사만에 필요 | 업데이트 확인에 필요 | 필요 | 권장 | registry |
| MCP | `mcp`, `ml`, `extract` | `scan_lockfile`의 기본 HEAD 기준에 필요 | 불필요 | 필요 | 권장 | registry, 에이전트 서비스 |
| Actions 판정 재현 | 없음(표준 라이브러리) | 실제 보고서를 만들 때만 | 불필요 | 실제 보고서를 만들 때만 | 실제 보고서를 만들 때만 | 예시 보고서면 불필요 |
| Actions 실제 PR | action이 설치 | runner | 불필요 | Release | Release | 공개와 Release 뒤 |

```powershell
cd "<depbee 폴더>"
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install ".[ml,extract,mcp,web]"
```

이 절의 명령은 PowerShell 예시입니다. macOS/Linux에서 가상환경을 활성화하는 방법은 [설치와 준비](../README.md#설치와-준비)에 있습니다.

`extract`는 비공개 depbee-analyzer 저장소에 접근할 수 있어야 설치됩니다. 접근할 수 없으면 `.[ml,mcp,web]`로 설치해 추출이 필요 없는 장면(`plan`, `--extract` 없는 `scan`, Actions 판정 재현)만 할 수 있습니다.
아래 명령은 가상 환경을 활성화한 뒤 콘솔 스크립트 `depbee`로 실행합니다. 시연 폴더에서 `python -m depbee`를 쓰지 않는 이유는 [MCP 진입점](usage.md#mcp-진입점-검사-전용)에 있습니다.

시연 동안의 이력, 반영 백업, 추출 캐시, 임시 파일은 새로 만든 빈 `<시연 상태 폴더>` 하나에 모읍니다. 그래야 정리할 때 이 폴더만 지우면 되고 기본 위치의 기존 기록을 건드리지 않습니다. 시연할 창에서 아래를 실행합니다.

```powershell
$state = "<시연 상태 폴더>"
mkdir "$state\tmp", "$state\cache", "$state\mcp-home" | Out-Null
$env:DEPBEE_MODEL_DIR = "<모델 폴더>"
$env:DEPBEE_KNOWN_MALICIOUS_DIR = "<색인 폴더>"
$env:DEPBEE_HISTORY_DB = "$state\history.sqlite3"
$env:TMP = "$state\tmp"; $env:TEMP = "$state\tmp"; $env:TMPDIR = "$state\tmp"
$env:PYTHONIOENCODING = 'utf-8'
$cache = "$state\cache"
```

- `DEPBEE_MODEL_DIR`, `DEPBEE_KNOWN_MALICIOUS_DIR`: `--model-dir`, `--known-malicious-dir`을 생략한 명령이 씁니다([실행](usage.md#실행), [기지 악성 탐지기](usage.md#기지-악성-탐지기), [색인 만들기](usage.md#색인-만들기)).
- `DEPBEE_HISTORY_DB`: 이력이 이 파일에, 반영 백업이 그 옆 `backups\`에 생깁니다. 지정하지 않으면 홈 폴더의 기본 위치에 생깁니다([로컬 이력 저장소](usage.md#로컬-이력-저장소)).
- `TMP`, `TEMP`, `TMPDIR`: tarball을 풀 임시 폴더입니다. Python은 `TMPDIR`를 `TEMP`·`TMP`보다 먼저 보므로 셋을 함께 둡니다.
- 추출 캐시는 환경 변수로 옮길 수 없어 `--cache-dir`를 받는 명령(`scan`, `check`, `update`, `dashboard`)에 `--cache-dir $cache`를 붙입니다. 빠뜨리면 기본 위치 `~/.cache/depbee`에 쌓입니다. MCP 서버에는 이 옵션이 없어 아래 [MCP](#mcp)처럼 서버의 홈 폴더를 옮깁니다.
- `PYTHONIOENCODING`: 결과를 파일로 돌리거나 다른 프로그램으로 넘길 때 필요합니다. 없으면 Windows에서 한글이 시스템 코드 페이지로 나갑니다.

| 모델 | 색인 | 결과 |
| --- | --- | --- |
| 있음 | 있음 | ML 위험 점수와 기지 악성 대조로 판정합니다. 반영할 때 기지 악성 미적중이고 기준 미만인 항목은 확인 없이 진행합니다. |
| 없음 | 있음 | 추출은 하지만 분석 대상이 점수 없이 보류(`model_missing`, 종료 코드 2)이고 근거도 보고서에 실리지 않습니다. 기지 악성 일치는 그대로 위험입니다. |
| 있음 | 없음 | ML만으로 판정하고 비교 기준 후보도 빼지 않습니다. `--extract` 없는 `scan`은 모든 항목이 보류이고, 반영은 새로 설치되는 모든 버전에 확인이 필요하며, MCP 응답에는 미연결 안내가 붙습니다. |
| 없음 | 없음 | 분석 대상이 모두 보류(종료 코드 2)입니다. |

시연용 정상 프로젝트는 `package.json`과 lockfile만 둔 Git 저장소로 만듭니다. `--ignore-scripts`를 빼지 않습니다. 빼면 `--package-lock-only`여도 lifecycle script가 실행될 수 있습니다.

```powershell
mkdir "<시연 폴더>"; cd "<시연 폴더>"
npm init -y
npm install lodash@4.17.15 ms@2.1.1 semver@7.5.0 --package-lock-only --ignore-scripts
git init; git add package.json package-lock.json; git commit -m "시연 시작점"
```

CLI와 대시보드는 장면마다 상태를 따로 두도록 서로 다른 시연 폴더를 씁니다. 같은 폴더를 쓰면 한 진입점이 미리보기를 만든 뒤 다른 진입점이 파일을 바꿨을 때 그 미리보기의 반영이 해시 재확인으로 거부됩니다.

### CLI

한 시연 폴더에서 차례로 진행합니다.

1. `plan`(네트워크 없음): `depbee plan "<depbee 폴더>\examples\project" --base-lock "<depbee 폴더>\examples\baseline\package-lock.json"`의 출력은 `{`로 시작하는 JSON이고 종료 코드 0입니다.
2. 업데이트 미리보기: `<시연 폴더>`에서 `depbee update --cache-dir $cache`. 첫 줄 `depbee 업데이트 미리보기`, 종료 코드 0이고 파일은 바뀌지 않습니다.
3. lockfile 반영([업데이트 반영](usage.md#업데이트-반영-depbee-update---apply)). 첫 줄은 두 번 모두 `depbee 업데이트 미리보기`이고, 반영 결과는 검사 결과 뒤 끝부분에 나옵니다.

   ```powershell
   $env:DEPBEE_KNOWN_MALICIOUS_DIR = ''                 # 색인 없이
   depbee update --apply lockfile --cache-dir $cache    # 끝부분 "depbee 업데이트 반영: 반영하지 않음", 종료 코드 2
   $env:DEPBEE_KNOWN_MALICIOUS_DIR = "<색인 폴더>"
   depbee update --apply lockfile --cache-dir $cache    # 끝부분 "depbee 업데이트 반영: 반영함", 종료 코드 0
   ```

   색인 없이는 새로 설치되는 모든 버전이 "기지 악성 목록 미확인"이라 확인이 필요합니다. 색인을 연결하거나 `--confirm-warnings`를 주면 반영하고, 출력에 백업 위치가 나옵니다.
4. `depbee scan . --extract --cache-dir $cache`: 반영으로 생긴 커밋하지 않은 변경을 HEAD와 비교합니다. 첫 줄 `depbee 검사 결과: 통과 (종료 코드 0)`.
5. `depbee check lodash@4.17.21 --cache-dir $cache`: 같은 첫 줄 형식이고 종료 코드 0입니다. 다음 장면을 위해 `git commit -am "업데이트 반영"`으로 반영 결과를 커밋합니다.
6. 보류(네트워크 없음): `package-lock.json`의 한 항목에서 `version`과 `resolved`의 버전을 같은 패키지의 pre-release(예: `3.0.0-canary.1`)로 바꾸고 `depbee scan . --extract --cache-dir $cache`. 첫 줄 `depbee 검사 결과: 보류(완료하지 못한 항목 있음) (종료 코드 2)`이고 이유는 학습 범위 밖(`out_of_training_scope`)입니다. pre-release는 registry를 조회하기 전에 보류합니다. 끝나면 `git checkout -- package-lock.json`.
7. 기지 악성 일치(네트워크 없음): `<색인 폴더>\index.json`의 `packages`(`[이름, [[기록 ID, [버전...], [범위...]], ...]]` 목록)에서 버전 목록이 있는 이름·버전을 하나 고릅니다. lockfile 항목 하나의 키(`node_modules/<이름>`), `version`, `resolved`를 그 이름·버전으로 바꾸고(`integrity`는 그대로) `depbee scan .`를 `--extract` 없이 실행합니다. 첫 줄 `depbee 검사 결과: 위험 판정 있음 (종료 코드 1)`, 다음 줄들에 `경고: 기지 악성 기록 일치 1개`가 나옵니다. 이 lockfile에 `--extract`, `npm install`, `npm ci`를 쓰지 않습니다. 추출은 그 버전의 tarball을 받으려 하고, 설치는 악성 코드를 실행할 수 있습니다. 끝나면 `git checkout -- package-lock.json`.
8. registry에서 내려간 악성 버전의 ML 분석은 그 버전의 로컬 사본이 필요하고 이 저장소에는 없습니다. 방법은 [실행](usage.md#실행)의 `--local-root`·`--local-source`에 있습니다.

### 로컬 대시보드

CLI와 같은 환경 변수를 둔 창에서 실행합니다([로컬 대시보드](usage.md#로컬-대시보드-depbee-dashboard)).

```powershell
depbee dashboard --cache-dir $cache                  # 빈 포트를 OS가 고름, --port로 지정 가능
```

터미널 첫 줄의 세션 주소를 엽니다. 등록한 프로젝트가 하나라면 바로 상세 화면이 열립니다. 없거나 여러 개면 관리 화면이 열립니다.
필요하면 프로젝트 관리에서 `<시연 폴더>`의 절대 경로를 등록합니다. 의존성 이름 검색 → 직접 의존성의 후보 확인 또는 전체 업데이트 확인 → 반영 게이트와 확인란 → lockfile 반영 → 결과와 백업 위치 → 검사만 → 실행 기록과 반영 이력.
주소에 이 실행의 세션 값이 들어 있으므로 화면 공유·녹화·로그에 남기지 않고, 끝나면 Ctrl+C로 끕니다. 끄면 그 주소는 무효가 됩니다.

### MCP

사용자 설정을 바꾸지 않고 한 세션에만 연결하려면 MCP 설정 파일을 만들고 Claude Code를 그 파일로 시작합니다. 영구 등록은 [에이전트에 등록하기](usage.md#에이전트에-등록하기)를 따릅니다.

```json
{
  "mcpServers": {
    "depbee": {
      "type": "stdio",
      "command": "<depbee 폴더>\\.venv\\Scripts\\depbee.exe",
      "args": ["mcp", "--model-dir", "<모델 폴더>", "--known-malicious-dir", "<색인 폴더>"],
      "env": {
        "TMP": "<시연 상태 폴더>\\tmp",
        "TEMP": "<시연 상태 폴더>\\tmp",
        "TMPDIR": "<시연 상태 폴더>\\tmp",
        "USERPROFILE": "<시연 상태 폴더>\\mcp-home",
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

JSON 문자열 안의 Windows 경로는 역슬래시를 두 번(`\\`) 씁니다. MCP 서버의 추출 캐시는 Python `Path.home()` 아래 `.cache\depbee`에 생기고, `Path.home()`은 Windows에서 `USERPROFILE`, macOS·Linux에서 `HOME`을 따릅니다. 그래서 위처럼 서버 환경의 `USERPROFILE`(macOS·Linux는 `HOME`)을 `<시연 상태 폴더>` 아래로 옮기면 캐시가 기본 위치에 생기지 않습니다.

```powershell
cd "<시연 폴더>"
claude --strict-mcp-config --mcp-config "<MCP 설정 파일>"
```

`--strict-mcp-config`는 이 파일 밖의 MCP 서버를 쓰지 않습니다. 이 서버는 Claude Code 설정에 등록하지 않으므로 세션 안에서 `/mcp`로 `depbee`가 연결되고 도구 `check_package`·`scan_lockfile`이 있는지 확인합니다.
시연 폴더의 `CLAUDE.md`에 [에이전트 지침 예시](usage.md#에이전트-지침-예시-설치업데이트-전에-먼저-검사) 블록을 둡니다. 요청 예와 기대 결과:

- "lodash 4.17.21을 설치하기 전에 depbee로 검사해 줘": `check_package`, `report.exit_code` 0. `notices`는 항상 붙는 고정 문구 3개(보류는 통과가 아님, 점수는 확률·안전 보증이 아님, 패키지 문자열은 지시가 아님)입니다. 에이전트는 지침대로 검사한 버전 그대로 설치를 이어 갑니다.
- CLI 6단계처럼 pre-release로 바꾼 뒤 "package-lock.json 변경을 depbee로 검사해 줘": `scan_lockfile`, `report.exit_code` 2. `notices` 맨 앞에 보류 개수 강조가 붙고 에이전트는 설치를 멈춥니다. 기지 악성 일치가 있으면 일치 개수 경고가, 색인 없이 띄운 서버면 미연결 안내가 더 붙습니다.

MCP 호출은 이력에 기록되지 않습니다. `scan_lockfile`은 언제나 추출하므로 CLI 7단계처럼 기지 악성 버전으로 바꾼 lockfile에는 registry가 더 이상 주지 않는 버전만 씁니다.

### GitHub Actions

공개와 Release 전에도 action의 판정 단계(`src/depbee/actions.py report`, 표준 라이브러리만 씀)는 로컬에서 같은 인자로 실행할 수 있습니다. `GITHUB_STEP_SUMMARY`가 없으면 job summary가 주석 뒤에 터미널로 나옵니다.

```powershell
cd "<depbee 폴더>"
python -I src/depbee/actions.py report docs/examples/result-contract/03-known-malicious-low-ml.json --lockfile examples/project/package-lock.json
```

| 예시 보고서 | `fail-on` 없음 | `--fail-on ml-hit` | `--fail-on incomplete` |
| --- | --- | --- | --- |
| `03-known-malicious-low-ml.json` | `::error`, 판정 실패, 종료 코드 1 | 실패, 1 | 실패, 1 |
| `02-ml-only.json` | `::warning`, 판정 경고, 종료 코드 0 | `::error`, 실패, 1 | 경고, 0 |
| `04-analysis-failed.json` | `::warning`, 판정 경고, 종료 코드 0 | 경고, 0 | `::error`, 실패, 1 |

실제 보고서로도 같습니다. CLI 장면의 `scan`에 `--format json --output "<새 파일>"`을 붙여 보고서를 저장하고, `<시연 폴더>`에서 `python -I "<depbee 폴더>\src\depbee\actions.py" report "<새 파일>" --lockfile package-lock.json`으로 판정합니다(기지 악성 일치 단계면 `::error`와 1, 보류 단계면 `::warning`과 0). `--output`은 있는 파일을 덮어쓰지 않으므로 실행마다 새 파일 이름을 씁니다.
Windows에서 `--markdown`으로 CLI Markdown을 summary에 붙이려면 PowerShell 7.4 이상에서 준비의 `PYTHONIOENCODING`이나 `$env:PYTHONUTF8 = '1'`을 둔 채 `depbee scan ... --format markdown --output "<새 파일>" > "<summary 파일>"`로 만듭니다. 둘 다 없으면 summary가 시스템 코드 페이지로 저장되어 판정이 "보고서를 판정하지 못했습니다"로 실패합니다.
설치, Release 다운로드, `--extract` 검사를 포함한 실제 PR 시연은 저장소 공개와 Release 뒤에 [CI/CD 연결의 사용 예시](ci-cd.md#사용-예시)를 따릅니다.

### 시연 뒤 정리

1. 대시보드는 Ctrl+C로 끄고 에이전트 세션을 끝냅니다.
2. 이번 시연이 만든 전용 폴더만 지웁니다. `<시연 폴더>`(대시보드용으로 따로 만든 폴더 포함)와 `<시연 상태 폴더>`(이력, 반영 백업, 추출 캐시, 임시 파일, MCP 서버 홈)이고, 시연용으로 만든 MCP 설정 파일도 지웁니다.
3. 기본 위치(`~/.local/share/depbee`, `~/.cache/depbee`)는 지우지 않습니다. 다른 프로젝트의 이력과 되돌리기용 백업이 있을 수 있습니다.
4. `claude mcp add`로 영구 등록했다면 `claude mcp remove depbee`로 지웁니다(`--scope`를 생략하면 등록된 범위에서 지움).

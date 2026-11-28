# 진입점별 시연

지금 구현으로 네 진입점(CLI, 로컬 대시보드, MCP, GitHub Actions)을 한 PC에서 차례로 보여 주는 절차입니다. 단계마다 명령과 기대하는 첫 줄·종료 코드만 적고, 옵션·보안·반영 게이트·되돌리기는 각 절을 따릅니다. 점수와 개수는 모델과 registry 상태에 따라 달라지므로 적지 않습니다. `<depbee 폴더>`, `<시연 폴더>`, `<시연 상태 폴더>`는 절대 경로로 바꿉니다. 경로가 든 인자는 공백이 있어도 되도록 큰따옴표로 감쌌습니다.

### 준비

모델과 기지 악성 색인은 설치본에 들어 있어 따로 준비하지 않습니다([기본 자산](usage.md#기본-자산): 모델 ID `D04-E00`, 색인 기준 시점 `2026-10-06T14:00:47Z`). 아래 표의 "설치본"은 그 자산을 그대로 쓴다는 뜻입니다.

| 진입점 | extra | Git | Node.js·npm | 모델 | 기지 악성 색인 | 네트워크 |
| --- | --- | --- | --- | --- | --- | --- |
| `plan` | 없음 | `--base-lock`이면 불필요 | 불필요 | 불필요 | 불필요 | 불필요 |
| `--extract` 없는 `scan` | 없음 | 기본 HEAD 기준이면 2.45 이상 | 불필요 | 불필요 | 설치본 | 불필요 |
| `scan --extract`, `check` | `extract` | `scan`의 기본 HEAD 기준이면 2.45 이상 | 불필요 | 설치본 | 설치본 | registry |
| `update` 미리보기·반영 | `extract` | 불필요 | 필요 | 설치본 | 설치본 | registry |
| 대시보드 | `web`, `extract` | lockfile 변경 검사에 필요 | 업데이트 미리보기에 필요 | 설치본 | 설치본 | registry |
| MCP | `mcp`, `extract` | `scan_lockfile`의 기본 HEAD 기준에 필요 | 불필요 | 설치본 | 설치본 | registry, 에이전트 서비스 |
| Actions 공개 시연(합성 정책) | 설치 없음 | 불필요 | 불필요 | 불필요 | 불필요(가상 목록) | github.com 열람 |
| Actions 판정 재현 | 없음(표준 라이브러리) | 실제 보고서를 만들 때만 | 불필요 | 실제 보고서를 만들 때만 | 실제 보고서를 만들 때만 | 예시 보고서면 불필요 |
| Actions 실제 PR | action이 설치 | runner | 불필요 | 설치본(Release는 명시해 바꿀 때만) | 설치본(Release는 명시해 바꿀 때만) | runner의 GitHub·PyPI·registry 연결 |

```powershell
cd "<depbee 폴더>"
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install ".[extract,mcp,web]"
```

이 절의 명령은 PowerShell 예시입니다. macOS/Linux에서 가상환경을 활성화하는 방법은 [설치와 준비](../README.md#설치와-준비)에 있습니다.

`extract`는 공개 저장소 depbee-analyzer를 고정된 커밋으로 받아 설치합니다. 로그인이나 토큰은 필요 없습니다. 추출이 필요 없는 장면(`plan`, `--extract` 없는 `scan`, Actions 판정 재현)만 한다면 `.[mcp,web]`로 설치해도 됩니다.
아래 명령은 가상 환경을 활성화한 뒤 콘솔 스크립트 `depbee`로 실행합니다. 시연 폴더에서 `python -m depbee`를 쓰지 않는 이유는 [MCP 진입점](usage.md#mcp-진입점-검사-전용)에 있습니다.

시연 동안의 이력, 반영 백업, 추출 캐시, 임시 파일은 새로 만든 빈 `<시연 상태 폴더>` 하나에 모읍니다. 그래야 정리할 때 이 폴더만 지우면 되고 기본 위치의 기존 기록을 건드리지 않습니다. 시연할 창에서 아래를 실행합니다.

```powershell
$state = "<시연 상태 폴더>"
mkdir "$state\tmp", "$state\cache", "$state\mcp-home" | Out-Null
Remove-Item Env:DEPBEE_MODEL_DIR, Env:DEPBEE_KNOWN_MALICIOUS_DIR -ErrorAction SilentlyContinue
$env:DEPBEE_HISTORY_DB = "$state\history.sqlite3"
$env:DEPBEE_CONFIG_DIR = "$state\config"
$env:TMP = "$state\tmp"; $env:TEMP = "$state\tmp"; $env:TMPDIR = "$state\tmp"
$env:PYTHONIOENCODING = 'utf-8'
$cache = "$state\cache"
```

- `DEPBEE_MODEL_DIR`, `DEPBEE_KNOWN_MALICIOUS_DIR`: 이 창에 남아 있으면 설치본보다 먼저 쓰이므로 지웁니다. 지운 뒤에는 `--model-dir`, `--known-malicious-dir`을 생략한 명령이 설치본 자산을 씁니다([기본 자산](usage.md#기본-자산), [기지 악성 탐지기](usage.md#기지-악성-탐지기)).
- `DEPBEE_HISTORY_DB`: 이력이 이 파일에, 반영 백업이 그 옆 `backups\`에 생깁니다. 지정하지 않으면 홈 폴더의 기본 위치에 생깁니다([로컬 이력 저장소](usage.md#로컬-이력-저장소)).
- `DEPBEE_CONFIG_DIR`: 사용자 설정 폴더입니다. 절대 경로여야 합니다(`$state`가 절대 경로). 지정하지 않으면 이 창의 명령도 홈 폴더(`~/.config/depbee/`)에 `depbee setup`으로 저장해 둔 모델·색인을 설치본보다 먼저 읽어, 시연에 쓰이는 모델과 색인이 달라질 수 있습니다. 백그라운드 대시보드(`depbee dashboard --background`)의 상태 파일도 이 폴더에 생깁니다([자산 폴더 설정](usage.md#자산-폴더-설정-depbee-setup)).
- `TMP`, `TEMP`, `TMPDIR`: tarball을 풀 임시 폴더입니다. Python은 `TMPDIR`를 `TEMP`·`TMP`보다 먼저 보므로 셋을 함께 둡니다.
- 추출 캐시는 환경 변수로 옮길 수 없어 `--cache-dir`를 받는 명령(`scan`, `check`, `update`, `dashboard`)에 `--cache-dir $cache`를 붙입니다. 빠뜨리면 기본 위치 `~/.cache/depbee`에 쌓입니다. MCP 서버에는 이 옵션이 없어 아래 [MCP](#mcp)처럼 서버의 홈 폴더를 옮깁니다.
- `PYTHONIOENCODING`: 결과를 파일로 돌리거나 다른 프로그램으로 넘길 때 필요합니다. 없으면 Windows에서 한글이 시스템 코드 페이지로 나갑니다.

설치본 자산으로 실행하면 ML 위험 점수와 기지 악성 대조로 판정하고, 반영할 때 기지 악성 미적중이고 기준 미만인 항목은 확인 없이 진행합니다. 시연 결과를 기록하거나 인용할 때는 보고서의 모델 ID와 색인 기준 시점, depbee의 고정 버전·커밋을 함께 남깁니다([결과 재현에 남길 값](usage.md#결과-재현에-남길-값)).

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
3. lockfile 반영([업데이트 반영](usage.md#업데이트-반영-depbee-update---apply)). 첫 줄은 `depbee 업데이트 미리보기`이고, 반영 결과는 검사 결과 뒤 끝부분에 나옵니다.

   ```powershell
   depbee update --apply lockfile --cache-dir $cache    # 끝부분 "depbee 업데이트 반영: 반영함", 종료 코드 0
   ```

   설치본 색인과 대조해 미적중이고 ML 기준 미만인 항목은 확인 없이 반영하고, 출력에 백업 위치가 나옵니다. ML 기준 이상, 보류, 대조 실패 항목이 있으면 그 목록을 보이며 반영하지 않고(끝부분 `depbee 업데이트 반영: 반영하지 않음`), 목록을 검토한 뒤 `--confirm-warnings`를 주어야 반영합니다.
4. `depbee scan . --extract --cache-dir $cache`: 반영으로 생긴 커밋하지 않은 변경을 HEAD와 비교합니다. 첫 줄 `depbee 검사 결과: 통과 (종료 코드 0)`.
5. `depbee check lodash@4.17.21 --cache-dir $cache`: 같은 첫 줄 형식이고 종료 코드 0입니다. 다음 장면을 위해 `git commit -am "업데이트 반영"`으로 반영 결과를 커밋합니다.
6. 보류(네트워크 없음): `package-lock.json`의 한 항목에서 `version`과 `resolved`의 버전을 같은 패키지의 pre-release(예: `3.0.0-canary.1`)로 바꾸고 `depbee scan . --extract --cache-dir $cache`. 첫 줄 `depbee 검사 결과: 보류(완료하지 못한 항목 있음) (종료 코드 2)`이고 이유는 학습 범위 밖(`out_of_training_scope`)입니다. pre-release는 registry를 조회하기 전에 보류합니다. 끝나면 `git checkout -- package-lock.json`.
7. 기지 악성 일치(네트워크 없음): 설치본 색인 `assets\index\index.json`(설치된 depbee 패키지 폴더 안, 폴더 위치는 `python -c "import depbee; print(depbee.__path__[0])"`로 확인)의 `packages`(`[이름, [[기록 ID, [버전...], [범위...]], ...]]` 목록)에서 버전 목록이 있는 이름·버전을 하나 고릅니다. lockfile 항목 하나의 키(`node_modules/<이름>`), `version`, `resolved`를 그 이름·버전으로 바꾸고(`integrity`는 그대로) `depbee scan .`를 `--extract` 없이 실행합니다. 첫 줄 `depbee 검사 결과: 위험 판정 있음 (종료 코드 1)`, 다음 줄들에 `경고: 기지 악성 기록 일치 1개`가 나옵니다. 이 lockfile에 `--extract`, `npm install`, `npm ci`를 쓰지 않습니다. 추출은 그 버전의 tarball을 받으려 하고, 설치는 악성 코드를 실행할 수 있습니다. 끝나면 `git checkout -- package-lock.json`.
8. registry에서 내려간 악성 버전의 ML 분석은 그 버전의 로컬 사본이 필요하고 이 저장소에는 없습니다. 방법은 [실행](usage.md#실행)의 `--local-root`·`--local-source`에 있습니다.
9. 저장소의 예시로 재현(npm과 Git 없음): `depbee scan "<depbee 폴더>\examples\lodash-updated" --base-lock "<depbee 폴더>\examples\lodash-update\package-lock.json" --extract --cache-dir $cache`. lodash 4.17.20에서 4.17.21로의 변경을 registry와 분석기로 검사하고, 첫 줄은 `depbee 검사 결과: 통과 (종료 코드 0)`입니다. depbee 저장소의 CI도 이 예시를 씁니다.

### 로컬 대시보드

CLI와 같은 환경 변수를 둔 창에서 실행합니다([로컬 대시보드](usage.md#로컬-대시보드-depbee-dashboard)).

```powershell
depbee dashboard --cache-dir $cache                  # http://127.0.0.1:18765/, --port로 다른 포트 지정 가능
```

터미널에 출력된 주소를 엽니다. 등록한 프로젝트가 없으면 **프로젝트 추가** 버튼 하나만 있는 화면이 열리고, 누르면 폴더 선택 창이 뜹니다. 등록한 프로젝트가 하나 이상이면 현황판에서 프로젝트별 최근 검사와 업데이트 이력을 비교하고, 프로젝트 이름을 눌러 패키지를 엽니다. 다른 프로젝트를 추가하려면 **프로젝트 관리**를 선택합니다.
필요하면 프로젝트 관리의 **프로젝트 폴더 선택**이 여는 폴더 선택 창에서 `<시연 폴더>`를 골라 등록합니다(경로를 적어 넣는 칸과 파일 업로드는 없습니다). 현황판에서 시연할 프로젝트 이름을 선택합니다. 넓은 화면에서는 왼쪽 프로젝트 목록으로도 전환할 수 있습니다. 패키지 화면에서 이름 검색과 종류 확인 → 직접 의존성의 **이 패키지 업데이트 검사** 또는 머리의 **전체 업데이트 검사(update)** → 확인 창에서 대상을 보고 시작 → 진행이 끝나면 열리는 업데이트 검사 결과 화면의 검사 결과와 반영 게이트, 확인란 → lockfile 반영 → 결과와 백업 위치 → 머리의 **lockfile 변경 검사(scan)** → 기록 화면의 실행 기록과 반영 이력. 미리보기 화면에서 반영하지 않고 돌아가면 패키지·업데이트 화면에 후보 버전과 검사 근거가 보이고 후보의 **이 후보의 미리보기 검토·반영**으로 다시 엽니다. 업데이트 미리보기 뒤에는 패키지·업데이트 화면에 후보 버전과 검사 근거가 보이고, 반영해 파일이 바뀌면 그 결과는 더 이상 현재 후보로 보이지 않습니다.
주소는 이 PC 안에서만 열리고 로그인이 없어, 켜 둔 동안에는 이 PC의 다른 계정과 프로그램도 열 수 있습니다. 끝나면 Ctrl+C로 끕니다. 그 포트를 다른 프로그램이 쓰고 있으면 시작하지 않고 이유를 알리므로 `--port`로 다른 포트를 고릅니다.

### MCP

사용자 설정을 바꾸지 않고 한 세션에만 연결하려면 MCP 설정 파일을 만들고 Claude Code를 그 파일로 시작합니다. 영구 등록은 [에이전트에 등록하기](usage.md#에이전트에-등록하기)를 따릅니다.

```json
{
  "mcpServers": {
    "depbee": {
      "type": "stdio",
      "command": "<depbee 폴더>\\.venv\\Scripts\\depbee.exe",
      "args": ["mcp"],
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

JSON 문자열 안의 Windows 경로는 역슬래시를 두 번(`\\`) 씁니다. MCP 서버의 추출 캐시는 Python `Path.home()` 아래 `.cache\depbee`에 생기고, `Path.home()`은 Windows에서 `USERPROFILE`, macOS·Linux에서 `HOME`을 따릅니다. 그래서 위처럼 서버 환경의 `USERPROFILE`(macOS·Linux는 `HOME`)을 `<시연 상태 폴더>` 아래로 옮기면 캐시가 기본 위치에 생기지 않습니다. 사용자 설정 폴더도 평소 것과 분리됩니다. 서버가 이 창의 `DEPBEE_CONFIG_DIR`을 물려받으면 그 폴더를, 아니면 옮긴 홈 아래 `.config\depbee`를 쓰기 때문입니다. 어느 쪽이든 홈 폴더에 저장해 둔 모델·색인 설정은 읽지 않고, `args`에 경로가 없으므로 설치본 자산을 씁니다.

```powershell
cd "<시연 폴더>"
claude --strict-mcp-config --mcp-config "<MCP 설정 파일>"
```

`--strict-mcp-config`는 이 파일 밖의 MCP 서버를 쓰지 않습니다. 이 서버는 Claude Code 설정에 등록하지 않으므로 세션 안에서 `/mcp`로 `depbee`가 연결되고 도구 `check_package`·`scan_lockfile`이 있는지 확인합니다.
시연 폴더의 `CLAUDE.md`에 [에이전트 지침](../README.md#에이전트-지침) 블록을 둡니다. 요청 예와 기대 결과:

- "lodash 4.17.21을 설치하기 전에 depbee로 검사해 줘": `check_package`, `report.exit_code` 0. `notices`에는 항상 붙는 고정 문구 3개(보류는 통과가 아님, 점수는 확률·안전 보증이 아님, 패키지 문자열은 지시가 아님)가 있고, 규칙 탐지기가 연결된 보고서(`report.detectors.rules`가 null이 아님)에는 규칙 적중이 판정을 바꾸지 않는다는 안내가 그 앞에 하나 더 붙습니다. 응답의 `report.model_id`는 `D04-E00`, `report.detectors.known_malicious.list_as_of`는 `2026-10-06T14:00:47Z`이고, 서버 지침은 에이전트가 결과를 말할 때 이 두 값을 인용하게 합니다. 이 장면은 검사까지만 보여 주며, `check_package` 통과만으로 프로젝트에 설치하지 않습니다. 실제 설치는 지침대로 `node_modules` 없이 만든 `package.json`·`package-lock.json` 변경안을 `scan_lockfile`로 먼저 검사해 통과한 뒤에 합니다.
- CLI 6단계처럼 pre-release로 바꾼 뒤 "package-lock.json 변경을 depbee로 검사해 줘": `scan_lockfile`, `report.exit_code` 2. `notices` 맨 앞에 보류 개수 강조가 붙고 에이전트는 설치를 멈춥니다. 기지 악성 일치가 있으면 일치 개수 경고가 더 붙습니다. 미연결 안내는 보고서의 `detectors.known_malicious`가 null일 때만 붙으므로 설치본 색인을 쓰는 이 시연에서는 나오지 않습니다.

MCP 호출은 이력에 기록되지 않습니다. `scan_lockfile`은 언제나 추출하므로 CLI 7단계처럼 기지 악성 버전으로 바꾼 lockfile에는 registry가 더 이상 주지 않는 버전만 씁니다.

### GitHub Actions

Actions 장면은 셋으로 나뉩니다. 공개 시연 저장소의 fixture 장면은 합성 lockfile로 정책이 PR에 어떻게 나타나는지 보여 줍니다. 실제 제품 검사는 Action을 고정한 workflow가 PR의 lockfile 변경을 검사합니다. 로컬 판정 재현은 depbee의 판정 단계를 예시 보고서로 실행합니다.

**공개 시연 저장소(합성 정책 시연).** [depbee-actions-demo](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo)는 설치 없이 브라우저로 볼 수 있습니다. 열린 PR 세 개가 장면 하나씩이고 모두 `package-lock.json` 한 파일만 바꿉니다.

| 장면 | PR | lockfile에서 바뀐 것 | Check | lockfile 줄 주석 |
| --- | --- | --- | --- | --- |
| 정상 버전 변경 | [#1](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/pull/1) | `ms` 2.1.1에서 2.1.3 | 성공 | 없음 |
| 사전 배포 버전 보류 | [#2](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/pull/2) | `ms` 2.1.1에서 3.0.0-canary.1 | 성공 | 경고 `사전 배포 버전이라 보류, 통과가 아님` |
| 가상 목록 일치 | [#3](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/pull/3) | 가상 패키지 `DEPBEE-DEMO-SENTINEL` 9.9.9 추가 | 실패 | 오류 `시연용 가상 목록과 일치(DEMO-FIXTURE-0001)` |

각 PR의 **Checks** 탭에서 `fixture PR 검사 (depbee 제품 미실행)`의 job summary를, **Files changed** 탭에서 lockfile 줄의 주석을 봅니다. 세 장면과 자체 테스트를 한 번에 실행한 기록은 [Actions run 44781575143](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/actions/runs/44781575143)입니다(workflow `fixture 시연 (depbee 제품 미실행)`의 수동 실행). 가상 목록 일치 장면의 실패가 기대 결과이므로 이 실행은 전체가 실패로 표시됩니다. 다시 실행하는 방법과 실행 결과에서 확인할 것은 시연 저장소 README의 [fixture 시연의 세 장면](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo#fixture-시연의-세-장면)에 있습니다.

이 fixture 검사는 depbee 제품을 실행하지 않습니다. 시연 저장소의 fixture 게이트(`tools/fixture_gate.py`)가 lockfile의 이름과 버전을 가상 목록과 비교할 뿐이고, 기지 악성 색인 대조와 tarball 추출과 ML 위험 점수는 없습니다. 그래서 fixture Check의 성공은 depbee가 검사해서 통과했다는 뜻이 아니며 보안 판정도 아닙니다. 이 시연이 보여 주는 것은 정책입니다. 일치는 실패이고, 보류는 경고이되 통과가 아니며, 결과는 Check와 lockfile 줄 주석과 summary와 보고서 artifact로 남습니다. 시연 저장소의 artifact는 7일 뒤 지워집니다. `DEPBEE-DEMO-SENTINEL`은 시연을 위해 지은 가상의 이름이며 실제 악성 패키지 기록이 아닙니다.

**실제 제품 검사.** depbee와, 설치 단계에서 받는 depbee-analyzer는 공개 저장소입니다. PR의 lockfile 변경을 실제로 검사하려면 대상 저장소의 `.github/workflows/depbee.yml`에 [CI/CD 연결의 사용 예시](ci-cd.md#사용-예시)를 둡니다. secret, 토큰, 저장소 변수는 필요 없습니다. workflow는 Action을 전체 커밋 SHA로 고정합니다. 모델과 기지 악성 색인은 그 커밋의 설치본에 포함된 것을 기본으로 쓰고, Release 태그와 SHA-256은 다른 모델이나 색인을 명시해 바꿀 때만 지정합니다. 지금 게시된 Release는 없습니다.

lockfile을 바꾼 PR을 열면 Checks의 job summary에 모델 ID, 색인 기준 시점, 항목별 판정이 나오고, 경고나 실패 항목에는 lockfile 줄 주석이 붙으며, `depbee-report` artifact가 생깁니다.

실제 실행은 두 곳에서 볼 수 있습니다.

- 공개 시연 저장소의 [PR #8](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/pull/8)은 `ms`를 2.1.1에서 2.1.3으로 올린 lockfile 변경 하나입니다. 그 저장소의 workflow가 `759cc68`로 고정한 Action을 불렀고, `depbee scan (제품 실제 검사)` job이 통과로 판정했습니다([Actions run 45290776914](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/actions/runs/45290776914)). summary의 모델 ID는 `D04-E00`, 색인 기준 시점은 `2026-10-06T14:00:47Z`이고, artifact의 `report.json`에는 비교 버전 2.1.2와 분석기 커밋(`provenance.feature_extractor.commit`)이 있습니다. lockfile을 바꾸지 않은 PR에서는 바뀐 의존성 0개로 통과합니다([Actions run 45290763429](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/actions/runs/45290763429)).
- depbee 저장소의 CI는 PR마다 이 Action으로 lodash 4.17.20에서 4.17.21로의 변경을 검사합니다. 그 저장소 Actions 탭의 `action` job에서 summary와 artifact를 볼 수 있습니다([자기 검사](ci-cd.md#자기-검사-depbee-ci-action-job)).

시연 저장소의 `main`에서 제품 검사가 켜져 있는지와 켜는 순서는 [그 저장소의 README](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo#readme)를 따릅니다. 가상 목록 일치 장면은 실제 색인에 없는 이름이라 제품 검사에서는 재현되지 않습니다.

**로컬 판정 재현.** action의 판정 단계(`src/depbee/actions.py report`, 표준 라이브러리만 씀)는 설치 없이 로컬에서 같은 인자로 실행할 수 있습니다. `GITHUB_STEP_SUMMARY`가 없으면 job summary가 주석 뒤에 터미널로 나옵니다.

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
설치와 `--extract` 검사를 포함한 실제 PR 검사는 위 **실제 제품 검사**의 workflow를 따릅니다.

### 네 진입점 보고서 대조

같은 lockfile 변경을 네 진입점이 같게 보고하는지는 `.github/scripts/check_lodash_report.py --compare`로 확인합니다. 대상은 저장소 예시의 정상 변경 하나(lodash 4.17.20에서 4.17.21)이고, 모델·임계값·색인·분석기는 설치본 그대로 씁니다. 이 스크립트는 보고서를 체크아웃의 모델·색인 manifest와 `pyproject.toml`의 분석기 고정 커밋에 비추어 확인하므로, `<depbee 폴더>`는 설치한 depbee와 같은 커밋이어야 합니다.

1. 대조용 프로젝트를 만듭니다. Git HEAD의 lockfile은 4.17.20, 작업 파일은 4.17.21입니다.

   ```powershell
   mkdir "<대조 폴더>"; cd "<대조 폴더>"
   Copy-Item "<depbee 폴더>\examples\lodash-update\package.json", "<depbee 폴더>\examples\lodash-update\package-lock.json" .
   git init; git add package.json package-lock.json; git commit -m "lodash 4.17.20"
   Copy-Item "<depbee 폴더>\examples\lodash-updated\package-lock.json" . -Force
   ```

2. CLI, MCP, 대시보드의 보고서를 한 번에 받습니다. `<새 결과 폴더>`는 아직 없는 절대 경로여야 합니다.

   ```powershell
   python -I "<depbee 폴더>\.github\scripts\capture_entry_reports.py" "<대조 폴더>" "<새 결과 폴더>"
   ```

   이 스크립트는 설치된 depbee의 세 진입점을 실제로 실행합니다. `cli.json`은 `depbee scan --extract`의 보고서이고, `mcp.json`은 stdio로 띄운 MCP 서버의 `scan_lockfile` 응답입니다. `dashboard.json`은 프로젝트를 이력 API(`history.register_project`, 대시보드의 폴더 선택 창이 부르는 것과 같은 함수)로 등록하고 대시보드 서버를 띄워 lockfile 변경 검사 폼을 보낸 뒤, 서버가 이력에 저장한 실행을 다시 읽은 것입니다. 브라우저 클릭과 에이전트 대화는 거치지 않습니다. 이력, 홈 폴더, 추출 캐시는 결과 폴더 안에만 생기고, 세 진입점이 캐시 하나를 같이 써서 tarball은 한 번만 받습니다.
3. Action 보고서는 depbee 저장소의 같은 커밋 PR 실행에서 받습니다. Actions 탭에서 그 실행의 `action` job이 남긴 `depbee-report` artifact를 내려받으면 `report.json`이 들어 있습니다(로그인 필요, `gh run download <실행 번호> --repo 26-Capstone-Project-Team01/depbee --name depbee-report --dir "<내려받을 폴더>"`도 같습니다). push 실행의 artifact는 workflow가 action의 명령으로 직접 실행한 scan을 action이 판정해 올린 것이므로, action이 스스로 scan한 보고서가 필요하면 PR 실행의 것을 씁니다.
4. 네 보고서를 대조합니다.

   ```powershell
   python -I "<depbee 폴더>\.github\scripts\check_lodash_report.py" --compare "cli=<새 결과 폴더>\cli.json" "mcp=<새 결과 폴더>\mcp.json" "dashboard=<새 결과 폴더>\dashboard.json" "action=<내려받을 폴더>\report.json"
   ```

   파일마다 확인 한 줄이 나오고, 모두 같으면 마지막 줄이 `4 reports say the same (cli, mcp, dashboard, action)`으로 시작하며 종료 코드는 0입니다. 다르면 종료 코드 1과 함께 `report parity failed` 아래에 필드마다 한 줄씩 `results[0].score differs: cli=..., mcp=..., dashboard=..., action=...`처럼 필드 이름과 진입점별 값이 나옵니다.

보고서의 모든 값을 비교합니다. 요청 ID와 변경 ID, lockfile 위치, 패키지와 이전·이후·비교 버전, 모델 ID와 모델·manifest 해시, 임계값, 색인 기준 시점과 해시, 분석기 버전·커밋·설치 파일 digest, 특징 값, 점수와 그 설명, 근거 문구, 규칙 묶음 버전, 규칙 여섯 개 각각의 버전·결과·근거, ML·기지 악성·규칙 판정과 둘의 일치 여부(`rule_ml_agreement`), 항목 판정, 전체 판정과 종료 코드가 모두 들어갑니다. 한 번의 실행이나 한 대의 PC에만 속하는 값 세 가지는 비교하지 않습니다. 보고서와 항목의 소요 시간(`elapsed_seconds`), 항목의 캐시 사용 여부(`cache_hit`), 분석기를 실행한 Python 버전(`provenance.feature_extractor.python`)입니다. 값은 종류와 값이 정확히 같아야 합니다. 임계값, 특징 값, 개수, 설명에 다시 적힌 특징 값도 정확히 비교합니다. 모델이 부동소수점으로 계산한 네 가지(점수 `score`, 설명의 기여도 `contribution`, 나머지 기여도 합 `others_sum`, 기준값 `base_value`)만 운영체제의 수학 라이브러리 차이를 넘지 않는 상대 오차 1e-12까지 같은 값으로 봅니다. 이 허용은 보고서 안의 정확한 위치로 정해지므로, 같은 이름의 특징 값에는 적용되지 않습니다. 분석기 설치 파일 digest는 Windows와 Linux 설치에서 같은 값이므로, 다른 PC에서 만든 Action 보고서와도 그대로 비교됩니다.

`이름=파일`은 둘 이상이면 되고, 직접 저장한 파일도 받습니다. `scan --format json --output`의 보고서, `update --format json`의 출력, MCP 도구 응답, `history.get_run`이 돌려준 실행을 JSON으로 저장한 파일이 그대로 쓰입니다. Action 보고서 없이 대조했다면 세 진입점 대조로 기록하고, 네 진입점 대조라고 적지 않습니다.

이 대조는 위 lodash 변경의 통과 보고서만 받습니다. 기지 악성 일치와 보류 장면에서 진입점별 조치가 같은지는 자동으로 대조하지 않으므로 각 절의 기대 결과로 확인합니다. depbee 저장소의 CI는 `action` job에서 같은 대조를 다섯 보고서(action, `update` 미리보기, CLI scan, MCP, 대시보드)로 실행합니다.

### 시연 뒤 정리

1. 대시보드는 Ctrl+C로 끄고 에이전트 세션을 끝냅니다.
2. 이번 시연이 만든 전용 폴더만 지웁니다. `<시연 폴더>`(대시보드용으로 따로 만든 폴더 포함)와 `<시연 상태 폴더>`(이력, 반영 백업, 추출 캐시, 임시 파일, MCP 서버 홈)이고, 시연용으로 만든 MCP 설정 파일도 지웁니다.
3. 기본 위치(`~/.local/share/depbee`, `~/.cache/depbee`)는 지우지 않습니다. 다른 프로젝트의 이력과 되돌리기용 백업이 있을 수 있습니다.
4. `claude mcp add`로 영구 등록했다면 `claude mcp remove depbee`로 지웁니다(`--scope`를 생략하면 등록된 범위에서 지움).

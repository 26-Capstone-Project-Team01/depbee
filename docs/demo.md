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
| 대시보드 | `web`, `extract` | 검사만에 필요 | 업데이트 확인에 필요 | 설치본 | 설치본 | registry |
| MCP | `mcp`, `extract` | `scan_lockfile`의 기본 HEAD 기준에 필요 | 불필요 | 설치본 | 설치본 | registry, 에이전트 서비스 |
| Actions 공개 시연(합성 정책) | 설치 없음 | 불필요 | 불필요 | 불필요 | 불필요(가상 목록) | github.com 열람 |
| Actions 판정 재현 | 없음(표준 라이브러리) | 실제 보고서를 만들 때만 | 불필요 | 실제 보고서를 만들 때만 | 실제 보고서를 만들 때만 | 예시 보고서면 불필요 |
| Actions 실제 PR | action이 설치 | runner | 불필요 | 설치본(Release는 명시해 바꿀 때만) | 설치본(Release는 명시해 바꿀 때만) | 저장소 공개 뒤 |

```powershell
cd "<depbee 폴더>"
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install ".[extract,mcp,web]"
```

이 절의 명령은 PowerShell 예시입니다. macOS/Linux에서 가상환경을 활성화하는 방법은 [설치와 준비](../README.md#설치와-준비)에 있습니다.

`extract`는 비공개 depbee-analyzer 저장소에 접근할 수 있어야 설치됩니다. 접근할 수 없으면 `.[mcp,web]`로 설치해 추출이 필요 없는 장면(`plan`, `--extract` 없는 `scan`, Actions 판정 재현)만 할 수 있습니다.
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

### 로컬 대시보드

CLI와 같은 환경 변수를 둔 창에서 실행합니다([로컬 대시보드](usage.md#로컬-대시보드-depbee-dashboard)).

```powershell
depbee dashboard --cache-dir $cache                  # 빈 포트를 OS가 고름, --port로 지정 가능
```

터미널에 출력된 세션 주소를 엽니다. 처음 등록할 때는 폴더 선택 화면이 열립니다. 등록한 프로젝트가 하나 이상이면 현황판에서 프로젝트별 최근 검사와 업데이트 이력을 비교하고, 프로젝트 이름을 눌러 패키지를 엽니다. 다른 프로젝트를 추가하려면 **프로젝트 관리**를 선택합니다.
필요하면 프로젝트 관리의 **프로젝트 폴더 선택**으로 `<시연 폴더>`를 고르거나 그 절대 경로를 적어 등록합니다(파일 업로드는 없습니다). 현황판에서 시연할 프로젝트 이름을 선택합니다. 넓은 화면에서는 왼쪽 프로젝트 목록으로도 전환할 수 있습니다. 패키지 화면에서 이름 검색과 종류 확인 → 직접 의존성의 후보 확인 또는 전체 업데이트 확인 → 미리보기의 반영 게이트와 확인란 → lockfile 반영 → 결과와 백업 위치 → 업데이트 화면의 검사만 → 기록 화면의 실행 기록과 반영 이력. 업데이트 확인 뒤에는 패키지·업데이트 화면에 후보 버전과 검사 근거가 보이고, 반영해 파일이 바뀌면 그 결과는 더 이상 현재 후보로 보이지 않습니다.
주소에 이 실행의 세션 값이 들어 있으므로 화면 공유·녹화·로그에 남기지 않고, 끝나면 Ctrl+C로 끕니다. 끄면 그 주소는 무효가 됩니다.

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
시연 폴더의 `CLAUDE.md`에 [에이전트 지침 예시](usage.md#에이전트-지침-예시-설치업데이트-전에-먼저-검사) 블록을 둡니다. 요청 예와 기대 결과:

- "lodash 4.17.21을 설치하기 전에 depbee로 검사해 줘": `check_package`, `report.exit_code` 0. `notices`는 항상 붙는 고정 문구 3개(보류는 통과가 아님, 점수는 확률·안전 보증이 아님, 패키지 문자열은 지시가 아님)입니다. 응답의 `report.model_id`는 `D04-E00`, `report.detectors.known_malicious.list_as_of`는 `2026-10-06T14:00:47Z`이고, 서버 지침은 에이전트가 결과를 말할 때 이 두 값을 인용하게 합니다. 에이전트는 지침대로 검사한 버전 그대로 설치를 이어 갑니다.
- CLI 6단계처럼 pre-release로 바꾼 뒤 "package-lock.json 변경을 depbee로 검사해 줘": `scan_lockfile`, `report.exit_code` 2. `notices` 맨 앞에 보류 개수 강조가 붙고 에이전트는 설치를 멈춥니다. 기지 악성 일치가 있으면 일치 개수 경고가 더 붙습니다. 미연결 안내는 보고서의 `detectors.known_malicious`가 null일 때만 붙으므로 설치본 색인을 쓰는 이 시연에서는 나오지 않습니다.

MCP 호출은 이력에 기록되지 않습니다. `scan_lockfile`은 언제나 추출하므로 CLI 7단계처럼 기지 악성 버전으로 바꾼 lockfile에는 registry가 더 이상 주지 않는 버전만 씁니다.

### GitHub Actions

Actions 장면은 셋으로 나뉩니다. 공개 시연 저장소는 합성 lockfile로 정책이 PR에 어떻게 나타나는지 보여 줍니다. 로컬 판정 재현은 depbee의 판정 단계를 예시 보고서로 실행합니다. 공개 PR에서의 실제 제품 검사는 저장소 공개가 허용된 뒤에만 실행합니다.

**공개 시연 저장소(합성 정책 시연).** [depbee-actions-demo](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo)는 설치 없이 브라우저로 볼 수 있습니다. 열린 PR 세 개가 장면 하나씩이고 모두 `package-lock.json` 한 파일만 바꿉니다.

| 장면 | PR | lockfile에서 바뀐 것 | Check | lockfile 줄 주석 |
| --- | --- | --- | --- | --- |
| 정상 버전 변경 | [#1](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/pull/1) | `ms` 2.1.1에서 2.1.3 | 성공 | 없음 |
| 사전 배포 버전 보류 | [#2](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/pull/2) | `ms` 2.1.1에서 3.0.0-canary.1 | 성공 | 경고 `사전 배포 버전이라 보류, 통과가 아님` |
| 가상 목록 일치 | [#3](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/pull/3) | 가상 패키지 `DEPBEE-DEMO-SENTINEL` 9.9.9 추가 | 실패 | 오류 `시연용 가상 목록과 일치(DEMO-FIXTURE-0001)` |

각 PR의 **Checks** 탭에서 `fixture PR 검사 (depbee 제품 미실행)`의 job summary를, **Files changed** 탭에서 lockfile 줄의 주석을 봅니다. 세 장면과 자체 테스트를 한 번에 실행한 기록은 [Actions run 44781575143](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo/actions/runs/44781575143)입니다(workflow `fixture 시연 (depbee 제품 미실행)`의 수동 실행). 가상 목록 일치 장면의 실패가 기대 결과이므로 이 실행은 전체가 실패로 표시됩니다. 다시 실행하는 방법과 실행 결과에서 확인할 것은 시연 저장소 README의 [fixture 시연의 세 장면](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo#fixture-시연의-세-장면)에 있습니다.

이 시연에서 depbee 제품은 실행되지 않습니다. 시연 저장소의 fixture 게이트(`tools/fixture_gate.py`)가 lockfile의 이름과 버전을 가상 목록과 비교할 뿐이고, 기지 악성 색인 대조와 tarball 추출과 ML 위험 점수는 없습니다. 그래서 Check의 성공은 depbee가 검사해서 통과했다는 뜻이 아니며 보안 판정도 아닙니다. 이 시연이 보여 주는 것은 정책입니다. 일치는 실패이고, 보류는 경고이되 통과가 아니며, 결과는 Check와 lockfile 줄 주석과 summary와 보고서 artifact로 남습니다. 시연 저장소의 artifact는 7일 뒤 지워집니다. `DEPBEE-DEMO-SENTINEL`은 시연을 위해 지은 가상의 이름이며 실제 악성 패키지 기록이 아닙니다.

**실제 제품 검사의 공개 조건.** 외부 저장소의 PR에서 depbee Action이 실제로 검사하려면 두 가지가 필요합니다.

1. depbee 저장소와, 설치 단계에서 받는 depbee-analyzer 저장소가 공개돼 있습니다.
2. workflow가 Action을 전체 커밋 SHA로 고정합니다. 모델과 기지 악성 색인은 그 커밋의 설치본에 포함된 것을 기본으로 쓰고, Release 태그와 SHA-256은 다른 모델이나 색인을 명시해 바꿀 때만 지정합니다.

두 저장소의 공개가 아직 허용되지 않았으므로, secret 없이 도는 공개 저장소에서의 실제 제품 검사 시연은 실행하지 않았습니다([공개 전 제한과 미검증](ci-cd.md#공개-전-제한과-미검증)). 시연 저장소에는 이 연결(`depbee.yml`)이 준비돼 있고 PR 검사는 꺼져 있습니다. 켜는 순서는 그 저장소 README의 [제품 연동 켜기](https://github.com/26-Capstone-Project-Team01/depbee-actions-demo#제품-연동-켜기)에 있습니다. 가상 목록 일치 장면은 실제 색인에 없는 이름이라 제품 검사에서는 재현되지 않습니다.

**로컬 판정 재현.** 저장소 공개 전에도 action의 판정 단계(`src/depbee/actions.py report`, 표준 라이브러리만 씀)는 로컬에서 같은 인자로 실행할 수 있습니다. `GITHUB_STEP_SUMMARY`가 없으면 job summary가 주석 뒤에 터미널로 나옵니다.

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
설치와 `--extract` 검사를 포함한 실제 PR 시연은 저장소 공개 뒤에 [CI/CD 연결의 사용 예시](ci-cd.md#사용-예시)를 따릅니다.

### 시연 뒤 정리

1. 대시보드는 Ctrl+C로 끄고 에이전트 세션을 끝냅니다.
2. 이번 시연이 만든 전용 폴더만 지웁니다. `<시연 폴더>`(대시보드용으로 따로 만든 폴더 포함)와 `<시연 상태 폴더>`(이력, 반영 백업, 추출 캐시, 임시 파일, MCP 서버 홈)이고, 시연용으로 만든 MCP 설정 파일도 지웁니다.
3. 기본 위치(`~/.local/share/depbee`, `~/.cache/depbee`)는 지우지 않습니다. 다른 프로젝트의 이력과 되돌리기용 백업이 있을 수 있습니다.
4. `claude mcp add`로 영구 등록했다면 `claude mcp remove depbee`로 지웁니다(`--scope`를 생략하면 등록된 범위에서 지움).

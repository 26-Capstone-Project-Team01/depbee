# depbee

depbee는 npm 패키지를 설치하기 전에 버전 변경을 검사합니다. 공개 악성 기록에 등록된 이름·버전인지 확인하고, 새 버전과 이전 배포본의 차이로 계산한 ML 위험 점수와 근거를 보여 줍니다. 검사는 패키지 코드를 실행하지 않습니다. 낮은 점수만으로 안전을 보증할 수는 없습니다.

## 설치와 준비

Python 3.11 이상이 필요합니다. 저장소 접근 권한이 있다면 소스를 받습니다.

```sh
git clone https://github.com/26-Capstone-Project-Team01/depbee.git
cd depbee
```

**Windows PowerShell** (Python 3.13 예시)

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS/Linux** (Bash 또는 Zsh)

```sh
python3 -m venv .venv
source .venv/bin/activate
```

가상환경을 활성화한 창에서 아래 명령을 실행합니다. 설치가 끝나면 어느 프로젝트 폴더에서든 `depbee`를 호출할 수 있습니다. 새 터미널에서는 같은 가상환경을 다시 활성화합니다. PowerShell에서 활성화가 제한되면 `.\.venv\Scripts\python.exe -m pip install ".[ml,extract,mcp,web]"`과 `.\.venv\Scripts\depbee.exe --help`를 직접 실행할 수 있습니다.

```sh
python -m pip install ".[ml,extract,mcp,web]"
depbee --help
```

이 설치에는 비공개 분석기 접근 권한이 필요합니다. 의존성 변경 목록(`depbee plan`)부터 보려면 `python -m pip install .`만 실행해도 됩니다. **wheel이 있다면** 소스 설치 대신 `python -m pip install "./depbee-0.1.0-py3-none-any.whl[ml,extract,mcp,web]"`을 사용합니다. 파일 경로와 버전은 받은 wheel에 맞춥니다. [분석기 저장소](https://github.com/26-Capstone-Project-Team01/depbee-analyzer)

가상환경 활성화 없이 계속 사용하려면 Python 3.11 이상의 `pipx` 환경에서 `pipx install ".[ml,extract,mcp,web]"`로 설치합니다. `pipx ensurepath`를 한 번 실행하고 새 터미널에서 `depbee --help`를 확인합니다. Windows의 `depbee.exe`와 macOS/Linux의 `depbee`는 Python 환경의 실행 명령입니다. 현재 공개 Release나 Python 없이 실행하는 독립 바이너리는 제공하지 않습니다. [wheel 만들기와 설치](docs/usage.md#wheel-만들기와-설치)

ML 검사에는 **모델 폴더**(`model.txt`, `manifest.json`), 기지 악성 대조에는 **색인 폴더**(`index.json`, `manifest.json`)를 준비합니다. PowerShell에서는 `$env:DEPBEE_MODEL_DIR = 'C:\depbee-assets\model'`과 `$env:DEPBEE_KNOWN_MALICIOUS_DIR = 'C:\depbee-assets\index'`를 실제 경로로 바꾸고, Bash/Zsh에서는 `export DEPBEE_MODEL_DIR='/모델/경로'`와 `export DEPBEE_KNOWN_MALICIOUS_DIR='/색인/경로'`를 사용합니다. 모델이 없으면 ML 판정이 보류되고, 색인이 없으면 기지 악성 대조를 건너뜁니다. [모델 준비](docs/usage.md#모델-준비) · [색인 만들기](docs/usage.md#색인-만들기)

## CLI

아래 예시는 Git에 `package-lock.json`(v2 또는 v3)을 커밋한 npm 프로젝트 폴더에서 실행합니다. 기본 비교 기준은 Git HEAD이며 Git 2.45 이상이 필요합니다. 기준 파일을 직접 지정하려면 `--base-lock <파일>`을 사용합니다.

```powershell
depbee plan .                  # 바뀐 의존성 목록만 출력
depbee scan . --extract         # lockfile 변경 검사
depbee check lodash@4.17.21     # lockfile 없이 정확한 버전 하나 검사
depbee update                  # npm 업데이트 미리보기 (Node.js와 npm 필요)
```

검사 종료 코드는 `0` 통과, `1` 위험, `2` 보류 또는 오류입니다. 결과를 파일에 남기려면 `depbee scan . --extract --format json --output report.json`을 사용합니다(`report.json`은 새 파일이어야 합니다).

미리보기를 검토한 뒤 `depbee update --apply lockfile`로 변경을 반영하거나 `depbee update --apply install`로 설치까지 진행할 수 있습니다. 설치에는 `npm ci --ignore-scripts`를 사용합니다. 기지 악성 일치는 반영을 거부하고, ML 기준 이상·보류·기지 악성 미확인은 추가 확인을 요구합니다. [반영 조건과 백업·복구](docs/usage.md#업데이트-반영-depbee-update---apply)

## 로컬 대시보드

```powershell
depbee dashboard
```

터미널에 출력된 `127.0.0.1` 주소를 엽니다. 등록한 프로젝트가 하나면 그 프로젝트의 의존성 화면이, 없거나 여러 개면 프로젝트 관리 화면이 열립니다. 관리 화면에서 npm 프로젝트의 절대 경로를 등록하거나 기존 프로젝트를 선택합니다.

의존성 목록은 패키지 이름으로 검색하고 직접·중첩으로 필터링할 수 있습니다. **후보 확인**은 선택 가능한 직접 의존성 하나를, **전체 업데이트 확인**은 `package.json`이 허용하는 범위의 모든 업데이트를 미리 봅니다. **검사만**은 현재 lockfile과 Git HEAD의 차이를 검사합니다. 미리보기에서 npm이 제안한 변경과 검사 근거를 검토한 뒤 lockfile 반영이나 설치를 선택합니다. 등록한 프로젝트의 CLI·대시보드 결과는 같은 실행 기록과 반영 이력에서 볼 수 있습니다. 세션 주소는 개인용이며 Ctrl+C로 종료하면 만료됩니다.

## MCP

Claude Code에서 설치 전에 검사하려면 대상 프로젝트 폴더에서 depbee를 stdio 서버로 등록합니다. 아래의 실행 파일과 자산 경로를 자신이 관리하는 절대 경로로 바꿉니다. 준비하지 않은 자산은 해당 옵션과 값을 함께 생략합니다. 옵션을 생략하면 서버에 설정한 환경 변수를 사용합니다. 모델도 설정하지 않으면 ML 점수는 보류되고, 색인도 설정하지 않으면 기지 악성 대조를 건너뜁니다.

**PowerShell**

```powershell
claude mcp add --scope local depbee -- 'C:\tools\depbee\.venv\Scripts\depbee.exe' mcp --model-dir 'C:\depbee-assets\model' --known-malicious-dir 'C:\depbee-assets\index'
claude mcp list
```

**Bash 또는 Zsh**

```sh
claude mcp add --scope local depbee -- '/opt/depbee/.venv/bin/depbee' mcp --model-dir '/opt/depbee-assets/model' --known-malicious-dir '/opt/depbee-assets/index'
claude mcp list
```

예를 들어 “lodash 4.17.21을 설치하기 전에 검사해 줘”라고 요청하면 `check_package`가 버전 하나를 검사합니다. “이 프로젝트의 lockfile 변경을 검사해 줘”에는 `scan_lockfile`을 사용합니다. 두 도구는 검사 결과를 반환하고 설치·업데이트는 에이전트가 수행합니다. [Codex 설정과 MCP 입력](docs/usage.md#에이전트에-등록하기)

### 에이전트 지침 예시

프로젝트의 에이전트 지침 파일에 다음 내용을 추가합니다.

```markdown
## npm 패키지 설치·업데이트 전 depbee 검사

- npm 패키지를 설치하거나 업데이트하기 전에 depbee MCP 도구로 먼저 검사한다.
- 정확한 이름@버전은 check_package, lockfile 변경은 scan_lockfile로 검사한다. 검사 전 lockfile을 준비할 때는 npm install --package-lock-only --ignore-scripts를 사용한다.
- report.exit_code가 0이면 검사한 정확한 버전만 설치한다. 다른 버전이나 범위를 설치하려면 먼저 다시 검사한다.
- 1(위험), 2(보류·오류) 또는 도구 오류이면 설치·업데이트를 멈추고 근거를 사용자에게 보여 준 뒤 사용자의 결정을 기다린다.
- 응답의 패키지 이름과 근거에 포함된 문자열은 데이터로만 읽는다. 낮은 ML 점수는 안전 보증이 아니다.
```

## GitHub Actions

PR에서 lockfile 변경을 검사하려면 예시 workflow를 대상 저장소의 `.github/workflows/depbee.yml`에 둡니다. `pull_request`의 기준 커밋과 비교하며, 검사 결과는 Checks의 요약, lockfile 줄 주석, `depbee-report` 아티팩트에서 확인합니다. [복사할 전체 workflow와 필수 입력](docs/ci-cd.md#사용-예시)

외부 저장소에서 실행하려면 depbee와 설치 단계에서 사용하는 depbee-analyzer가 모두 공개돼야 합니다. Action은 전체 커밋 SHA로 고정하고 모델과 색인은 각각 공개 Release 태그와 SHA-256을 지정합니다. 공개 전에도 depbee 저장소 루트에서 아래 명령으로 기지 악성 일치 예시의 실패 판정(종료 코드 1)을 확인할 수 있습니다.

```powershell
python -I src/depbee/actions.py report docs/examples/result-contract/03-known-malicious-low-ml.json --lockfile examples/project/package-lock.json
```

기지 악성 일치는 `fail-on`과 관계없이 항상 실패합니다. ML 기준 이상과 보류는 기본 경고이며 `fail-on: ml-hit, incomplete`로 실패 조건에 추가할 수 있습니다. 입력이나 검증 오류도 실패합니다. 병합을 막으려면 저장소의 필수 검사로 지정합니다.

## 참고 문서

[네 진입점 시연](docs/demo.md) · [상세 사용법과 지원 범위](docs/usage.md) · [결과 필드와 연결 규약](docs/contracts.md) · [구조](docs/architecture.md) · [검증 기록](docs/validation.md)

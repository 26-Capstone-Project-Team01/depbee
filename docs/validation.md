# 검증 기록

## 2026-11-05: 시간 예산이 지난 뒤의 결과 거부(PR 전 교차 리뷰 02 M1 잔여)

- 아래 기록의 첫 구현은 `bounded.run()`이 남은 시간을 한 번만 계산해, 부모가 호출을 pickle로 만들거나 자식을 시작하는 동안 쓴 시간을 자식 대기 시간에 다시 반영하지 않았고 결과를 해석한 뒤에도 확인하지 않았다. 리뷰가 예산 0.4초에 이 단계마다 0.7초를 더해 약 0.85초 뒤의 정상 결과가 받아들여지고, 실제 `check_package`가 `passed`·종료 코드 0을 내는 것을 재현했다. 또 메타데이터를 해석한 뒤 캐시 hit이면 다음 자식 단계가 없어 그 뒤의 부모 작업이 예산을 넘겨도 확인할 곳이 없었다.
- 이제 `run()`은 시작할 때 정한 절대 deadline(예산 안이면 그 변경의 것, 예산 밖에서 부르면 그 호출의 것) 하나를 쓰고, 시작 전, pickle 뒤, 자식 대기 직전, 결과 해석 뒤에 다시 확인한다. 이미 지났으면 자식을 시작하지 않고, 시작한 자식은 종료한 뒤, 결과는 버리고 `TimeLimitError`를 낸다. 분석기는 완료 결과를 받아들이고 캐시에 저장하기 전에 같은 deadline을 확인한다(`bounded.check()`, 캐시 hit 포함). 이 확인은 그 변경에서 자식 단계가 하나라도 시작된 뒤에만 시계를 읽는다.
- 보장과 남는 한계: 자식 안의 작업(다운로드, 압축 해제, feature 추출)은 deadline에 종료된다. 부모가 직접 하는 동기 작업(pickle, 프로세스 시작, 결과 해석, 메타데이터 JSON 해석, 비교 기준·캐시·근거 처리)은 중간에 끊을 수 없어 그 작업 시간만큼 deadline을 넘길 수 있다. 다만 그렇게 늦게 끝난 결과는 받아들이지 않으므로 통과나 캐시 저장으로 바뀌지 않고 그 항목은 분석 실패(종료 코드 2)다. 추론과 보고서 작성은 예산에 들지 않는다.
- 테스트 143개 통과(skip 없음), `ruff check` 통과. 새 회귀 3개는 실제 자식 프로세스로 pickle, 프로세스 시작, 결과 해석 지연을 예산 안·밖에서 각각 넣어 오류와 자식 시작 여부·종료를 보고, 실제 `check_package`가 늦은 추출 결과를 `analysis_failed`·종료 코드 2로 끝내는지, 메타데이터 단계가 예산을 다 쓴 뒤의 캐시 hit이 거부되고 캐시 항목이 바뀌지 않는지 본다. 이 회귀만 수정 전 코드(`0b96311`)에 붙이면 실패 8개다(오류가 나지 않음 6개, 통과로 끝남 2개).

## 2026-11-05: 변경 하나의 전체 시간 예산과 작업 종료(PR 전 교차 리뷰 M1)

- 이전 구현(아래 "registry 다운로드" 기록)은 다운로드마다 120초를 따로 두고, 시간이 지나면 기다리던 쪽만 오류를 내고 작업 스레드와 연결은 그대로 두었다. 압축 해제와 feature 추출에는 시간 상한이 없었다. 교차 리뷰가 합성 재현으로 확인했다(시간 뒤에도 작업 스레드가 살아 있고, 가상 시계로 121초 걸린 압축 해제와 feature 추출도 통과).
- 이제 분석하는 변경 하나에 시간 예산 하나를 둔다. 메타데이터 다운로드, tarball 두 개 다운로드, 압축 해제, feature 추출이 그 예산을 함께 쓰고, 처음 단계가 시작될 때부터 잰다. `scan --extract`는 변경마다, `check`는 메타데이터 조회와 분석을 합쳐 하나다. 캐시 hit이면 메타데이터 조회만 예산을 쓴다. 이 단계들은 자식 Python 프로세스(`subprocess`, `python -I`)에서 실행하고, 예산이 끝나면 자식을 강제로 종료(Windows TerminateProcess, 그 밖 SIGKILL)한 뒤 끝난 것을 확인하고 나서 그 항목을 분석 실패(`incomplete`, 종료 코드 2)로 둔다. 그래서 자식이 하던 연결, 파일 쓰기, 계산이 함께 멈춘다. 압축을 푸는 폴더는 부모가 만들어 자식이 종료돼도 지운다. 다운로드마다 따로 두던 120초와 스레드 대기는 없앴다.
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
| 풀린 크기 | 512 MiB | pair archive의 버전 트리 2,334개(Git tree의 파일 크기 합)의 최대 261 MB(p99 84 MB)의 약 2배. 압축을 이 크기 넘게 풀지 않고, member가 선언한 크기의 합도 같은 상한으로 본다. |
| 파일 수 | 20,000 | 같은 표본의 최대 9,152개(p99 2,502개)의 약 2배 |
| 다운로드 하나의 벽시계 시간(이후 변경 하나의 예산 300초로 바뀜, 위 기록) | 120초 | 관측한 최대 tarball 28.8 MB를 1 MB/s에서 약 29초에 받는다. 128 MiB tarball은 약 1.1 MB/s 이상이어야 이 안에 받는다. 소켓 동작별 30초 제한은 feature-extractor와 같다. |

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

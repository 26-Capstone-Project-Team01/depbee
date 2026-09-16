# 개발 CI와 탐지 CI

## 현재 포함한 개발 CI

`.github/workflows/ci.yml`은 이 도구 자체의 Linux/Windows, Python 3.11/3.13 검사다.
lint·회귀 테스트·native LightGBM 합성 테스트·wheel/sdist 빌드를 수행한다.
실제 GitHub 원격 저장소와 push가 연결되기 전에는 서버에서 실행되지 않는다.
Action은 확인한 commit SHA로 고정했고 권한은 contents:read다.
의존성은 pyproject의 범위로 설치한다. 첫 환경 검증 후 팀 공통 lock/constraints를 도입한다.

## 이후 구축할 대상 프로젝트 탐지 CI

1. 신뢰한 릴리스의 탐지기와 모델을 준비한다.
2. PR의 기준·신규 lockfile만 읽기 전용으로 추출한다. 이때 대상 npm 설치를 하지 않는다.
3. `plan`으로 요청을 생성한다.
4. 보호된 분석기가 파일 무결성 검증·정적 분석 후 해당 request_id의 특징 JSON을 만든다.
5. `scan`을 실행한다. 반환 코드 1과 2는 후속 job을 진행시키지 않는다.
6. 코드 0일 때만 정확히 분석한 lockfile/아카이브를 사용하는 설치·빌드 단계로 넘긴다.

연결 후 사용할 명령 형태:

```sh
npm-update-guard plan target --base-lock baseline/package-lock.json --output artifacts/request.json
# 이 사이에 팀원 분석기 어댑터가 필요하다.
npm-update-guard scan target --base-lock baseline/package-lock.json --analysis artifacts/analysis.json --model-dir trusted-model --format json --output artifacts/report.json
```

이 문서는 설계이며 바로 설치·차단을 수행하는 완성 workflow가 아니다.
실제 analyzer와 모델 전달 후 required check와 `needs` 관계를 구성한다.

## CI 신뢰 경계

- PR이 수정할 수 있는 모델·특징 JSON을 판정 근거로 신뢰하지 않는다.
- 도구/정책/모델은 보호된 참조에서 로딩한다. 대상 package.json의 script를 실행하지 않는다.
- `pull_request_target`으로 외부 PR 코드를 실행하지 않는다. 토큰·secrets를 분석기에 넘기지 않는다.
- 모델 실패를 무시하는 `continue-on-error`, `|| true`를 보안 게이트에 사용하지 않는다.
- 수동 승인은 특정 버전·파일 해시·분석 요청에 묶는다. 패키지 영구 허용은 별도 논의한다.
- 신규 패키지·사설 레지스트리 등 미지원 항목은 현재 보류 대상이다. 전체 의존성 안전 보장을 주장하지 않는다.

참고: [GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use),
[npm lockfile 형식](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).

# 동봉 자산 출처

depbee는 모델과 색인을 각각의 manifest와 함께 배포합니다. 검사를 시작할 때 `depbee/bundled.py`에 고정한 SHA-256으로 네 파일의 무결성을 확인합니다.

## 기지 악성 색인 (`index/`)

OpenSSF Malicious Packages 프로젝트가 수집하고 OSV가 배포하는 npm `MAL-` 기록을 사용했습니다. 원본 기록에는 Apache License 2.0이 적용됩니다. [OpenSSF 저장소](https://github.com/ossf/malicious-packages) · [OSV 데이터 출처](https://google.github.io/osv.dev/data/) · [동봉한 라이선스 전문](LICENSE-Apache-2.0.txt)

색인의 기준 시점은 OSV npm 스냅샷 `all.zip`을 받은 `2026-10-06T14:00:47Z`입니다. 스냅샷의 SHA-256은 `f7eb5cecff3d3e7d54da6ac69e109058bcf1c3c56679486efd330212503ee5fb`입니다.

`depbee.known_malicious.build_index`로 기록의 식별자, 패키지 이름, 버전, 영향 범위를 depbee 조회 형식으로 변환했습니다. 철회된 기록과 대조에 쓸 수 없는 항목은 제외했습니다.

## ML 모델 (`model/`)

depbee 팀이 학습한 D04-E00을 LightGBM 텍스트 형식으로 배포합니다. `manifest.json`에는 학습에 사용한 29개 특징의 순서와 학습 시 기본 판정 기준 점수 0.5가 기록되어 있습니다. 출력은 업데이트 검토를 위한 ML 위험 점수입니다.

## 대시보드 글꼴 (`dashboard/static/fonts/`)

로컬 대시보드는 글꼴을 외부에서 받지 않고 두 글꼴의 일부만 담은 파일을 함께 배포합니다. 본문과 프로젝트 이름은 Noto Sans KR, 패키지 이름·버전·경로·점수는 JetBrains Mono입니다. 둘 다 SIL Open Font License 1.1이 적용되며 라이선스 전문은 글꼴 옆의 `OFL-NotoSansKR.txt`, `OFL-JetBrainsMono.txt`에 있습니다.

원본은 google/fonts 저장소 커밋 `06bfe0d62a98375cb09c942fa18e68bd32cff057`의 가변 글꼴 `ofl/notosanskr/NotoSansKR[wght].ttf`(SHA-256 `194018e6b2b293a7964f037b25c0249ce1418bc9ab3c971060a03aa57861e252`)와 `ofl/jetbrainsmono/JetBrainsMono[wght].ttf`(SHA-256 `48715a42ec242c21e9f02692891e147d022299a52e48d5e413e1a942193ffeda`)입니다. `scripts/build_dashboard_fonts.py`로 KS X 1001 한글 2,350자, 라틴 문자, 화면에 쓰는 기호, depbee의 모든 화면 문구에 쓰인 글자만 남겼습니다. 남긴 글자 목록은 `coverage.txt`에 있습니다.

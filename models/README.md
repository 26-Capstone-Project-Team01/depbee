# 모델 보관

팀원이 전달한 후보 모델은 `models/<model-id>/model.txt`와 `manifest.json`으로 로컬에 보관한다. 이 폴더는 Git에서 제외된다.

설치본의 기본 모델은 [src/depbee/assets/model](../src/depbee/assets/model)에 있다. wheel에는 이 모델과 manifest가 함께 들어간다. 모델 교체와 검사에 쓰인 버전 확인 방법은 [사용 안내](../docs/usage.md#기본-자산)에 있다.

전달 규약: [docs/contracts.md](../docs/contracts.md).
확장자는 팀 합의에 따라 바꿀 수 있지만 현재 어댑터는 LightGBM의 native text 모델을 읽는다.
피클·joblib 객체를 읽지 않는다. 모델 해시는 무결성 확인이며 발행자 인증을 대신하지 않는다.

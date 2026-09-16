# 모델 보관

팀원이 전달한 신뢰할 수 있는 모델을 `models/<model-id>/model.txt`와
`manifest.json`으로 보관한다. 실제 모델은 Git에서 제외된다.

전달 규약: [docs/contracts.md](../docs/contracts.md).
확장자는 팀 합의에 따라 바꿀 수 있지만 현재 어댑터는 LightGBM의 native text 모델을 읽는다.
피클·joblib 객체를 읽지 않는다. 모델 해시는 무결성 확인이며 발행자 인증을 대신하지 않는다.

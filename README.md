# mobile-sec-check

KCP Wallet용 모바일 보안점검 smoke checker.

## 범위

1. `ios`: IPA 정적 점검
2. `aos`: APK/AAB 기본 구조 점검
3. `rn`: React Native bundle/AppGuard 흔적 점검

## 실행

Flutter macOS 앱:

```bash
open app_flutter/build/macos/Build/Products/Release/KCPMobileSecCheck.app
```

로컬 웹 UI:

```bash
python3 mobile_sec_check_app.py
```

브라우저가 열리면 점검할 파일의 전체 경로를 입력한다.

CLI:

```bash
python3 mobile_sec_check.py scan /Users/user/src/StableCoinFE_Wallet/apps/mobile/build/ios/KCPWallet-appguard.ipa --out /tmp/mobile-sec-check
```

결과:

```txt
/tmp/mobile-sec-check/report.json
/tmp/mobile-sec-check/report.html
```

## 기준표

```txt
rules/checklist.yaml
```

공식 기준 전체를 복제하지 않고, 우리 앱 점검에 필요한 모바일 항목과 probe 매핑만 둔다.

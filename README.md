# samizdat-ios

iOS client for the Samizdat protocol (lantern-box ecosystem).

Currently: a minimal SwiftUI "Hello World" app used to validate the full
build+sign+sideload pipeline on GitHub Actions (no local Mac required).

## Build locally (requires Mac + Xcode)

```sh
brew install xcodegen
xcodegen generate
open samizdat-ios.xcodeproj
```

## Build on GitHub Actions

Push to `main` or trigger the `Build IPA` workflow manually.
The `.ipa` appears as a workflow artifact.

## Bundle / signing

- Team ID: `DRMTP6V372`
- Bundle ID: `com.anarki.samizdat-test`
- Signing: manual, Ad Hoc distribution, profile `Samizdat Test AdHoc`

Secrets required on the repo (Settings → Secrets → Actions):

| Name | Value |
|---|---|
| `BUILD_CERTIFICATE_BASE64` | base64 of `.p12` |
| `P12_PASSWORD` | password for the `.p12` |
| `BUILD_PROVISION_PROFILE_BASE64` | base64 of `.mobileprovision` |
| `KEYCHAIN_PASSWORD` | any random string (temp keychain password) |

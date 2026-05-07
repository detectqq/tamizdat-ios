# tamizdat-ios

iOS client for the tamizdat proxy protocol.

```
┌─────────────────────────────────────┐
│ App (SwiftUI)                       │
│  ├─ ContentView   status + button   │
│  ├─ ConfigPaste   modal             │
│  ├─ LogView       modal             │
│  └─ tamizdatBridge → Go shim ───────┼──► tamizdatClient.xcframework
│                                     │      (gomobile bind ./mobile/tamizdat)
│ tamizdat-tunnel (extension, stub)   │
│  └─ PacketTunnelProvider            │
└─────────────────────────────────────┘
```

## Status

**Iteration 1 (current).** End-to-end pipeline (Go → gomobile → xcframework
→ Xcode → IPA → Sideloadly → iPhone) is wired up. The Go shim parses real
`tamizdat://` config blobs but `Connect()` is a simulation — no real
network tunnel yet. Lets us validate UI + signing + extension target
without the integration risk of the real tamizdat client.

**Iteration 2 (next).** Replace the simulation with `tamizdat.NewClient`
inside the PacketTunnelProvider extension, plus a tun2socks layer so all
device traffic flows through the tunnel.

## Layout

```
mobile/                          # Go module — gomobile-friendly shim
  go.mod
  tamizdat/
    tamizdat.go                  # API: Connect, Disconnect, Status, Logs, …
    tamizdat_test.go

tamizdat-ios/                    # main app target (SwiftUI)
  App.swift
  ContentView.swift
  ConfigPasteView.swift
  LogView.swift
  ConfigStore.swift              # Keychain-backed config persistence
  tamizdatBridge.swift           # Swift wrapper around the Go shim
  Info.plist
  tamizdat-ios.entitlements      # Network Extensions + App Group
  Assets.xcassets/

tamizdat-tunnel/                 # extension target (PacketTunnelProvider)
  PacketTunnelProvider.swift     # iter1 stub
  Info.plist
  tamizdat-tunnel.entitlements

project.yml                      # XcodeGen config — generates .xcodeproj
ExportOptions.plist              # Ad-hoc export, both bundle IDs
.github/workflows/build.yml      # CI: Go bind + Xcode archive + upload IPA
```

## Building

Local Mac (optional):

```sh
brew install xcodegen go
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
( cd mobile && gomobile bind -target=ios -o ../Frameworks/tamizdatClient.xcframework ./tamizdat )
xcodegen generate
open tamizdat-ios.xcodeproj
```

Without a Mac (the actual deployment path):

```
git push                  → GitHub Actions builds → IPA artifact
download artifact         → Sideloadly → iPhone
```

## Bundle / signing

| Item | Value |
|---|---|
| Team ID | `DRMTP6V372` |
| App bundle ID | `com.anarki.tamizdat-test` |
| Tunnel bundle ID | `com.anarki.tamizdat-test.tunnel` |
| App Group | `group.com.anarki.tamizdat-test` |
| App profile | `tamizdat Test AdHoc` (Ad Hoc) |
| Tunnel profile | `tamizdat Tunnel AdHoc` (Ad Hoc) |
| Cert | Apple Distribution (1-year validity) |

## Required GitHub Secrets

| Name | Contents |
|---|---|
| `BUILD_CERTIFICATE_BASE64` | base64 of the `.p12` |
| `P12_PASSWORD` | password protecting the `.p12` |
| `BUILD_PROVISION_PROFILE_BASE64` | base64 of `tamizdat Test AdHoc.mobileprovision` |
| `BUILD_TUNNEL_PROVISION_PROFILE_BASE64` | base64 of `tamizdat Tunnel AdHoc.mobileprovision` |
| `KEYCHAIN_PASSWORD` | any random string (temp keychain unlock) |

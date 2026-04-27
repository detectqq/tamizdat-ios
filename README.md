# samizdat-ios

iOS client for the Samizdat proxy protocol.

```
┌─────────────────────────────────────┐
│ App (SwiftUI)                       │
│  ├─ ContentView   status + button   │
│  ├─ ConfigPaste   modal             │
│  ├─ LogView       modal             │
│  └─ SamizdatBridge → Go shim ───────┼──► SamizdatClient.xcframework
│                                     │      (gomobile bind ./mobile/samizdat)
│ samizdat-tunnel (extension, stub)   │
│  └─ PacketTunnelProvider            │
└─────────────────────────────────────┘
```

## Status

**Iteration 1 (current).** End-to-end pipeline (Go → gomobile → xcframework
→ Xcode → IPA → Sideloadly → iPhone) is wired up. The Go shim parses real
`samizdat://` config blobs but `Connect()` is a simulation — no real
network tunnel yet. Lets us validate UI + signing + extension target
without the integration risk of the real samizdat client.

**Iteration 2 (next).** Replace the simulation with `samizdat.NewClient`
inside the PacketTunnelProvider extension, plus a tun2socks layer so all
device traffic flows through the tunnel.

## Layout

```
mobile/                          # Go module — gomobile-friendly shim
  go.mod
  samizdat/
    samizdat.go                  # API: Connect, Disconnect, Status, Logs, …
    samizdat_test.go

samizdat-ios/                    # main app target (SwiftUI)
  App.swift
  ContentView.swift
  ConfigPasteView.swift
  LogView.swift
  ConfigStore.swift              # Keychain-backed config persistence
  SamizdatBridge.swift           # Swift wrapper around the Go shim
  Info.plist
  samizdat-ios.entitlements      # Network Extensions + App Group
  Assets.xcassets/

samizdat-tunnel/                 # extension target (PacketTunnelProvider)
  PacketTunnelProvider.swift     # iter1 stub
  Info.plist
  samizdat-tunnel.entitlements

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
( cd mobile && gomobile bind -target=ios -o ../Frameworks/SamizdatClient.xcframework ./samizdat )
xcodegen generate
open samizdat-ios.xcodeproj
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
| App bundle ID | `com.anarki.samizdat-test` |
| Tunnel bundle ID | `com.anarki.samizdat-test.tunnel` |
| App Group | `group.com.anarki.samizdat-test` |
| App profile | `Samizdat Test AdHoc` (Ad Hoc) |
| Tunnel profile | `Samizdat Tunnel AdHoc` (Ad Hoc) |
| Cert | Apple Distribution (1-year validity) |

## Required GitHub Secrets

| Name | Contents |
|---|---|
| `BUILD_CERTIFICATE_BASE64` | base64 of the `.p12` |
| `P12_PASSWORD` | password protecting the `.p12` |
| `BUILD_PROVISION_PROFILE_BASE64` | base64 of `Samizdat Test AdHoc.mobileprovision` |
| `BUILD_TUNNEL_PROVISION_PROFILE_BASE64` | base64 of `Samizdat Tunnel AdHoc.mobileprovision` |
| `KEYCHAIN_PASSWORD` | any random string (temp keychain unlock) |

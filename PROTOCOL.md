# Samizdat iOS build/debug protocol

Date: 2026-04-27

## Goal

Build an iOS VPN client without a local Mac, using GitHub Actions, Apple paid developer signing, and Sideloadly.

The app should create a real iOS `PacketTunnelProvider` VPN, route device traffic into the tunnel, and forward TCP/UDP via the Samizdat Go client.

## Repo

Main repo:

`C:\Users\Anarki\projects\samizdat-ios`

Useful external context:

`C:\Users\Anarki\Desktop\samizdat-ios`
`C:\Users\Anarki\Desktop\samizdat-client\samizdat-lib`

## Current config string

User config in app:

```text
samizdat://llm2.detectqq.dpdns.org:8443/?sni=ok.ru&pubkey=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&shortid=d1b122782219759f&fp=chrome
```

This format is valid for the current parser.

## Important build artifacts

Last successful IPA with fake-DNS protection:

`C:\Users\Anarki\projects\samizdat-ios\ipa\run-25009686642\samizdat-ios.ipa`

GitHub Actions run:

`https://github.com/detectqq/samizdat-ios/actions/runs/25009686642`

Earlier successful real PacketTunnel build:

`C:\Users\Anarki\projects\samizdat-ios\ipa\run-25009210922\samizdat-ios.ipa`

## Problems found and fixes applied

### 1. `gomobile bind` failed: missing `golang.org/x/mobile/bind`

Symptom:

```text
unable to import bind: no Go package in golang.org/x/mobile/bind
unable to import bind/objc: no Go package in golang.org/x/mobile/bind/objc
```

Fix:

- Added `mobile/tools.go` with tool-only imports.
- Added/pinned `golang.org/x/mobile` in `mobile/go.mod`.
- Updated `.github/workflows/build.yml` so Actions installs `gomobile`/`gobind` from the pinned `x/mobile` version instead of floating `@latest`.

### 2. Swift gomobile API mismatch

Symptom:

Swift expected optional strings from gomobile functions, but generated API returned non-optional `String`.

Fix:

- Updated `samizdat-ios/SamizdatBridge.swift` to stop using `??` and optional chaining for gomobile string functions.

### 3. IPA export succeeded but inspect step failed

Symptom:

IPA was created, but CI failed while inspecting embedded provisioning profiles through `/dev/stdin`.

Fix:

- Reworked `.github/workflows/build.yml` inspect step to decode profiles into real temporary plist files before reading them with `PlistBuddy`.

### 4. App did not request VPN profile

Cause:

Having a `PacketTunnelProvider` extension inside the IPA is not enough. iOS shows the VPN prompt only after `NETunnelProviderManager.saveToPreferences()`.

Fix:

- Added `samizdat-ios/VPNProfileStore.swift`.
- App now creates/saves a `NETunnelProviderManager`.
- App calls `NETunnelProviderSession.startVPNTunnel()` on Connect.

### 5. Initial extension was only a stub

Cause:

The first PacketTunnelProvider only returned an error and did not route packets.

Fix:

- Replaced stub with a real `PacketTunnelProvider`.
- Added `NEPacketTunnelNetworkSettings`.
- Added IPv4 default route and later IPv6 default route.
- Wired `packetFlow.readPackets` / `packetFlow.writePackets`.

### 6. Real Samizdat core was not in the iOS framework

Fix:

- Copied core Go client files from:

`C:\Users\Anarki\Desktop\samizdat-client\samizdat-lib`

into:

`mobile/internal/samizdatcore`

- Added real `TunnelStart`, `TunnelInjectPacket`, `TunnelReadPacket`, and `TunnelStop` gomobile API.
- Added gVisor netstack to convert IP packets into TCP/UDP connections.
- Pinned gVisor to `v0.0.0-20260325202830-7644cf3a343c` because newer gVisor module had package layout issues on local test.

### 7. Logs were empty

Cause:

The main app read logs from its own process memory, while the real VPN engine runs in the extension process.

Fix:

- Added `NETunnelProviderSession.sendProviderMessage` from app to extension.
- Extension now returns its Go log buffer to the app.
- Logs screen now shows extension logs.

### 8. Extension hung after `PacketTunnelProvider startTunnel`

Observed log:

```text
info: PacketTunnelProvider startTunnel
```

and nothing else.

Cause:

Extension did synchronous `getaddrinfo()` during `startTunnel`, which could block before completion handler.

Fix:

- Moved server DNS resolution to the main app before starting the VPN.
- Added timeout around DNS resolution.
- Extension no longer calls synchronous DNS before applying tunnel settings.

### 9. `Invalid NETunnelNetworkSettings tunnelRemoteAddress`

Observed log:

```text
error: setTunnelNetworkSettings: Invalid NETunnelNetworkSettings tunnelRemoteAddress
```

Cause:

`NEPacketTunnelNetworkSettings(tunnelRemoteAddress:)` was given an invalid/non-IP value.

Fix:

- Use pre-resolved server IPv4 as `tunnelRemoteAddress`.
- Fallback to `127.0.0.1` only to keep settings syntactically valid.

### 10. Fake DNS result broke bootstrap

Observed log:

```text
packet tunnel active via 198.18.0.12:8444
TCP dial to 198.18.0.12:8444: i/o timeout
```

Cause:

`198.18.0.0/15` is a reserved/fake-IP range. Some DNS/proxy layer returned a fake address, and the app used it as the Samizdat server.

Fix:

- Reject `198.18.*` and `198.19.*` bootstrap DNS results.
- Added DoH fallback via `https://1.1.1.1/dns-query`.
- Go parser now supports `connect_host` and `connect_port` query fields, so the original `samizdat://host:8443` URL is kept intact while the actual TCP dial endpoint can be explicit.

## Current state

The VPN now starts and routes packets into the Go/gVisor stack.

Recent observed logs:

```text
info: preparing VPN profile
info: resolved server IPv4 before VPN start
info: starting NETunnelProviderSession
info: PacketTunnelProvider startTunnel
info: using pre-resolved server IPv4
info: applying packet tunnel network settings
info: packet tunnel active ...
info: packet tunnel started
```

This means:

- iOS VPN profile starts.
- PacketTunnelProvider starts.
- Network settings are accepted.
- iOS traffic reaches the extension.
- DNS packets reach the Go/gVisor stack.
- Samizdat TLS/H2 transport reaches the server enough to receive HTTP status responses.

## Current blocker

Observed latest error:

```text
DNS TCP dial 1.1.1.1:53: opening tunnel to 1.1.1.1:53: CONNECT to 1.1.1.1:53 returned status 421
DNS TCP dial 8.8.8.8:53: opening tunnel to 8.8.8.8:53: CONNECT to 8.8.8.8:53 returned status 421
```

Meaning:

- The iOS VPN path is no longer the blocker.
- The client successfully reaches the Samizdat HTTP/2 server.
- The Samizdat server rejects CONNECT requests with HTTP `421`.

Likely area to inspect next:

- `mobile/internal/samizdatcore/h2transport.go`
- source server/client implementation in `C:\Users\Anarki\Desktop\samizdat-client\samizdat-lib`
- server-side Samizdat logs on `llm2`

Likely hypotheses:

1. HTTP/2 CONNECT request is malformed for the server's expected format.
2. `Host` / `:authority` / request URL handling in `h2transport.openTunnel` is incompatible with current server.
3. Server rejects DNS destinations like `1.1.1.1:53` specifically.
4. iOS build's copied Samizdat core differs from the server version.
5. Server route expects a specific CONNECT authority/path/header not currently sent by the gomobile client.

## Files most relevant for next debugging

App / profile / logs:

- `samizdat-ios/SamizdatBridge.swift`
- `samizdat-ios/VPNProfileStore.swift`
- `samizdat-ios/ContentView.swift`

Extension:

- `samizdat-tunnel/PacketTunnelProvider.swift`

Go VPN/gVisor bridge:

- `mobile/samizdat/samizdat.go`

Samizdat core copied into iOS module:

- `mobile/internal/samizdatcore/client.go`
- `mobile/internal/samizdatcore/h2transport.go`
- `mobile/internal/samizdatcore/auth.go`
- `mobile/internal/samizdatcore/samizdat.go`

CI/signing:

- `.github/workflows/build.yml`
- `project.yml`
- `ExportOptions.plist`

## Operational advice

Before testing a new IPA:

1. Delete old VPN profile in iOS Settings -> VPN if behavior looks stale.
2. Install newest IPA via Sideloadly.
3. Open app.
4. Confirm config is saved.
5. Tap Connect.
6. Open Logs and copy all lines from the first `preparing VPN profile` through first error.

For the next session, start from the `421` blocker, not from iOS profile/signing. The iOS tunnel now starts; the next useful work is protocol compatibility with the server.

module github.com/anarki/samizdat-ios/mobile

go 1.25.5

// Vendored copy of the tamizdat client/server module (renamed from
// samizdat 2026-05-01, github.com/detectqq/tamizdat). Replace points
// at ./upstream-tamizdat so we always stay in sync with what the
// production server actually serves.
replace github.com/detectqq/tamizdat => ./upstream-tamizdat

// iOS-vendor patch of golang.org/x/net to shrink the http2 client's
// transportDefaultConnFlow (1 GiB → 4 MiB) and transportDefaultStreamFlow
// (4 MiB → 256 KiB). Without this, every CONNECT stream advertises a
// 4 MiB receive window — under Speedtest fanout (~64 parallel streams)
// the server can push up to 256 MiB at us before WINDOW_UPDATE, blowing
// past the iOS NEPacketTunnelProvider 50 MB RSS cap. See
// vendor-x-net/http2/transport.go for the patched constants.
replace golang.org/x/net => ./vendor-x-net

require (
	github.com/detectqq/tamizdat v0.0.0-00010101000000-000000000000
	github.com/sagernet/sing v0.8.9
	golang.org/x/mobile v0.0.0-20260410095206-2cfb76559b7b
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	gvisor.dev/gvisor v0.0.0-20260325202830-7644cf3a343c
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cbeuw/connutil v1.0.1 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/pion/dtls/v3 v3.1.2 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/stun/v3 v3.1.2 // indirect
	github.com/pion/transport/v4 v4.0.1 // indirect
	github.com/pion/turn/v5 v5.0.4 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

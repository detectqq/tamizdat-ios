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

// Phase C: sing-tun pulls in gvisor via the sagernet/gvisor fork
// (a separate module path). Some upstream deps still pull in the
// canonical gvisor.dev/gvisor. Both module paths can coexist —
// they're different Go modules.

require (
	github.com/detectqq/tamizdat v0.0.0-00010101000000-000000000000
	github.com/sagernet/sing v0.8.9
	github.com/sagernet/sing-tun v0.8.9
	golang.org/x/mobile v0.0.0-20260410095206-2cfb76559b7b
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/florianl/go-nfqueue/v2 v2.0.2 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/mdlayher/netlink v1.9.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/sagernet/fswatch v0.1.1 // indirect
	github.com/sagernet/gvisor v0.0.0-20250811.0-sing-box-mod.1 // indirect
	github.com/sagernet/netlink v0.0.0-20240612041022-b9a21c07ac6a // indirect
	github.com/sagernet/nftables v0.3.0-mod.2 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/exp v0.0.0-20240613232115-7f521ea00fb8 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
)

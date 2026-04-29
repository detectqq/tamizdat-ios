module github.com/getlantern/samizdat

go 1.24.0

toolchain go1.24.1

// Mirror the parent mobile/ module's vendor patch for golang.org/x/net.
// See ../go.mod for rationale.
replace golang.org/x/net => ../vendor-x-net

require (
	github.com/refraction-networking/utls v1.8.2
	github.com/xjasonlyu/tun2socks/v2 v2.6.0
	golang.org/x/crypto v0.45.0
	golang.org/x/net v0.47.0
	golang.org/x/sys v0.38.0
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/go-gost/relay v0.5.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb // indirect
	gvisor.dev/gvisor v0.0.0-20250523182742-eede7a881b20 // indirect
)

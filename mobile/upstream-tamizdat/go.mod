module github.com/detectqq/tamizdat

go 1.25.0

toolchain go1.25.1

// Mirror the parent mobile/ module's vendor patch for golang.org/x/net.
// See ../go.mod for rationale.
replace golang.org/x/net => ../vendor-x-net

require (
	github.com/cbeuw/connutil v1.0.1
	github.com/pion/dtls/v3 v3.1.2
	github.com/pion/logging v0.2.4
	github.com/pion/turn/v5 v5.0.4
	github.com/refraction-networking/utls v1.8.2
	github.com/xjasonlyu/tun2socks/v2 v2.6.0
	golang.org/x/crypto v0.50.0
	golang.org/x/net v0.52.0
	golang.org/x/sys v0.43.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/go-gost/relay v0.5.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/stun/v3 v3.1.2 // indirect
	github.com/pion/transport/v4 v4.0.1 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250523182742-eede7a881b20 // indirect
)

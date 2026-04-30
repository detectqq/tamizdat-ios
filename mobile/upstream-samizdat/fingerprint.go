package samizdat

import (
	utls "github.com/refraction-networking/utls"
)

// fingerprintRotator randomises the uTLS ClientHelloID across new TCP
// connections so a passive observer does not see the exact same TLS
// fingerprint on every connection from a client host. This implements
// P1.3 of the Samizdat audit roadmap.
//
// When mode=="chrome" / "firefox" / "safari" / "edge" / "ios" the rotator
// pins that browser family but varies specific versions. When mode=="mix"
// (or empty) the rotator picks across the whole weighted pool.
type fingerprintRotator struct {
	pool []utls.ClientHelloID
}

func newFingerprintRotator(mode string) *fingerprintRotator {
	var pool []utls.ClientHelloID
	switch mode {
	case "", "mix", "auto", "rotate":
		// IPA-L: only current fingerprints. ANY 2022-era preset
		// (Chrome 100/106, Safari 16, Edge 106) gets DPI-flagged as
		// "stale browser" on Russian mobile carriers and the handshake
		// is dropped. The 0xFE0C extension fix removed our biggest DPI
		// signal but Chrome 100 in 2026 is still a strong "stale browser"
		// signature; keeping pool aggressively current.
		pool = []utls.ClientHelloID{
			utls.HelloChrome_Auto, // Chrome 133, ML-KEM-768 in supported_groups
			utls.HelloChrome_131,
			utls.HelloChrome_120_PQ,
			utls.HelloChrome_120,
			utls.HelloFirefox_120,
		}
	case "firefox":
		pool = []utls.ClientHelloID{utls.HelloFirefox_120}
	case "safari":
		pool = []utls.ClientHelloID{
			utls.HelloChrome_Auto, // primary
			utls.HelloSafari_16_0, // single 2022 preset, weighted via Chrome_Auto above
		}
	case "edge":
		pool = []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloEdge_106}
	case "ios":
		pool = []utls.ClientHelloID{utls.HelloChrome_Auto}
	default: // "chrome" and any unrecognised value: default to modern Chrome only
		// IPA-L: dropped HelloChrome_100/106_Shuffle/115_PQ from the
		// default chrome case. Most existing samizdat:// URLs carry
		// fp=chrome literal and would otherwise hit 2022-era presets.
		pool = []utls.ClientHelloID{
			utls.HelloChrome_Auto,
			utls.HelloChrome_131,
			utls.HelloChrome_120_PQ,
			utls.HelloChrome_120,
		}
	}
	return &fingerprintRotator{pool: pool}
}

// pick returns a fingerprint for the next new TCP connection.
func (r *fingerprintRotator) pick() utls.ClientHelloID {
	if r == nil || len(r.pool) == 0 {
		return utls.HelloChrome_Auto
	}
	idx := randomInt(0, len(r.pool))
	if idx >= len(r.pool) {
		idx = len(r.pool) - 1
	}
	return r.pool[idx]
}

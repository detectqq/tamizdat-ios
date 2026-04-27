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
		// Weighted (by internet share): more Chrome than Safari etc.
		pool = []utls.ClientHelloID{
			utls.HelloChrome_120,
			utls.HelloChrome_115_PQ,
			utls.HelloChrome_106_Shuffle,
			utls.HelloChrome_100,
			utls.HelloFirefox_120,
			utls.HelloFirefox_105,
			utls.HelloSafari_16_0,
			utls.HelloIOS_14,
			utls.HelloEdge_106,
		}
	case "firefox":
		pool = []utls.ClientHelloID{
			utls.HelloFirefox_120, utls.HelloFirefox_105, utls.HelloFirefox_102,
		}
	case "safari":
		pool = []utls.ClientHelloID{
			utls.HelloSafari_16_0, utls.HelloIOS_14, utls.HelloIOS_13,
		}
	case "edge":
		pool = []utls.ClientHelloID{utls.HelloEdge_106, utls.HelloEdge_85}
	case "ios":
		pool = []utls.ClientHelloID{utls.HelloIOS_14, utls.HelloIOS_13, utls.HelloIOS_12_1}
	default: // "chrome" and any unrecognised value: default to Chrome family
		pool = []utls.ClientHelloID{
			utls.HelloChrome_120, utls.HelloChrome_115_PQ,
			utls.HelloChrome_106_Shuffle, utls.HelloChrome_100,
			utls.HelloChrome_Auto,
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

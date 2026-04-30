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
		// IPA-K: only current fingerprints. ANY 2022-era preset
		// (Chrome 100/106, Safari 16, Edge 106) gets DPI-flagged as
		// "stale browser" on Russian mobile carriers and the handshake
		// is dropped. We don't have a use case for backward-compat with
		// old browser identities -- the actual iOS device running this
		// is on iOS 17+ with Safari that auto-updates; pretending to be
		// 3-year-old browsers is net negative.
		pool = []utls.ClientHelloID{
			utls.HelloChrome_Auto, // Chrome 133, ML-KEM-768 in supported_groups
			utls.HelloChrome_131,
			utls.HelloChrome_120_PQ,
			utls.HelloChrome_120,
			utls.HelloFirefox_120,
		}
	case "firefox":
		// Firefox_120 is the most recent uTLS preset (Dec 2023). Older
		// Firefox 102/105 dropped -- 2022-era fingerprints get flagged.
		pool = []utls.ClientHelloID{utls.HelloFirefox_120}
	case "safari":
		// Safari 16 (Sept 2022) is the freshest Safari preset uTLS has;
		// pair it with Chrome_Auto so we don't pin a single stale ID.
		// iOS 13/14 (2019/2020!) explicitly dropped -- those would be
		// reading as a 6-year-old iPhone, instant DPI flag.
		pool = []utls.ClientHelloID{
			utls.HelloChrome_Auto, // primary
			utls.HelloSafari_16_0, // single 2022 preset, weighted via duplicate Chrome_Auto above
		}
	case "edge":
		// Same problem as safari: only stale Edge presets exist in uTLS.
		// Mix Chrome_Auto in heavily.
		pool = []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloEdge_106}
	case "ios":
		// uTLS only has iOS 12/13/14 -- all 5+ years old. Use Chrome_Auto
		// instead; on iOS the actual Safari TLS stack matches Chrome more
		// closely than these stale presets do anyway.
		pool = []utls.ClientHelloID{utls.HelloChrome_Auto}
	default: // "chrome" and any unrecognised value: default to Chrome family
		// IPA-K: same modernisation as the mix pool above -- the previous
		// pool included Chrome 100 (April 2022) and Chrome 106 (September
		// 2022) which Russian mobile DPI flags. Most existing samizdat://
		// URLs carry fp=chrome literal, so this case MUST stay current.
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

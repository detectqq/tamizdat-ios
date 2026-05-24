package wgturnclient

// Credentials holds the TURN parameters that the iOS app obtains
// out-of-band (via WKWebView captcha solver + 5-step VK API call done
// in Swift) and feeds in via Config.PreloadedCreds. On iOS we never
// solve VK captcha in Go — that lives in CaptchaWebViewManager.swift
// and runs in the main app process, so this file is intentionally
// the bare minimum: no fhttp / tls-client / RJS captcha code that
// would pull conflicting deps into the gomobile bundle.
//
// TurnURLs is the legacy "host:port" list (scheme + transport already
// stripped on the Swift side) kept for callers that only need a dial
// target. TurnServers, if non-empty, is the authoritative source —
// it carries scheme (turn|turns) + transport (udp|tcp) so the
// dispatcher can pick the right wire protocol. When TurnServers is
// empty (legacy / pre-v2 wire format) callers fall back to TurnURLs
// + the runner-wide UseUDP/UseTCP knob.
type Credentials struct {
	User        string
	Pass        string
	TurnURLs    []string
	TurnServers []TurnServer
	Lifetime    int
}

// TurnServer carries one TURN URL split into its components so the
// dispatcher can honour VK's per-URL transport preference. Wire
// format mirrors the Swift `turn_servers_v2` JSON shape (lowercase
// JSON keys via the gomobile-safe Go struct tags in
// mobile/socksstub/vkturn.go::parseVKTurnCredsJSON).
type TurnServer struct {
	Host      string
	Port      int
	Scheme    string // "turn" | "turns"
	Transport string // "udp" | "tcp"
}

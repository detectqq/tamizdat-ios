package wgturnclient

// Credentials holds the TURN parameters that the iOS app obtains
// out-of-band (via WKWebView captcha solver + 5-step VK API call done
// in Swift) and feeds in via Config.PreloadedCreds. On iOS we never
// solve VK captcha in Go — that lives in CaptchaWebViewManager.swift
// and runs in the main app process, so this file is intentionally
// the bare minimum: no fhttp / tls-client / RJS captcha code that
// would pull conflicting deps into the gomobile bundle.
type Credentials struct {
	User     string
	Pass     string
	TurnURLs []string
	Lifetime int
}

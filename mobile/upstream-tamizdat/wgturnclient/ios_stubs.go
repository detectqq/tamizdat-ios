package wgturnclient

import (
	"context"
	"fmt"
)

// iOS-only stubs for runner methods that used to live in creds.go and
// slider_captcha.go. Those files were removed from this vendored copy
// because they pull in bogdanfinn/tls-client + fhttp, which conflict
// with the iOS app's patched golang.org/x/net (see ../vendor-x-net).
//
// On iOS, captcha solving + the 5-step VK API exchange happen in Swift
// (CaptchaWebViewManager + VKCredsClient + TURNCredsRefresher), so the
// runner here MUST be invoked with Config.PreloadedCreds set — the
// only path that needs these stubs is the cycle's GetCredsWithFallback
// call, which simply returns the preloaded creds.

func (r *Runner) getCaptchaMode() string {
	if s, ok := r.captchaMode.Load().(string); ok && s != "" {
		return s
	}
	return "wv"
}

// getCredsWithFallback returns the preloaded credentials. iOS callers
// must set Config.PreloadedCreds before calling Start; the VK API
// solver is not compiled into this build.
func (r *Runner) getCredsWithFallback(ctx context.Context, tp *TurnParams, hash string, stats *Stats) (*Credentials, error) {
	if pc := r.preloadedCreds.Load(); pc != nil {
		dup := *pc
		return &dup, nil
	}
	return nil, fmt.Errorf("wgturnclient (iOS build): PreloadedCreds is required — VK API solver is not compiled in")
}

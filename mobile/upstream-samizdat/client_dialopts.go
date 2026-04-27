package samizdat

import (
	"context"
	"expvar"
)

var clientForcedPrewarmGateBypassed = expvar.NewInt("samizdat.bbcr.client.forced_prewarm_gate_bypassed")

type forcedPrewarmCtxKey struct{}

func ctxWithForcedPrewarm(ctx context.Context) context.Context {
	return context.WithValue(ctx, forcedPrewarmCtxKey{}, true)
}

func ctxIsForcedPrewarm(ctx context.Context) bool {
	v, ok := ctx.Value(forcedPrewarmCtxKey{}).(bool)
	return ok && v
}

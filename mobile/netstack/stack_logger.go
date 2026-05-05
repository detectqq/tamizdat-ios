//go:build netstack_real

package netstack

import (
	"context"
	"fmt"

	"github.com/sagernet/sing/common/logger"
)

// stackLogger satisfies sing/common/logger.ContextLogger so we can pass
// it as StackOptions.Logger. Routes everything through samizdat.AddLog
// (App Group log file) at info-or-warn level depending on severity.
//
// Why not logger.NOP(): IPA-B2 used NOP and lost the load-bearing
// "bind forwarder to interface: <err>" warning at stack_system.go:117-128
// that would have surfaced the missing ForwarderBindInterface +
// InterfaceFinder fields. Routing sing-tun's own warnings to our log
// sink is the difference between "TCP doesn't open" mystery and "TCP
// doesn't open because BindToInterface0 returned <err>".
//
// Performance: log lines from sing-tun are infrequent (mostly stack
// init + per-flow errors), so calling rtLog (which acquires a small
// mutex inside samizdat.appendLog) per emission is fine.
type stackLogger struct{}

var _ logger.ContextLogger = (*stackLogger)(nil)

func newStackLogger() logger.ContextLogger { return &stackLogger{} }

func (l *stackLogger) Trace(args ...any) { rtLog("trace: " + l.fmt(args...)) }
func (l *stackLogger) Debug(args ...any) { rtLog("debug: " + l.fmt(args...)) }
func (l *stackLogger) Info(args ...any)  { rtLog("info: stack: " + l.fmt(args...)) }
func (l *stackLogger) Warn(args ...any)  { rtLog("warn: stack: " + l.fmt(args...)) }
func (l *stackLogger) Error(args ...any) { rtLog("error: stack: " + l.fmt(args...)) }
func (l *stackLogger) Fatal(args ...any) { rtLog("fatal: stack: " + l.fmt(args...)) }
func (l *stackLogger) Panic(args ...any) { rtLog("panic: stack: " + l.fmt(args...)) }

func (l *stackLogger) TraceContext(_ context.Context, args ...any) { l.Trace(args...) }
func (l *stackLogger) DebugContext(_ context.Context, args ...any) { l.Debug(args...) }
func (l *stackLogger) InfoContext(_ context.Context, args ...any)  { l.Info(args...) }
func (l *stackLogger) WarnContext(_ context.Context, args ...any)  { l.Warn(args...) }
func (l *stackLogger) ErrorContext(_ context.Context, args ...any) { l.Error(args...) }
func (l *stackLogger) FatalContext(_ context.Context, args ...any) { l.Fatal(args...) }
func (l *stackLogger) PanicContext(_ context.Context, args ...any) { l.Panic(args...) }

// fmt mirrors fmt.Sprint's space-only-between-non-strings rule;
// sing's logger usage assumes Concat-style joining without spaces
// between adjacent string args (e.g. "bind forwarder to interface: ", err).
func (l *stackLogger) fmt(args ...any) string {
	switch len(args) {
	case 0:
		return ""
	case 1:
		if s, ok := args[0].(string); ok {
			return s
		}
		return fmt.Sprint(args[0])
	default:
		return fmt.Sprint(args...)
	}
}

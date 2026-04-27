package bbcr

import "time"

type Clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) Timer
	NewTicker(d time.Duration) Ticker
}
type Timer interface {
	Stop() bool
	Reset(d time.Duration) bool
}
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type RealClock struct{}

func (RealClock) Now() time.Time                            { return time.Now() }
func (RealClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }
func (RealClock) NewTicker(d time.Duration) Ticker          { return realTicker{time.NewTicker(d)} }

type realTicker struct{ t *time.Ticker }

func (t realTicker) C() <-chan time.Time { return t.t.C }
func (t realTicker) Stop()               { t.t.Stop() }

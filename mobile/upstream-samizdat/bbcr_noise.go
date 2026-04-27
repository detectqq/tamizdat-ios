package samizdat

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"expvar"
	"math"
	"sync"
	"time"

	"github.com/getlantern/samizdat/bbcr"
)

const (
	bbcrNoisePayloadLen   = 8
	bbcrNoiseMeanInterval = 2 * time.Second
	bbcrNoiseMinInterval  = 500 * time.Millisecond
	bbcrNoiseMaxInterval  = 10 * time.Second
	bbcrNoiseSendTimeout  = 2 * time.Second
)

var (
	bbcrNoiseFramesSent     = expvar.NewInt("samizdat.bbcr.noise.frames_sent")
	bbcrNoiseFramesReceived = expvar.NewInt("samizdat.bbcr.noise.frames_received")

	bbcrNoiseIntervalMu sync.RWMutex
	bbcrNoiseIntervalFn = defaultBBCRNoiseInterval
)

func (c ServerConfig) bbcrNoiseEnabled() bool {
	if c.NoiseEnabled != nil {
		return *c.NoiseEnabled
	}
	if c.DisableDefaultSecurity {
		return c.NoiseFrames
	}
	return true
}

func (s *Server) startBBCRNoiseLoop(ctx context.Context, sessionID uint64, sched *bbcr.Scheduler) {
	if sched == nil || !s.config.bbcrNoiseEnabled() {
		return
	}
	go s.bbcrNoiseLoop(ctx, sessionID, sched)
}

func (s *Server) bbcrNoiseLoop(ctx context.Context, sessionID uint64, sched *bbcr.Scheduler) {
	for {
		timer := time.NewTimer(nextBBCRNoiseInterval())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-s.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		payload, err := randomBBCRNoisePayload()
		if err != nil {
			continue
		}
		tr := sched.AnyActiveTransport()
		if tr == nil {
			continue
		}
		f := bbcr.Frame{
			Header: bbcr.FrameHeader{
				Version:        bbcr.Version1,
				Type:           bbcr.FrameNOISE,
				Flags:          bbcr.FlagDirS2C | bbcr.FlagPriorityControl,
				HeaderLen:      bbcr.HeaderLenV1,
				SessionID:      sessionID,
				TransportEpoch: tr.Epoch(),
			},
			Payload: payload,
		}
		sendCtx, cancel := context.WithTimeout(ctx, bbcrNoiseSendTimeout)
		err = tr.SendFrame(sendCtx, f)
		cancel()
		if err == nil {
			bbcrNoiseFramesSent.Add(1)
		}
	}
}

func randomBBCRNoisePayload() ([]byte, error) {
	payload := make([]byte, bbcrNoisePayloadLen)
	_, err := cryptorand.Read(payload)
	return payload, err
}

func nextBBCRNoiseInterval() time.Duration {
	bbcrNoiseIntervalMu.RLock()
	fn := bbcrNoiseIntervalFn
	bbcrNoiseIntervalMu.RUnlock()
	return clipBBCRNoiseInterval(fn())
}

func defaultBBCRNoiseInterval() time.Duration {
	u, err := cryptoUnitFloat64()
	if err != nil {
		return bbcrNoiseMeanInterval
	}
	return time.Duration(-math.Log1p(-u) * float64(bbcrNoiseMeanInterval))
}

func clipBBCRNoiseInterval(d time.Duration) time.Duration {
	if d < bbcrNoiseMinInterval {
		return bbcrNoiseMinInterval
	}
	if d > bbcrNoiseMaxInterval {
		return bbcrNoiseMaxInterval
	}
	return d
}

func cryptoUnitFloat64() (float64, error) {
	var buf [8]byte
	if _, err := cryptorand.Read(buf[:]); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(buf[:]) >> 11 // 53 random mantissa bits.
	return (float64(v) + 0.5) / float64(uint64(1)<<53), nil
}

func setBBCRNoiseIntervalForTest(d time.Duration) func() {
	bbcrNoiseIntervalMu.Lock()
	old := bbcrNoiseIntervalFn
	bbcrNoiseIntervalFn = func() time.Duration { return d }
	bbcrNoiseIntervalMu.Unlock()
	return func() {
		bbcrNoiseIntervalMu.Lock()
		bbcrNoiseIntervalFn = old
		bbcrNoiseIntervalMu.Unlock()
	}
}

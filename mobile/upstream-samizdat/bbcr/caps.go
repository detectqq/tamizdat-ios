package bbcr

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"sync"
)

const (
	TLSRecordOverhead        uint64 = 21
	H2DataFrameOverhead      uint64 = 9
	FramePcapOverhead        uint64 = uint64(HeaderLenV1) + H2DataFrameOverhead + TLSRecordOverhead
	ControlFramePcapOverhead        = FramePcapOverhead

	DefaultTLS13ServerFlightBudget uint64 = 4100
	DefaultH2SetupS2CBudget        uint64 = 90
	DefaultConnectResponseBudget   uint64 = 70
	DefaultRebindAcceptBudget      uint64 = FramePcapOverhead
	DefaultControlReserveBudget    uint64 = FramePcapOverhead
	DefaultFixedS2CBudget          uint64 = DefaultTLS13ServerFlightBudget + DefaultH2SetupS2CBudget + DefaultConnectResponseBudget + DefaultRebindAcceptBudget + DefaultControlReserveBudget
)

var ErrPcapBudgetExhausted = errors.New("bbcr: pcap hard cap budget exhausted")

type CapEstimator interface {
	ObserveFixedS2C(wireBytes uint64)
	EstimateFrameS2C(f Frame) uint64
	CumulativeEstimate() uint64
	RemainingBeforeHardCap() uint64
}

type ConservativeCapEstimator struct {
	mu       sync.Mutex
	hardCap  uint64
	fixed    uint64
	cumul    uint64
	overhead uint64
}

func NewConservativeCapEstimator(fixedS2C uint64) *ConservativeCapEstimator {
	if fixedS2C == 0 {
		fixedS2C = DefaultFixedS2CBudget
	}
	return &ConservativeCapEstimator{hardCap: HardCapPcap, fixed: fixedS2C, cumul: fixedS2C, overhead: FramePcapOverhead}
}

func (e *ConservativeCapEstimator) ObserveFixedS2C(wireBytes uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if wireBytes <= e.fixed {
		return
	}
	delta := wireBytes - e.fixed
	e.fixed = wireBytes
	e.cumul = saturatingAdd(e.cumul, delta)
}

func (e *ConservativeCapEstimator) EstimateFrameS2C(f Frame) uint64 {
	payload := uint64(len(f.Payload))
	if f.Header.PayloadLen > uint16(payload) {
		payload = uint64(f.Header.PayloadLen)
	}
	e.mu.Lock()
	overhead := e.overhead
	e.mu.Unlock()
	return saturatingAdd(payload, overhead)
}

func (e *ConservativeCapEstimator) ObserveFrameS2C(f Frame) uint64 {
	n := e.EstimateFrameS2C(f)
	e.mu.Lock()
	e.cumul = saturatingAdd(e.cumul, n)
	e.mu.Unlock()
	return n
}

func (e *ConservativeCapEstimator) CumulativeEstimate() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cumul
}

func (e *ConservativeCapEstimator) RemainingBeforeHardCap() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cumul >= e.hardCap {
		return 0
	}
	return e.hardCap - e.cumul
}

func (e *ConservativeCapEstimator) HardCap() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.hardCap
}

func saturatingAdd(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

type CapPolicy struct {
	SoftCap        uint64
	PrewarmTrigger uint64
	HardCap        uint64
}

type int63Source interface{ Int63() int64 }

type secureInt63Source struct{}

func (secureInt63Source) Int63() int64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0x2a2a2a2a
	}
	return int64(binary.BigEndian.Uint64(b[:]) & ((uint64(1) << 63) - 1))
}

func NewRandomizedCapPolicy() (CapPolicy, error) {
	return NewRandomizedCapPolicyWithRand(secureInt63Source{})
}

func NewRandomizedCapPolicyWithRand(r int63Source) (CapPolicy, error) {
	if r == nil {
		r = secureInt63Source{}
	}
	soft := uint64(7800 + positiveMod(r.Int63(), 900))     // 7800..8699, never fixed 8192.
	prewarm := uint64(9600 + positiveMod(r.Int63(), 1200)) // 9600..10799, never fixed 10240 after adjustment.
	for soft == 8192 || soft == 10240 || soft == HardCapPcap {
		soft++
	}
	for prewarm == 8192 || prewarm == 10240 || prewarm == HardCapPcap || prewarm <= soft {
		prewarm++
	}
	maxPrewarm := HardCapPcap - ControlFramePcapOverhead - 1
	if prewarm > maxPrewarm {
		prewarm = maxPrewarm
	}
	if prewarm == 10240 {
		prewarm++
	}
	if soft >= prewarm || prewarm >= HardCapPcap {
		return CapPolicy{}, ErrPcapBudgetExhausted
	}
	return CapPolicy{SoftCap: soft, PrewarmTrigger: prewarm, HardCap: HardCapPcap}, nil
}

func positiveMod(v int64, n int64) int64 {
	if n <= 0 {
		return 0
	}
	m := v % n
	if m < 0 {
		m += n
	}
	return m
}

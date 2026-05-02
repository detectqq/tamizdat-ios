package tamizdat

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type TrafficClass int32

const (
	TrafficBulk TrafficClass = iota
	TrafficRealtime
)

func (c TrafficClass) String() string {
	switch c {
	case TrafficRealtime:
		return "realtime"
	case TrafficBulk:
		return "bulk"
	default:
		return "unknown"
	}
}

type ShapeMode int32

const (
	ShapeFull ShapeMode = iota
	ShapeLite
)

func (m ShapeMode) String() string {
	switch m {
	case ShapeLite:
		return "lite"
	case ShapeFull:
		return "full"
	default:
		return "unknown"
	}
}

type FlowMeta struct {
	Network  string
	Address  string
	Host     string
	Port     int
	Protocol string
	Payload  []byte
}

func NewFlowMeta(network, address string) FlowMeta {
	return normalizeFlowMeta(FlowMeta{Network: network, Address: address})
}

func normalizeFlowMeta(meta FlowMeta) FlowMeta {
	meta.Network = strings.ToLower(strings.TrimSpace(meta.Network))
	meta.Protocol = strings.ToLower(strings.TrimSpace(meta.Protocol))
	if meta.Address != "" && (meta.Host == "" || meta.Port == 0) {
		if host, port, err := net.SplitHostPort(meta.Address); err == nil {
			meta.Host = host
			if p, perr := strconv.Atoi(port); perr == nil {
				meta.Port = p
			}
		} else if meta.Host == "" {
			meta.Host = meta.Address
		}
	}
	return meta
}


// PortRange is an inclusive UDP port range used by RealtimeDetectorConfig
// to classify dynamic-range UDP destinations as realtime.
type PortRange struct {
	Lo int `json:"lo"`
	Hi int `json:"hi"`
}

type RealtimeDetectorConfig struct {
	RealtimePorts           []int
	SmoothnessSamples       int
	SmoothnessWindows       int
	RealtimePortRanges []PortRange
	SmoothnessMaxJitterFrac float64
	SmoothnessMinInterval   time.Duration
	SmoothnessMaxInterval   time.Duration
}

type RealtimeDetector struct {
	ports map[int]struct{}
	cfg   RealtimeDetectorConfig

	mu    sync.Mutex
	flows map[uint64]*realtimeSmoothState
}

type realtimeSmoothState struct {
	last          time.Time
	intervals     []time.Duration
	smoothWindows int
}

func newRealtimeDetector() *RealtimeDetector {
	return newRealtimeDetectorWithConfig(defaultRealtimeDetectorConfig())
}

func defaultRealtimeDetectorConfig() RealtimeDetectorConfig {
	return RealtimeDetectorConfig{
		RealtimePorts: []int{
			3478, 3479, 5349, 5350, // STUN/TURN
			19302, 19305, // common public STUN services
			5004, 5005, 10000, // RTP/RTCP/SFU defaults
			6568, 7070, // AnyDesk relay/listener
		},
		// RealtimePortRanges treats UDP destinations in these inclusive
		// ranges as realtime. The IANA dynamic/ephemeral range 49152-65535
		// covers Roblox, Discord voice, AnyDesk P2P direct, most modern
		// games and WebRTC apps. False-positive risk is low: outbound UDP
		// to dynamic ports is rarely bulk download.
		RealtimePortRanges: []PortRange{
			{Lo: 49152, Hi: 65535},
		},
		SmoothnessSamples:       5,
		SmoothnessWindows:       3,
		SmoothnessMaxJitterFrac: 0.35,
		SmoothnessMinInterval:   5 * time.Millisecond,
		SmoothnessMaxInterval:   80 * time.Millisecond,
	}
}

func newRealtimeDetectorWithConfig(cfg RealtimeDetectorConfig) *RealtimeDetector {
	if cfg.SmoothnessSamples <= 0 {
		cfg.SmoothnessSamples = 5
	}
	if cfg.SmoothnessWindows <= 0 {
		cfg.SmoothnessWindows = 3
	}
	if cfg.SmoothnessMaxJitterFrac <= 0 {
		cfg.SmoothnessMaxJitterFrac = 0.35
	}
	if cfg.SmoothnessMinInterval <= 0 {
		cfg.SmoothnessMinInterval = 5 * time.Millisecond
	}
	if cfg.SmoothnessMaxInterval <= 0 {
		cfg.SmoothnessMaxInterval = 80 * time.Millisecond
	}
	if len(cfg.RealtimePorts) == 0 {
		cfg.RealtimePorts = defaultRealtimeDetectorConfig().RealtimePorts
	}
	ports := make(map[int]struct{}, len(cfg.RealtimePorts))
	for _, p := range cfg.RealtimePorts {
		if p > 0 && p <= 65535 {
			ports[p] = struct{}{}
		}
	}
	return &RealtimeDetector{ports: ports, cfg: cfg, flows: make(map[uint64]*realtimeSmoothState)}
}

func (d *RealtimeDetector) ClassifyOpen(meta FlowMeta) TrafficClass {
	if d == nil {
		return TrafficBulk
	}
	meta = normalizeFlowMeta(meta)
	if meta.Protocol == "stun" || meta.Protocol == "rtp" || meta.Protocol == "rtcp" {
		return TrafficRealtime
	}
	if looksLikeRealtimeMagic(meta.Payload) {
		return TrafficRealtime
	}
	if _, ok := d.ports[meta.Port]; ok {
		return TrafficRealtime
	}
	for _, r := range d.cfg.RealtimePortRanges {
		if meta.Port >= r.Lo && meta.Port <= r.Hi {
			return TrafficRealtime
		}
	}
	return TrafficBulk
}

func (d *RealtimeDetector) ObservePacket(flowID uint64, at time.Time, payload []byte) TrafficClass {
	if d == nil || flowID == 0 {
		return TrafficBulk
	}
	if looksLikeRealtimeMagic(payload) {
		return TrafficRealtime
	}
	if at.IsZero() {
		at = time.Now()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.flows[flowID]
	if st == nil {
		st = &realtimeSmoothState{}
		d.flows[flowID] = st
	}
	if !st.last.IsZero() {
		iv := at.Sub(st.last)
		if iv > 0 {
			st.intervals = append(st.intervals, iv)
		}
	}
	st.last = at
	if len(st.intervals) < d.cfg.SmoothnessSamples {
		return TrafficBulk
	}
	if d.smoothWindow(st.intervals) {
		st.smoothWindows++
	} else {
		st.smoothWindows = 0
	}
	st.intervals = st.intervals[:0]
	if st.smoothWindows >= d.cfg.SmoothnessWindows {
		return TrafficRealtime
	}
	return TrafficBulk
}

func (d *RealtimeDetector) Forget(flowID uint64) {
	if d == nil || flowID == 0 {
		return
	}
	d.mu.Lock()
	delete(d.flows, flowID)
	d.mu.Unlock()
}

func (d *RealtimeDetector) smoothWindow(intervals []time.Duration) bool {
	if len(intervals) == 0 {
		return false
	}
	var sum time.Duration
	for _, iv := range intervals {
		if iv < d.cfg.SmoothnessMinInterval || iv > d.cfg.SmoothnessMaxInterval {
			return false
		}
		sum += iv
	}
	mean := float64(sum) / float64(len(intervals))
	if mean <= 0 {
		return false
	}
	var dev float64
	for _, iv := range intervals {
		delta := float64(iv) - mean
		if delta < 0 {
			delta = -delta
		}
		dev += delta
	}
	return dev/float64(len(intervals))/mean <= d.cfg.SmoothnessMaxJitterFrac
}

func looksLikeRealtimeMagic(payload []byte) bool {
	return looksLikeSTUN(payload) || looksLikeRTP(payload)
}

func looksLikeSTUN(payload []byte) bool {
	return len(payload) >= 20 && payload[0]&0xc0 == 0 && binary.BigEndian.Uint32(payload[4:8]) == 0x2112a442
}

func looksLikeRTP(payload []byte) bool {
	return len(payload) >= 12 && payload[0]&0xc0 == 0x80
}

type RealtimeController struct {
	Detector *RealtimeDetector

	mode       atomic.Int32
	nextFlowID atomic.Uint64

	mu                  sync.Mutex
	activeRealtimeCount int
	hysteresisTimer     *time.Timer
	flowMap             map[uint64]TrafficClass
	hysteresisMin       time.Duration
	hysteresisMax       time.Duration
	onRealtimeOpen      func()
	onLastRealtimeClose func()
	onModeReturnToFull  func()
}

func newRealtimeController() *RealtimeController {
	return newRealtimeControllerWithConfig(newRealtimeDetector(), 30*time.Second, 60*time.Second)
}

func newRealtimeControllerWithConfig(detector *RealtimeDetector, hysteresisMin, hysteresisMax time.Duration) *RealtimeController {
	if detector == nil {
		detector = newRealtimeDetector()
	}
	if hysteresisMin <= 0 {
		hysteresisMin = 30 * time.Second
	}
	if hysteresisMax < hysteresisMin {
		hysteresisMax = hysteresisMin
	}
	c := &RealtimeController{
		Detector:      detector,
		flowMap:       make(map[uint64]TrafficClass),
		hysteresisMin: hysteresisMin,
		hysteresisMax: hysteresisMax,
	}
	c.mode.Store(int32(ShapeFull))
	return c
}

func (c *RealtimeController) Mode() ShapeMode {
	if c == nil {
		return ShapeFull
	}
	return ShapeMode(c.mode.Load())
}

func (c *RealtimeController) Open(class TrafficClass) uint64 {
	if c == nil {
		return 0
	}
	flowID := c.nextFlowID.Add(1)
	callOpen := false
	c.mu.Lock()
	c.flowMap[flowID] = class
	if class == TrafficRealtime {
		if c.activeRealtimeCount == 0 {
			c.mode.Store(int32(ShapeLite))
			c.cancelHysteresisLocked()
			callOpen = c.onRealtimeOpen != nil
		}
		c.activeRealtimeCount++
	}
	setRealtimeFlowsActive(c.activeRealtimeCount)
	onRealtimeOpen := c.onRealtimeOpen
	c.mu.Unlock()
	if callOpen {
		onRealtimeOpen()
	}
	return flowID
}

func (c *RealtimeController) Promote(flowID uint64) {
	if c == nil || flowID == 0 {
		return
	}
	callOpen := false
	c.mu.Lock()
	oldClass, ok := c.flowMap[flowID]
	if ok && oldClass == TrafficBulk {
		c.flowMap[flowID] = TrafficRealtime
		if c.activeRealtimeCount == 0 {
			c.mode.Store(int32(ShapeLite))
			c.cancelHysteresisLocked()
			callOpen = c.onRealtimeOpen != nil
		}
		c.activeRealtimeCount++
	}
	onRealtimeOpen := c.onRealtimeOpen
	c.mu.Unlock()
	if callOpen {
		onRealtimeOpen()
	}
}

func (c *RealtimeController) Close(flowID uint64) {
	if c == nil || flowID == 0 {
		return
	}
	callLastClose := false
	c.mu.Lock()
	oldClass, ok := c.flowMap[flowID]
	if ok {
		if oldClass == TrafficRealtime && c.activeRealtimeCount > 0 {
			c.activeRealtimeCount--
			if c.activeRealtimeCount == 0 {
				c.armHysteresisLocked()
				callLastClose = c.onLastRealtimeClose != nil
			}
		}
		delete(c.flowMap, flowID)
	}
	setRealtimeFlowsActive(c.activeRealtimeCount)
	onLastRealtimeClose := c.onLastRealtimeClose
	c.mu.Unlock()
	if callLastClose {
		onLastRealtimeClose()
	}
	if c.Detector != nil {
		c.Detector.Forget(flowID)
	}
}

func (c *RealtimeController) ActiveRealtimeCount() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activeRealtimeCount
}

func (c *RealtimeController) cancelHysteresisLocked() {
	if c.hysteresisTimer != nil {
		c.hysteresisTimer.Stop()
		c.hysteresisTimer = nil
	}
}

func (c *RealtimeController) armHysteresisLocked() {
	c.cancelHysteresisLocked()
	delay := c.hysteresisMin
	if c.hysteresisMax > c.hysteresisMin {
		delay = randomDuration(c.hysteresisMin, c.hysteresisMax+time.Nanosecond)
	}
	c.hysteresisTimer = time.AfterFunc(delay, c.returnToFull)
}

func (c *RealtimeController) returnToFull() {
	callReturnToFull := false
	c.mu.Lock()
	if c.activeRealtimeCount == 0 {
		c.mode.Store(int32(ShapeFull))
		callReturnToFull = c.onModeReturnToFull != nil
	}
	c.hysteresisTimer = nil
	onModeReturnToFull := c.onModeReturnToFull
	c.mu.Unlock()
	if callReturnToFull {
		onModeReturnToFull()
	}
}

// observe is called only from UDP packet wrappers. TCP byte-stream wrappers
// deliberately skip smoothness observation because read-buffer coalescing can
// make bulk transfers look packet-paced.
func (c *RealtimeController) observe(flowID uint64, payload []byte) {
	if c == nil || c.Detector == nil || flowID == 0 {
		return
	}
	if c.Detector.ObservePacket(flowID, time.Now(), payload) == TrafficRealtime {
		c.Promote(flowID)
	}
}

type realtimeTrackedConn struct {
	net.Conn
	controller *RealtimeController
	flowID     uint64
	closeOnce  sync.Once
}

func wrapRealtimeConn(conn net.Conn, controller *RealtimeController, flowID uint64) net.Conn {
	if conn == nil || controller == nil || flowID == 0 {
		return conn
	}
	return &realtimeTrackedConn{Conn: conn, controller: controller, flowID: flowID}
}

func (c *realtimeTrackedConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.controller.Close(c.flowID)
		err = c.Conn.Close()
	})
	return err
}

func (c *realtimeTrackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type realtimeTrackedPacketConn struct {
	net.PacketConn
	controller *RealtimeController
	flowID     uint64
	closeOnce  sync.Once
}

func wrapRealtimePacketConn(conn net.PacketConn, controller *RealtimeController, flowID uint64) net.PacketConn {
	if conn == nil || controller == nil || flowID == 0 {
		return conn
	}
	return &realtimeTrackedPacketConn{PacketConn: conn, controller: controller, flowID: flowID}
}

func (c *realtimeTrackedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.controller.observe(c.flowID, p[:n])
	}
	return n, addr, err
}

func (c *realtimeTrackedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n > 0 {
		c.controller.observe(c.flowID, p[:n])
	}
	return n, err
}

func (c *realtimeTrackedPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.controller.Close(c.flowID)
		err = c.PacketConn.Close()
	})
	return err
}

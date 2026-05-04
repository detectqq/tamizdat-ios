package tamizdat

import (
	"encoding/binary"
	"log"
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
	// AppHint is a lowercased process / application name supplied by the
	// client (e.g. "anydesk", "roblox", "chrome"). Empty when the platform
	// cannot attribute the connection to a process. Used as a Tier 3 side
	// signal in ClassifyOpen against RealtimeAppHints; never trusted on its
	// own, only used to break ties / promote known-realtime apps.
	AppHint string
}

func NewFlowMeta(network, address string) FlowMeta {
	return normalizeFlowMeta(FlowMeta{Network: network, Address: address})
}

func normalizeFlowMeta(meta FlowMeta) FlowMeta {
	meta.Network = strings.ToLower(strings.TrimSpace(meta.Network))
	meta.Protocol = strings.ToLower(strings.TrimSpace(meta.Protocol))
	meta.AppHint = strings.ToLower(strings.TrimSpace(meta.AppHint))
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
	meta.Host = strings.ToLower(strings.TrimSpace(meta.Host))
	return meta
}

// PortRange is an inclusive UDP port range retained for backward-compatible
// operator configuration. The default v2 config deliberately leaves ranges
// empty: the IANA dynamic range is no longer a realtime signal.
type PortRange struct {
	Lo int `json:"lo"`
	Hi int `json:"hi"`
}

type RealtimeDetectorConfig struct {
	// Existing fields, preserved for callers/tests that set them directly.
	RealtimePorts           []int
	SmoothnessSamples       int
	SmoothnessWindows       int
	RealtimePortRanges      []PortRange
	RealtimeAppHints        []string
	SmoothnessMaxJitterFrac float64
	SmoothnessMinInterval   time.Duration
	SmoothnessMaxInterval   time.Duration

	// Score thresholds. Values are scaled to Q8.8 internally.
	PromoteScore float64 // default 0.55
	DemoteScore  float64 // default 0.25
	WatchScore   float64 // default 0.30

	// State-machine timing defaults.
	MinPromoteAge    time.Duration // default 200ms
	SilentDemoteAge  time.Duration // default 1.5s
	BulkConfirmAge   time.Duration // default 5s
	IdleReleaseAge   time.Duration // default 30s
	EndpointCacheTTL time.Duration // default 60s
	JitterAlphaInv   int           // default 16, RFC 3550 EWMA denominator

	// Tier 1 weights, Q8.8 fixed-point.
	StunScoreQ8            int16
	TurnChannelDataScoreQ8 int16
	DtlsHandshakeScoreQ8   int16
	DtlsAppDataScoreQ8     int16
	RtpCandidateScoreQ8    int16
	RtpConfirmedScoreQ8    int16
	RtcpScoreQ8            int16
	QuicLongHeaderScoreQ8  int16
	TlsLargeAppDataScoreQ8 int16

	// Tier 2 weights, Q8.8 fixed-point.
	SmoothWindowScoreQ8 int16
	OpusBonusScoreQ8    int16
	SmallPktScoreQ8     int16
	MtuBulkScoreQ8      int16
	DirSymmetryScoreQ8  int16
	DirAsymmetryScoreQ8 int16
	CadenceBreakScoreQ8 int16

	// Tier 3 weights, Q4.4 fixed-point.
	AppHintScoreQ4          int8
	KnownPortScoreQ4        int8
	EndpointCacheHitScoreQ4 int8
	UdpPriorScoreQ4         int8
	TcpBulkPortScoreQ4      int8

	// MaxConcurrentFlows caps detector state; 0 disables the cap.
	MaxConcurrentFlows int
	// LegacyPortPromote preserves v1 ClassifyOpen behavior for known ports,
	// app hints, protocol strings, and realtime-looking initial payloads.
	LegacyPortPromote bool

	// Plan B Hybrid knobs. Bool false and zero durations/rates are meaningful
	// operator opt-outs, so fillRealtimeDefaults intentionally does not
	// overwrite them; newRealtimeDetector() uses defaultRealtimeDetectorConfig()
	// to provide the production defaults from the spec.
	PlanBDefaultPromoteUDP  bool
	PlanBRateCapWindow      time.Duration
	PlanBRateCapBytesPerSec int64

	// Plan B+ migration knobs. MigrationEnabled defaults true only in
	// defaultRealtimeDetectorConfig(); explicit false disables migration for
	// tests/operators constructing configs directly.
	MigrationEnabled             bool
	MigrationDebounceWindow      time.Duration
	MigrationWindowByteThreshold uint32
	MigrationCumulativeFloor     uint64
}

type Direction uint8

const (
	DirOutbound Direction = 0
	DirInbound  Direction = 1
	DirUnknown  Direction = 2
)

type ObservedPacket struct {
	FlowID    uint64
	At        time.Time
	Payload   []byte
	Size      int
	Direction Direction
}

// PlanBStats is a lock-free snapshot of Plan B-specific decisions.
type PlanBStats struct {
	Promotes uint64
	Demotes  uint64
	Lockins  uint64

	MigrationFires            uint64
	MigrationSkippedFloor     uint64
	MigrationSkippedNoHandle  uint64
	MigrationSkippedV1        uint64
	MigrationFailedNoBulk     uint64
	MigrationFailedForceClose uint64
	MigrationDurationNanos    uint64
}

const (
	q8Scale = 256

	flowStateNew uint8 = iota
	flowStateProvisionalBulk
	flowStateProvisionalRT
	flowStateConfirmedBulk
	flowStateConfirmedRT
)

const (
	flagStrongPrefix uint8 = 1 << 0
	flagT3Set        uint8 = 1 << 1
	flagTCP          uint8 = 1 << 2
	flagIdleReleased uint8 = 1 << 3
	flagLiteLocked   uint8 = 1 << 4
)

const (
	protoUnknown uint8 = 0
	protoUDP     uint8 = 1
	protoTCP     uint8 = 2
)

const (
	t1SeenSTUN uint16 = 1 << iota
	t1SeenTURN
	t1SeenDTLSHandshake
	t1SeenDTLSApp
	t1SeenRTPCandidate
	t1SeenRTPConfirmed
	t1SeenRTCP
	t1SeenQUIC
	t1SeenTLSLarge
)

const (
	t2SeenOpus uint16 = 1 << iota
)

const (
	tier1MaxQ8 = int16(141)
	tier1MinQ8 = int16(-77)
	tier2MaxQ8 = int16(115)
	tier2MinQ8 = int16(-115)
	tier3MaxQ4 = int8(5)
	tier3MinQ4 = int8(-2)

	defaultIatBandLowUnits  = uint32(50)  // 5 ms in 100-us units
	defaultIatBandHighUnits = uint32(800) // 80 ms in 100-us units
	tightIatLowUnits        = uint32(120) // 12 ms
	tightIatHighUnits       = uint32(500) // 50 ms
)

type flowState struct {
	openTimeNS  int64
	lastSeenNS  int64
	confirmedNS int64
	lastInterNS int64

	planBWindowStartNS int64

	pkts             uint16
	pktsIn           uint16
	pktsOut          uint16
	_ctrPad          uint16
	bytesUp          uint32
	bytesDown        uint32
	planBWindowBytes uint32
	windowByteSum    uint32

	windowStartNS int64
	totalBytes    uint64

	iatRing  [16]uint16
	sizeRing [16]uint16
	ringHead uint8
	ringLen  uint8

	smoothWins uint8
	failedWins uint8
	jitterQ16  uint32

	rtpSSRC   [2]uint32
	rtpSeq    [2]uint16
	rtpRunLen [2]uint8

	t1Flags uint16
	t2Flags uint16

	scoreT1 int16
	scoreT2 int16
	scoreT3 int8
	state   uint8
	flags   uint8
	proto   uint8

	lowScorePkts uint8
	migrating    bool
	migrated     bool
}

type endpointInfo struct {
	host      string
	prefix24  uint32
	hasPrefix bool
}

type pendingOpen struct {
	st       flowState
	endpoint endpointInfo
	created  time.Time
}

const forceBulkCacheTTL = 5 * time.Minute

type forceBulkEntry struct {
	untilNS int64
}

type migrationHandle struct {
	fastCloseFn           func() error
	ensureBulkFn          func() error
	dstAddr               string
	originalTransportLite bool
}

type migrationRequest struct {
	flowID      uint64
	dstAddr     string
	windowBytes uint32
	totalBytes  uint64
}

type RealtimeDetector struct {
	ports    map[int]struct{}
	appHints []string
	cfg      RealtimeDetectorConfig

	planBPromotes atomic.Uint64
	planBDemotes  atomic.Uint64
	planBLockins  atomic.Uint64

	migrationFires            atomic.Uint64
	migrationSkippedFloor     atomic.Uint64
	migrationSkippedNoHandle  atomic.Uint64
	migrationSkippedV1        atomic.Uint64
	migrationFailedNoBulk     atomic.Uint64
	migrationFailedForceClose atomic.Uint64
	migrationDurationNanos    atomic.Uint64

	promoteQ8 int16
	demoteQ8  int16
	watchQ8   int16

	smoothJitterPermille int64
	tightJitterPermille  int64

	mu             sync.Mutex
	flows          map[uint64]*flowState
	flowEndpoints  map[uint64]endpointInfo
	flowOrder      []uint64
	flowOrderHead  int
	pending        []pendingOpen
	endpointByHost map[string]int64
	endpointByPref map[uint32]int64
	controller     *RealtimeController
	cleanupStarted sync.Once

	forceBulkCache    sync.Map // string(canonical dst) -> forceBulkEntry
	migrationDispatch sync.Map // uint64(flowID) -> *migrationHandle
}

func newRealtimeDetector() *RealtimeDetector {
	return newRealtimeDetectorWithConfig(defaultRealtimeDetectorConfig())
}

func defaultRealtimeDetectorConfig() RealtimeDetectorConfig {
	return RealtimeDetectorConfig{
		RealtimePorts: []int{
			3478, 3479, 5349, 5350,
			19302, 19305,
			5004, 5005, 10000,
			6568, 7070,
		},
		RealtimePortRanges: []PortRange{},
		RealtimeAppHints: []string{
			"anydesk", "roblox", "discord", "zoom", "webex",
			"teams", "skype", "telegram", "signal", "whatsapp",
			"viber", "obs", "streamlabs", "mumble", "teamspeak",
			"vmware-view", "rdp", "mstsc", "parsec", "steam",
		},
		SmoothnessSamples:            5,
		SmoothnessWindows:            2,
		SmoothnessMaxJitterFrac:      0.55,
		SmoothnessMinInterval:        5 * time.Millisecond,
		SmoothnessMaxInterval:        80 * time.Millisecond,
		PromoteScore:                 0.55,
		DemoteScore:                  0.25,
		WatchScore:                   0.30,
		MinPromoteAge:                200 * time.Millisecond,
		SilentDemoteAge:              1500 * time.Millisecond,
		BulkConfirmAge:               5 * time.Second,
		IdleReleaseAge:               30 * time.Second,
		EndpointCacheTTL:             60 * time.Second,
		JitterAlphaInv:               16,
		StunScoreQ8:                  115,
		TurnChannelDataScoreQ8:       102,
		DtlsHandshakeScoreQ8:         102,
		DtlsAppDataScoreQ8:           64,
		RtpCandidateScoreQ8:          38,
		RtpConfirmedScoreQ8:          102,
		RtcpScoreQ8:                  77,
		QuicLongHeaderScoreQ8:        -51,
		TlsLargeAppDataScoreQ8:       -77,
		SmoothWindowScoreQ8:          64,
		OpusBonusScoreQ8:             38,
		SmallPktScoreQ8:              26,
		MtuBulkScoreQ8:               -77,
		DirSymmetryScoreQ8:           26,
		DirAsymmetryScoreQ8:          -51,
		CadenceBreakScoreQ8:          -26,
		AppHintScoreQ4:               5,
		KnownPortScoreQ4:             2,
		EndpointCacheHitScoreQ4:      2,
		UdpPriorScoreQ4:              1,
		TcpBulkPortScoreQ4:           -2,
		MaxConcurrentFlows:           100_000,
		LegacyPortPromote:            true,
		PlanBDefaultPromoteUDP:       true,
		PlanBRateCapWindow:           500 * time.Millisecond,
		PlanBRateCapBytesPerSec:      256 * 1024, // TODO calibrate under BBR.
		MigrationEnabled:             true,
		MigrationDebounceWindow:      1500 * time.Millisecond,
		MigrationWindowByteThreshold: 384 * 1024,
		MigrationCumulativeFloor:     10 * 1024 * 1024,
	}
}

func newRealtimeDetectorWithConfig(cfg RealtimeDetectorConfig) *RealtimeDetector {
	cfg = fillRealtimeDefaults(cfg)
	ports := make(map[int]struct{}, len(cfg.RealtimePorts))
	for _, p := range cfg.RealtimePorts {
		if p > 0 && p <= 65535 {
			ports[p] = struct{}{}
		}
	}
	hints := make([]string, 0, len(cfg.RealtimeAppHints))
	for _, h := range cfg.RealtimeAppHints {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			hints = append(hints, h)
		}
	}
	d := &RealtimeDetector{
		ports:                ports,
		appHints:             hints,
		cfg:                  cfg,
		promoteQ8:            q8FromFloat(cfg.PromoteScore),
		demoteQ8:             q8FromFloat(cfg.DemoteScore),
		watchQ8:              q8FromFloat(cfg.WatchScore),
		smoothJitterPermille: permilleFromFloat(cfg.SmoothnessMaxJitterFrac, 550),
		tightJitterPermille:  300,
		flows:                make(map[uint64]*flowState),
		flowEndpoints:        make(map[uint64]endpointInfo),
		endpointByHost:       make(map[string]int64),
		endpointByPref:       make(map[uint32]int64),
	}
	return d
}

func fillRealtimeDefaults(cfg RealtimeDetectorConfig) RealtimeDetectorConfig {
	def := defaultRealtimeDetectorConfig()
	if len(cfg.RealtimePorts) == 0 {
		cfg.RealtimePorts = def.RealtimePorts
	}
	if cfg.RealtimeAppHints == nil {
		cfg.RealtimeAppHints = def.RealtimeAppHints
	}
	if cfg.SmoothnessSamples <= 0 {
		cfg.SmoothnessSamples = def.SmoothnessSamples
	}
	if cfg.SmoothnessWindows <= 0 {
		cfg.SmoothnessWindows = def.SmoothnessWindows
	}
	if cfg.SmoothnessMaxJitterFrac <= 0 {
		cfg.SmoothnessMaxJitterFrac = def.SmoothnessMaxJitterFrac
	}
	if cfg.SmoothnessMinInterval <= 0 {
		cfg.SmoothnessMinInterval = def.SmoothnessMinInterval
	}
	if cfg.SmoothnessMaxInterval <= 0 {
		cfg.SmoothnessMaxInterval = def.SmoothnessMaxInterval
	}
	if cfg.PromoteScore <= 0 {
		cfg.PromoteScore = def.PromoteScore
	}
	if cfg.DemoteScore <= 0 {
		cfg.DemoteScore = def.DemoteScore
	}
	if cfg.WatchScore <= 0 {
		cfg.WatchScore = def.WatchScore
	}
	if cfg.MinPromoteAge <= 0 {
		cfg.MinPromoteAge = def.MinPromoteAge
	}
	if cfg.SilentDemoteAge <= 0 {
		cfg.SilentDemoteAge = def.SilentDemoteAge
	}
	if cfg.BulkConfirmAge <= 0 {
		cfg.BulkConfirmAge = def.BulkConfirmAge
	}
	if cfg.IdleReleaseAge <= 0 {
		cfg.IdleReleaseAge = def.IdleReleaseAge
	}
	if cfg.EndpointCacheTTL <= 0 {
		cfg.EndpointCacheTTL = def.EndpointCacheTTL
	}
	if cfg.JitterAlphaInv <= 0 {
		cfg.JitterAlphaInv = def.JitterAlphaInv
	}
	if cfg.StunScoreQ8 == 0 {
		cfg.StunScoreQ8 = def.StunScoreQ8
	}
	if cfg.TurnChannelDataScoreQ8 == 0 {
		cfg.TurnChannelDataScoreQ8 = def.TurnChannelDataScoreQ8
	}
	if cfg.DtlsHandshakeScoreQ8 == 0 {
		cfg.DtlsHandshakeScoreQ8 = def.DtlsHandshakeScoreQ8
	}
	if cfg.DtlsAppDataScoreQ8 == 0 {
		cfg.DtlsAppDataScoreQ8 = def.DtlsAppDataScoreQ8
	}
	if cfg.RtpCandidateScoreQ8 == 0 {
		cfg.RtpCandidateScoreQ8 = def.RtpCandidateScoreQ8
	}
	if cfg.RtpConfirmedScoreQ8 == 0 {
		cfg.RtpConfirmedScoreQ8 = def.RtpConfirmedScoreQ8
	}
	if cfg.RtcpScoreQ8 == 0 {
		cfg.RtcpScoreQ8 = def.RtcpScoreQ8
	}
	if cfg.QuicLongHeaderScoreQ8 == 0 {
		cfg.QuicLongHeaderScoreQ8 = def.QuicLongHeaderScoreQ8
	}
	if cfg.TlsLargeAppDataScoreQ8 == 0 {
		cfg.TlsLargeAppDataScoreQ8 = def.TlsLargeAppDataScoreQ8
	}
	if cfg.SmoothWindowScoreQ8 == 0 {
		cfg.SmoothWindowScoreQ8 = def.SmoothWindowScoreQ8
	}
	if cfg.OpusBonusScoreQ8 == 0 {
		cfg.OpusBonusScoreQ8 = def.OpusBonusScoreQ8
	}
	if cfg.SmallPktScoreQ8 == 0 {
		cfg.SmallPktScoreQ8 = def.SmallPktScoreQ8
	}
	if cfg.MtuBulkScoreQ8 == 0 {
		cfg.MtuBulkScoreQ8 = def.MtuBulkScoreQ8
	}
	if cfg.DirSymmetryScoreQ8 == 0 {
		cfg.DirSymmetryScoreQ8 = def.DirSymmetryScoreQ8
	}
	if cfg.DirAsymmetryScoreQ8 == 0 {
		cfg.DirAsymmetryScoreQ8 = def.DirAsymmetryScoreQ8
	}
	if cfg.CadenceBreakScoreQ8 == 0 {
		cfg.CadenceBreakScoreQ8 = def.CadenceBreakScoreQ8
	}
	if cfg.AppHintScoreQ4 == 0 {
		cfg.AppHintScoreQ4 = def.AppHintScoreQ4
	}
	if cfg.KnownPortScoreQ4 == 0 {
		cfg.KnownPortScoreQ4 = def.KnownPortScoreQ4
	}
	if cfg.EndpointCacheHitScoreQ4 == 0 {
		cfg.EndpointCacheHitScoreQ4 = def.EndpointCacheHitScoreQ4
	}
	if cfg.UdpPriorScoreQ4 == 0 {
		cfg.UdpPriorScoreQ4 = def.UdpPriorScoreQ4
	}
	if cfg.TcpBulkPortScoreQ4 == 0 {
		cfg.TcpBulkPortScoreQ4 = def.TcpBulkPortScoreQ4
	}
	if cfg.MaxConcurrentFlows == 0 {
		cfg.MaxConcurrentFlows = def.MaxConcurrentFlows
	}
	// NOTE: bool default-fill cannot distinguish "unset" from "explicit false".
	// The current default is true; operators who want to disable legacy port
	// promotion must use a custom config struct that bypasses this fill.
	// TODO(realtime-v2.1): switch to *bool or LegacyPortPromoteSet flag if
	// operators report a need to disable explicitly via partial config.
	if !cfg.LegacyPortPromote {
		cfg.LegacyPortPromote = def.LegacyPortPromote
	}
	// Plan B defaults are applied only by defaultRealtimeDetectorConfig(). The
	// spec simultaneously requires default-on promotion and 0/false as disable
	// values; preserving explicit opt-outs here is the least surprising choice.
	return cfg
}

func q8FromFloat(v float64) int16 {
	if v < 0 {
		return int16(v*float64(q8Scale) - 0.5)
	}
	return int16(v*float64(q8Scale) + 0.5)
}

func permilleFromFloat(v float64, fallback int64) int64 {
	if v <= 0 {
		return fallback
	}
	return int64(v*1000 + 0.5)
}

func (d *RealtimeDetector) appHintMatch(hint string) bool {
	if hint == "" || len(d.appHints) == 0 {
		return false
	}
	hint = strings.ToLower(strings.TrimSpace(hint))
	for _, needle := range d.appHints {
		if strings.Contains(hint, needle) {
			return true
		}
	}
	return false
}

func (d *RealtimeDetector) ClassifyOpen(meta FlowMeta) TrafficClass {
	if d == nil {
		return TrafficBulk
	}
	meta = normalizeFlowMeta(meta)
	now := time.Now()
	if d.forceBulkClassify(meta, now) {
		return TrafficBulk
	}
	st := newFlowStateForMeta(meta, now)
	endpoint := endpointFromMeta(meta)
	if d.planBDefaultPromoteOpen(meta) {
		// Ambiguity resolved: Plan B's open-time promotion is recorded as
		// CONFIRMED_RT, not merely PROVISIONAL_RT, so controller.Open(class)
		// binds a flow whose first Observe already returns TrafficRealtime.
		nowNS := now.UnixNano()
		st.state = flowStateConfirmedRT
		st.confirmedNS = nowNS
		st.lastInterNS = nowNS
		d.planBPromotes.Add(1)
		d.mu.Lock()
		d.enqueuePendingLocked(pendingOpen{st: st, endpoint: endpoint, created: now})
		d.rememberEndpointLocked(endpoint, now)
		d.mu.Unlock()
		return TrafficRealtime
	}
	knownPort := d.hasRealtimePort(meta.Port)
	appHint := d.appHintMatch(meta.AppHint)

	d.mu.Lock()
	st.scoreT3 = d.tier3ScoreLocked(meta, endpoint, knownPort, appHint, now)
	st.flags |= flagT3Set
	d.mu.Unlock()

	if len(meta.Payload) > 0 {
		d.applyTier1(&st, meta.Payload, DirUnknown)
	}
	d.transitionState(&st, now)
	score := st.totalScoreQ8()

	class := TrafficBulk
	legacyProtocol := meta.Protocol == "stun" || meta.Protocol == "rtp" || meta.Protocol == "rtcp"
	legacyPayload := looksLikeRealtimeMagic(meta.Payload)
	if score >= d.promoteQ8 || (d.cfg.LegacyPortPromote && (knownPort || appHint || legacyProtocol || legacyPayload)) {
		class = TrafficRealtime
	}

	d.mu.Lock()
	d.enqueuePendingLocked(pendingOpen{st: st, endpoint: endpoint, created: now})
	if st.state == flowStateConfirmedRT || score >= d.promoteQ8 {
		d.rememberEndpointLocked(endpoint, now)
	}
	d.mu.Unlock()
	return class
}

func (d *RealtimeDetector) planBDefaultPromoteOpen(meta FlowMeta) bool {
	return d.cfg.PlanBDefaultPromoteUDP && meta.Network == "udp" && meta.Port != 53 && meta.Port != 853
}

func (d *RealtimeDetector) forceBulkClassify(meta FlowMeta, now time.Time) bool {
	if d == nil {
		return false
	}
	key := forceBulkCacheKey(meta)
	if key == "" {
		return false
	}
	v, ok := d.forceBulkCache.Load(key)
	if !ok {
		return false
	}
	e, ok := v.(forceBulkEntry)
	if !ok {
		d.forceBulkCache.Delete(key)
		return false
	}
	if now.UnixNano() < e.untilNS {
		return true
	}
	d.forceBulkCache.Delete(key)
	return false
}

func forceBulkCacheKey(meta FlowMeta) string {
	meta = normalizeFlowMeta(meta)
	if meta.Host != "" && meta.Port > 0 {
		return net.JoinHostPort(meta.Host, strconv.Itoa(meta.Port))
	}
	return strings.ToLower(strings.TrimSpace(meta.Address))
}

func forceBulkCacheKeyFromAddress(address string) string {
	return forceBulkCacheKey(NewFlowMeta("udp", address))
}

func (d *RealtimeDetector) PlanBStats() PlanBStats {
	if d == nil {
		return PlanBStats{}
	}
	return PlanBStats{
		Promotes:                  d.planBPromotes.Load(),
		Demotes:                   d.planBDemotes.Load(),
		Lockins:                   d.planBLockins.Load(),
		MigrationFires:            d.migrationFires.Load(),
		MigrationSkippedFloor:     d.migrationSkippedFloor.Load(),
		MigrationSkippedNoHandle:  d.migrationSkippedNoHandle.Load(),
		MigrationSkippedV1:        d.migrationSkippedV1.Load(),
		MigrationFailedNoBulk:     d.migrationFailedNoBulk.Load(),
		MigrationFailedForceClose: d.migrationFailedForceClose.Load(),
		MigrationDurationNanos:    d.migrationDurationNanos.Load(),
	}
}

func newFlowStateForMeta(meta FlowMeta, now time.Time) flowState {
	st := flowState{openTimeNS: now.UnixNano(), lastSeenNS: 0, lastInterNS: now.UnixNano(), state: flowStateNew}
	switch meta.Network {
	case "tcp":
		st.proto = protoTCP
		st.flags |= flagTCP
	case "udp":
		st.proto = protoUDP
	default:
		st.proto = protoUnknown
	}
	return st
}

func (d *RealtimeDetector) ObservePacket(flowID uint64, at time.Time, payload []byte) TrafficClass {
	return d.Observe(ObservedPacket{FlowID: flowID, At: at, Payload: payload, Size: len(payload), Direction: DirUnknown})
}

func (d *RealtimeDetector) Observe(p ObservedPacket) TrafficClass {
	if d == nil || p.FlowID == 0 {
		return TrafficBulk
	}
	if p.At.IsZero() {
		p.At = time.Now()
	}
	if p.Size <= 0 {
		p.Size = len(p.Payload)
	}
	nowNS := p.At.UnixNano()

	d.mu.Lock()
	st := d.flows[p.FlowID]
	if st == nil {
		initial := flowState{openTimeNS: nowNS, lastInterNS: nowNS, state: flowStateNew, proto: protoUDP}
		st = &initial
		d.addFlowLocked(p.FlowID, st, endpointInfo{})
	}
	if st.openTimeNS == 0 {
		st.openTimeNS = nowNS
	}
	if st.lastInterNS == 0 {
		st.lastInterNS = nowNS
	}
	migrationReq := d.accountMigrationBytesLocked(p.FlowID, st, p, nowNS)
	if st.state == flowStateConfirmedBulk {
		st.lastSeenNS = nowNS
		d.mu.Unlock()
		if migrationReq != nil {
			go d.runMigration(migrationReq)
		}
		return TrafficBulk
	}
	if st.lastSeenNS == 0 && nowNS < st.openTimeNS {
		// Synthetic tests may ClassifyOpen with wall-clock time and then feed
		// deterministic packet timestamps in the past. Treat the first packet as
		// the logical flow-open time so age gates remain based on packet time.
		st.openTimeNS = nowNS
		if st.lastInterNS > nowNS {
			st.lastInterNS = nowNS
		}
	}

	wasReleased := st.flags&flagIdleReleased != 0
	if wasReleased {
		st.flags &^= flagIdleReleased
	}
	wasConfirmedRT := st.state == flowStateConfirmedRT
	before := st.totalScoreQ8()
	d.observePacketLocked(st, p)
	after := st.totalScoreQ8()
	if after > before {
		st.lastInterNS = nowNS
	}
	promoted := d.transitionState(st, p.At)
	if promoted {
		if ep, ok := d.flowEndpoints[p.FlowID]; ok {
			d.rememberEndpointLocked(ep, p.At)
		}
	}
	class := TrafficBulk
	if st.state == flowStateConfirmedRT {
		class = TrafficRealtime
	}
	releaseActive := wasConfirmedRT && st.state != flowStateConfirmedRT
	controller := d.controller
	d.mu.Unlock()
	if migrationReq != nil {
		go d.runMigration(migrationReq)
	}
	if releaseActive && controller != nil {
		controller.ReleaseActive(p.FlowID)
	}
	return class
}

func (d *RealtimeDetector) observePacketLocked(st *flowState, p ObservedPacket) {
	nowNS := p.At.UnixNano()
	if st.pkts < ^uint16(0) {
		st.pkts++
	}
	size := p.Size
	if size < 0 {
		size = 0
	}
	if size > 65535 {
		size = 65535
	}
	dirIdx := 0
	switch p.Direction {
	case DirInbound:
		dirIdx = 1
		if st.pktsIn < ^uint16(0) {
			st.pktsIn++
		}
		st.bytesDown = satAddUint32(st.bytesDown, uint32(size))
	case DirOutbound:
		if st.pktsOut < ^uint16(0) {
			st.pktsOut++
		}
		st.bytesUp = satAddUint32(st.bytesUp, uint32(size))
	default:
		// Unknown direction is intentionally excluded from asymmetry scoring.
	}

	if !st.isTCP() {
		d.applyPlanBPacketControlsLocked(st, p.Payload, p.Size, nowNS)
	}

	if !(st.isTCP() && st.pkts > 1) {
		d.applyTier1(st, p.Payload, p.Direction)
	}

	if !st.isTCP() {
		if st.lastSeenNS != 0 && nowNS > st.lastSeenNS {
			iatUnits := durationTo100us(time.Duration(nowNS - st.lastSeenNS))
			st.writeRing(iatUnits, uint16(size))
		} else {
			st.writeSizeOnly(uint16(size))
		}
		window := d.windowSize()
		if window > 0 && int(st.pkts) >= window && int(st.pkts)%window == 0 {
			d.recomputeTier2(st)
		}
	} else if st.pkts == 1 {
		_ = dirIdx
	}
	st.lastSeenNS = nowNS
}

func (d *RealtimeDetector) applyPlanBRTPStickyLockLocked(st *flowState, payload []byte) {
	if st == nil {
		return
	}
	if len(payload) > 0 && payload[0]&0xc0 == 0x80 {
		if st.flags&flagLiteLocked == 0 {
			st.flags |= flagLiteLocked
			d.planBLockins.Add(1)
		}
	}
}

func (d *RealtimeDetector) accountMigrationBytesLocked(flowID uint64, st *flowState, p ObservedPacket, nowNS int64) *migrationRequest {
	if d == nil || st == nil || st.isTCP() || flowID == 0 {
		return nil
	}
	d.applyPlanBRTPStickyLockLocked(st, p.Payload)
	size := p.Size
	if size < 0 {
		size = 0
	}
	size32 := uint32FromNonNegativeInt(size)
	st.totalBytes += uint64(size32)
	window := d.cfg.MigrationDebounceWindow
	threshold := d.cfg.MigrationWindowByteThreshold
	if window <= 0 || threshold == 0 {
		return nil
	}
	if st.windowStartNS == 0 || nowNS < st.windowStartNS || time.Duration(nowNS-st.windowStartNS) > window {
		st.windowStartNS = nowNS
		st.windowByteSum = size32
	} else {
		st.windowByteSum = satAddUint32(st.windowByteSum, size32)
	}
	if st.windowByteSum < threshold {
		return nil
	}
	windowBytes := st.windowByteSum
	totalBytes := st.totalBytes
	dst := ""
	if !d.cfg.MigrationEnabled {
		d.logMigrationAttempt(flowID, dst, windowBytes, totalBytes, 0, "skipped_disabled")
		return nil
	}
	if st.flags&flagLiteLocked != 0 {
		d.logMigrationAttempt(flowID, dst, windowBytes, totalBytes, 0, "skipped_rtp_locked")
		return nil
	}
	if st.migrated || st.migrating {
		return nil
	}
	v, ok := d.migrationDispatch.Load(flowID)
	if !ok {
		d.migrationSkippedNoHandle.Add(1)
		d.logMigrationAttempt(flowID, dst, windowBytes, totalBytes, 0, "skipped_no_handle")
		return nil
	}
	h, ok := v.(*migrationHandle)
	if !ok || h == nil {
		d.migrationSkippedNoHandle.Add(1)
		d.logMigrationAttempt(flowID, dst, windowBytes, totalBytes, 0, "skipped_no_handle")
		return nil
	}
	dst = h.dstAddr
	if !h.originalTransportLite {
		d.migrationSkippedV1.Add(1)
		d.logMigrationAttempt(flowID, dst, windowBytes, totalBytes, 0, "skipped_v1_single_transport")
		return nil
	}
	if totalBytes < d.cfg.MigrationCumulativeFloor {
		d.migrationSkippedFloor.Add(1)
		d.logMigrationAttempt(flowID, dst, windowBytes, totalBytes, 0, "skipped_below_floor")
		return nil
	}
	st.migrating = true
	return &migrationRequest{flowID: flowID, dstAddr: dst, windowBytes: windowBytes, totalBytes: totalBytes}
}

func (d *RealtimeDetector) applyPlanBPacketControlsLocked(st *flowState, payload []byte, size int, nowNS int64) {
	if st == nil || st.isTCP() {
		return
	}
	// ORDER MATTERS per spec: a single RTP/RTCP version byte locks the flow
	// before the same packet can be evaluated by the anti-bulk rate cap.
	d.applyPlanBRTPStickyLockLocked(st, payload)
	if st.flags&flagLiteLocked != 0 {
		return
	}
	if st.state != flowStateProvisionalRT && st.state != flowStateConfirmedRT {
		return
	}
	window := d.cfg.PlanBRateCapWindow
	bytesPerSec := d.cfg.PlanBRateCapBytesPerSec
	if window <= 0 || bytesPerSec <= 0 {
		return
	}
	if size < 0 {
		size = 0
	}
	if st.planBWindowStartNS == 0 || nowNS < st.planBWindowStartNS || time.Duration(nowNS-st.planBWindowStartNS) > window {
		st.planBWindowStartNS = nowNS
		st.planBWindowBytes = uint32FromNonNegativeInt(size)
	} else {
		st.planBWindowBytes = satAddUint32(st.planBWindowBytes, uint32FromNonNegativeInt(size))
	}
	limit := uint64(bytesPerSec) * uint64(window) / uint64(time.Second)
	if uint64(st.planBWindowBytes) > limit {
		st.state = flowStateConfirmedBulk
		d.planBDemotes.Add(1)
	}
}

func uint32FromNonNegativeInt(v int) uint32 {
	if v <= 0 {
		return 0
	}
	if uint64(v) > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v)
}

func (st *flowState) isTCP() bool {
	return st.proto == protoTCP || st.flags&flagTCP != 0
}

func satAddUint32(a, b uint32) uint32 {
	if ^uint32(0)-a < b {
		return ^uint32(0)
	}
	return a + b
}

func (d *RealtimeDetector) registerMigrationHandle(flowID uint64, h *migrationHandle) {
	if d == nil || flowID == 0 || h == nil {
		return
	}
	d.migrationDispatch.Store(flowID, h)
}

func (d *RealtimeDetector) deregisterMigrationHandle(flowID uint64) {
	if d == nil || flowID == 0 {
		return
	}
	d.migrationDispatch.Delete(flowID)
}

func (d *RealtimeDetector) runMigration(req *migrationRequest) {
	if d == nil || req == nil || req.flowID == 0 {
		return
	}
	started := time.Now()
	finish := func(outcome string, migrated bool) {
		duration := time.Since(started)
		d.finishMigrationState(req.flowID, migrated)
		if migrated {
			d.migrationDurationNanos.Add(uint64(duration.Nanoseconds()))
			d.migrationFires.Add(1)
		}
		d.logMigrationAttempt(req.flowID, req.dstAddr, req.windowBytes, req.totalBytes, duration, outcome)
	}

	v, ok := d.migrationDispatch.Load(req.flowID)
	if !ok {
		d.migrationSkippedNoHandle.Add(1)
		finish("skipped_no_handle", false)
		return
	}
	h, ok := v.(*migrationHandle)
	if !ok || h == nil {
		d.migrationSkippedNoHandle.Add(1)
		finish("skipped_no_handle", false)
		return
	}
	if req.dstAddr == "" {
		req.dstAddr = h.dstAddr
	}
	if !h.originalTransportLite {
		d.migrationSkippedV1.Add(1)
		finish("skipped_v1_single_transport", false)
		return
	}
	if h.ensureBulkFn != nil {
		if err := h.ensureBulkFn(); err != nil {
			d.migrationFailedNoBulk.Add(1)
			finish("error_no_bulk", false)
			return
		}
	}
	key := forceBulkCacheKeyFromAddress(h.dstAddr)
	if key != "" {
		d.forceBulkCache.Store(key, forceBulkEntry{untilNS: time.Now().Add(forceBulkCacheTTL).UnixNano()})
	}
	if h.fastCloseFn == nil {
		d.migrationFailedForceClose.Add(1)
		finish("error_force_close", false)
		return
	}
	if err := h.fastCloseFn(); err != nil {
		d.migrationFailedForceClose.Add(1)
		finish("error_force_close", false)
		return
	}
	if d.controller != nil {
		d.controller.ReleaseActive(req.flowID)
	}
	finish("migrated", true)
}

func (d *RealtimeDetector) finishMigrationState(flowID uint64, migrated bool) {
	if d == nil || flowID == 0 {
		return
	}
	d.mu.Lock()
	if st := d.flows[flowID]; st != nil {
		st.migrating = false
		if migrated {
			st.migrated = true
			st.state = flowStateConfirmedBulk
		}
	}
	d.mu.Unlock()
}

func (d *RealtimeDetector) logMigrationAttempt(flowID uint64, dst string, windowBytes uint32, totalBytes uint64, duration time.Duration, outcome string) {
	log.Printf("[tamizdat] migration: flowID=%d dst=%s window_bytes=%d total_bytes=%d duration_ms=%d outcome=%s",
		flowID, dst, windowBytes, totalBytes, duration.Milliseconds(), outcome)
}

func durationTo100us(d time.Duration) uint16 {
	if d <= 0 {
		return 0
	}
	u := d / (100 * time.Microsecond)
	if u > 65535 {
		return 65535
	}
	if u == 0 {
		return 1
	}
	return uint16(u)
}

func (st *flowState) writeSizeOnly(size uint16) {
	idx := st.ringHead & 15
	st.sizeRing[idx] = size
	if st.ringLen < 16 {
		st.ringLen++
	}
	st.ringHead = (st.ringHead + 1) & 15
}

func (st *flowState) writeRing(iat, size uint16) {
	idx := st.ringHead & 15
	st.iatRing[idx] = iat
	st.sizeRing[idx] = size
	if st.ringLen < 16 {
		st.ringLen++
	}
	st.ringHead = (st.ringHead + 1) & 15
}

func (d *RealtimeDetector) windowSize() int {
	if d.cfg.SmoothnessSamples > 0 {
		return d.cfg.SmoothnessSamples
	}
	return 5
}

func (d *RealtimeDetector) smoothWindowCap() int {
	if d.cfg.SmoothnessWindows > 0 {
		return d.cfg.SmoothnessWindows
	}
	return 2
}

func (d *RealtimeDetector) recomputeTier2(st *flowState) {
	if st.ringLen == 0 {
		return
	}
	count := int(st.ringLen)
	window := d.windowSize()
	if count > window {
		count = window
	}
	if count <= 0 {
		return
	}
	var sumIAT uint32
	var maxSize uint16
	var sumSize uint32
	var mtuCount int
	validIATs := 0
	outsideBand := false
	for i := 0; i < count; i++ {
		idx := int(st.ringHead+16-uint8(1+i)) & 15
		iat := uint32(st.iatRing[idx])
		sz := st.sizeRing[idx]
		if iat > 0 {
			validIATs++
			sumIAT += iat
			if iat < defaultIatBandLowUnits || iat > defaultIatBandHighUnits {
				outsideBand = true
			}
		}
		sumSize += uint32(sz)
		if sz > maxSize {
			maxSize = sz
		}
		if sz >= 1300 {
			mtuCount++
		}
	}
	if validIATs == 0 {
		return
	}
	meanIAT := sumIAT / uint32(validIATs)
	if meanIAT == 0 {
		meanIAT = 1
	}
	var absDevSum uint32
	for i := 0; i < count; i++ {
		idx := int(st.ringHead+16-uint8(1+i)) & 15
		iat := uint32(st.iatRing[idx])
		if iat == 0 {
			continue
		}
		if iat > meanIAT {
			absDevSum += iat - meanIAT
		} else {
			absDevSum += meanIAT - iat
		}
	}
	dev := absDevSum / uint32(validIATs)
	devQ16 := dev << 16
	alpha := uint32(d.cfg.JitterAlphaInv)
	if alpha == 0 {
		alpha = 16
	}
	if st.jitterQ16 == 0 {
		st.jitterQ16 = devQ16
	} else if devQ16 > st.jitterQ16 {
		st.jitterQ16 += (devQ16 - st.jitterQ16) / alpha
	} else {
		st.jitterQ16 -= (st.jitterQ16 - devQ16) / alpha
	}

	smooth := !outsideBand && jitterWithin(st.jitterQ16, meanIAT, d.smoothJitterPermille)
	if smooth {
		if st.smoothWins < 8 {
			st.smoothWins++
		}
		st.failedWins = 0
	} else {
		if st.failedWins < 4 {
			st.failedWins++
		}
	}
	tight := smooth && meanIAT >= tightIatLowUnits && meanIAT <= tightIatHighUnits && jitterWithin(st.jitterQ16, meanIAT, d.tightJitterPermille)
	if tight {
		st.t2Flags |= t2SeenOpus
	}

	meanSize := sumSize / uint32(count)
	small := meanSize <= 250 && maxSize <= 600
	mtuBulk := meanIAT > defaultIatBandHighUnits && mtuCount*100 >= count*70

	score := int32(0)
	smoothWins := int(st.smoothWins)
	capWins := d.smoothWindowCap()
	if capWins > 2 && d.cfg.SmoothnessWindows == 2 {
		capWins = 2
	}
	if smoothWins > capWins {
		smoothWins = capWins
	}
	score += int32(smoothWins) * int32(d.cfg.SmoothWindowScoreQ8)
	if st.t2Flags&t2SeenOpus != 0 {
		score += int32(d.cfg.OpusBonusScoreQ8)
	}
	if small {
		score += int32(d.cfg.SmallPktScoreQ8)
	}
	if mtuBulk {
		score += int32(d.cfg.MtuBulkScoreQ8)
	}
	if st.pkts >= 30 {
		total := uint64(st.bytesUp) + uint64(st.bytesDown)
		if total > 0 {
			up := uint64(st.bytesUp) * 100
			if up >= total*30 && up <= total*70 {
				score += int32(d.cfg.DirSymmetryScoreQ8)
			} else if up < total*5 || up > total*95 {
				score += int32(d.cfg.DirAsymmetryScoreQ8)
			}
		}
	}
	failed := int(st.failedWins)
	if failed > 3 {
		failed = 3
	}
	score += int32(failed) * int32(d.cfg.CadenceBreakScoreQ8)
	st.scoreT2 = clampInt16(score, tier2MinQ8, tier2MaxQ8)
}

func jitterWithin(jitterQ16 uint32, meanUnits uint32, permille int64) bool {
	if meanUnits == 0 {
		return false
	}
	left := uint64(jitterQ16) * 1000
	right := uint64(meanUnits) * 65536 * uint64(permille)
	return left <= right
}

func (d *RealtimeDetector) applyTier1(st *flowState, payload []byte, dir Direction) {
	if len(payload) == 0 {
		return
	}
	if looksLikeSTUN(payload) && st.t1Flags&t1SeenSTUN == 0 {
		st.t1Flags |= t1SeenSTUN
		d.addTier1(st, d.cfg.StunScoreQ8)
		st.flags |= flagStrongPrefix
	}
	if looksLikeTURNChannelData(payload) && st.t1Flags&t1SeenTURN == 0 {
		st.t1Flags |= t1SeenTURN
		d.addTier1(st, d.cfg.TurnChannelDataScoreQ8)
		st.flags |= flagStrongPrefix
	}
	if looksLikeDTLSRecord(payload, 0x14, 0x15, 0x16) && st.t1Flags&t1SeenDTLSHandshake == 0 {
		st.t1Flags |= t1SeenDTLSHandshake
		d.addTier1(st, d.cfg.DtlsHandshakeScoreQ8)
		st.flags |= flagStrongPrefix
	}
	if looksLikeDTLSRecord(payload, 0x17) && st.t1Flags&t1SeenDTLSApp == 0 {
		st.t1Flags |= t1SeenDTLSApp
		d.addTier1(st, d.cfg.DtlsAppDataScoreQ8)
	}
	if looksLikeRTCP(payload) && st.t1Flags&t1SeenRTCP == 0 {
		st.t1Flags |= t1SeenRTCP
		d.addTier1(st, d.cfg.RtcpScoreQ8)
	}
	if validRTPCandidate(payload) {
		if st.t1Flags&t1SeenRTPCandidate == 0 && st.t1Flags&t1SeenRTPConfirmed == 0 {
			st.t1Flags |= t1SeenRTPCandidate
			d.addTier1(st, d.cfg.RtpCandidateScoreQ8)
		}
		d.updateRTPValidation(st, payload, dir)
	}
	if looksLikeQUICLongHeader(payload) && st.t1Flags&t1SeenQUIC == 0 {
		st.t1Flags |= t1SeenQUIC
		d.addTier1(st, d.cfg.QuicLongHeaderScoreQ8)
	}
	if st.pkts <= 3 && looksLikeTLSLargeAppData(payload) && st.t1Flags&t1SeenTLSLarge == 0 {
		st.t1Flags |= t1SeenTLSLarge
		d.addTier1(st, d.cfg.TlsLargeAppDataScoreQ8)
	}
}

func (d *RealtimeDetector) updateRTPValidation(st *flowState, payload []byte, dir Direction) {
	idx := 0
	if dir == DirInbound {
		idx = 1
	}
	ssrc := binary.BigEndian.Uint32(payload[8:12])
	seq := binary.BigEndian.Uint16(payload[2:4])
	if st.rtpRunLen[idx] == 0 || st.rtpSSRC[idx] != ssrc {
		st.rtpSSRC[idx] = ssrc
		st.rtpSeq[idx] = seq
		st.rtpRunLen[idx] = 1
		return
	}
	delta := uint16(seq - st.rtpSeq[idx])
	st.rtpSeq[idx] = seq
	if delta >= 1 && delta <= 4 {
		if st.rtpRunLen[idx] < 8 {
			st.rtpRunLen[idx]++
		}
	} else {
		st.rtpRunLen[idx] = 1
	}
	if st.rtpRunLen[idx] >= 3 && st.t1Flags&t1SeenRTPConfirmed == 0 {
		st.t1Flags |= t1SeenRTPConfirmed
		deltaScore := d.cfg.RtpConfirmedScoreQ8
		if st.t1Flags&t1SeenRTPCandidate != 0 {
			deltaScore -= d.cfg.RtpCandidateScoreQ8
		}
		d.addTier1(st, deltaScore)
	}
}

func (d *RealtimeDetector) addTier1(st *flowState, delta int16) {
	st.scoreT1 = clampInt16(int32(st.scoreT1)+int32(delta), tier1MinQ8, tier1MaxQ8)
}

func (d *RealtimeDetector) transitionState(st *flowState, now time.Time) bool {
	nowNS := now.UnixNano()
	if st.openTimeNS == 0 {
		st.openTimeNS = nowNS
	}
	age := time.Duration(nowNS - st.openTimeNS)
	if age < 0 {
		age = 0
	}
	score := st.totalScoreQ8()
	promoted := false
	confirm := func() {
		if st.state != flowStateConfirmedRT {
			st.state = flowStateConfirmedRT
			st.confirmedNS = nowNS
			st.lastInterNS = nowNS
			promoted = true
		}
	}
	realtimeReady := func() bool {
		return (score >= d.promoteQ8 && age >= d.cfg.MinPromoteAge) || d.cadenceConfirmed(st, score)
	}
	switch st.state {
	case flowStateNew:
		if score >= d.watchQ8 || st.flags&flagStrongPrefix != 0 {
			st.state = flowStateProvisionalRT
			if realtimeReady() {
				confirm()
			}
		} else {
			st.state = flowStateProvisionalBulk
		}
	case flowStateProvisionalBulk:
		if score >= d.watchQ8 {
			st.state = flowStateProvisionalRT
			if realtimeReady() {
				confirm()
			}
		} else if score < d.demoteQ8 {
			if st.lowScorePkts < 255 {
				st.lowScorePkts++
			}
			if st.lowScorePkts >= 5 || age >= d.cfg.BulkConfirmAge {
				st.state = flowStateConfirmedBulk
			}
		} else {
			st.lowScorePkts = 0
		}
	case flowStateProvisionalRT:
		if realtimeReady() {
			confirm()
		} else if score < d.demoteQ8 && age >= d.cfg.SilentDemoteAge {
			st.state = flowStateProvisionalBulk
			st.lowScorePkts = 0
		}
	case flowStateConfirmedRT:
		if st.flags&flagLiteLocked == 0 && score <= d.demoteQ8 && age >= 30*time.Second {
			st.state = flowStateProvisionalBulk
			st.lowScorePkts = 0
		}
	case flowStateConfirmedBulk:
		// Anti-flap pin: no transitions out.
	}
	return promoted
}

// cadenceConfirmed is a design rule (not a spec deviation): if a flow has
// observed N consecutive smooth-cadence windows AND the Opus signature
// (20-30 ms IAT, small frames), AND total score is at least watchQ8 (+0.30),
// AND scoreT2 is positive — then promote to CONFIRMED_RT even though the
// raw score has not crossed the +0.55 promote threshold. Rationale: Tier 2
// is capped at +0.45 (per spec §9); a pure voice/game flow with no Tier 1
// payload signature and only a UDP prior in Tier 3 (+0.05) maxes out at
// 0.50, one tick below promote. The smoothness windows + Opus flag provide
// the missing corroboration that a single high score otherwise would.
// Reconciles spec §3.2 narrative (+0.50 cap mentioned) vs §9 table (+115
// = +0.45). Documented under deviations_from_spec; spec amendment pending.
func (d *RealtimeDetector) cadenceConfirmed(st *flowState, score int16) bool {
	if st == nil || st.isTCP() || score < d.watchQ8 || st.scoreT2 <= 0 {
		return false
	}
	need := d.smoothWindowCap()
	if need <= 0 {
		need = 2
	}
	return int(st.smoothWins) >= need && st.t2Flags&t2SeenOpus != 0
}

func (st *flowState) totalScoreQ8() int16 {
	score := int32(st.scoreT1) + int32(st.scoreT2) + int32(st.scoreT3)*16
	return clampInt16(score, -256, 512)
}

func clampInt16(v int32, lo, hi int16) int16 {
	if v < int32(lo) {
		return lo
	}
	if v > int32(hi) {
		return hi
	}
	return int16(v)
}

func clampInt8(v int32, lo, hi int8) int8 {
	if v < int32(lo) {
		return lo
	}
	if v > int32(hi) {
		return hi
	}
	return int8(v)
}

func (d *RealtimeDetector) hasRealtimePort(port int) bool {
	_, ok := d.ports[port]
	return ok
}

func (d *RealtimeDetector) tier3ScoreLocked(meta FlowMeta, endpoint endpointInfo, knownPort, appHint bool, now time.Time) int8 {
	var score int32
	if appHint {
		score += int32(d.cfg.AppHintScoreQ4)
	}
	if knownPort {
		score += int32(d.cfg.KnownPortScoreQ4)
	}
	if d.endpointCacheHitLocked(endpoint, now) {
		score += int32(d.cfg.EndpointCacheHitScoreQ4)
	}
	if meta.Network == "udp" {
		score += int32(d.cfg.UdpPriorScoreQ4)
	}
	if meta.Network == "tcp" && (meta.Port == 80 || meta.Port == 443 || meta.Port == 8080 || meta.Port == 8443) {
		score += int32(d.cfg.TcpBulkPortScoreQ4)
	}
	return clampInt8(score, tier3MinQ4, tier3MaxQ4)
}

func endpointFromMeta(meta FlowMeta) endpointInfo {
	host := strings.ToLower(strings.TrimSpace(meta.Host))
	if host == "" {
		host = strings.ToLower(strings.TrimSpace(meta.Address))
	}
	ep := endpointInfo{host: host}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			ep.prefix24 = uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8
			ep.hasPrefix = true
		}
	}
	return ep
}

func (d *RealtimeDetector) endpointCacheHitLocked(ep endpointInfo, now time.Time) bool {
	if d.cfg.EndpointCacheTTL <= 0 {
		return false
	}
	cutoff := now.Add(-d.cfg.EndpointCacheTTL).UnixNano()
	if ep.hasPrefix {
		if ts, ok := d.endpointByPref[ep.prefix24]; ok && ts >= cutoff {
			return true
		}
	}
	if ep.host != "" {
		if ts, ok := d.endpointByHost[ep.host]; ok && ts >= cutoff {
			return true
		}
	}
	return false
}

func (d *RealtimeDetector) rememberEndpointLocked(ep endpointInfo, now time.Time) {
	ts := now.UnixNano()
	if ep.hasPrefix {
		d.endpointByPref[ep.prefix24] = ts
	}
	if ep.host != "" {
		d.endpointByHost[ep.host] = ts
	}
}

func (d *RealtimeDetector) enqueuePendingLocked(p pendingOpen) {
	if len(d.pending) >= 128 {
		copy(d.pending, d.pending[1:])
		d.pending[len(d.pending)-1] = p
		return
	}
	d.pending = append(d.pending, p)
}

func (d *RealtimeDetector) bindOpen(flowID uint64, class TrafficClass) {
	if d == nil || flowID == 0 {
		return
	}
	now := time.Now()
	d.mu.Lock()
	var st flowState
	var ep endpointInfo
	if len(d.pending) > 0 {
		p := d.pending[0]
		copy(d.pending, d.pending[1:])
		d.pending = d.pending[:len(d.pending)-1]
		if now.Sub(p.created) <= 5*time.Second {
			st = p.st
			ep = p.endpoint
		}
	}
	if st.openTimeNS == 0 {
		st = flowState{openTimeNS: now.UnixNano(), lastInterNS: now.UnixNano(), state: flowStateProvisionalBulk, proto: protoUDP}
		if class == TrafficRealtime {
			st.state = flowStateConfirmedRT
			st.confirmedNS = now.UnixNano()
		}
	}
	if class == TrafficRealtime && st.state == flowStateNew {
		st.state = flowStateProvisionalRT
	}
	d.addFlowLocked(flowID, &st, ep)
	d.mu.Unlock()
}

func (d *RealtimeDetector) addFlowLocked(flowID uint64, st *flowState, ep endpointInfo) {
	if d.cfg.MaxConcurrentFlows > 0 {
		for len(d.flows) >= d.cfg.MaxConcurrentFlows {
			if !d.evictOldestLocked() {
				break
			}
		}
	}
	d.flows[flowID] = st
	if ep.host != "" || ep.hasPrefix {
		d.flowEndpoints[flowID] = ep
	}
	d.flowOrder = append(d.flowOrder, flowID)
}

func (d *RealtimeDetector) evictOldestLocked() bool {
	for d.flowOrderHead < len(d.flowOrder) {
		id := d.flowOrder[d.flowOrderHead]
		d.flowOrderHead++
		if _, ok := d.flows[id]; ok {
			delete(d.flows, id)
			delete(d.flowEndpoints, id)
			if d.flowOrderHead > 1024 && d.flowOrderHead*2 > len(d.flowOrder) {
				d.flowOrder = append([]uint64(nil), d.flowOrder[d.flowOrderHead:]...)
				d.flowOrderHead = 0
			}
			return true
		}
	}
	return false
}

func (d *RealtimeDetector) Forget(flowID uint64) {
	if d == nil || flowID == 0 {
		return
	}
	d.mu.Lock()
	delete(d.flows, flowID)
	delete(d.flowEndpoints, flowID)
	d.mu.Unlock()
	d.deregisterMigrationHandle(flowID)
}

func (d *RealtimeDetector) Score(flowID uint64) float64 {
	if d == nil || flowID == 0 {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if st := d.flows[flowID]; st != nil {
		return float64(st.totalScoreQ8()) / 256.0
	}
	return 0
}

func (d *RealtimeDetector) markFlowTCP(flowID uint64) {
	if d == nil || flowID == 0 {
		return
	}
	d.mu.Lock()
	st := d.flows[flowID]
	if st == nil {
		now := time.Now().UnixNano()
		initial := flowState{openTimeNS: now, lastInterNS: now, state: flowStateProvisionalBulk, proto: protoTCP, flags: flagTCP}
		d.addFlowLocked(flowID, &initial, endpointInfo{})
	} else {
		st.proto = protoTCP
		st.flags |= flagTCP
	}
	d.mu.Unlock()
}

func (d *RealtimeDetector) setController(c *RealtimeController) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.controller = c
	d.mu.Unlock()
	d.cleanupStarted.Do(func() {
		go d.cleanupLoop()
	})
}

func (d *RealtimeDetector) cleanupLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for now := range t.C {
		d.sweepIdle(now)
	}
}

func (d *RealtimeDetector) sweepIdle(now time.Time) {
	if d == nil {
		return
	}
	var release []uint64
	d.mu.Lock()
	for id, st := range d.flows {
		if st.state != flowStateConfirmedRT || st.flags&flagIdleReleased != 0 {
			continue
		}
		last := st.lastInterNS
		if last == 0 {
			last = st.confirmedNS
		}
		if last == 0 {
			last = st.lastSeenNS
		}
		if last != 0 && now.Sub(time.Unix(0, last)) >= d.cfg.IdleReleaseAge {
			st.flags |= flagIdleReleased
			release = append(release, id)
		}
	}
	c := d.controller
	d.mu.Unlock()
	if c != nil {
		for _, id := range release {
			c.ReleaseActive(id)
		}
	}
}

func (d *RealtimeDetector) sweepIdleForTest(now time.Time) { d.sweepIdle(now) }

func (d *RealtimeDetector) pendingOpenStateForTest() flowState {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.pending) == 0 {
		return flowState{}
	}
	return d.pending[len(d.pending)-1].st
}

func (d *RealtimeDetector) expireEndpointCacheForTest(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg.EndpointCacheTTL <= 0 {
		clear(d.endpointByPref)
		clear(d.endpointByHost)
		return
	}
	cutoff := now.Add(-d.cfg.EndpointCacheTTL).UnixNano()
	for k, ts := range d.endpointByPref {
		if ts <= cutoff || ts > now.UnixNano() {
			delete(d.endpointByPref, k)
		}
	}
	for k, ts := range d.endpointByHost {
		if ts <= cutoff || ts > now.UnixNano() {
			delete(d.endpointByHost, k)
		}
	}
}

func looksLikeRealtimeMagic(payload []byte) bool {
	return looksLikeSTUN(payload) || looksLikeRTP(payload)
}

func looksLikeSTUN(payload []byte) bool {
	return len(payload) >= 20 && payload[0]&0xc0 == 0 && binary.BigEndian.Uint32(payload[4:8]) == 0x2112a442
}

func looksLikeTURNChannelData(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	ch := binary.BigEndian.Uint16(payload[0:2])
	ln := int(binary.BigEndian.Uint16(payload[2:4]))
	return payload[0]&0xc0 == 0x40 && ch >= 0x4000 && ch <= 0x7fff && ln <= len(payload)-4
}

func looksLikeDTLSRecord(payload []byte, types ...byte) bool {
	if len(payload) < 13 || payload[1] != 0xfe {
		return false
	}
	if payload[2] != 0xfd && payload[2] != 0xff && payload[2] != 0xfc {
		return false
	}
	for _, typ := range types {
		if payload[0] == typ {
			return true
		}
	}
	return false
}

func validRTPCandidate(payload []byte) bool {
	if len(payload) < 12 || len(payload) > 1500 || payload[0]&0xc0 != 0x80 {
		return false
	}
	pt := payload[1] & 0x7f
	return pt <= 34 || (pt >= 96 && pt <= 127)
}

func looksLikeRTP(payload []byte) bool {
	return len(payload) >= 12 && payload[0]&0xc0 == 0x80
}

func looksLikeRTCP(payload []byte) bool {
	return len(payload) >= 8 && payload[0]&0xc0 == 0x80 && payload[1] >= 200 && payload[1] <= 211
}

func looksLikeQUICLongHeader(payload []byte) bool {
	if len(payload) < 7 || payload[0]&0xc0 != 0xc0 {
		return false
	}
	ver := binary.BigEndian.Uint32(payload[1:5])
	known := ver == 0x00000001 || ver == 0x00000000 || ver == 0x6b3343cf || ver == 0x709a50c4
	grease := payload[1]&0x0f == 0x0a
	return known || grease
}

func looksLikeTLSLargeAppData(payload []byte) bool {
	if len(payload) < 5 || payload[0] != 0x17 || payload[1] != 0x03 {
		return false
	}
	if payload[2] != 0x01 && payload[2] != 0x03 && payload[2] != 0x04 {
		return false
	}
	return binary.BigEndian.Uint16(payload[3:5]) >= 1300
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
	return newRealtimeControllerWithConfig(newRealtimeDetector(), 15*time.Second, 30*time.Second)
}

func newRealtimeControllerWithConfig(detector *RealtimeDetector, hysteresisMin, hysteresisMax time.Duration) *RealtimeController {
	if detector == nil {
		detector = newRealtimeDetector()
	}
	if hysteresisMin <= 0 {
		hysteresisMin = 15 * time.Second
	}
	if hysteresisMax < hysteresisMin {
		hysteresisMax = hysteresisMin
	}
	c := &RealtimeController{Detector: detector, flowMap: make(map[uint64]TrafficClass), hysteresisMin: hysteresisMin, hysteresisMax: hysteresisMax}
	c.mode.Store(int32(ShapeFull))
	detector.setController(c)
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
	if c.Detector != nil {
		c.Detector.bindOpen(flowID, class)
	}
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
	setRealtimeFlowsActive(c.activeRealtimeCount)
	onRealtimeOpen := c.onRealtimeOpen
	c.mu.Unlock()
	if callOpen {
		onRealtimeOpen()
	}
}

func (c *RealtimeController) ReleaseActive(flowID uint64) {
	if c == nil || flowID == 0 {
		return
	}
	callLastClose := false
	c.mu.Lock()
	oldClass, ok := c.flowMap[flowID]
	if ok && oldClass == TrafficRealtime && c.activeRealtimeCount > 0 {
		c.flowMap[flowID] = TrafficBulk
		c.activeRealtimeCount--
		if c.activeRealtimeCount == 0 {
			c.armHysteresisLocked()
			callLastClose = c.onLastRealtimeClose != nil
		}
	}
	setRealtimeFlowsActive(c.activeRealtimeCount)
	onLastRealtimeClose := c.onLastRealtimeClose
	c.mu.Unlock()
	if callLastClose {
		onLastRealtimeClose()
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

func (c *RealtimeController) observe(flowID uint64, payload []byte) {
	c.observePacketAt(flowID, payload, DirUnknown, time.Now())
}

func (c *RealtimeController) observePacket(flowID uint64, payload []byte, dir Direction) {
	c.observePacketAt(flowID, payload, dir, time.Now())
}

func (c *RealtimeController) observePacketAt(flowID uint64, payload []byte, dir Direction, at time.Time) {
	if c == nil || c.Detector == nil || flowID == 0 {
		return
	}
	if c.Detector.Observe(ObservedPacket{FlowID: flowID, At: at, Payload: payload, Size: len(payload), Direction: dir}) == TrafficRealtime {
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
	if controller.Detector != nil {
		controller.Detector.markFlowTCP(flowID)
	}
	return &realtimeTrackedConn{Conn: conn, controller: controller, flowID: flowID}
}

func (c *realtimeTrackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.controller.observePacket(c.flowID, p[:n], DirUnknown)
	}
	return n, err
}

func (c *realtimeTrackedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.controller.observePacket(c.flowID, p[:n], DirUnknown)
	}
	return n, err
}

func (c *realtimeTrackedConn) Close() error {
	var err error
	c.closeOnce.Do(func() { c.controller.Close(c.flowID); err = c.Conn.Close() })
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
		c.controller.observePacket(c.flowID, p[:n], DirInbound)
	}
	return n, addr, err
}

func (c *realtimeTrackedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n > 0 {
		c.controller.observePacket(c.flowID, p[:n], DirOutbound)
	}
	return n, err
}

func (c *realtimeTrackedPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.controller != nil {
			c.controller.Close(c.flowID)
			if c.controller.Detector != nil {
				c.controller.Detector.deregisterMigrationHandle(c.flowID)
			}
		}
		err = c.PacketConn.Close()
	})
	return err
}

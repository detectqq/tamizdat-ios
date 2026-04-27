package bbcr

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	MaxEpochLag                 uint32        = 8
	DefaultMaxSessionsPerID     int           = 16
	DefaultMaxStreamsPerSession int           = 100
	DefaultRebindTimeout        time.Duration = 5 * time.Second
	DefaultDrainTimeout         time.Duration = 5 * time.Second
	DefaultSessionIdleTimeout   time.Duration = 60 * time.Second

	RebindModeRequest uint8 = 0
	RebindModeAccept  uint8 = 1
	RebindModeReject  uint8 = 2
)

var (
	ErrFirstFrameNotRebind           = errors.New("bbcr: first frame is not REBIND")
	ErrInvalidEpoch                  = errors.New("bbcr: invalid transport epoch")
	ErrStaleEpoch                    = errors.New("bbcr: stale transport epoch")
	ErrPreviousEpochMismatch         = errors.New("bbcr: previous epoch mismatch")
	ErrAuthBindingFailed             = errors.New("bbcr: auth binding failed")
	ErrSessionCollision              = errors.New("bbcr: active session collision")
	ErrSessionLimit                  = errors.New("bbcr: session limit exceeded")
	ErrMaxStreamsPerSession          = errors.New("bbcr: max streams per session exceeded")
	ErrSessionNotActive              = errors.New("bbcr: session not active")
	ErrSessionClosed                 = errors.New("bbcr: session closed")
	ErrSessionUnknown                = errors.New("bbcr: session unknown")
	ErrAuthRevoked                   = errors.New("bbcr: auth revoked")
	ErrClientHelloFingerprintChanged = errors.New("bbcr: clienthello fingerprint changed within session")
)

type AuthIdentity [8]byte

type SessionKey struct {
	AuthIdentity AuthIdentity
	SessionID    uint64
}

type SessionState int

const (
	SessionInitializing SessionState = iota
	SessionActive
	SessionSuspect
	SessionCautious
	SessionPinnedCautious
	SessionTeardown
)

type SessionManagerConfig struct {
	Clock                  Clock
	MaxSessionsPerIdentity int
	MaxStreamsPerSession   int
	RebindTimeout          time.Duration
	DrainTimeout           time.Duration
	IdleTimeout            time.Duration
}

type SessionConfig struct {
	Key          SessionKey
	Clock        Clock
	MaxStreams   int
	DrainTimeout time.Duration
	IdleTimeout  time.Duration
	OnClose      func(SessionKey)
}

type SessionManager struct {
	mu       sync.Mutex
	clock    Clock
	maxSess  int
	maxStr   int
	rebindTO time.Duration
	drainTO  time.Duration
	idleTO   time.Duration
	sessions map[SessionKey]*Session
	revoked  map[AuthIdentity]bool
}

func NewSessionManager(cfg SessionManagerConfig) *SessionManager {
	return &SessionManager{
		clock: clockOrReal(cfg.Clock), maxSess: positiveInt(cfg.MaxSessionsPerIdentity, DefaultMaxSessionsPerID), maxStr: positiveInt(cfg.MaxStreamsPerSession, DefaultMaxStreamsPerSession),
		rebindTO: positiveDuration(cfg.RebindTimeout, DefaultRebindTimeout), drainTO: positiveDuration(cfg.DrainTimeout, DefaultDrainTimeout), idleTO: positiveDuration(cfg.IdleTimeout, DefaultSessionIdleTimeout),
		sessions: make(map[SessionKey]*Session), revoked: make(map[AuthIdentity]bool),
	}
}

func clockOrReal(c Clock) Clock {
	if c != nil {
		return c
	}
	return RealClock{}
}
func positiveInt(v, d int) int {
	if v > 0 {
		return v
	}
	return d
}
func positiveDuration(v, d time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return d
}

func (m *SessionManager) AttachTransport(ctx context.Context, auth AuthIdentity, tr *OuterTransport, first Frame) (*Session, error) {
	return m.AttachTransportWithFingerprint(ctx, auth, tr, first, "")
}

func (m *SessionManager) AttachTransportWithFingerprint(ctx context.Context, auth AuthIdentity, tr *OuterTransport, first Frame, fingerprint string) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if tr == nil {
		tr = NewOuterTransport(OuterTransportConfig{Epoch: first.Header.TransportEpoch, Clock: m.clock})
	}
	reject := func(err error) (*Session, error) { _ = tr.Close(err); return nil, err }
	tr.ArmRebindTimeout(m.rebindTO, nil)
	if first.Header.Type != FrameREBIND {
		return reject(ErrFirstFrameNotRebind)
	}
	if first.Header.TransportEpoch == 0 {
		return reject(ErrInvalidEpoch)
	}
	first.Header = normalizeHeaderForMarshal(first.Header, len(first.Payload))
	if err := ValidateFrame(first.Header, len(first.Payload), DecodeOptions{}); err != nil {
		return reject(err)
	}
	payload, err := ParseRebind(first.Payload)
	if err != nil {
		return reject(err)
	}
	key := SessionKey{AuthIdentity: auth, SessionID: first.Header.SessionID}

	m.mu.Lock()
	if m.revoked[auth] {
		m.mu.Unlock()
		return reject(ErrAuthRevoked)
	}
	s, exists := m.sessions[key]
	if payload.PreviousEpoch == 0 {
		if first.Header.TransportEpoch != 1 {
			m.mu.Unlock()
			return reject(ErrPreviousEpochMismatch)
		}
		if exists && s.State() != SessionTeardown {
			m.mu.Unlock()
			return reject(ErrSessionCollision)
		}
		if m.sessionsForIdentityLocked(auth) >= m.maxSess {
			m.mu.Unlock()
			return reject(ErrSessionLimit)
		}
		s = NewSession(SessionConfig{Key: key, Clock: m.clock, MaxStreams: m.maxStr, DrainTimeout: m.drainTO, IdleTimeout: m.idleTO, OnClose: m.removeSession})
		m.sessions[key] = s
	} else {
		if !exists {
			if m.hasSessionIDLocked(first.Header.SessionID) {
				m.mu.Unlock()
				return reject(ErrAuthBindingFailed)
			}
			m.mu.Unlock()
			return reject(ErrSessionUnknown)
		}
	}
	m.mu.Unlock()

	if err := s.attachRebind(ctx, tr, first, payload, fingerprint); err != nil {
		return reject(err)
	}
	return s, nil
}

func (m *SessionManager) Get(key SessionKey) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[key]
	return s, ok
}

func (m *SessionManager) RevokeAuth(auth AuthIdentity) {
	m.mu.Lock()
	m.revoked[auth] = true
	var doomed []*Session
	for k, s := range m.sessions {
		if k.AuthIdentity == auth {
			doomed = append(doomed, s)
		}
	}
	m.mu.Unlock()
	for _, s := range doomed {
		_ = s.Close(ErrAuthRevoked)
	}
}

func (m *SessionManager) SessionCount() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.sessions) }

func (m *SessionManager) removeSession(key SessionKey) {
	m.mu.Lock()
	delete(m.sessions, key)
	m.mu.Unlock()
}

func (m *SessionManager) sessionsForIdentityLocked(auth AuthIdentity) int {
	count := 0
	for k, s := range m.sessions {
		if k.AuthIdentity == auth && s.State() != SessionTeardown {
			count++
		}
	}
	return count
}

func (m *SessionManager) hasSessionIDLocked(sessionID uint64) bool {
	for k, s := range m.sessions {
		if k.SessionID == sessionID && s.State() != SessionTeardown {
			return true
		}
	}
	return false
}

type Session struct {
	mu           sync.Mutex
	key          SessionKey
	clock        Clock
	maxStreams   int
	drainTO      time.Duration
	idleTO       time.Duration
	onClose      func(SessionKey)
	state        SessionState
	lastEpoch    uint32
	transports   map[uint32]*OuterTransport
	streams      map[uint32]*Stream
	idleTimer    Timer
	fingerprint  string
	scheduler    *Scheduler
	detectorStop chan struct{}
	closed       bool
}

func NewSession(cfg SessionConfig) *Session {
	return &Session{
		key: cfg.Key, clock: clockOrReal(cfg.Clock), maxStreams: positiveInt(cfg.MaxStreams, DefaultMaxStreamsPerSession),
		drainTO: positiveDuration(cfg.DrainTimeout, DefaultDrainTimeout), idleTO: positiveDuration(cfg.IdleTimeout, DefaultSessionIdleTimeout), onClose: cfg.OnClose,
		state: SessionInitializing, transports: make(map[uint32]*OuterTransport), streams: make(map[uint32]*Stream),
	}
}

func (s *Session) Key() SessionKey           { return s.key }
func (s *Session) State() SessionState       { s.mu.Lock(); defer s.mu.Unlock(); return s.state }
func (s *Session) LastAcceptedEpoch() uint32 { s.mu.Lock(); defer s.mu.Unlock(); return s.lastEpoch }
func (s *Session) StreamCount() int          { s.mu.Lock(); defer s.mu.Unlock(); return len(s.streams) }
func (s *Session) TransportCount() int       { s.mu.Lock(); defer s.mu.Unlock(); return len(s.transports) }

func (s *Session) Scheduler() *Scheduler {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scheduler
}

func (s *Session) EnsureScheduler(cfg SchedulerConfig) *Scheduler {
	s.mu.Lock()
	if s.scheduler != nil {
		sched := s.scheduler
		s.mu.Unlock()
		return sched
	}
	transports := make([]Transport, 0, len(s.transports))
	for _, tr := range s.transports {
		transports = append(transports, tr)
	}
	cfg.Transports = append(cfg.Transports, transports...)
	sched := NewScheduler(cfg)
	stop := make(chan struct{})
	s.scheduler = sched
	s.detectorStop = stop
	s.mu.Unlock()
	go s.detectorLoop(sched, stop)
	return sched
}

func (s *Session) TotalUnackedBytes() uint64 {
	s.mu.Lock()
	streams := make([]*Stream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.mu.Unlock()
	var total uint64
	for _, st := range streams {
		total += st.UnackedBytes()
	}
	return total
}

func (s *Session) detectorLoop(sched *Scheduler, stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			sched.CheckACKStall(s.TotalUnackedBytes())
			sched.CheckCleanExit()
		case <-stop:
			return
		}
	}
}

func (s *Session) TransportState(epoch uint32) TransportState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tr, ok := s.transports[epoch]; ok {
		return tr.State()
	}
	return TransportClosed
}

func (s *Session) attachRebind(ctx context.Context, tr *OuterTransport, first Frame, payload RebindPayload, fingerprint string) error {
	s.mu.Lock()
	if s.closed || s.state == SessionTeardown {
		s.mu.Unlock()
		return ErrSessionClosed
	}
	if fingerprint != "" {
		if s.fingerprint == "" {
			s.fingerprint = fingerprint
		} else if s.fingerprint != fingerprint {
			s.mu.Unlock()
			return ErrClientHelloFingerprintChanged
		}
	}
	epoch := first.Header.TransportEpoch
	if epoch == 0 {
		s.mu.Unlock()
		return ErrInvalidEpoch
	}
	if epoch <= s.lastEpoch {
		s.mu.Unlock()
		return ErrStaleEpoch
	}
	if payload.PreviousEpoch != s.lastEpoch {
		s.mu.Unlock()
		return ErrPreviousEpochMismatch
	}
	tr.setSession(s)
	tr.setEpoch(epoch)
	tr.setState(TransportIdle)
	s.transports[epoch] = tr
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	s.mu.Unlock()

	acceptPayload := payload
	acceptPayload.Mode = RebindModeAccept
	acceptPayload.ReasonCode = 0
	encoded, err := MarshalRebind(acceptPayload)
	if err != nil {
		return err
	}
	accept := Frame{Header: FrameHeader{Version: Version1, Type: FrameREBIND, Flags: FlagDirS2C | FlagAckEliciting, HeaderLen: HeaderLenV1, SessionID: s.key.SessionID, TransportEpoch: epoch, SeqOffset: first.Header.SeqOffset}, Payload: encoded}
	if err := tr.sendFrameDuringHandshake(ctx, accept); err != nil {
		return err
	}
	tr.MarkActive()

	s.mu.Lock()
	if s.lastEpoch != 0 {
		if old, ok := s.transports[s.lastEpoch]; ok && old.State() == TransportActive {
			old.MarkDraining()
		}
	}
	s.lastEpoch = epoch
	s.state = SessionActive
	s.mu.Unlock()
	return nil
}

func (s *Session) OpenStream(streamID uint32, direction FrameFlags) (*Stream, error) {
	s.mu.Lock()
	if s.closed || s.state == SessionTeardown {
		s.mu.Unlock()
		return nil, ErrSessionClosed
	}
	if s.state == SessionInitializing {
		s.mu.Unlock()
		return nil, ErrSessionNotActive
	}
	if streamID == 0 {
		s.mu.Unlock()
		return nil, streamStateProtocolError(streamID, FrameOPENSTREAM, "stream id must be nonzero")
	}
	if existing, ok := s.streams[streamID]; ok {
		s.mu.Unlock()
		return existing, nil
	}
	if len(s.streams) >= s.maxStreams {
		s.mu.Unlock()
		return nil, ErrMaxStreamsPerSession
	}
	tr := s.transports[s.lastEpoch]
	sched := s.scheduler
	s.mu.Unlock()
	st, err := NewStream(StreamConfig{StreamID: streamID, SessionID: s.key.SessionID, Direction: direction, Clock: s.clock, Transport: tr, Scheduler: sched, EnableRetransmitLoop: true})
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if len(s.streams) >= s.maxStreams {
		s.mu.Unlock()
		_ = st.Close()
		return nil, ErrMaxStreamsPerSession
	}
	s.streams[streamID] = st
	s.mu.Unlock()
	return st, nil
}

func (s *Session) HandleFrame(f Frame) error {
	s.mu.Lock()
	last := s.lastEpoch
	state := s.state
	stream := s.streams[f.Header.StreamID]
	s.mu.Unlock()
	if state == SessionTeardown {
		return ErrSessionClosed
	}
	if f.Header.TransportEpoch == 0 {
		return ErrInvalidEpoch
	}
	if f.Header.TransportEpoch < last {
		return nil
	}
	if err := ValidateFrame(f.Header, len(f.Payload), DecodeOptions{}); err != nil {
		return err
	}
	if f.Header.StreamID == 0 {
		return nil
	}
	if stream == nil {
		return nil
	}
	switch f.Header.Type {
	case FrameDATA:
		return stream.ReceiveData(f.Header.SeqOffset, f.Payload)
	case FrameFIN:
		return stream.ReceiveFIN(f.Header.SeqOffset)
	case FrameACK:
		return stream.HandleACK(f.Header.AckOffset)
	case FrameSACK:
		ranges, err := ParseSACK(f.Payload, f.Header.AckOffset)
		if err != nil {
			return err
		}
		return stream.HandleSACK(f.Header.AckOffset, ranges)
	case FrameRST:
		p, err := ParseRST(f.Payload)
		if err != nil {
			return err
		}
		return stream.ReceiveRST(p)
	case FrameWINDOWUPDATE:
		p, err := ParseWindowUpdate(f.Payload)
		if err != nil {
			return err
		}
		return stream.HandleWindowUpdate(p.WindowEndOffset)
	default:
		return nil
	}
}

func (s *Session) MarkTransportDraining(epoch uint32) {
	s.mu.Lock()
	tr := s.transports[epoch]
	s.mu.Unlock()
	if tr != nil {
		tr.MarkDraining()
	}
}

func (s *Session) Close(err error) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.state = SessionTeardown
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
	streams := make([]*Stream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	transports := make([]*OuterTransport, 0, len(s.transports))
	for _, tr := range s.transports {
		transports = append(transports, tr)
	}
	sched := s.scheduler
	stop := s.detectorStop
	s.scheduler = nil
	s.detectorStop = nil
	s.streams = make(map[uint32]*Stream)
	s.transports = make(map[uint32]*OuterTransport)
	onClose := s.onClose
	key := s.key
	s.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	if sched != nil {
		sched.Close()
	}
	for _, st := range streams {
		_ = st.Close()
	}
	for _, tr := range transports {
		_ = tr.Close(err)
	}
	if onClose != nil {
		onClose(key)
	}
	return nil
}

func (s *Session) onTransportClosed(epoch uint32) {
	s.mu.Lock()
	if s.closed || s.state == SessionTeardown {
		s.mu.Unlock()
		return
	}
	allInactive := true
	for _, tr := range s.transports {
		if tr.State() == TransportActive {
			allInactive = false
			break
		}
	}
	if allInactive && s.idleTimer == nil {
		s.idleTimer = s.clock.AfterFunc(s.idleTO, func() { _ = s.Close(ErrSessionClosed) })
	}
	s.mu.Unlock()
}

package bbcr

import "fmt"

type TransportState int

const (
	TransportOpen TransportState = iota
	TransportDraining
	TransportClosed
)

func (s TransportState) String() string {
	switch s {
	case TransportOpen:
		return "open"
	case TransportDraining:
		return "draining"
	case TransportClosed:
		return "closed"
	default:
		return fmt.Sprintf("transport-state-%d", int(s))
	}
}

type StreamState int

const (
	StreamStateIdle StreamState = iota
	StreamStateOpen
	StreamStateHalfClosedLocal
	StreamStateHalfClosedRemote
	StreamStateClosed
	StreamStateReset
)

func (s StreamState) String() string {
	switch s {
	case StreamStateIdle:
		return "idle"
	case StreamStateOpen:
		return "open"
	case StreamStateHalfClosedLocal:
		return "half-closed-local"
	case StreamStateHalfClosedRemote:
		return "half-closed-remote"
	case StreamStateClosed:
		return "closed"
	case StreamStateReset:
		return "reset"
	default:
		return fmt.Sprintf("stream-state-%d", int(s))
	}
}

func (s StreamState) Terminal() bool { return s == StreamStateClosed || s == StreamStateReset }

type StreamEvent int

const (
	StreamEventOpen StreamEvent = iota
	StreamEventLocalFIN
	StreamEventRemoteFIN
	StreamEventClose
	StreamEventRST
)

func (e StreamEvent) String() string {
	switch e {
	case StreamEventOpen:
		return "open"
	case StreamEventLocalFIN:
		return "local-fin"
	case StreamEventRemoteFIN:
		return "remote-fin"
	case StreamEventClose:
		return "close"
	case StreamEventRST:
		return "rst"
	default:
		return fmt.Sprintf("stream-event-%d", int(e))
	}
}

type StreamStateMachine struct{ state StreamState }

func NewStreamStateMachine(initial StreamState) *StreamStateMachine {
	return &StreamStateMachine{state: initial}
}
func (m *StreamStateMachine) State() StreamState {
	if m == nil {
		return StreamStateClosed
	}
	return m.state
}

func (m *StreamStateMachine) Apply(event StreamEvent) error {
	if m == nil {
		return streamStateProtocolError(0, FrameRST, "nil state machine")
	}
	next, ok := nextStreamState(m.state, event)
	if !ok {
		return streamStateProtocolError(0, FrameRST, fmt.Sprintf("illegal stream transition %s on %s", event, m.state))
	}
	m.state = next
	return nil
}

func nextStreamState(state StreamState, event StreamEvent) (StreamState, bool) {
	switch event {
	case StreamEventRST:
		if state == StreamStateReset {
			return StreamStateReset, true
		}
		return StreamStateReset, true
	case StreamEventClose:
		if state == StreamStateReset || state == StreamStateClosed {
			return state, true
		}
		return StreamStateClosed, true
	case StreamEventOpen:
		if state == StreamStateIdle {
			return StreamStateOpen, true
		}
		return state, false
	case StreamEventLocalFIN:
		switch state {
		case StreamStateOpen:
			return StreamStateHalfClosedLocal, true
		case StreamStateHalfClosedRemote:
			return StreamStateClosed, true
		}
	case StreamEventRemoteFIN:
		switch state {
		case StreamStateOpen:
			return StreamStateHalfClosedRemote, true
		case StreamStateHalfClosedLocal:
			return StreamStateClosed, true
		}
	}
	return state, false
}

func streamStateProtocolError(streamID uint32, frameType FrameType, msg string) error {
	return ProtocolError{Err: fmt.Errorf("bbcr: %s", msg), Code: ErrCodeStreamRSTProtocol, Tier: TierStreamRST, FrameType: frameType, StreamID: streamID}
}

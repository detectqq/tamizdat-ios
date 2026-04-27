package bbcr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const Version1 uint8 = 0x01
const HeaderLenV1 uint16 = 48
const MaxFramePayload uint16 = 1400
const MaxDataPayload uint16 = 1350
const MinDataPayload uint16 = 700
const HardCapPcap uint64 = 12288

type FrameType uint8

const (
	FrameDATA         FrameType = 0x00
	FrameACK          FrameType = 0x01
	FrameSACK         FrameType = 0x02
	FrameOPENSTREAM   FrameType = 0x03
	FrameCLOSESTREAM  FrameType = 0x04
	FramePING         FrameType = 0x05
	FramePONG         FrameType = 0x06
	FrameREBIND       FrameType = 0x07
	FrameFIN          FrameType = 0x08
	FrameRST          FrameType = 0x09
	FrameWINDOWUPDATE FrameType = 0x0A
	// FrameMAYREBIND is a server-emitted advisory hint that the active outer is
	// approaching its packet-capture cap. It carries no payload; the client
	// treats reception as a strong signal to dial a fresh outer immediately,
	// bypassing churn-gate cooldown. Added in P0.5 Cycle 3.2 (validator audit
	// d31a51a) so the server can drive REBIND when its scheduler hits cap
	// exhaustion.
	FrameMAYREBIND FrameType = 0x0B
	// FrameNOISE is a server-emitted P1.2 cadence-mask control frame. It carries
	// exactly 8 random bytes and is validated/dropped by receivers without being
	// propagated to any stream.
	FrameNOISE FrameType = 0x0C
)

type FrameFlags uint16

const (
	FlagDirS2C          FrameFlags = 1 << 0
	FlagAckEliciting    FrameFlags = 1 << 1
	FlagAckPiggyback    FrameFlags = 1 << 2
	FlagRetransmit      FrameFlags = 1 << 3
	FlagPriorityControl FrameFlags = 1 << 4
	FlagAEADPresent     FrameFlags = 1 << 5
)

const reservedFlagMask FrameFlags = ^FrameFlags(0x003f)

type Role int

const (
	RoleClient Role = iota
	RoleServer
)

type Range struct{ Start, End uint64 }

type FrameHeader struct {
	Version        uint8
	Type           FrameType
	Flags          FrameFlags
	HeaderLen      uint16
	PayloadLen     uint16
	SessionID      uint64
	TransportEpoch uint32
	StreamID       uint32
	SeqOffset      uint64
	AckOffset      uint64
	FrameNo        uint64
}

type Frame struct {
	Header  FrameHeader
	Payload []byte
}

type DecodeOptions struct {
	LocalRole         Role
	ValidateDirection bool
	MaxPayload        uint16
}

type ProtocolTier int

const (
	TierIgnore ProtocolTier = iota
	TierStreamRST
	TierSessionTeardown
	TierCloseConnectNoResponse
)

type ProtocolErrorCode int

const (
	ErrCodeBadVersion ProtocolErrorCode = iota + 1
	ErrCodeBadHeaderLen
	ErrCodeReservedFlags
	ErrCodeAEADPresent
	ErrCodePayloadTooLarge
	ErrCodeMalformedPayload
	ErrCodeDirectionMismatch
	ErrCodeStreamControlMisuse
	ErrCodeUnknownCritical
	ErrCodeUnknownNonCritical
	ErrCodeACKBeyondSent
	ErrCodeStreamRSTProtocol
	ErrCodeSessionTeardownProtocol
)

var (
	ErrBadVersion              = errors.New("bbcr: bad version")
	ErrBadHeaderLen            = errors.New("bbcr: bad header length")
	ErrReservedFlags           = errors.New("bbcr: reserved flags set")
	ErrAEADPresent             = errors.New("bbcr: AEAD_PRESENT is reserved in P0.5")
	ErrPayloadTooLarge         = errors.New("bbcr: payload too large")
	ErrMalformedPayload        = errors.New("bbcr: malformed payload")
	ErrDirectionMismatch       = errors.New("bbcr: frame direction mismatch")
	ErrStreamControlMisuse     = errors.New("bbcr: stream/control frame misuse")
	ErrUnknownCritical         = errors.New("bbcr: unknown critical frame type")
	ErrUnknownNonCritical      = errors.New("bbcr: unknown noncritical frame type")
	ErrACKBeyondSent           = errors.New("bbcr: ack beyond sent offset")
	ErrStreamRSTProtocol       = errors.New("bbcr: stream reset protocol error")
	ErrSessionTeardownProtocol = errors.New("bbcr: session teardown protocol error")
)

type ProtocolError struct {
	Err        error
	Tier       ProtocolTier
	FrameType  FrameType
	StreamID   uint32
	DetailCode uint32
	Code       ProtocolErrorCode
}

func (e ProtocolError) Error() string {
	if e.Err == nil {
		return "bbcr: protocol error"
	}
	return e.Err.Error()
}
func (e ProtocolError) Unwrap() error { return e.Err }

func newProtocolError(code ProtocolErrorCode, err error, tier ProtocolTier, h FrameHeader) error {
	return ProtocolError{Err: err, Code: code, Tier: tier, FrameType: h.Type, StreamID: h.StreamID}
}

func EncodeFrame(w io.Writer, h FrameHeader, payload []byte) error {
	b, err := MarshalFrame(h, payload)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func DecodeFrame(r io.Reader, opts DecodeOptions) (Frame, error) {
	header := make([]byte, HeaderLenV1)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, err
	}
	h := parseHeader(header)
	max := effectiveMaxPayload(opts)
	if h.PayloadLen > max || h.PayloadLen > MaxFramePayload {
		return Frame{}, newProtocolError(ErrCodePayloadTooLarge, ErrPayloadTooLarge, TierSessionTeardown, h)
	}
	payload := make([]byte, int(h.PayloadLen))
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	err := ValidateFrame(h, len(payload), opts)
	return Frame{Header: h, Payload: payload}, err
}

func MarshalFrame(h FrameHeader, payload []byte) ([]byte, error) {
	h = normalizeHeaderForMarshal(h, len(payload))
	if err := ValidateFrame(h, len(payload), DecodeOptions{}); err != nil && !isIgnorableProtocolError(err) {
		return nil, err
	}
	b := make([]byte, int(HeaderLenV1)+len(payload))
	b[0] = h.Version
	b[1] = byte(h.Type)
	binary.BigEndian.PutUint16(b[2:4], uint16(h.Flags))
	binary.BigEndian.PutUint16(b[4:6], h.HeaderLen)
	binary.BigEndian.PutUint16(b[6:8], h.PayloadLen)
	binary.BigEndian.PutUint64(b[8:16], h.SessionID)
	binary.BigEndian.PutUint32(b[16:20], h.TransportEpoch)
	binary.BigEndian.PutUint32(b[20:24], h.StreamID)
	binary.BigEndian.PutUint64(b[24:32], h.SeqOffset)
	binary.BigEndian.PutUint64(b[32:40], h.AckOffset)
	binary.BigEndian.PutUint64(b[40:48], h.FrameNo)
	copy(b[48:], payload)
	return b, nil
}

func ParseFrame(buf []byte, opts DecodeOptions) (Frame, int, error) {
	if len(buf) < int(HeaderLenV1) {
		return Frame{}, 0, io.ErrUnexpectedEOF
	}
	h := parseHeader(buf[:HeaderLenV1])
	max := effectiveMaxPayload(opts)
	if h.PayloadLen > max || h.PayloadLen > MaxFramePayload {
		return Frame{}, 0, newProtocolError(ErrCodePayloadTooLarge, ErrPayloadTooLarge, TierSessionTeardown, h)
	}
	consumed := int(h.HeaderLen) + int(h.PayloadLen)
	if h.HeaderLen != HeaderLenV1 {
		return Frame{}, 0, newProtocolError(ErrCodeBadHeaderLen, ErrBadHeaderLen, TierSessionTeardown, h)
	}
	if len(buf) < consumed {
		return Frame{}, 0, io.ErrUnexpectedEOF
	}
	payload := append([]byte(nil), buf[int(HeaderLenV1):consumed]...)
	err := ValidateFrame(h, len(payload), opts)
	return Frame{Header: h, Payload: payload}, consumed, err
}

func ValidateFrame(h FrameHeader, payloadLen int, opts DecodeOptions) error {
	if h.Version != Version1 {
		return newProtocolError(ErrCodeBadVersion, ErrBadVersion, TierCloseConnectNoResponse, h)
	}
	if h.HeaderLen != HeaderLenV1 {
		return newProtocolError(ErrCodeBadHeaderLen, ErrBadHeaderLen, TierSessionTeardown, h)
	}
	if h.Flags&reservedFlagMask != 0 {
		return newProtocolError(ErrCodeReservedFlags, ErrReservedFlags, TierSessionTeardown, h)
	}
	if h.Flags&FlagAEADPresent != 0 {
		return newProtocolError(ErrCodeAEADPresent, ErrAEADPresent, TierSessionTeardown, h)
	}
	if payloadLen < 0 || payloadLen > int(MaxFramePayload) || payloadLen > int(effectiveMaxPayload(opts)) || int(h.PayloadLen) != payloadLen {
		return newProtocolError(ErrCodePayloadTooLarge, ErrPayloadTooLarge, TierSessionTeardown, h)
	}
	if opts.ValidateDirection {
		wantS2C := opts.LocalRole == RoleClient
		gotS2C := h.Flags&FlagDirS2C != 0
		if gotS2C != wantS2C {
			return newProtocolError(ErrCodeDirectionMismatch, ErrDirectionMismatch, TierSessionTeardown, h)
		}
	}
	if !isKnownType(h.Type) {
		if h.Type >= 0x80 {
			return newProtocolError(ErrCodeUnknownNonCritical, ErrUnknownNonCritical, TierIgnore, h)
		}
		tier := TierSessionTeardown
		if h.StreamID != 0 {
			tier = TierStreamRST
		}
		return newProtocolError(ErrCodeUnknownCritical, ErrUnknownCritical, tier, h)
	}
	if err := validateTypeSemantics(h, payloadLen); err != nil {
		return err
	}
	return nil
}

func parseHeader(b []byte) FrameHeader {
	return FrameHeader{
		Version: b[0], Type: FrameType(b[1]), Flags: FrameFlags(binary.BigEndian.Uint16(b[2:4])),
		HeaderLen: binary.BigEndian.Uint16(b[4:6]), PayloadLen: binary.BigEndian.Uint16(b[6:8]),
		SessionID: binary.BigEndian.Uint64(b[8:16]), TransportEpoch: binary.BigEndian.Uint32(b[16:20]),
		StreamID: binary.BigEndian.Uint32(b[20:24]), SeqOffset: binary.BigEndian.Uint64(b[24:32]),
		AckOffset: binary.BigEndian.Uint64(b[32:40]), FrameNo: binary.BigEndian.Uint64(b[40:48]),
	}
}

func normalizeHeaderForMarshal(h FrameHeader, payloadLen int) FrameHeader {
	if h.Version == 0 {
		h.Version = Version1
	}
	if h.HeaderLen == 0 {
		h.HeaderLen = HeaderLenV1
	}
	if payloadLen >= 0 && payloadLen <= 0xffff {
		h.PayloadLen = uint16(payloadLen)
	}
	return h
}

func effectiveMaxPayload(opts DecodeOptions) uint16 {
	if opts.MaxPayload == 0 || opts.MaxPayload > MaxFramePayload {
		return MaxFramePayload
	}
	return opts.MaxPayload
}

func isKnownType(t FrameType) bool { return t <= FrameNOISE }

func isIgnorableProtocolError(err error) bool {
	var pe ProtocolError
	return errors.As(err, &pe) && pe.Code == ErrCodeUnknownNonCritical && pe.Tier == TierIgnore
}

func validateTypeSemantics(h FrameHeader, payloadLen int) error {
	streamRST := func(code ProtocolErrorCode, err error) error { return newProtocolError(code, err, TierStreamRST, h) }
	teardown := func(code ProtocolErrorCode, err error) error {
		return newProtocolError(code, err, TierSessionTeardown, h)
	}
	requireStream := func() error {
		if h.StreamID == 0 {
			return streamRST(ErrCodeStreamControlMisuse, ErrStreamControlMisuse)
		}
		return nil
	}
	requireControl := func() error {
		if h.StreamID != 0 {
			return teardown(ErrCodeStreamControlMisuse, ErrStreamControlMisuse)
		}
		return nil
	}
	switch h.Type {
	case FrameDATA:
		if err := requireStream(); err != nil {
			return err
		}
		if payloadLen < 1 || payloadLen > int(MaxDataPayload) {
			return streamRST(ErrCodeMalformedPayload, ErrMalformedPayload)
		}
	case FrameACK:
		if err := requireStream(); err != nil {
			return err
		}
		if h.SeqOffset != 0 || payloadLen != 0 {
			return streamRST(ErrCodeMalformedPayload, ErrMalformedPayload)
		}
	case FrameSACK:
		if err := requireStream(); err != nil {
			return err
		}
		if h.SeqOffset != 0 || payloadLen < 4 || (payloadLen-4)%16 != 0 || (payloadLen-4)/16 > 32 {
			return streamRST(ErrCodeMalformedPayload, ErrMalformedPayload)
		}
	case FrameOPENSTREAM:
		if err := requireStream(); err != nil {
			return err
		}
		if h.SeqOffset != 0 || h.AckOffset != 0 || payloadLen < 8 || payloadLen > 512 {
			return streamRST(ErrCodeMalformedPayload, ErrMalformedPayload)
		}
	case FrameCLOSESTREAM:
		if err := requireStream(); err != nil {
			return err
		}
		if payloadLen != 20 {
			return streamRST(ErrCodeMalformedPayload, ErrMalformedPayload)
		}
	case FramePING, FramePONG:
		if err := requireControl(); err != nil {
			return err
		}
		if payloadLen != 16 {
			return teardown(ErrCodeMalformedPayload, ErrMalformedPayload)
		}
	case FrameREBIND:
		if err := requireControl(); err != nil {
			return err
		}
		if h.AckOffset != 0 || payloadLen != 28 {
			return teardown(ErrCodeMalformedPayload, ErrMalformedPayload)
		}
	case FrameFIN:
		if err := requireStream(); err != nil {
			return err
		}
		if payloadLen != 0 {
			return streamRST(ErrCodeMalformedPayload, ErrMalformedPayload)
		}
	case FrameRST:
		if h.SeqOffset != 0 || payloadLen != 8 {
			return streamRST(ErrCodeMalformedPayload, ErrMalformedPayload)
		}
	case FrameWINDOWUPDATE:
		if payloadLen != 8 {
			return streamRST(ErrCodeMalformedPayload, ErrMalformedPayload)
		}
	case FrameMAYREBIND:
		if err := requireControl(); err != nil {
			return err
		}
		if h.SeqOffset != 0 || h.AckOffset != 0 || payloadLen != 0 {
			return teardown(ErrCodeMalformedPayload, ErrMalformedPayload)
		}
	case FrameNOISE:
		if err := requireControl(); err != nil {
			return err
		}
		if h.SeqOffset != 0 || h.AckOffset != 0 || payloadLen != 8 {
			return teardown(ErrCodeMalformedPayload, ErrMalformedPayload)
		}
	default:
		return fmt.Errorf("unreachable frame type %d", h.Type)
	}
	return nil
}

func (t FrameType) String() string {
	switch t {
	case FrameDATA:
		return "DATA"
	case FrameACK:
		return "ACK"
	case FrameSACK:
		return "SACK"
	case FrameOPENSTREAM:
		return "OPEN_STREAM"
	case FrameCLOSESTREAM:
		return "CLOSE_STREAM"
	case FramePING:
		return "PING"
	case FramePONG:
		return "PONG"
	case FrameREBIND:
		return "REBIND"
	case FrameFIN:
		return "FIN"
	case FrameRST:
		return "RST"
	case FrameWINDOWUPDATE:
		return "WINDOW_UPDATE"
	case FrameMAYREBIND:
		return "MAY_REBIND"
	case FrameNOISE:
		return "NOISE"
	default:
		return fmt.Sprintf("FrameType(0x%02x)", uint8(t))
	}
}

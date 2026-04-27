package bbcr

import "encoding/binary"

const (
	openAddrIPv4   uint8 = 0x01
	openAddrDNS    uint8 = 0x03
	openAddrIPv6   uint8 = 0x04
	openNetworkTCP uint8 = 0x01
)

type RebindPayload struct {
	Mode            uint8
	CapabilityFlags uint8
	ReasonCode      uint16
	PreviousEpoch   uint32
	MaxFramePayload uint16
	RebindNonce128  [16]byte
}
type OpenStreamPayload struct {
	AddressType uint8
	Network     uint8
	Port        uint16
	Host        []byte
	Flags       uint8
}
type CloseStreamPayload struct {
	CloseCode    uint16
	FinalRecvAck uint64
	FinalSendAck uint64
}
type RSTPayload struct {
	ErrorCode  uint16
	DetailCode uint32
}
type WindowUpdatePayload struct{ WindowEndOffset uint64 }
type PingPongPayload struct {
	Nonce          uint64
	SenderUnixNano uint64
}

func MarshalSACK(ranges []Range) ([]byte, error) {
	if len(ranges) > 32 {
		return nil, payloadError(FrameSACK, 0)
	}
	if err := validateRanges(ranges, 0, false); err != nil {
		return nil, err
	}
	p := make([]byte, 4+16*len(ranges))
	p[0] = byte(len(ranges))
	off := 4
	for _, r := range ranges {
		binary.BigEndian.PutUint64(p[off:off+8], r.Start)
		binary.BigEndian.PutUint64(p[off+8:off+16], r.End)
		off += 16
	}
	return p, nil
}

func ParseSACK(payload []byte, ackOffset uint64) ([]Range, error) {
	if len(payload) < 4 || payload[1] != 0 || payload[2] != 0 || payload[3] != 0 {
		return nil, payloadError(FrameSACK, 0)
	}
	n := int(payload[0])
	if n > 32 || len(payload) != 4+16*n {
		return nil, payloadError(FrameSACK, 0)
	}
	ranges := make([]Range, n)
	off := 4
	for i := range ranges {
		ranges[i] = Range{Start: binary.BigEndian.Uint64(payload[off : off+8]), End: binary.BigEndian.Uint64(payload[off+8 : off+16])}
		off += 16
	}
	if err := validateRanges(ranges, ackOffset, true); err != nil {
		return nil, err
	}
	return ranges, nil
}

func MarshalRebind(v RebindPayload) ([]byte, error) {
	if v.MaxFramePayload == 0 || v.MaxFramePayload > MaxFramePayload {
		return nil, payloadError(FrameREBIND, 0)
	}
	p := make([]byte, 28)
	p[0], p[1] = v.Mode, v.CapabilityFlags
	binary.BigEndian.PutUint16(p[2:4], v.ReasonCode)
	binary.BigEndian.PutUint32(p[4:8], v.PreviousEpoch)
	binary.BigEndian.PutUint16(p[8:10], v.MaxFramePayload)
	copy(p[12:28], v.RebindNonce128[:])
	return p, nil
}

func ParseRebind(payload []byte) (RebindPayload, error) {
	if len(payload) != 28 || payload[10] != 0 || payload[11] != 0 {
		return RebindPayload{}, payloadError(FrameREBIND, 0)
	}
	v := RebindPayload{Mode: payload[0], CapabilityFlags: payload[1], ReasonCode: binary.BigEndian.Uint16(payload[2:4]), PreviousEpoch: binary.BigEndian.Uint32(payload[4:8]), MaxFramePayload: binary.BigEndian.Uint16(payload[8:10])}
	if v.MaxFramePayload == 0 || v.MaxFramePayload > MaxFramePayload {
		return RebindPayload{}, payloadError(FrameREBIND, 0)
	}
	copy(v.RebindNonce128[:], payload[12:28])
	return v, nil
}

func MarshalOpenStream(v OpenStreamPayload) ([]byte, error) {
	if err := validateOpenStream(v); err != nil {
		return nil, err
	}
	p := make([]byte, 6+len(v.Host)+2)
	p[0], p[1] = v.AddressType, v.Network
	binary.BigEndian.PutUint16(p[2:4], v.Port)
	p[4] = byte(len(v.Host))
	copy(p[5:5+len(v.Host)], v.Host)
	p[5+len(v.Host)] = v.Flags
	return p, nil
}

func ParseOpenStream(payload []byte) (OpenStreamPayload, error) {
	if len(payload) < 8 || len(payload) > 512 {
		return OpenStreamPayload{}, payloadError(FrameOPENSTREAM, 0)
	}
	hostLen := int(payload[4])
	if len(payload) != 6+hostLen+2 || payload[len(payload)-2] != 0 || payload[len(payload)-1] != 0 {
		return OpenStreamPayload{}, payloadError(FrameOPENSTREAM, 0)
	}
	v := OpenStreamPayload{AddressType: payload[0], Network: payload[1], Port: binary.BigEndian.Uint16(payload[2:4]), Host: append([]byte(nil), payload[5:5+hostLen]...), Flags: payload[5+hostLen]}
	if err := validateOpenStream(v); err != nil {
		return OpenStreamPayload{}, err
	}
	return v, nil
}

func MarshalCloseStream(v CloseStreamPayload) ([]byte, error) {
	p := make([]byte, 20)
	binary.BigEndian.PutUint16(p[0:2], v.CloseCode)
	binary.BigEndian.PutUint64(p[4:12], v.FinalRecvAck)
	binary.BigEndian.PutUint64(p[12:20], v.FinalSendAck)
	return p, nil
}

func ParseCloseStream(payload []byte) (CloseStreamPayload, error) {
	if len(payload) != 20 || payload[2] != 0 || payload[3] != 0 {
		return CloseStreamPayload{}, payloadError(FrameCLOSESTREAM, 0)
	}
	return CloseStreamPayload{CloseCode: binary.BigEndian.Uint16(payload[0:2]), FinalRecvAck: binary.BigEndian.Uint64(payload[4:12]), FinalSendAck: binary.BigEndian.Uint64(payload[12:20])}, nil
}

func MarshalRST(v RSTPayload) ([]byte, error) {
	p := make([]byte, 8)
	binary.BigEndian.PutUint16(p[0:2], v.ErrorCode)
	binary.BigEndian.PutUint32(p[4:8], v.DetailCode)
	return p, nil
}

func ParseRST(payload []byte) (RSTPayload, error) {
	if len(payload) != 8 || payload[2] != 0 || payload[3] != 0 {
		return RSTPayload{}, payloadError(FrameRST, 0)
	}
	return RSTPayload{ErrorCode: binary.BigEndian.Uint16(payload[0:2]), DetailCode: binary.BigEndian.Uint32(payload[4:8])}, nil
}

func MarshalWindowUpdate(v WindowUpdatePayload) ([]byte, error) {
	p := make([]byte, 8)
	binary.BigEndian.PutUint64(p, v.WindowEndOffset)
	return p, nil
}

func ParseWindowUpdate(payload []byte) (WindowUpdatePayload, error) {
	if len(payload) != 8 {
		return WindowUpdatePayload{}, payloadError(FrameWINDOWUPDATE, 0)
	}
	return WindowUpdatePayload{WindowEndOffset: binary.BigEndian.Uint64(payload)}, nil
}

func MarshalPingPong(v PingPongPayload) ([]byte, error) {
	p := make([]byte, 16)
	binary.BigEndian.PutUint64(p[0:8], v.Nonce)
	binary.BigEndian.PutUint64(p[8:16], v.SenderUnixNano)
	return p, nil
}

func ParsePingPong(payload []byte) (PingPongPayload, error) {
	if len(payload) != 16 {
		return PingPongPayload{}, payloadError(FramePING, 0)
	}
	return PingPongPayload{Nonce: binary.BigEndian.Uint64(payload[0:8]), SenderUnixNano: binary.BigEndian.Uint64(payload[8:16])}, nil
}

func validateRanges(ranges []Range, ackOffset uint64, checkAck bool) error {
	var prevEnd uint64
	for i, r := range ranges {
		if r.End <= r.Start {
			return payloadError(FrameSACK, 0)
		}
		if checkAck && r.Start < ackOffset {
			return payloadError(FrameSACK, 0)
		}
		if i > 0 && r.Start < prevEnd {
			return payloadError(FrameSACK, 0)
		}
		prevEnd = r.End
	}
	return nil
}

func validateOpenStream(v OpenStreamPayload) error {
	if v.Network != openNetworkTCP || v.Port == 0 {
		return payloadError(FrameOPENSTREAM, 0)
	}
	if len(v.Host) == 0 || len(v.Host) > 253 || 6+len(v.Host)+2 > 512 {
		return payloadError(FrameOPENSTREAM, 0)
	}
	switch v.AddressType {
	case openAddrIPv4:
		if len(v.Host) != 4 {
			return payloadError(FrameOPENSTREAM, 0)
		}
	case openAddrIPv6:
		if len(v.Host) != 16 {
			return payloadError(FrameOPENSTREAM, 0)
		}
	case openAddrDNS:
		if len(v.Host) < 1 || len(v.Host) > 253 {
			return payloadError(FrameOPENSTREAM, 0)
		}
	default:
		return payloadError(FrameOPENSTREAM, 0)
	}
	return nil
}

func payloadError(ft FrameType, streamID uint32) error {
	return ProtocolError{Err: ErrMalformedPayload, Code: ErrCodeMalformedPayload, Tier: TierStreamRST, FrameType: ft, StreamID: streamID}
}

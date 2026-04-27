package samizdat

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// SamizdatKeyShareExtensionType is the private-use TLS extension type for P0.3. Go 1.24 treats 0xFE0D as ECH, so integration uses adjacent private-use 0xFE0C.
	SamizdatKeyShareExtensionType uint16 = 0xFE0C

	samizdatKeyShareVersion     byte = 0x01
	samizdatKeyShareCurveX25519 byte = 0x01
	samizdatKeySharePayloadLen       = 1 + 1 + 2 + x25519KeyLen
	samizdatKeyShareWireLen          = 4 + samizdatKeySharePayloadLen
)

// BuildSamizdatKeyShareExtension marshals the P0.3 samizdat_keyshare TLS extension.
func BuildSamizdatKeyShareExtension(ephemeralPublicKey []byte) ([]byte, error) {
	return MarshalKeyShareExtension(ephemeralPublicKey)
}

// MarshalKeyShareExtension marshals the full TLS extension wire image:
// type(2) || length(2) || version(1) || curve(1) || reserved(2) || eph_pub(32).
func MarshalKeyShareExtension(ephemeralPublicKey []byte) ([]byte, error) {
	if len(ephemeralPublicKey) != x25519KeyLen {
		return nil, fmt.Errorf("ephemeral public key length %d, want %d", len(ephemeralPublicKey), x25519KeyLen)
	}
	ext := make([]byte, samizdatKeyShareWireLen)
	binary.BigEndian.PutUint16(ext[0:2], SamizdatKeyShareExtensionType)
	binary.BigEndian.PutUint16(ext[2:4], samizdatKeySharePayloadLen)
	ext[4] = samizdatKeyShareVersion
	ext[5] = samizdatKeyShareCurveX25519
	// ext[6:8] reserved bytes are zero in v1.
	copy(ext[8:], ephemeralPublicKey)
	return ext, nil
}

// UnmarshalKeyShareExtension parses the full samizdat_keyshare TLS extension
// and returns the embedded X25519 ephemeral public key.
func UnmarshalKeyShareExtension(extension []byte) ([x25519KeyLen]byte, error) {
	var ephPub [x25519KeyLen]byte
	if len(extension) < 4 {
		return ephPub, errors.New("samizdat_keyshare extension too short for header")
	}
	if typ := binary.BigEndian.Uint16(extension[0:2]); typ != SamizdatKeyShareExtensionType {
		return ephPub, fmt.Errorf("unexpected TLS extension type 0x%04x", typ)
	}
	payloadLen := int(binary.BigEndian.Uint16(extension[2:4]))
	if payloadLen != samizdatKeySharePayloadLen {
		return ephPub, fmt.Errorf("samizdat_keyshare payload length %d, want %d", payloadLen, samizdatKeySharePayloadLen)
	}
	if len(extension) != 4+payloadLen {
		return ephPub, fmt.Errorf("samizdat_keyshare wire length %d, want %d", len(extension), 4+payloadLen)
	}
	payload := extension[4:]
	if payload[0] != samizdatKeyShareVersion {
		return ephPub, fmt.Errorf("unsupported samizdat_keyshare version 0x%02x", payload[0])
	}
	if payload[1] != samizdatKeyShareCurveX25519 {
		return ephPub, fmt.Errorf("unsupported samizdat_keyshare curve 0x%02x", payload[1])
	}
	if payload[2] != 0 || payload[3] != 0 {
		return ephPub, errors.New("samizdat_keyshare reserved bytes must be zero")
	}
	copy(ephPub[:], payload[4:])
	return ephPub, nil
}

// DerivePSKFromExtension parses a full samizdat_keyshare TLS extension and
// derives the server-side P0.3 PSK using the server static private key.
func DerivePSKFromExtension(serverPrivateKey []byte, extension []byte, shortID [shortIDLen]byte) ([]byte, [x25519KeyLen]byte, error) {
	ephPub, err := UnmarshalKeyShareExtension(extension)
	if err != nil {
		return nil, ephPub, err
	}
	psk, err := DeriveServerPSK(serverPrivateKey, ephPub[:], shortID)
	if err != nil {
		return nil, ephPub, err
	}
	return psk, ephPub, nil
}

// ExtractSamizdatKeyShareExtension extracts the full P0.3 samizdat_keyshare
// TLS extension wire image from raw ClientHello bytes. It accepts a TLS record,
// a handshake message, or a bare ClientHello body.
func ExtractSamizdatKeyShareExtension(clientHello []byte) ([]byte, error) {
	body, err := clientHelloBody(clientHello)
	if err != nil {
		return nil, err
	}

	pos := 2 + 32 // legacy_version + random
	if len(body) < pos+1 {
		return nil, errors.New("ClientHello too short for session_id length")
	}
	sessionIDLen := int(body[pos])
	pos++
	if len(body) < pos+sessionIDLen+2 {
		return nil, errors.New("ClientHello too short for cipher_suites length")
	}
	pos += sessionIDLen

	cipherSuitesLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if len(body) < pos+cipherSuitesLen+1 {
		return nil, errors.New("ClientHello too short for compression_methods length")
	}
	pos += cipherSuitesLen

	compressionMethodsLen := int(body[pos])
	pos++
	if len(body) < pos+compressionMethodsLen {
		return nil, errors.New("ClientHello compression_methods exceeds data")
	}
	pos += compressionMethodsLen
	if len(body) == pos {
		return nil, errors.New("ClientHello has no extensions")
	}
	if len(body) < pos+2 {
		return nil, errors.New("ClientHello too short for extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if len(body) < pos+extensionsLen {
		return nil, errors.New("ClientHello extensions exceed data")
	}

	end := pos + extensionsLen
	for pos < end {
		if pos+4 > end {
			return nil, errors.New("ClientHello truncated TLS extension header")
		}
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		if pos+4+extLen > end {
			return nil, errors.New("ClientHello TLS extension length exceeds block")
		}
		if binary.BigEndian.Uint16(body[pos:pos+2]) == SamizdatKeyShareExtensionType {
			ext := make([]byte, 4+extLen)
			copy(ext, body[pos:pos+4+extLen])
			return ext, nil
		}
		pos += 4 + extLen
	}
	return nil, errors.New("samizdat_keyshare extension not found")
}

// ExtractSamizdatKeyShare extracts the P0.3 ephemeral public key from raw
// ClientHello bytes. It accepts a TLS record, a handshake message, or a bare
// ClientHello body.
func ExtractSamizdatKeyShare(clientHello []byte) ([x25519KeyLen]byte, error) {
	var zero [x25519KeyLen]byte
	body, err := clientHelloBody(clientHello)
	if err != nil {
		return zero, err
	}

	pos := 2 + 32 // legacy_version + random
	if len(body) < pos+1 {
		return zero, errors.New("ClientHello too short for session_id length")
	}
	sessionIDLen := int(body[pos])
	pos++
	if len(body) < pos+sessionIDLen+2 {
		return zero, errors.New("ClientHello too short for cipher_suites length")
	}
	pos += sessionIDLen

	cipherSuitesLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if len(body) < pos+cipherSuitesLen+1 {
		return zero, errors.New("ClientHello too short for compression_methods length")
	}
	pos += cipherSuitesLen

	compressionMethodsLen := int(body[pos])
	pos++
	if len(body) < pos+compressionMethodsLen {
		return zero, errors.New("ClientHello compression_methods exceeds data")
	}
	pos += compressionMethodsLen
	if len(body) == pos {
		return zero, errors.New("ClientHello has no extensions")
	}
	if len(body) < pos+2 {
		return zero, errors.New("ClientHello too short for extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if len(body) < pos+extensionsLen {
		return zero, errors.New("ClientHello extensions exceed data")
	}

	end := pos + extensionsLen
	for pos < end {
		if pos+4 > end {
			return zero, errors.New("ClientHello truncated TLS extension header")
		}
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		if pos+4+extLen > end {
			return zero, errors.New("ClientHello TLS extension length exceeds block")
		}
		if binary.BigEndian.Uint16(body[pos:pos+2]) == SamizdatKeyShareExtensionType {
			return UnmarshalKeyShareExtension(body[pos : pos+4+extLen])
		}
		pos += 4 + extLen
	}
	return zero, errors.New("samizdat_keyshare extension not found")
}

func clientHelloBody(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("ClientHello empty")
	}
	pos := 0
	if data[0] == 0x16 { // TLS Handshake record
		if len(data) < 5 {
			return nil, errors.New("TLS record too short")
		}
		recordLen := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+recordLen {
			return nil, errors.New("TLS record length exceeds data")
		}
		pos = 5
		data = data[pos : pos+recordLen]
	}
	if len(data) == 0 {
		return nil, errors.New("ClientHello empty after TLS record header")
	}
	if data[0] == 0x01 { // HandshakeTypeClientHello
		if len(data) < 4 {
			return nil, errors.New("ClientHello too short for handshake header")
		}
		handshakeLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		if len(data) < 4+handshakeLen {
			return nil, errors.New("ClientHello handshake length exceeds data")
		}
		return data[4 : 4+handshakeLen], nil
	}
	return data, nil
}

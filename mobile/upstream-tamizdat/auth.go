package tamizdat

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// authLabel is the HKDF info string for deriving the auth key.
	authLabel = "TAMIZDAT v1"
	// authKeyLen is the length of the derived HMAC key.
	authKeyLen = 32
	// sessionIDLen is the TLS SessionID field length.
	sessionIDLen = 32
	// hmacTagLen is the truncated HMAC-SHA256 tag length in the SessionID.
	hmacTagLen = 16
	// shortIDLen is the length of the pre-shared short identifier.
	shortIDLen = 8
	// nonceLen is the auth nonce length (8 bytes to fit in SessionID layout:
	// 8 shortID + 8 nonce + 16 HMAC tag = 32 bytes).
	nonceLen = 8
	// x25519KeyLen is the encoded length of X25519 public/private keys and shared secrets.
	x25519KeyLen = 32
)

// GenerateKeyPair generates a new X25519 keypair for use as server credentials.
// Returns (privateKey, publicKey, error).
func GenerateKeyPair() ([]byte, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating private key: %w", err)
	}
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

// GenerateShortID generates a random 8-byte short identifier.
func GenerateShortID() ([shortIDLen]byte, error) {
	var id [shortIDLen]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, fmt.Errorf("generating short ID: %w", err)
	}
	return id, nil
}

// PublicKeyFromPrivate computes the X25519 public key for a raw 32-byte private key.
func PublicKeyFromPrivate(privateKey []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 private key: %w", err)
	}
	return priv.PublicKey().Bytes(), nil
}

// GenerateEphemeralKeyPair generates a fresh X25519 keypair for one client dial.
// The returned private key must be discarded after the SessionID/PSK are built.
func GenerateEphemeralKeyPair() (privateKey []byte, publicKey []byte, err error) {
	return GenerateKeyPair()
}

// ECDHSharedSecret computes X25519(privateKey, peerPublicKey).
func ECDHSharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != x25519KeyLen {
		return nil, fmt.Errorf("X25519 private key length %d, want %d", len(privateKey), x25519KeyLen)
	}
	if len(peerPublicKey) != x25519KeyLen {
		return nil, fmt.Errorf("X25519 public key length %d, want %d", len(peerPublicKey), x25519KeyLen)
	}
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 private key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing X25519 public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("X25519 ECDH: %w", err)
	}
	return shared, nil
}

// derivePSK derives a 32-byte auth key with HKDF-SHA256.
//
// P0.3 ECDH-A changed the IKM from the legacy public server key to the
// X25519 shared secret. The signature remains []byte + shortID so legacy
// callers still compile until ECDH-C wires the new ECDH flow into client/server.
func derivePSK(sharedSecret []byte, shortID [shortIDLen]byte) ([]byte, error) {
	if len(sharedSecret) != x25519KeyLen {
		return nil, fmt.Errorf("shared secret length %d, want %d", len(sharedSecret), x25519KeyLen)
	}
	// salt = shortID, ikm = X25519 shared secret, info = "TAMIZDAT v1".
	hkdfReader := hkdf.New(sha256.New, sharedSecret, shortID[:], []byte(authLabel))
	key := make([]byte, authKeyLen)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}
	return key, nil
}

// DerivePSKFromSharedSecret derives the P0.3 auth key from an X25519 shared secret.
func DerivePSKFromSharedSecret(sharedSecret []byte, shortID [shortIDLen]byte) ([]byte, error) {
	return derivePSK(sharedSecret, shortID)
}

// DeriveClientPSK derives the P0.3 auth key on the client from its ephemeral
// private key and the server's long-lived static public key.
func DeriveClientPSK(ephemeralPrivateKey, serverPublicKey []byte, shortID [shortIDLen]byte) ([]byte, error) {
	shared, err := ECDHSharedSecret(ephemeralPrivateKey, serverPublicKey)
	if err != nil {
		return nil, err
	}
	return derivePSK(shared, shortID)
}

// DeriveServerPSK derives the P0.3 auth key on the server from its long-lived
// static private key and the client's ephemeral public key.
func DeriveServerPSK(serverPrivateKey, ephemeralPublicKey []byte, shortID [shortIDLen]byte) ([]byte, error) {
	shared, err := ECDHSharedSecret(serverPrivateKey, ephemeralPublicKey)
	if err != nil {
		return nil, err
	}
	return derivePSK(shared, shortID)
}

// BuildSessionIDv1 constructs a P0.3 SessionID.
// Layout: shortID(8) || nonce(8) || hmac_tag(16), where
// hmac_tag = HMAC-SHA256(PSK, version || shortID || nonce || eph_pub)[:16].
// If nonce is nil, a fresh random nonce is generated; otherwise it must be 8 bytes.
func BuildSessionIDv1(psk []byte, shortID [shortIDLen]byte, ephemeralPublicKey []byte, nonce []byte) ([sessionIDLen]byte, error) {
	var sessionID [sessionIDLen]byte
	if len(psk) != authKeyLen {
		return sessionID, fmt.Errorf("PSK length %d, want %d", len(psk), authKeyLen)
	}
	if len(ephemeralPublicKey) != x25519KeyLen {
		return sessionID, fmt.Errorf("ephemeral public key length %d, want %d", len(ephemeralPublicKey), x25519KeyLen)
	}

	copy(sessionID[:shortIDLen], shortID[:])
	nonceDst := sessionID[shortIDLen : shortIDLen+nonceLen]
	if nonce == nil {
		if _, err := io.ReadFull(rand.Reader, nonceDst); err != nil {
			return sessionID, fmt.Errorf("generating nonce: %w", err)
		}
	} else {
		if len(nonce) != nonceLen {
			return sessionID, fmt.Errorf("nonce length %d, want %d", len(nonce), nonceLen)
		}
		copy(nonceDst, nonce)
	}

	tag := sessionIDTagV1(psk, shortID, nonceDst, ephemeralPublicKey)
	copy(sessionID[shortIDLen+nonceLen:], tag)
	return sessionID, nil
}

// VerifySessionIDv1 checks whether a P0.3 SessionID contains a valid tag bound
// to the provided ephemeral public key and one allowed shortID.
func VerifySessionIDv1(sessionID []byte, psk []byte, ephemeralPublicKey []byte, allowedShortIDs [][shortIDLen]byte) ([shortIDLen]byte, bool, error) {
	var zero [shortIDLen]byte
	if len(sessionID) != sessionIDLen {
		return zero, false, nil
	}
	if len(psk) != authKeyLen {
		return zero, false, fmt.Errorf("PSK length %d, want %d", len(psk), authKeyLen)
	}
	if len(ephemeralPublicKey) != x25519KeyLen {
		return zero, false, fmt.Errorf("ephemeral public key length %d, want %d", len(ephemeralPublicKey), x25519KeyLen)
	}

	var candidateShortID [shortIDLen]byte
	copy(candidateShortID[:], sessionID[:shortIDLen])
	if !shortIDAllowed(candidateShortID, allowedShortIDs) {
		return zero, false, nil
	}
	nonce := sessionID[shortIDLen : shortIDLen+nonceLen]
	tag := sessionID[shortIDLen+nonceLen:]
	expectedTag := sessionIDTagV1(psk, candidateShortID, nonce, ephemeralPublicKey)
	if !hmac.Equal(tag, expectedTag) {
		return zero, false, nil
	}
	return candidateShortID, true, nil
}

// VerifySessionIDv1WithServerKey derives the PSK from serverPrivateKey and
// ephemeralPublicKey, then verifies the v1 SessionID.
func VerifySessionIDv1WithServerKey(sessionID []byte, serverPrivateKey []byte, ephemeralPublicKey []byte, allowedShortIDs [][shortIDLen]byte) ([shortIDLen]byte, bool, error) {
	var zero [shortIDLen]byte
	if len(sessionID) != sessionIDLen {
		return zero, false, nil
	}
	var candidateShortID [shortIDLen]byte
	copy(candidateShortID[:], sessionID[:shortIDLen])

	// Timing-oracle hardening: derive and verify the HMAC for the candidate
	// shortID before consulting the server's allowed-shortID pool. Unknown
	// shortIDs and known-shortID/bad-tag probes therefore both pay the same
	// X25519+HKDF+HMAC cost before they fail.
	psk, err := DeriveServerPSK(serverPrivateKey, ephemeralPublicKey, candidateShortID)
	if err != nil {
		return zero, false, err
	}
	nonce := sessionID[shortIDLen : shortIDLen+nonceLen]
	tag := sessionID[shortIDLen+nonceLen:]
	expectedTag := sessionIDTagV1(psk, candidateShortID, nonce, ephemeralPublicKey)
	tagOK := hmac.Equal(tag, expectedTag)
	allowed := shortIDAllowed(candidateShortID, allowedShortIDs)
	if !tagOK || !allowed {
		return zero, false, nil
	}
	return candidateShortID, true, nil
}

func sessionIDTagV1(psk []byte, shortID [shortIDLen]byte, nonce []byte, ephemeralPublicKey []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte{0x01}) // SessionIDv1 version byte
	mac.Write(shortID[:])
	mac.Write(nonce)
	mac.Write(ephemeralPublicKey)
	return mac.Sum(nil)[:hmacTagLen]
}

func shortIDAllowed(candidate [shortIDLen]byte, allowedShortIDs [][shortIDLen]byte) bool {
	for _, allowed := range allowedShortIDs {
		if candidate == allowed {
			return true
		}
	}
	return false
}

// derivePublicKey computes the X25519 public key from a private key.
// Returns both the original private key and the derived public key.
func derivePublicKey(privateKey []byte) ([]byte, []byte, error) {
	publicKey, err := PublicKeyFromPrivate(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("computing public key: %w", err)
	}
	return privateKey, publicKey, nil
}

// ExtractSessionID extracts the session_id field from raw ClientHello bytes.
func ExtractSessionID(clientHello []byte) ([]byte, error) {
	if len(clientHello) < 6 {
		return nil, errors.New("ClientHello too short")
	}

	pos := 0
	if clientHello[0] == 0x01 { // HandshakeTypeClientHello
		if len(clientHello) < 4 {
			return nil, errors.New("ClientHello too short for handshake header")
		}
		pos = 4
	}

	// Skip client_version(2) + random(32)
	pos += 2 + 32
	if pos >= len(clientHello) {
		return nil, errors.New("ClientHello too short for session_id length")
	}

	sessionIDLength := int(clientHello[pos])
	pos++
	if pos+sessionIDLength > len(clientHello) {
		return nil, errors.New("ClientHello session_id exceeds data")
	}

	sessionID := make([]byte, sessionIDLength)
	copy(sessionID, clientHello[pos:pos+sessionIDLength])
	return sessionID, nil
}

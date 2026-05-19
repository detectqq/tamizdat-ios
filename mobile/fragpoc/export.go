package fragpoc

import (
	"context"
	"io"
	"net"
)

// Exported wrappers for internal crypto/protocol helpers used by the
// socksstub test probes (ProbeMaxPayload, ProbeMaxConns). These live in
// a separate file so the core client/server code stays unchanged.

func DeriveSecureStaticKey(shortID [ShortIDLen]byte) [32]byte {
	return deriveSecureStaticKey(shortID)
}

// NewSecureNonce returns a fresh random nonce as a slice (exported
// wrapper avoids leaking the unexported secureNonceLen constant).
func NewSecureNonce() ([]byte, error) {
	nonce, err := newSecureNonce()
	if err != nil {
		return nil, err
	}
	return nonce[:], nil
}

func SecureRequestAD(op byte, id []byte) []byte {
	return secureRequestAD(op, id)
}

func SecureResponseAD(op byte, id []byte) []byte {
	return secureResponseAD(op, id)
}

func WriteSecureBodyWithNonce(w io.Writer, key [32]byte, ad []byte, nonce []byte, plaintext []byte) error {
	return writeSecureBodyWithNonce(w, key, ad, nonce, plaintext)
}

func ReadSecureBody(r io.Reader, key [32]byte, ad []byte, plaintextLimit int) ([]byte, []byte, error) {
	return readSecureBody(r, key, ad, plaintextLimit)
}

func ApplyDeadlineFromContext(conn net.Conn, ctx context.Context) {
	applyDeadlineFromContext(conn, ctx)
}

func SecureOpenPrefix(shortID [ShortIDLen]byte) []byte {
	prefix := make([]byte, 1+ShortIDLen+1)
	prefix[0] = secureWireOp(OpOpenSecure)
	copy(prefix[1:1+ShortIDLen], shortID[:])
	prefix[1+ShortIDLen] = secureOpenMarker
	return prefix
}

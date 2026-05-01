package tamizdat

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveShortIDPool computes a deterministic shortID pool from a master
// shortID and an epoch key. Both client and server compute this independently
// and compare results.
func DeriveShortIDPool(master [8]byte, epochKey string, size int) [][8]byte {
	if size < 0 {
		panic("shortID pool size must be non-negative")
	}
	if size > 1000 {
		panic("shortID pool size must be <= 1000")
	}
	if size == 0 {
		return [][8]byte{}
	}

	prk := hkdf.Extract(sha256.New, master[:], []byte(epochKey))
	pool := make([][8]byte, size)
	for i := 0; i < size; i++ {
		var info [4]byte
		binary.BigEndian.PutUint32(info[:], uint32(i))
		reader := hkdf.Expand(sha256.New, prk, info[:])
		if _, err := io.ReadFull(reader, pool[i][:]); err != nil {
			panic(fmt.Sprintf("HKDF expand shortID %d: %v", i, err))
		}
	}
	return pool
}

// Package bbcr implements the Samizdat BBCR Phase A wire contract.
//
// Phase A is intentionally limited to the public frame format, typed protocol
// errors, payload marshal/parse helpers, and deterministic clock interfaces
// consumed by later BBCR blocks. It does not start goroutines and does not own
// retransmission, reassembly, scheduler, transport registry, or integration
// state machines.
//
// All BBCR v1 frame integer fields are encoded big-endian in a fixed 48-byte
// header. DecodeFrame and ParseFrame return payload slices owned by the caller:
// returned payload memory is stable until the caller mutates it.
package bbcr

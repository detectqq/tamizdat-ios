//go:build !with_gvisor && netstack_real

// File only compiled when the netstack_real build tag is set (Phase 1
// onward, when the IPA actually wires the gvisor stack) AND the
// with_gvisor tag is missing. Triggers a deliberate compile error so
// gomobile bind cannot silently produce a binary where sing-tun's
// gvisor implementation is the stub returning ErrGVisorNotIncluded.
//
// Phase 0 path (no netstack_real tag): file is excluded, build is
// green either way — the gvisor stack is not yet referenced.
//
// Phase 1 path (netstack_real tag, no with_gvisor tag): build fails
// here with a loud message. Add -tags=with_gvisor,netstack_real to
// `gomobile bind` and `go build` invocations.
//
// Phase 1 path (both tags set): file is excluded, the real
// stack_gvisor.go in sing-tun links, NewGVisor returns a working
// stack.
package netstack

const _ = "ERROR: build with -tags=with_gvisor,netstack_real for Phase 1 netstack — without with_gvisor sing-tun's NewGVisor returns ErrGVisorNotIncluded" - 1

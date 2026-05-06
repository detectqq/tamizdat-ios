//go:build !netstack_real

package netstack

func buildFlavor() string { return "STUB (no netstack_real tag)" }

//go:build !linux

package main

import "net"

// processNameForLocalConn is a no-op on non-Linux platforms. macOS, Windows
// and BSD have similar but platform-specific APIs (proc_pidfdsocketinfo on
// Darwin; GetExtendedTcpTable on Windows; sysctl KERN_PROC_PID on BSD)
// which can be added later as separate _<os>.go files.
func processNameForLocalConn(local, peer net.Addr) string {
	return ""
}

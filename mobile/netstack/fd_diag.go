//go:build netstack_real

package netstack

import (
	"fmt"
	"syscall"
	"unsafe"
)

// diagFdIdentity logs the fd's getpeername (must be AF_SYSTEM=32)
// and UTUN_OPT_IFNAME (must be "utunN"). Called once at startTunnel.
//
// Per DR analyst report:
//
//	getpeername errno=ENOTCONN OR sa_family != 32 → wrong fd
//	ifname doesn't start with "utun" → wrong fd
//	Both OK but no reads → routing/DNS settings problem
func diagFdIdentity(fd int) {
	// Get peername — should be sockaddr_ctl with sa_family = AF_SYSTEM(32).
	var ssa syscall.RawSockaddrAny
	salen := uint32(syscall.SizeofSockaddrAny)
	_, _, e1 := syscall.Syscall6(
		syscall.SYS_GETPEERNAME,
		uintptr(fd),
		uintptr(unsafe.Pointer(&ssa)),
		uintptr(unsafe.Pointer(&salen)),
		0, 0, 0,
	)
	if e1 != 0 {
		rtLog(fmt.Sprintf("warn: diag fd=%d getpeername errno=%v", fd, e1))
	} else {
		rtLog(fmt.Sprintf("info: diag fd=%d getpeername sa_family=%d", fd, ssa.Addr.Family))
	}

	// Get utun ifname via SYSPROTO_CONTROL=2 / UTUN_OPT_IFNAME=2.
	const (
		sysprotoControl = 2
		utunOptIfname   = 2
	)
	var ifname [16]byte
	sz := uint32(len(ifname))
	_, _, e2 := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		sysprotoControl,
		utunOptIfname,
		uintptr(unsafe.Pointer(&ifname[0])),
		uintptr(unsafe.Pointer(&sz)),
		0,
	)
	if e2 != 0 {
		rtLog(fmt.Sprintf("warn: diag fd=%d getsockopt(UTUN_OPT_IFNAME) errno=%v", fd, e2))
		return
	}
	// sz includes trailing NUL.
	end := int(sz)
	if end > 0 && ifname[end-1] == 0 {
		end--
	}
	rtLog(fmt.Sprintf("info: diag fd=%d utun ifname=%q", fd, string(ifname[:end])))
}

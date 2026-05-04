//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// procAttr looks up the process name for a local TCP connection by parsing
// /proc/net/tcp and walking /proc/<pid>/fd/* for matching socket inodes.
//
// This is the standard Linux pattern used by lsof, ss -p, etc. Works without
// root because /proc/net/tcp is world-readable and /proc/<pid>/fd is
// readable by the owner (= same UID as the SOCKS5 client process which is
// our own UID for local-loopback connections).
//
// Cost: ~1-5 ms per lookup (one /proc/net/tcp scan + walking ~50-200 PIDs'
// fd directories). Cached for 250 ms to amortize cost when an app opens
// many parallel connections quickly.

type procAttrCacheEntry struct {
	name   string
	cached time.Time
}

var (
	procAttrMu    sync.RWMutex
	procAttrCache = make(map[string]procAttrCacheEntry, 64)
	procAttrTTL   = 250 * time.Millisecond
)

// processNameForLocalConn returns the comm of the process owning the TCP
// connection from peer to our SOCKS5 listener. peer is the remote side as
// seen by us (e.g. "127.0.0.1:54321"); local is our listener address (e.g.
// "127.0.0.1:1080"). On any error or no-match, returns "".
func processNameForLocalConn(local, peer net.Addr) string {
	peerTCP, ok := peer.(*net.TCPAddr)
	if !ok {
		return ""
	}
	localTCP, ok := local.(*net.TCPAddr)
	if !ok {
		return ""
	}

	// Cache key: peer ip:port + local port (local IP is always our listener).
	key := fmt.Sprintf("%s:%d-%d", peerTCP.IP.String(), peerTCP.Port, localTCP.Port)

	procAttrMu.RLock()
	if e, ok := procAttrCache[key]; ok && time.Since(e.cached) < procAttrTTL {
		procAttrMu.RUnlock()
		return e.name
	}
	procAttrMu.RUnlock()

	// /proc/net/tcp has TWO entries per loopback TCP connection (one row per
	// socket -- our accepted socket AND peer's connecting socket). We want the
	// peer's row to get the peer process's socket inode. Peer's row has:
	//   local_addr = peer_app_ephemeral (their side)
	//   rem_addr   = our_listener
	// (the inverse of how it looks from our perspective).
	inode, err := findInodeForConn(peerTCP, localTCP)
	if err != nil || inode == 0 {
		// Try /proc/net/tcp6 if peer is IPv6 OR if v4 lookup missed (some
		// kernels register v4-mapped-v6 in tcp6).
		inode, _ = findInodeForConn6(peerTCP, localTCP)
	}
	if inode == 0 {
		setCache(key, "")
		return ""
	}

	name := procNameForInode(inode)
	setCache(key, name)
	return name
}

func setCache(key, name string) {
	procAttrMu.Lock()
	procAttrCache[key] = procAttrCacheEntry{name: name, cached: time.Now()}
	if len(procAttrCache) > 1024 {
		// LRU-ish: dump everything older than 5×TTL.
		cutoff := time.Now().Add(-5 * procAttrTTL)
		for k, v := range procAttrCache {
			if v.cached.Before(cutoff) {
				delete(procAttrCache, k)
			}
		}
	}
	procAttrMu.Unlock()
}

// /proc/net/tcp format (one header line, then space-separated fields):
//   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
// where local_address is HEX-IP:HEX-PORT (IPv4 = 8 hex chars, big-endian
// reversed!) and inode is a decimal number (column 9, 0-indexed).
func findInodeForConn(local, peer *net.TCPAddr) (uint64, error) {
	return scanProcNetTCP("/proc/net/tcp", local, peer, false)
}

func findInodeForConn6(local, peer *net.TCPAddr) (uint64, error) {
	return scanProcNetTCP("/proc/net/tcp6", local, peer, true)
}

func scanProcNetTCP(path string, local, peer *net.TCPAddr, isV6 bool) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	wantLocal := encodeProcAddr(local.IP, local.Port, isV6)
	wantPeer := encodeProcAddr(peer.IP, peer.Port, isV6)
	if wantLocal == "" || wantPeer == "" {
		return 0, nil
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256), 1024*1024)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		// fields[1] = local_address, fields[2] = rem_address
		if !equalProcAddr(fields[1], wantLocal) {
			continue
		}
		if !equalProcAddr(fields[2], wantPeer) {
			continue
		}
		// fields[9] = inode (decimal, may also be at position 9, depends on
		// kernel version; safe to find by looking for the second-to-last
		// numeric field that's > 0).
		// Standard layout has inode at index 9 in the space-split fields.
		if len(fields) <= 9 {
			continue
		}
		ino, err := strconv.ParseUint(fields[9], 10, 64)
		if err == nil && ino > 0 {
			return ino, nil
		}
	}
	return 0, scanner.Err()
}

// encodeProcAddr formats an IP+port into the /proc/net/tcp hex form:
//   IPv4: "0100007F:1F90"  (= 127.0.0.1:8080) -- IP is little-endian-reversed!
//   IPv6: 32 hex chars in network-order ... actually little-endian within each
//         32-bit word. /proc uses 8x4-byte words, each in host (LE) order.
func encodeProcAddr(ip net.IP, port int, isV6 bool) string {
	if isV6 {
		ip16 := ip.To16()
		if ip16 == nil {
			return ""
		}
		// Encode 4 4-byte little-endian words for the address.
		var sb strings.Builder
		for i := 0; i < 4; i++ {
			word := binary.BigEndian.Uint32(ip16[i*4:])
			// /proc/net/tcp6 stores each 32-bit word as little-endian within the
			// hex text. Reverse the bytes of the word.
			le := make([]byte, 4)
			binary.LittleEndian.PutUint32(le, word)
			sb.WriteString(fmt.Sprintf("%02X%02X%02X%02X", le[0], le[1], le[2], le[3]))
		}
		sb.WriteString(":")
		sb.WriteString(fmt.Sprintf("%04X", port))
		return sb.String()
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	// Reverse bytes (LE in /proc).
	rev := []byte{ip4[3], ip4[2], ip4[1], ip4[0]}
	return fmt.Sprintf("%02X%02X%02X%02X:%04X", rev[0], rev[1], rev[2], rev[3], port)
}

func equalProcAddr(a, b string) bool {
	return strings.EqualFold(a, b)
}

// procNameForInode walks /proc/[pid]/fd/* and finds the PID whose fd points
// at "socket:[<inode>]". Returns the comm of that PID (e.g. "discord",
// "anydesk", "Roblox.exe-via-Wine").
func procNameForInode(inode uint64) string {
	want := fmt.Sprintf("socket:[%d]", inode)
	d, err := os.Open("/proc")
	if err != nil {
		return ""
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue // permission denied = not our PID, skip
		}
		for _, fe := range fdEntries {
			target, err := os.Readlink(filepath.Join(fdDir, fe.Name()))
			if err != nil {
				continue
			}
			if target == want {
				name, _ := readProcComm(pid)
				return name
			}
		}
	}
	return ""
}

func readProcComm(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// silence unused-import in non-linux builds
var _ = fs.ModeSocket

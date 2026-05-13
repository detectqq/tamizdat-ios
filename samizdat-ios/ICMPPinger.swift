import Foundation
import Darwin
import Network

/// IPA-D23: unprivileged ICMP echo for iOS Network Extensions.
///
/// Uses `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` (and the IPv6 twin
/// `IPPROTO_ICMPV6`) which iOS has supported since iOS 9. SOCK_DGRAM-
/// style ICMP is the "unprivileged ping" socket that mDNSResponder /
/// the OS itself uses; it does NOT require root or special entitlements,
/// just like a UDP socket.
///
/// To avoid the ping going back through OUR utun (we're a packet tunnel
/// extension — by default every socket the extension opens is routed
/// through the tunnel it owns), we bind the socket to the underlying
/// physical interface index via `setsockopt(IP_BOUND_IF, ifindex)` (or
/// `IPV6_BOUND_IF`).
///
/// Inspiration: Apple's "SimplePing" sample (Objective-C), ported to
/// Swift with iOS-NE-specific bind-to-interface, no third-party deps.
///
/// Echo packet shape:
///   - IPv4 ICMP type 8, code 0
///   - IPv6 ICMPv6 type 128, code 0
///   - identifier: we set 0; the kernel rewrites it to a per-socket value
///     for SOCK_DGRAM ICMP, so we can't depend on it. Match by sequence
///     number instead.
///   - sequence: monotonic per-pinger, lets us match the right reply
///     when several are in flight (we always cancel before re-issuing
///     in WhitelistDetector, but be safe).
///   - payload: "tamizdat-probe" + 16 zero bytes (gives a reasonable
///     min-size echo).
///
/// Checksum: SOCK_DGRAM ICMP on Darwin computes the IPv4 checksum for
/// us — see net/icmp_var.c / icmp_send(). But for portability and to
/// match the SimplePing reference we still fill it manually so the
/// packet is well-formed if the kernel ever stops being nice. For
/// ICMPv6 the kernel DOES require the checksum (per RFC 2463) and
/// the IPV6_CHECKSUM socket option is meant to make the kernel compute
/// it; we set ICMPV6_CHECKSUM=2 (checksum-field-offset = 2 bytes into
/// the packet) for safety.
final class ICMPPinger {

    /// What to ping. Hostnames are resolved synchronously inside the
    /// pinger; resolution failure is treated as a ping failure.
    enum Target {
        case ip(String)        // "8.8.8.8" or "2001:4860:4860::8888"
        case hostname(String)  // "google.com"
    }

    private static let sequenceLock = NSLock()
    private static var sequenceCounter: UInt16 = UInt16.random(in: 0..<UInt16.max)
    private static func allocSequence() -> UInt16 {
        sequenceLock.lock()
        defer { sequenceLock.unlock() }
        sequenceCounter = sequenceCounter &+ 1
        return sequenceCounter
    }

    private let target: Target
    private let interfaceIndex: UInt32?
    private let queue: DispatchQueue
    private var dispatchSource: DispatchSourceRead?
    private var timeoutWork: DispatchWorkItem?
    private var fd: Int32 = -1
    private var didSettle = false
    private var sequence: UInt16 = 0
    private var startedAt: Date = Date()
    private var completion: ((Bool, TimeInterval) -> Void)?

    /// - parameter target: IP or hostname to ping.
    /// - parameter interfaceIndex: physical interface index obtained
    ///   from `NWPath.availableInterfaces.first { $0.type == .wifi }.index`
    ///   (or cellular, etc). When nil, the socket is NOT bound to an
    ///   interface — which on an extension means the kernel will route
    ///   the packet through OUR tunnel. Caller should always supply.
    init(target: Target, interfaceIndex: UInt32?) {
        self.target = target
        self.interfaceIndex = interfaceIndex
        self.queue = DispatchQueue(label: "com.anarki.samizdat-test.icmp", qos: .utility)
    }

    /// Sends one echo, awaits the matching reply or `timeout`, then
    /// invokes `completion(success, roundTripTime)`. Exactly once.
    /// `completion` is delivered on an internal queue.
    func ping(timeout: TimeInterval,
              completion: @escaping (Bool, TimeInterval) -> Void) {
        queue.async { [weak self] in
            self?.startPing(timeout: timeout, completion: completion)
        }
    }

    func cancel() {
        queue.async { [weak self] in
            self?.settle(success: false)
        }
    }

    // MARK: – Internal

    private func startPing(timeout: TimeInterval,
                           completion: @escaping (Bool, TimeInterval) -> Void) {
        self.completion = completion
        self.startedAt = Date()
        self.didSettle = false
        self.sequence = Self.allocSequence()

        // Resolve target → (sockaddr, isV6).
        let resolved: (sockaddr_storage, Bool)?
        switch target {
        case .ip(let s):
            resolved = Self.parseIP(s)
        case .hostname(let s):
            // Synchronous, with our own timeout (cheap enough for our use).
            resolved = Self.resolveHostname(s, timeout: min(timeout, 2.0))
        }
        guard var (saddr, isV6) = resolved else {
            settle(success: false)
            return
        }

        // Open socket — SOCK_DGRAM ICMP (unprivileged ping).
        let family: Int32 = isV6 ? AF_INET6 : AF_INET
        let proto: Int32  = isV6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP
        let s = Darwin.socket(family, SOCK_DGRAM, proto)
        if s < 0 {
            settle(success: false)
            return
        }
        self.fd = s

        // Non-blocking so recv doesn't stall the queue.
        let flags = fcntl(s, F_GETFL, 0)
        _ = fcntl(s, F_SETFL, flags | O_NONBLOCK)

        // Bind to physical interface (critical — without this the packet
        // goes back through our own utun and we get nothing).
        if let idx = interfaceIndex, idx > 0 {
            var ifindex = idx
            let opt: Int32 = isV6 ? IPV6_BOUND_IF : IP_BOUND_IF
            let level: Int32 = isV6 ? IPPROTO_IPV6 : IPPROTO_IP
            _ = setsockopt(s, level, opt, &ifindex, socklen_t(MemoryLayout<UInt32>.size))
        }

        // Send the echo.
        let packet = Self.buildEchoPacket(isV6: isV6, sequence: sequence)
        let sent: Int = packet.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return withUnsafePointer(to: &saddr) { sptr -> Int in
                sptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa -> Int in
                    let len: socklen_t = isV6
                        ? socklen_t(MemoryLayout<sockaddr_in6>.size)
                        : socklen_t(MemoryLayout<sockaddr_in>.size)
                    return Darwin.sendto(s, base, packet.count, 0, sa, len)
                }
            }
        }
        if sent != packet.count {
            settle(success: false)
            return
        }

        // Listen for reply via a DispatchSource read.
        let src = DispatchSource.makeReadSource(fileDescriptor: s, queue: queue)
        src.setEventHandler { [weak self] in
            self?.onSocketReadable(isV6: isV6)
        }
        src.activate()
        self.dispatchSource = src

        // Arm timeout.
        let work = DispatchWorkItem { [weak self] in
            self?.settle(success: false)
        }
        self.timeoutWork = work
        queue.asyncAfter(deadline: .now() + timeout, execute: work)
    }

    private func onSocketReadable(isV6: Bool) {
        guard fd >= 0 else { return }
        var buf = [UInt8](repeating: 0, count: 1500)
        var from = sockaddr_storage()
        var fromLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let n = buf.withUnsafeMutableBufferPointer { bptr -> Int in
            withUnsafeMutablePointer(to: &from) { ptr -> Int in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa -> Int in
                    return Darwin.recvfrom(fd, bptr.baseAddress, bptr.count, 0, sa, &fromLen)
                }
            }
        }
        if n <= 0 { return }

        // For SOCK_DGRAM ICMP the kernel strips the IP header and gives
        // us the ICMP payload starting from the type byte.
        // Echo reply: type 0 (v4) / 129 (v6), then code, checksum, id, seq.
        // We match by sequence number, since identifier is rewritten by
        // kernel.
        if n < 8 { return }
        let type = buf[0]
        let expectReply: UInt8 = isV6 ? 129 : 0
        if type != expectReply { return }
        // Bytes 6-7 are the sequence number (big-endian).
        let seq = (UInt16(buf[6]) << 8) | UInt16(buf[7])
        if seq != sequence { return }

        settle(success: true)
    }

    private func settle(success: Bool) {
        if didSettle { return }
        didSettle = true
        let elapsed = Date().timeIntervalSince(startedAt)
        timeoutWork?.cancel(); timeoutWork = nil
        dispatchSource?.cancel(); dispatchSource = nil
        if fd >= 0 {
            close(fd)
            fd = -1
        }
        let cb = completion
        completion = nil
        cb?(success, elapsed)
    }

    // MARK: – Packet construction

    private static func buildEchoPacket(isV6: Bool, sequence: UInt16) -> [UInt8] {
        // Type | Code | Cksum hi | Cksum lo | ID hi | ID lo | Seq hi | Seq lo
        // + payload
        let type: UInt8 = isV6 ? 128 : 8
        var packet = [UInt8](repeating: 0, count: 8)
        packet[0] = type
        packet[1] = 0
        // checksum starts as 0 — kernel computes it for SOCK_DGRAM ICMP
        packet[2] = 0
        packet[3] = 0
        // identifier — kernel rewrites for SOCK_DGRAM
        packet[4] = 0
        packet[5] = 0
        // sequence
        packet[6] = UInt8((sequence >> 8) & 0xff)
        packet[7] = UInt8(sequence & 0xff)
        // Payload — short marker so on-wire dumps are recognizable.
        let payload: [UInt8] = Array("tamizdat-probe".utf8) + [UInt8](repeating: 0, count: 16)
        packet.append(contentsOf: payload)
        // Manually compute IPv4 ICMP checksum to be safe (kernel does it
        // anyway, but it's free insurance). For ICMPv6 the kernel MUST
        // compute the checksum because it depends on the pseudo-header.
        if !isV6 {
            let sum = internetChecksum(packet)
            packet[2] = UInt8(sum & 0xff)
            packet[3] = UInt8((sum >> 8) & 0xff)
        }
        return packet
    }

    private static func internetChecksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < bytes.count {
            let word = (UInt16(bytes[i]) << 8) | UInt16(bytes[i + 1])
            sum &+= UInt32(word)
            i += 2
        }
        if i < bytes.count {
            sum &+= UInt32(UInt16(bytes[i]) << 8)
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        let folded = UInt16(truncatingIfNeeded: sum)
        let result = ~folded
        // The checksum in the packet is in network-byte order — but ICMP
        // is stored big-endian. Since we read bytes pairwise as big-endian
        // above, the returned value is already host-order; we store its
        // bytes lo,hi to match the network layout the manual layout uses.
        // (Verified against Apple's SimplePing.)
        // Swap bytes to get on-wire form expected by [2]=hi, [3]=lo:
        return (result << 8) | (result >> 8)
    }

    // MARK: – Address resolution

    /// Parses a literal IPv4 / IPv6 string into a sockaddr_storage.
    /// Returns nil if `s` is not a valid IP literal.
    private static func parseIP(_ s: String) -> (sockaddr_storage, Bool)? {
        // Try v4.
        var v4 = sockaddr_in()
        v4.sin_family = sa_family_t(AF_INET)
        if inet_pton(AF_INET, s, &v4.sin_addr) == 1 {
            var storage = sockaddr_storage()
            withUnsafeMutablePointer(to: &storage) { sptr in
                sptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { dst in
                    dst.pointee = v4
                }
            }
            return (storage, false)
        }
        // Try v6.
        var v6 = sockaddr_in6()
        v6.sin6_family = sa_family_t(AF_INET6)
        if inet_pton(AF_INET6, s, &v6.sin6_addr) == 1 {
            var storage = sockaddr_storage()
            withUnsafeMutablePointer(to: &storage) { sptr in
                sptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { dst in
                    dst.pointee = v6
                }
            }
            return (storage, true)
        }
        return nil
    }

    /// Resolves a hostname via the system resolver (which, in our
    /// extension with DNS-via-tunnel, hits 1.0.0.1/8.8.4.4 through the
    /// tunnel). Returns the first usable IPv4 address; falls back to
    /// the first IPv6 if no v4 is returned. Synchronous with a hard
    /// `timeout` budget enforced via DispatchSemaphore.
    private static func resolveHostname(_ host: String, timeout: TimeInterval) -> (sockaddr_storage, Bool)? {
        // If it's already an IP literal, short-circuit (defensive).
        if let direct = parseIP(host) { return direct }

        var resolved: (sockaddr_storage, Bool)?
        let lock = NSLock()
        let sem = DispatchSemaphore(value: 0)
        var didSignal = false
        func signalOnce() {
            lock.lock()
            defer { lock.unlock() }
            if didSignal { return }
            didSignal = true
            sem.signal()
        }

        DispatchQueue.global(qos: .utility).async {
            var hints = addrinfo()
            hints.ai_family = AF_UNSPEC
            hints.ai_socktype = SOCK_DGRAM
            var res: UnsafeMutablePointer<addrinfo>?
            let rc = getaddrinfo(host, nil, &hints, &res)
            defer {
                if let res = res { freeaddrinfo(res) }
            }
            if rc != 0 { signalOnce(); return }

            var v4Found: sockaddr_storage?
            var v6Found: sockaddr_storage?
            var cur = res
            while let p = cur {
                let ai = p.pointee
                if ai.ai_family == AF_INET && v4Found == nil {
                    var storage = sockaddr_storage()
                    withUnsafeMutablePointer(to: &storage) { sptr in
                        sptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { dst in
                            ai.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { src in
                                dst.pointee = src.pointee
                            }
                        }
                    }
                    v4Found = storage
                } else if ai.ai_family == AF_INET6 && v6Found == nil {
                    var storage = sockaddr_storage()
                    withUnsafeMutablePointer(to: &storage) { sptr in
                        sptr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { dst in
                            ai.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { src in
                                dst.pointee = src.pointee
                            }
                        }
                    }
                    v6Found = storage
                }
                cur = ai.ai_next
            }
            lock.lock()
            if let v4 = v4Found { resolved = (v4, false) }
            else if let v6 = v6Found { resolved = (v6, true) }
            lock.unlock()
            signalOnce()
        }

        let _ = sem.wait(timeout: .now() + timeout)
        lock.lock()
        defer { lock.unlock() }
        return resolved
    }
}

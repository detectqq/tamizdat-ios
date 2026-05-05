import Foundation
import Darwin
import NetworkExtension
import SamizdatClient

/// IPA-V — Packet bridge with metadata extraction.
///
/// Sits between Apple's `NEPacketTunnelFlow` (which carries per-flow
/// `NEFlowMetaData.sourceAppSigningIdentifier`) and hev-socks5-tunnel
/// (which expects a single fd it can `read`/`write` to in the iOS
/// utun-style 4-byte-AF-prefix framing).
///
/// Data flow:
///
/// ```
///                                 ┌──────────────────────┐
///                                 │   iOS app traffic    │
///                                 └──────────┬───────────┘
///                                            ▼
///                            ┌─────────────────────────────────┐
///                            │ packetFlow.readPacketsAndMetadata│
///                            │  → metadata.sourceAppSigningId    │
///                            └──────────┬──────────────────────┘
///                                       │ (Data, AF, meta)
///                                       ▼
///                          ┌─────────────────────────────────┐
///                          │  parseDestination5Tuple(packet)  │
///                          │   → SubmitAppHint(proto,dst,hint)│
///                          └──────────┬──────────────────────┘
///                                     │ AF-prefix + IP packet
///                                     ▼ write(swiftSideFD)
///                              ┌──────────────┐
///                              │  socketpair  │
///                              └──────┬───────┘
///                                     ▼ read(hevSideFD)
///                              ┌──────────────┐
///                              │ hev (lwIP)   │ → SOCKS5 → socksstub
///                              └──────┬───────┘
///                                     ▼ write(hevSideFD)  reply pkts
///                              ┌──────────────┐
///                              │  socketpair  │
///                              └──────┬───────┘
///                                     ▼ read(swiftSideFD)
///                          ┌─────────────────────────────────┐
///                          │  packetFlow.writePackets        │
///                          └─────────────────────────────────┘
/// ```
///
/// **Performance.** Adds two memcpy + two context switches per packet.
/// Production iOS proxy clients (sing-box-for-apple, etc.) use
/// equivalent Swift-mediated patterns and reach 100 Mbps+ on iPhone
/// 12 and later, so this should be fine on iPhone 16 Pro Max.
///
/// **Risk.** Hev was originally written for an actual utun kctl fd;
/// the only contract we rely on is that hev calls `read()`/`write()`
/// with utun framing (4-byte AF prefix + raw IP packet). A
/// `SOCK_DGRAM` socketpair preserves packet boundaries identically.
final class PacketBridge {

    /// Side fd Swift owns. Read here for outbound replies (hev → app).
    /// Write here for inbound packets we want hev to lwIP-process.
    private var swiftSideFD: Int32 = -1

    /// Side fd hev owns. Hand this to `hev_socks5_tunnel_main_from_str`.
    private(set) var hevSideFD: Int32 = -1

    private weak var provider: NEPacketTunnelProvider?
    private let log: (String) -> Void

    private var running = false
    private let writeQueue = DispatchQueue(label: "com.anarki.samizdat-test.bridge.write", qos: .userInitiated)

    /// Counters for the heartbeat log line.
    private var packetsToHev: UInt64 = 0
    private var packetsFromHev: UInt64 = 0
    private var hintsSubmitted: UInt64 = 0
    private let countersLock = NSLock()

    init(provider: NEPacketTunnelProvider, log: @escaping (String) -> Void) {
        self.provider = provider
        self.log = log
    }

    /// Allocate the socketpair, set generous buffer sizes, and spin up
    /// both read loops. Returns the hev-side fd (caller hands it to
    /// `hev_socks5_tunnel_main_from_str`). Returns -1 on failure.
    func start() -> Int32 {
        var fds: [Int32] = [-1, -1]
        let rc = fds.withUnsafeMutableBufferPointer { buf in
            socketpair(AF_LOCAL, SOCK_DGRAM, 0, buf.baseAddress)
        }
        if rc != 0 {
            log("error: socketpair() failed: errno=\(errno)")
            return -1
        }
        swiftSideFD = fds[0]
        hevSideFD = fds[1]

        // IPA-Z4: 256 KiB (Z3) throttled upstream throughput because
        // hev's drain rate occasionally lagged behind packetFlow's
        // produce rate during bursts → SO_SNDBUF fill → kernel drops →
        // TCP retransmits → speed cliff. 1 MiB × 4 sides = 4 MiB total
        // committed worst case, holds ~800 packets per buffer at 1280
        // MTU. Compromise: ~12 MiB lower than the original 16 MiB Z2
        // value, but leaves headroom for actual speedtest fanout.
        var sndbuf: Int32 = 1024 * 1024
        setsockopt(swiftSideFD, SOL_SOCKET, SO_SNDBUF, &sndbuf, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(swiftSideFD, SOL_SOCKET, SO_RCVBUF, &sndbuf, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(hevSideFD,   SOL_SOCKET, SO_SNDBUF, &sndbuf, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(hevSideFD,   SOL_SOCKET, SO_RCVBUF, &sndbuf, socklen_t(MemoryLayout<Int32>.size))

        log("info: PacketBridge socketpair fds swift=\(swiftSideFD) hev=\(hevSideFD), bufs=\(sndbuf)")

        running = true
        startInboundReader()
        startOutboundReader()
        return hevSideFD
    }

    /// Tear everything down. Idempotent.
    func stop() {
        running = false
        if swiftSideFD >= 0 { close(swiftSideFD); swiftSideFD = -1 }
        if hevSideFD >= 0 { close(hevSideFD); hevSideFD = -1 }
    }

    /// Snapshot for the heartbeat log.
    func counters() -> (toHev: UInt64, fromHev: UInt64, hints: UInt64) {
        countersLock.lock(); defer { countersLock.unlock() }
        return (packetsToHev, packetsFromHev, hintsSubmitted)
    }

    // MARK: – inbound (app → hev)

    /// Recursive read loop on `packetFlow.readPacketsAndMetadata`. Each
    /// callback delivers a batch of (data, AF, metadata). For each
    /// packet:
    ///
    /// 1. Try to extract a destination 5-tuple. Pass the bundle-id (if
    ///    any) to socksstub via `SocksstubSubmitAppHint` so that, when
    ///    hev later opens a SOCKS5 CONNECT for the corresponding flow,
    ///    socksstub finds the hint and tags the upstream H2 CONNECT.
    /// 2. Frame the packet with a 4-byte big-endian AF prefix and
    ///    `write()` it to the hev side of the socketpair.
    private func startInboundReader() {
        guard let provider else { return }
        // `readPacketObjects` returns `[NEPacket]`, where each NEPacket
        // carries `.data`, `.protocolFamily`, `.direction`, and (iOS 14+)
        // `.metadata`. `metadata.sourceAppSigningIdentifier` is the
        // string we want.
        provider.packetFlow.readPacketObjects { [weak self] (packets: [NEPacket]) in
            guard let self, self.running else { return }
            self.handleInbound(packets: packets)
            // Re-arm.
            self.startInboundReader()
        }
    }

    private func handleInbound(packets: [NEPacket]) {
        for pkt in packets {
            let payload = pkt.data
            // protocolFamily is sa_family_t (UInt8 on Darwin).
            let af = UInt32(pkt.protocolFamily)
            let meta: NEFlowMetaData? = pkt.metadata

            // Step 1: extract dst, attribute to a process if metadata
            // has a non-nil bundle-id. Apple delivers metadata for
            // every packet but `sourceAppSigningIdentifier` is
            // typically nil for system / kernel-originated traffic and
            // populated for app traffic.
            if let bundleID = meta?.sourceAppSigningIdentifier,
               let tuple = parseDestinationTuple(packet: payload, af: af) {
                let normalized = normalizeBundleID(bundleID)
                if !normalized.isEmpty {
                    SocksstubSubmitAppHint(tuple.proto, tuple.dest, normalized, 5000)
                    countersLock.lock(); hintsSubmitted &+= 1; countersLock.unlock()
                }
            }

            // Step 2: write 4-byte AF prefix + packet to hev side.
            let prefixed = framePacket(packet: payload, af: af)
            prefixed.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
                guard let base = buf.baseAddress else { return }
                let n = write(swiftSideFD, base, prefixed.count)
                if n != prefixed.count {
                    // Partial write to a SOCK_DGRAM socketpair shouldn't
                    // happen unless EWOULDBLOCK / kernel drop. We don't
                    // retry — at 1280 MTU, a momentary buffer overflow
                    // is recoverable by upper-layer TCP retransmit.
                    if n < 0 && (errno != EAGAIN && errno != EINTR) {
                        log("warn: bridge write to hev: errno=\(errno)")
                    }
                }
            }
            countersLock.lock(); packetsToHev &+= 1; countersLock.unlock()
        }
    }

    // MARK: – outbound (hev → app)

    private func startOutboundReader() {
        writeQueue.async { [weak self] in
            self?.outboundReadLoop()
        }
    }

    private func outboundReadLoop() {
        // Reusable read buffer: 64 KiB is way more than any single utun
        // packet (1500 max, 1280 in our config).
        let bufferSize = 65_536
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        while running {
            let n = read(swiftSideFD, buffer, bufferSize)
            if n < 0 {
                if errno == EINTR { continue }
                if errno == EBADF { return } // we were stopped
                log("warn: bridge read from hev: errno=\(errno)")
                Thread.sleep(forTimeInterval: 0.01)
                continue
            }
            if n < 4 { continue }

            // Decode 4-byte big-endian AF prefix. iOS utun convention.
            let af: UInt32 =
                (UInt32(buffer[0]) << 24) |
                (UInt32(buffer[1]) << 16) |
                (UInt32(buffer[2]) << 8) |
                 UInt32(buffer[3])

            // Slice off the prefix; the rest is a complete IP packet.
            let payload = Data(bytes: buffer.advanced(by: 4), count: n - 4)

            // packetFlow.writePackets is the documented Apple API for
            // injecting packets back into the iOS app's network stack.
            // writePacketObjects (the NEPacket-array form) would let us
            // batch, but at one packet per syscall the single-call form
            // is equivalent.
            _ = provider?.packetFlow.writePackets(
                [payload], withProtocols: [NSNumber(value: af)]
            )

            countersLock.lock(); packetsFromHev &+= 1; countersLock.unlock()
        }
    }

    // MARK: – helpers

    /// 4-byte big-endian AF prefix + raw IP packet, in a single Data
    /// for one `write()`.
    private func framePacket(packet: Data, af: UInt32) -> Data {
        var prefix = Data(count: 4)
        prefix[0] = UInt8((af >> 24) & 0xff)
        prefix[1] = UInt8((af >> 16) & 0xff)
        prefix[2] = UInt8((af >> 8) & 0xff)
        prefix[3] = UInt8(af & 0xff)
        return prefix + packet
    }

    /// Strip the 10-char team-id prefix (e.g. `T6L52V2DZD.`) if present
    /// and lowercase. Examples observed in NEFlowMetaData:
    ///   `T6L52V2DZD.com.AnyDesk.AnyDesk` → `com.anydesk.anydesk`
    ///   `S86L44Q3G6.com.roblox.robloxmobile` → `com.roblox.robloxmobile`
    ///   `com.apple.mobilesafari` → `com.apple.mobilesafari` (no prefix)
    /// Server-side substring whitelist matches `anydesk`, `roblox`,
    /// etc. inside this string.
    private func normalizeBundleID(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "" }
        let lc = trimmed.lowercased()
        if let dot = lc.firstIndex(of: "."),
           lc.distance(from: lc.startIndex, to: dot) == 10 {
            return String(lc[lc.index(after: dot)...])
        }
        return lc
    }
}

// MARK: – 5-tuple parsing (file scope so unit tests can hit it)

struct DestinationTuple {
    let proto: String   // "tcp" or "udp"
    let dest: String    // "host:port" — IP literal on iOS
}

/// Pulls (transport-proto, dst-IP, dst-port) out of an IP packet. Only
/// TCP and UDP are interesting for app attribution; ICMP/IGMP get
/// nil. Returns nil for malformed or non-IPv4/IPv6 packets.
///
/// IPv4 layout (we only need a few bytes):
///   byte 0    : version (high 4 bits) + ihl (low 4 bits, in 32-bit words)
///   byte 9    : protocol  (TCP=6, UDP=17)
///   bytes 16-19: dst IP
///   then transport header at offset ihl*4
///
/// IPv6 layout:
///   byte 6    : next header
///   bytes 24-39: dst IP
///   transport header at offset 40 (no extension headers handled — TSPU
///   traffic on iOS is overwhelmingly extensionless)
func parseDestinationTuple(packet: Data, af: UInt32) -> DestinationTuple? {
    // NEPacketTunnelFlow.readPacketsAndMetadata delivers `protocols`
    // as host-order NSNumber containing AF_INET / AF_INET6.
    switch af {
    case UInt32(AF_INET):  return parseIPv4(packet)
    case UInt32(AF_INET6): return parseIPv6(packet)
    default:               return nil
    }
}

private func parseIPv4(_ packet: Data) -> DestinationTuple? {
    guard packet.count >= 20 else { return nil }
    let v0 = packet[0]
    let version = v0 >> 4
    let ihlWords = Int(v0 & 0x0f)
    guard version == 4, ihlWords >= 5 else { return nil }
    let ihlBytes = ihlWords * 4
    guard packet.count >= ihlBytes + 4 else { return nil }
    let proto = packet[9]
    let dstIP = String(format: "%u.%u.%u.%u", packet[16], packet[17], packet[18], packet[19])
    let dport: UInt16 = UInt16(packet[ihlBytes + 2]) << 8 | UInt16(packet[ihlBytes + 3])
    let protoStr: String
    switch proto {
    case 6:  protoStr = "tcp"
    case 17: protoStr = "udp"
    default: return nil
    }
    return DestinationTuple(proto: protoStr, dest: "\(dstIP):\(dport)")
}

private func parseIPv6(_ packet: Data) -> DestinationTuple? {
    guard packet.count >= 40 + 4 else { return nil }
    let v0 = packet[0]
    guard (v0 >> 4) == 6 else { return nil }
    let nextHdr = packet[6]
    // No extension-header walking. TSPU realtime traffic does not use them.
    let protoStr: String
    switch nextHdr {
    case 6:  protoStr = "tcp"
    case 17: protoStr = "udp"
    default: return nil
    }
    // Format dst IPv6 as 8 groups of 4 hex digits, no compression.
    var groups: [String] = []
    for i in stride(from: 24, to: 40, by: 2) {
        let hi = UInt16(packet[i]) << 8
        let lo = UInt16(packet[i + 1])
        groups.append(String(format: "%x", hi | lo))
    }
    let dstIP = groups.joined(separator: ":")
    let dport: UInt16 = UInt16(packet[40 + 2]) << 8 | UInt16(packet[40 + 3])
    return DestinationTuple(proto: protoStr, dest: "[\(dstIP)]:\(dport)")
}


import Foundation
import Network
import NetworkExtension
import OSLog
import os
import Darwin
import HevSocks5Tunnel
import SamizdatClient

/// Path 3 PacketTunnelProvider — pure C/lwIP via hev-socks5-tunnel, no Go
/// runtime in the extension. The heavy lifting (Go SOCKS5 listener,
/// optional samizdat proxy) lives in the main-app process where there is
/// no jetsam memory cap. The extension's job in this design is reduced to
/// just three things:
///
///   1. install NEPacketTunnelNetworkSettings;
///   2. find the utun file descriptor that NEPacketTunnelProvider just
///      opened for us (Apple does not pass it through the public API; we
///      enumerate fds and match the "com.apple.net.utun_control" socket
///      pattern — same trick every shipping iOS proxy app uses);
///   3. call hev_socks5_tunnel_main_from_str(config, len, fd), which
///      blocks until hev_socks5_tunnel_quit().
///
/// Memory profile observed on production iOS proxy clients (V2Box, FoXray,
/// Hiddify variants) running this exact pattern: 5-15 MB RSS sustained
/// even at 100 Mbps, vs. our ~30-40 MB Go/gVisor stack that hit jetsam at
/// 50 s. The savings come from: no Go runtime, no gVisor packet pools, no
/// gomobile cgo bridging, no per-flow Go goroutines.
final class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = Logger(subsystem: "com.anarki.samizdat-test.tunnel", category: "extension")
    private let runningState = OSAllocatedUnfairLock<Bool>(initialState: false)
    private var isRunning: Bool {
        get { runningState.withLock { $0 } }
        set { runningState.withLock { $0 = newValue } }
    }

    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let logFileName = "extension-log.txt"

    /// TCP port the main-app's SocksStubStart binds to on 127.0.0.1. Hev
    /// connects here for every flow it forwards. Hardcoded so extension
    /// and app agree without an extra rendezvous; collision-unlikely in
    /// the iOS sandbox.
    private static let socksPort: UInt16 = 18443

    private var swiftHeartbeatTimer: DispatchSourceTimer?
    private var swiftLogHandle: FileHandle?
    private var hevQueue = DispatchQueue(label: "com.anarki.samizdat-test.hev", qos: .userInitiated)

    // IPA-O: auto-reconnect on network change (Wi-Fi ↔ cellular flip).
    // Mirrors what V2Box / FoXray / Hiddify do: when the OS default interface
    // changes, the in-flight TLS+H2 transports to the upstream samizdat
    // server are tied to old socket fds and won't recover on their own;
    // we re-call SocksstubSetSamizdatConfig with the same blob, which
    // closes the old samizdat.Client and rebuilds a fresh one over the
    // current default interface.
    private let pathMonitor = NWPathMonitor()
    private let pathMonitorQueue = DispatchQueue(label: "com.anarki.samizdat-test.path", qos: .utility)
    private var lastPathInterfaceID: String? // sortable key from path.availableInterfaces
    private var lastReconnectAt = Date.distantPast

    // IPA-P: dual-endpoint storage. The combined blob arrives in
    // providerConfiguration; we split it into primary + optional backup
    // and pick which one to dial based on EndpointModeStore.current
    // (read from App Group UserDefaults — the main app writes when the
    // user taps the picker, then sends a "switchEndpoint" provider
    // message so we re-read live without disconnect).
    private var combinedConfigBlob: String = ""
    private var primaryBlob: String = ""
    private var backupBlob: String?

    // IPA-Q: WhitelistDetector — periodic out-of-tunnel cascade probe
    // that flips to backup when TSPU whitelist mode is detected and
    // back to primary when it lifts.
    private var whitelistDetector: WhitelistDetector?
    private var lastPathSatisfied: Bool = true

    // IPA-V: per-flow process attribution. PacketBridge sits between
    // packetFlow.readPacketsAndMetadata (where NEFlowMetaData lives)
    // and hev's tun fd. For every outbound packet with a non-nil
    // metadata.sourceAppSigningIdentifier it submits an app-hint to
    // socksstub, which then attaches a Tamizdat-App-Hint header to
    // the matching upstream H2 CONNECT.
    private var packetBridge: PacketBridge?

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        // Start writing into App Group log file immediately so we have a
        // timeline even if hev fails to launch.
        openLogSink()
        appendExtLog("info: PacketTunnelProvider startTunnel (Path 3 / hev)")

        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let configBlob = proto.providerConfiguration?["configBlob"] as? String else {
            appendExtLog("error: missing configBlob in providerConfiguration")
            completionHandler(makeError("missing samizdat config"))
            return
        }
        let serverIP = proto.providerConfiguration?["serverIP"] as? String

        // IPA-P: split the combined blob (which carries an optional
        // &backup=base64url(...) query param) into per-endpoint URLs.
        // The currently selected endpoint feeds SocksStubSetSamizdatConfig.
        let split = SamizdatURLCodec.split(configBlob)
        self.combinedConfigBlob = configBlob
        self.primaryBlob = split.primary
        self.backupBlob = split.backup
        let mode = EndpointModeStore.current
        let activeBlob = Self.pick(mode: mode, primary: split.primary, backup: split.backup)
        appendExtLog("info: endpoint mode = \(mode.rawValue) (backup configured: \(split.backup != nil))")

        // Bring the in-process SOCKS5 listener up FIRST. Both endpoints
        // of the loopback bridge live in this extension, so there is no
        // cross-process sandbox issue and the listener can never get
        // host-app-suspended out from under us.
        appendExtLog("info: starting in-process SocksStub on 127.0.0.1:\(Self.socksPort)")
        if !Self.startInProcessSocks(configBlob: activeBlob, log: appendExtLog) {
            completionHandler(makeError("SocksStub failed to start"))
            return
        }

        let settings = makeNetworkSettings(serverIP: serverIP)
        appendExtLog("info: applying packet tunnel network settings")
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                self.appendExtLog("error: setTunnelNetworkSettings: \(error.localizedDescription)")
                completionHandler(error)
                return
            }
            self.startHev(configBlob: configBlob, completionHandler: completionHandler)
        }
    }

    /// Starts the Go SOCKS5 listener and primes the samizdat client. Both
    /// run inside this extension process. Returns true on success.
    private static func startInProcessSocks(configBlob: String, log: (String) -> Void) -> Bool {
        // Mirror Go-shim logs to the App Group file so the bridge sees them
        // alongside extension logs.
        if let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupID
        ) {
            let logURL = containerURL.appendingPathComponent(logFileName)
            SocksstubSetLogSink(logURL.path)
        }
        var startErr: NSError?
        SocksstubStart("127.0.0.1:\(socksPort)", &startErr)
        if let startErr {
            // "already listening" is fine on a hot-restart of the tunnel
            // — surface but don't fail.
            let msg = startErr.localizedDescription
            if msg.contains("already listening") {
                log("info: SocksStub: already listening, reusing")
            } else {
                log("error: SocksstubStart: \(msg)")
                return false
            }
        }
        // IPA-X: seed Go-side with the persisted V1/V2/V3 picker before
        // building the client. The setter just stores the bit;
        // SetSamizdatConfig below reads it when constructing ClientConfig.
        // IPA-Y: Performance-mode toggle removed — Plan B+ realtime
        // detector auto-flips the bulk transport to ShapeLite during
        // any realtime flow (cover/fragmentation suspended for that
        // window only), so no static kill switch is needed.
        SocksstubSetPoolVariant(PoolVariantPreferences.current.rawValue)
        var cfgErr: NSError?
        SocksstubSetSamizdatConfig(configBlob, &cfgErr)
        if let cfgErr {
            log("error: SocksstubSetSamizdatConfig: \(cfgErr.localizedDescription)")
            return false
        }
        return true
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue, privacy: .public)")
        isRunning = false
        appendExtLog("info: PacketTunnelProvider stopTunnel reason=\(reason.rawValue)")
        whitelistDetector?.stop()
        whitelistDetector = nil
        WhitelistStatusStore.reset()
        pathMonitor.cancel()
        hev_socks5_tunnel_quit()
        // IPA-V: tear down the bridge AFTER hev has been told to quit
        // so hev sees EBADF / EOF on its side and exits cleanly.
        packetBridge?.stop()
        packetBridge = nil
        swiftHeartbeatTimer?.cancel()
        swiftHeartbeatTimer = nil
        try? swiftLogHandle?.close()
        swiftLogHandle = nil
        completionHandler()
    }

    // MARK: – auto-reconnect on network change

    /// Subscribes to NWPath updates so we can detect Wi-Fi ↔ cellular
    /// flips and other interface changes. When the underlying default
    /// interface changes, the OS sockets the samizdat client opened on
    /// the old interface are stale (may RST or just hang); rebuilding
    /// the upstream-facing pool from scratch is the cheapest correct
    /// fix and matches what every other production iOS proxy client
    /// does.
    private func startPathMonitor() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            self?.onPathUpdate(path)
        }
        pathMonitor.start(queue: pathMonitorQueue)
        appendExtLog("info: path monitor started")
    }

    private func onPathUpdate(_ path: Network.NWPath) {
        // Forward path-satisfied state to the WhitelistDetector so it
        // pauses probes during a network outage (lift / forest / metro).
        let satisfied = (path.status == .satisfied)
        if satisfied != lastPathSatisfied {
            lastPathSatisfied = satisfied
            whitelistDetector?.notePathChange(satisfied: satisfied)
        }

        // Compose a stable interface fingerprint: type + name(s). This
        // avoids treating "same Wi-Fi, just IP renewed" as a change.
        let kind = describePath(path)
        let prev = lastPathInterfaceID
        lastPathInterfaceID = kind

        // First update right after start — record baseline, do nothing.
        if prev == nil {
            appendExtLog("info: path baseline = \(kind)")
            return
        }
        if prev == kind {
            return
        }

        // Debounce: iOS can fire 3-4 path updates in a flap (interface
        // appears, gets DHCP, gets IPv6, becomes default, …). 3 s is
        // longer than typical flap settle but well below user patience.
        let now = Date()
        if now.timeIntervalSince(lastReconnectAt) < 3.0 {
            appendExtLog("info: path change \(prev ?? "?") → \(kind) — debounced")
            return
        }
        lastReconnectAt = now

        appendExtLog("info: path change \(prev ?? "?") → \(kind) — rewiring upstream")
        rewireUpstream()
    }

    private func describePath(_ path: Network.NWPath) -> String {
        if path.status != Network.NWPath.Status.satisfied {
            return "unsatisfied"
        }
        // Pick the dominant interface type for label purposes.
        let typeName: String
        if path.usesInterfaceType(NWInterface.InterfaceType.wifi) {
            typeName = "wifi"
        } else if path.usesInterfaceType(NWInterface.InterfaceType.cellular) {
            typeName = "cellular"
        } else if path.usesInterfaceType(NWInterface.InterfaceType.wiredEthernet) {
            typeName = "wired"
        } else if path.usesInterfaceType(NWInterface.InterfaceType.loopback) {
            typeName = "loopback"
        } else {
            typeName = "other"
        }
        let names = path.availableInterfaces.map { $0.name }.joined(separator: ",")
        return "\(typeName)[\(names)]"
    }

    /// Rebuilds the samizdat client by re-calling SocksstubSetSamizdatConfig
    /// with the stored config blob. This closes the old client (which
    /// closes its TLS+H2 transports tied to the previous interface) and
    /// constructs a new one whose first connect goes via the current
    /// default interface. The SOCKS5 listener itself stays up, so hev
    /// can keep using 127.0.0.1:\(socksPort) without restart.
    private func rewireUpstream() {
        let mode = EndpointModeStore.current
        let blob = Self.pick(mode: mode, primary: primaryBlob, backup: backupBlob)
        guard !blob.isEmpty else { return }
        // Run off the path monitor queue to avoid serializing further
        // updates while we sit inside Go-side teardown.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            var err: NSError?
            SocksstubSetSamizdatConfig(blob, &err)
            if let err {
                self.appendExtLog("error: rewire SetSamizdatConfig: \(err.localizedDescription)")
            } else {
                self.appendExtLog("info: rewire ok (mode=\(mode.rawValue)) — fresh samizdat client warmed")
            }
        }
    }

    /// Picks the appropriate blob for a given mode. In manual modes
    /// (.primary/.backup) it follows the user's pick. In .auto mode it
    /// honours WhitelistStatusStore.activeEndpoint — which the
    /// WhitelistDetector flips between .primary and .backup based on
    /// the cascade probe verdict.
    private static func pick(mode: EndpointMode, primary: String, backup: String?) -> String {
        switch mode {
        case .primary:
            return primary
        case .backup:
            return backup ?? primary
        case .auto:
            // Detector's effective choice; defaults to primary on first run.
            switch WhitelistStatusStore.activeEndpoint {
            case .backup: return backup ?? primary
            default:      return primary
            }
        }
    }

    // MARK: – WhitelistDetector lifecycle

    /// Starts the detector iff EndpointModeStore.current == .auto AND a
    /// backup blob is configured. Idempotent — calling again while the
    /// detector is already running is a no-op.
    private func startWhitelistDetectorIfNeeded() {
        let mode = EndpointModeStore.current
        let hasBackup = (backupBlob != nil)
        appendExtLog("info: detector lifecycle check: mode=\(mode.rawValue) hasBackup=\(hasBackup) running=\(whitelistDetector != nil)")
        guard mode == .auto else {
            // Mode is not auto → stop if it was running, paint badge as unknown
            // so the UI doesn't keep showing a stale verdict.
            if whitelistDetector != nil {
                appendExtLog("info: detector stopping (mode is \(mode.rawValue), not auto)")
                whitelistDetector?.stop()
                whitelistDetector = nil
            }
            WhitelistStatusStore.current = .unknown
            return
        }
        guard hasBackup else {
            // Auto requested but no backup blob to fail over TO. Be loud
            // about this — main app shows "Whitelist: monitoring..." silent
            // forever otherwise. User must Save backup config and reconnect.
            appendExtLog("warn: detector NOT started — auto mode requested but no backup configured (Save backup URL in Config and reconnect)")
            if whitelistDetector != nil {
                whitelistDetector?.stop()
                whitelistDetector = nil
            }
            WhitelistStatusStore.current = .unknown
            return
        }
        if whitelistDetector != nil {
            appendExtLog("info: detector already running")
            return
        }
        let detector = WhitelistDetector(
            log: { [weak self] line in self?.appendExtLog(line) },
            switchEndpoint: { [weak self] target in
                guard let self else { return }
                // The detector already wrote WhitelistStatusStore.activeEndpoint
                // before calling us; just trigger the rewire to apply it.
                self.appendExtLog("info: detector requested switch → \(target.rawValue)")
                self.rewireUpstream()
            },
            pathProvider: { [weak self] in self?.pathMonitor.currentPath }
        )
        // Seed with current path-status so first-cycle decisions don't
        // trip on a stale "satisfied" assumption.
        detector.notePathChange(satisfied: lastPathSatisfied)
        whitelistDetector = detector
        detector.start()
    }

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        let cmd = String(data: messageData, encoding: .utf8) ?? "ping"
        switch cmd {
        case "ping":
            completionHandler?("pong".data(using: .utf8))
        case "switchEndpoint":
            // IPA-P: main app updated EndpointModeStore in App Group
            // UserDefaults; we re-read and rewire to the new endpoint.
            let mode = EndpointModeStore.current
            appendExtLog("info: app requested endpoint switch → \(mode.rawValue)")
            // IPA-Q: also start/stop the WhitelistDetector based on
            // whether auto mode is now selected.
            startWhitelistDetectorIfNeeded()
            rewireUpstream()
            completionHandler?("switched:\(mode.rawValue)".data(using: .utf8))
        case "refreshSamizdatClient":
            // IPA-X: V1/V2/V3 picker changed in main-app UI. Push the
            // new variant into Go-side then rebuild the client.
            let variant = PoolVariantPreferences.current.rawValue
            appendExtLog("info: app requested samizdat refresh (pool variant = \(variant))")
            SocksstubSetPoolVariant(variant)
            rewireUpstream()
            completionHandler?("refreshed".data(using: .utf8))
        case "status":
            // IPA-Z: main-screen lamp polls this every 500 ms. Snapshot
            // is built from in-process Socksstub*() getters which read
            // tamizdat.Client atomic counters — no locks, no I/O.
            // Field names must stay in sync with TamizdatStatusSnapshot
            // in TamizdatStatusStore.swift.
            let payload: [String: Any] = [
                "realShape":   SocksstubRealShapeMode() ?? "",
                "lockedFlows": Int(SocksstubLockedRealtimeFlows()),
                "liteAlive":   Int(SocksstubLiteAlive()),
                "rttLiteMs":   Int(SocksstubRTTLiteP50Ms()),
                "rttBulkMs":   Int(SocksstubRTTBulkP50Ms()),
            ]
            let json = (try? JSONSerialization.data(withJSONObject: payload)) ?? Data()
            completionHandler?(json)
        default:
            completionHandler?(Data())
        }
    }

    // MARK: – hev invocation

    private func startHev(configBlob: String, completionHandler: @escaping (Error?) -> Void) {
        // hev's YAML config. iOS knobs from heiher's published memory-tuning
        // recommendations (issue #109): tiny task stacks, small TCP buffer,
        // bounded session count. socks5 endpoint = our main-app SOCKS5
        // listener on localhost. UDP-over-TCP keeps memory bounded for
        // QUIC-heavy traffic.
        // Notes from the Path 3 audit:
        //   - lwIP needs an explicit ipv4 in the tunnel block on some
        //     code paths, otherwise it silently drops packets.
        //   - connect-timeout 2 s (down from 5) — first DNS query
        //     should not stall 5 s on a brief startup race.
        let yaml = """
tunnel:
  mtu: 1280
  ipv4: '198.18.0.1'

socks5:
  port: \(Self.socksPort)
  address: '127.0.0.1'
  udp: 'tcp'

misc:
  task-stack-size: 24576
  log-level: 'info'
  connect-timeout: 2000
  read-write-timeout: 60000
"""
        appendExtLog("info: hev config built (\(yaml.utf8.count) bytes)")

        // IPA-V: instead of handing hev the raw utun fd (which bypasses
        // the Swift packetFlow API and hides NEFlowMetaData), we put a
        // socketpair-based PacketBridge between Apple's packetFlow and
        // hev. Swift reads packetFlow.readPacketsAndMetadata to get
        // sourceAppSigningIdentifier, submits app hints to socksstub
        // for each (proto, dst:port) tuple, and forwards the packet
        // to hev via the bridge socketpair. Reverse direction works
        // the same way.
        //
        // The KVO utun fd discovery used in IPA-H is no longer needed
        // for the data path — we never give hev the kctl fd. The
        // bridge owns the only fd hev sees.
        let bridge = PacketBridge(provider: self) { [weak self] line in
            self?.appendExtLog(line)
        }
        let fd = bridge.start()
        if fd < 0 {
            appendExtLog("error: PacketBridge failed to allocate socketpair")
            completionHandler(makeError("PacketBridge socketpair failed"))
            return
        }
        self.packetBridge = bridge
        appendExtLog("info: PacketBridge started; hev fd = \(fd)")

        // Verify main app's SOCKS5 listener is reachable before handing
        // packets to hev. If the app hasn't started SocksStubStart yet,
        // fail fast with a clear error so the user sees "open the app".
        if !Self.probeSocks5(port: Self.socksPort, timeout: 1.0) {
            appendExtLog("error: SOCKS5 listener not reachable on 127.0.0.1:\(Self.socksPort) — open the main app first")
            completionHandler(makeError("Open the Samizdat app first to start the SOCKS5 listener."))
            return
        }
        appendExtLog("info: SOCKS5 reachable; handing packets to hev")

        startSwiftHeartbeat()
        startPathMonitor()
        startWhitelistDetectorIfNeeded()
        isRunning = true

        // hev_socks5_tunnel_main_from_str blocks until quit. Run it on a
        // dedicated background queue.
        let yamlCopy = yaml
        hevQueue.async { [weak self] in
            let rc = yamlCopy.withCString { cstr -> Int32 in
                hev_socks5_tunnel_main_from_str(cstr, UInt32(yamlCopy.utf8.count), fd)
            }
            self?.appendExtLog("info: hev returned rc=\(rc)")
            self?.runningState.withLock { $0 = false }
        }

        // hev itself does not have a "ready" callback — it starts
        // accepting packets immediately on the fd. Synchronous return.
        completionHandler(nil)
    }

    // MARK: – utun fd discovery

    /// Enumerates open file descriptors and returns the highest-numbered
    /// utun fd, logging every candidate it finds along the way (with
    /// the utun unit number from `sc_unit`). On iOS 17+ with iCloud
    /// Private Relay this routinely returns the wrong fd because
    /// Apple's relay utun has a higher fd than ours. KVO is the
    /// preferred path; this scanner survives only as a diagnostic
    /// fallback.
    private static func findTunnelFileDescriptor(log: (String) -> Void) -> Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        var best: Int32 = -1
        var found: [String] = []
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                // sc_unit is 1-based: utun(N-1).
                let unit = Int(addr.sc_unit) - 1
                found.append("fd=\(fd)→utun\(unit)")
                if fd > best {
                    best = fd
                }
            }
        }
        log("info: utun candidates: [\(found.joined(separator: ", "))]")
        return best >= 0 ? best : nil
    }

    /// Best-effort TCP probe to see if the main app's SOCKS5 listener is up
    /// before we hand packets to hev. Avoids a 60-second hev timeout for
    /// each early flow when the app isn't running.
    private static func probeSocks5(port: UInt16, timeout: TimeInterval) -> Bool {
        let s = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard s >= 0 else { return false }
        defer { close(s) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        // Non-blocking connect with timeout.
        let flags = fcntl(s, F_GETFL, 0)
        _ = fcntl(s, F_SETFL, flags | O_NONBLOCK)

        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if rc == 0 { return true }
        if errno != EINPROGRESS { return false }

        // Wait for write-ready or timeout.
        var fdSet = fd_set()
        __darwin_fd_set(s, &fdSet)
        var tv = timeval(tv_sec: Int(timeout), tv_usec: __darwin_suseconds_t((timeout - floor(timeout)) * 1_000_000))
        let sel = select(s + 1, nil, &fdSet, nil, &tv)
        if sel <= 0 { return false }

        // Check SO_ERROR.
        var err: Int32 = 0
        var elen = socklen_t(MemoryLayout<Int32>.size)
        if getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 { return false }
        return err == 0
    }

    // MARK: – Network settings

    private func makeNetworkSettings(serverIP: String?) -> NEPacketTunnelNetworkSettings {
        let remoteAddress = serverIP ?? "127.0.0.1"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        settings.mtu = 1280

        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        if let serverIP {
            ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: serverIP, subnetMask: "255.255.255.255")]
        }
        // Critically: exclude 127.0.0.1/8 from the tunnel so hev's SOCKS5
        // dial to the main app's listener does NOT loop back through us.
        // (iOS may special-case loopback here but explicit is safer.)
        ipv4.excludedRoutes = (ipv4.excludedRoutes ?? []) + [
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
            // IPA-Q: WhitelistDetector probe targets must reach the
            // underlying interface, not loop through our own utun.
            // 1.1.1.1 + 8.8.8.8 are the global "is internet up" canaries;
            // 77.88.8.0/24 covers all Yandex DNS variants used as the
            // RU-whitelisted canary.
            NEIPv4Route(destinationAddress: "1.1.1.1", subnetMask: "255.255.255.255"),
            NEIPv4Route(destinationAddress: "8.8.8.8", subnetMask: "255.255.255.255"),
            NEIPv4Route(destinationAddress: "77.88.8.0", subnetMask: "255.255.255.0"),
        ]
        settings.ipv4Settings = ipv4

        // No IPv6 — see Phase 2.5 rationale; v4-only tunnel is unambiguous.
        settings.ipv6Settings = nil

        // IPA-J: force DNS through the tunnel.
        //
        // Earlier (IPA-F) we set dnsSettings = nil on the theory that iOS
        // mDNSResponder would scope DNS queries to the underlying Wi-Fi
        // interface (IP_BOUND_IF) and bypass the tunnel. On iOS 17/18 with
        // a default-route VPN, this is not what happens: with no
        // dnsSettings installed, iOS treats name resolution as broken
        // ("iPhone не подключен к интернету"), the captive-portal probe
        // to captive.apple.com fails, and Safari refuses to load even
        // direct-IP URLs.
        //
        // Now that IPA-I added cmd=0x05 / FWD_UDP support in SocksStub
        // backed by samizdat.Client.DialUDP, we can safely force DNS
        // (UDP/53) through the tunnel: hev wraps it as cmd=0x05, our
        // SocksStub opens a samizdat UDP tunnel to 1.1.1.1:53 / 8.8.8.8:53,
        // and the response comes back the same way. matchDomains=[""]
        // catches every domain (the empty-string match-all sentinel).
        let dns = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        return settings
    }

    // MARK: – Logging (App Group file)

    private func openLogSink() {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: Self.appGroupID
        ) else { return }
        let logURL = containerURL.appendingPathComponent(Self.logFileName)
        // Truncate per-session — the app reads the file from offset 0 on
        // bridge start, so a fresh file per tunnel is what we want.
        try? Data().write(to: logURL, options: .atomic)
        if let h = try? FileHandle(forWritingTo: logURL) {
            try? h.seekToEnd()
            swiftLogHandle = h
        }
    }

    private func startSwiftHeartbeat() {
        let queue = DispatchQueue(label: "com.anarki.samizdat-test.swift-hb", qos: .userInitiated)
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(2), repeating: .seconds(2))
        timer.setEventHandler { [weak self] in
            guard let self, self.isRunning else { return }
            let avail = os_proc_available_memory()
            var tx_pkts = 0, tx_bytes = 0, rx_pkts = 0, rx_bytes = 0
            hev_socks5_tunnel_stats(&tx_pkts, &tx_bytes, &rx_pkts, &rx_bytes)
            // Ask the Go runtime to return freed pages to iOS so they
            // don't sit on our jetsam ledger between heartbeats. Cheap
            // (a single madvise loop in Go's scavenger).
            SocksstubFreeOSMemory()
            // IPA-V: include PacketBridge counters + active app-hint
            // table size so we can confirm Swift is actually feeding
            // hev and that metadata is flowing through.
            let bridgeCounters = self.packetBridge?.counters() ?? (toHev: 0, fromHev: 0, hints: 0)
            let hintCount = SocksstubAppHintCount()
            self.appendExtLog(String(
                format: "info: hb avail=%dKB hev tx=%d/%dKB rx=%d/%dKB bridge to=%llu from=%llu hints=%llu live=%d",
                avail / 1024,
                tx_pkts, tx_bytes / 1024,
                rx_pkts, rx_bytes / 1024,
                bridgeCounters.toHev, bridgeCounters.fromHev, bridgeCounters.hints,
                hintCount
            ))
        }
        timer.resume()
        swiftHeartbeatTimer = timer
    }

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()

    private func appendExtLog(_ message: String) {
        let stamp = Self.timeFormatter.string(from: Date())
        let line = "\(stamp) \(message)\n"
        log.info("\(message, privacy: .public)")
        guard let h = swiftLogHandle else { return }
        do {
            try h.write(contentsOf: Data(line.utf8))
            try h.synchronize()
        } catch {
            // best-effort
        }
    }

    private func makeError(_ message: String) -> NSError {
        NSError(
            domain: "com.anarki.samizdat-test.tunnel",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}

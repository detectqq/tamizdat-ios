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
    // IPA-D18: emit heartbeat log line only every 5 ticks (every ~150 s
    // at the new 30 s cadence) to drop file-write rate from 3600/hour
    // to ~24/hour. Pressure events are still logged immediately.
    private var hbTick: Int = 0
    private var swiftLogHandle: FileHandle?
    private var memPressureSrc: DispatchSourceMemoryPressure?
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

    // IPA-D22: timestamp when startTunnel completed (the SOCKS5 listener
    // is up and we handed packets to hev). Surfaced in the "status" RPC
    // as uptimeSec so the main-app Uptime stat tile can render m:ss /
    // h:mm without keeping its own anchor.
    private let tunnelStartedAtLock = OSAllocatedUnfairLock<Date?>(initialState: nil)
    private var tunnelStartedAt: Date? {
        get { tunnelStartedAtLock.withLock { $0 } }
        set { tunnelStartedAtLock.withLock { $0 = newValue } }
    }

    // IPA-D22: 1 while rewireUpstream is mid-flight (SetSamizdatConfig
    // call running on a background queue). Surfaced as `isRewiring` in
    // the status RPC so the main-app shield can flip to amber
    // "Reconnecting…" instantly without waiting for path-monitor
    // settling. Read+written under runningState's same unfair lock for
    // cheapness — concurrency model: one rewire at a time.
    private let rewiringFlag = OSAllocatedUnfairLock<Bool>(initialState: false)
    private var isRewiring: Bool {
        get { rewiringFlag.withLock { $0 } }
        set { rewiringFlag.withLock { $0 = newValue } }
    }

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

    // IPA-D26: bridge object retained while the tunnel is up so the
    // Go-side rewire requester atomic.Value holds a valid pointer.
    private var autoRewireBridge: AutoRewireBridge?

    // IPA-A1: PacketBridge removed. We're back on the original
    // "Path 3" architecture (Pattern 1 in the iOS proxy taxonomy):
    // hev gets the raw utun file descriptor via KVO and reads/writes
    // packets directly in C. No Swift in the data path. Same setup
    // Shadowrocket / Surge / Tun2SocksKit use. Loss: per-flow
    // NEFlowMetaData (app bundle-id) — the Tamizdat-App-Hint header
    // (Tier 3 server classifier signal) is no longer sent. Server's
    // Tier 1 (port whitelist for Roblox/AnyDesk/Discord/IANA-dynamic)
    // and Tier 2 (cadence/jitter for RTP/opus) handle real workload
    // without it.

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

        // IPA-D26: register the auto-rewire bridge so the Go-side ping
        // prober can request a fresh client when it sees consecutive
        // misses. Catches the case where wifi is dying but iOS hasn't
        // yet failed over to LTE — system NWPath stays satisfied (or
        // takes 15-30 s to flip), but the prober knows the upstream
        // is unreachable RIGHT NOW. Throttled in Go to once per 15 s.
        let rewireBridge = AutoRewireBridge { [weak self] in
            guard let self else { return }
            self.appendExtLog("info: auto-rewire fired by ping prober (consecutive fails)")
            self.rewireUpstream()
        }
        // Stash a strong ref so the bridge isn't deallocated while Go
        // holds it via atomic.Value.
        self.autoRewireBridge = rewireBridge
        SocksstubSetRewireRequester(rewireBridge)

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
        // IPA-D22: pool variant picker deleted from the UI. V1 is the
        // hardcoded shipping choice (matches what mobile/socksstub
        // ships with). Setter is still called so the Go bridge has a
        // consistent value if anything reads it back; semantically a
        // no-op against the default.
        SocksstubSetPoolVariant("v1")
        // IPA-D21: push the configured real-internet ping probe URL into
        // Go-side before the first client is built, so the prober's first
        // tick fires against the user's chosen target. App-side updates
        // (via SettingsView) are pushed live through the
        // "refreshPingURL" provider message handled below.
        SocksstubSetPingProbeURL(PingURLPreferences.url)
        // Phase C iOS-notify (2026-05-10): register the bridge BEFORE the
        // first samizdat client is built. The first bundle fetch happens
        // immediately after SetSamizdatConfig, so a user who is already
        // over-quota at connect time still gets the notification.
        SocksstubSetNotificationCallback(NotificationBridge.shared)
        var cfgErr: NSError?
        SocksstubSetSamizdatConfig(configBlob, &cfgErr)
        if let cfgErr {
            log("error: SocksstubSetSamizdatConfig: \(cfgErr.localizedDescription)")
            return false
        }

        // Phase 2D-PART-C: attach VK TURN upstream when the operator
        // has explicitly opted in via Settings → VK TURN → mode = .vk.
        // Static helper because startInProcessSocks itself is static —
        // it has no `self`, only the log closure threaded through from
        // the instance-level caller. Failure paths log + fall through
        // silently so the hev tunnel still serves traffic.
        if EndpointTurnMode.current == .vk {
            Self.attachVKTurnUpstream(log: log)
        }
        return true
    }

    /// Spin up the VK TURN runner if the operator selected it.
    /// All inputs come from App Group UserDefaults — the user fills
    /// them in Settings → VK TURN before flipping the picker on.
    /// Traffic still flows over the existing hev path; this only logs
    /// the WireGuard config it receives so the operator can verify
    /// reachability. WireGuardKit attach is Phase 2D-followup.
    private static func attachVKTurnUpstream(log: @escaping (String) -> Void) {
        let peer = VKCredsPreferences.peerAddr
        let password = VKCredsPreferences.connectPassword
        guard !peer.isEmpty, !password.isEmpty else {
            log("warn: VK TURN attach skipped — peer or password empty")
            return
        }
        let deviceID = VKCredsPreferences.deviceID
        guard let creds = TURNCredsStore.shared.load(), TURNCredsStore.shared.isFresh else {
            log("warn: VK TURN attach skipped — no fresh creds")
            return
        }
        let json = vkCredsAsJSON(creds: creds)
        let err = SocksstubStartVKTurnUpstream(json, peer, password, deviceID, 9000)
        if !err.isEmpty {
            log("error: SocksstubStartVKTurnUpstream: \(err)")
            return
        }
        log("info: VK TURN upstream started, polling for WG config...")

        Task.detached(priority: .utility) {
            for _ in 0..<60 { // 60 * 250 ms = 15 s
                let wg = SocksstubTURNUpstreamWGConfig()
                if !wg.isEmpty {
                    log("info: VK TURN WG config received:\n\(wg)")
                    return
                }
                try? await Task.sleep(nanoseconds: 250_000_000)
            }
            log("warn: VK TURN WG config not received within 15 s")
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue, privacy: .public)")
        isRunning = false
        // IPA-D22: clear so the main-app Uptime tile flips to "—".
        tunnelStartedAt = nil
        isRewiring = false
        appendExtLog("info: PacketTunnelProvider stopTunnel reason=\(reason.rawValue)")
        // IPA-D26: drop the auto-rewire bridge so it doesn't keep a
        // strong reference to self after the tunnel is torn down.
        autoRewireBridge = nil
        whitelistDetector?.stop()
        whitelistDetector = nil
        // D61 FIX: do NOT call WhitelistStatusStore.reset() here.
        // reset() wipes activeEndpoint → defaults to .primary → Mode
        // tile flips from "Whitelist" to "Main" on every disconnect,
        // even though the network is still whitelist-filtered. The
        // main-app WhitelistMonitor resumes on disconnect and writes
        // fresh values; the 200s stale-check handles truly stale data.
        pathMonitor.cancel()
        // Phase 2D-PART-C: stop the VK TURN runner if it was attached.
        // Idempotent on the Go side — safe to call even when never started.
        SocksstubStopVKTurnUpstream()
        hev_socks5_tunnel_quit()
        swiftHeartbeatTimer?.cancel()
        swiftHeartbeatTimer = nil
        stopBurstProtection()  // IPA-D2
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

        // IPA-D17: removed 3-second blanket debounce. sing-box-for-apple
        // (ExtensionPlatformInterface.swift:260-271) calls onUpdate
        // DefaultInterface synchronously from the path callback with no
        // debounce; the same-kind early return above already coalesces
        // satisfied→satisfied churn for free. The 3-s blanket was the
        // reason users felt the WiFi-off → cellular-on switch hang for
        // ~30-60 seconds: dead flows kept running until their per-stream
        // read-timeout while we sat on the debounce.
        //
        // Skip rewire on .unsatisfied transitions — there is no upstream
        // to dial through, and rebuilding a samizdat.Client now would
        // just fail and waste the warm-up TLS handshake. The next
        // .satisfied callback with a fresh interface kind fires a real
        // rewire.
        if !satisfied {
            appendExtLog("info: path change \(prev ?? "?") → \(kind) — unsatisfied, deferring rewire to next satisfied path")
            return
        }
        lastReconnectAt = Date()

        appendExtLog("info: path change \(prev ?? "?") → \(kind) — rewiring upstream + force-closing stale flows")
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
        var seenNames = Set<String>()
        let names = path.availableInterfaces.compactMap { iface -> String? in
            let name = iface.name
            guard !name.hasPrefix("utun"), seenNames.insert(name).inserted else {
                return nil
            }
            return name
        }.joined(separator: ",")
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
        // IPA-D22: flip the isRewiring flag so the main-app shield can
        // render "Reconnecting…" instantly. Cleared in `defer` below.
        isRewiring = true
        // Run off the path monitor queue to avoid serializing further
        // updates while we sit inside Go-side teardown.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            defer { self.isRewiring = false }
            var err: NSError?
            SocksstubSetSamizdatConfig(blob, &err)
            if let err {
                self.appendExtLog("error: rewire SetSamizdatConfig: \(err.localizedDescription)")
                return
            }
            self.appendExtLog("info: rewire ok (mode=\(mode.rawValue)) — fresh samizdat client warmed")

            // IPA-D17: after the new client is in place, force-close
            // every loopback SOCKS5 flow that hev opened over the OLD
            // path. Apps see RST → reconnect immediately on the fresh
            // client, instead of hanging on dead H/2 streams until
            // per-stream read timeout (~30-60 s).
            //
            // Order matters: swap first, close flows second. Otherwise
            // the close would race with retries that have nowhere to go.
            //
            // Reference patterns:
            //   sing-box-for-apple: onUpdateDefaultInterface in libbox
            //     causes the route NetworkManager to flush per-flow
            //     DefaultMarker, propagating EOF to in-flight conns.
            //   Shadowrocket: -[DLWPacketTunnelProvider closeAllTunnels]
            //     (Ghidra @ 0x1000e43f4) walks 7 tunnel singletons.
            //
            // Our equivalent is the single SocksstubCloseAllFlows() over
            // the unified flowRegistry — same effect, less ceremony.
            let closed = SocksstubCloseAllFlows()
            self.appendExtLog("info: rewire force-closed \(closed) stale flows")
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
            // IPA-D22: pool-variant UI deleted. Path retained for
            // future cases where the app wants to force a samizdat
            // client rebuild; pool variant is now hardcoded V1 in the
            // setInProcessSocks bootstrap.
            appendExtLog("info: app requested samizdat refresh")
            SocksstubSetPoolVariant("v1")
            rewireUpstream()
            completionHandler?("refreshed".data(using: .utf8))
        case "refreshPingURL":
            // IPA-D21: SettingsView's ping-probe URL field changed in the
            // main app. Re-read from App Group UserDefaults and push into
            // Go-side. Prober picks it up on the next tick — no need to
            // rebuild the samizdat client.
            let url = PingURLPreferences.url
            appendExtLog("info: app requested ping URL refresh → \(url)")
            SocksstubSetPingProbeURL(url)
            completionHandler?("pingURLRefreshed".data(using: .utf8))
        case "refreshWhitelistProbes":
            // IPA-D23: SettingsView's whitelist probe targets changed.
            // Re-read prefs and tell the detector to adopt them. The
            // excludedRoutes change requires a tunnel reconnect to take
            // effect (we don't currently rebuild network settings live);
            // the UI shows a disclaimer about that.
            appendExtLog("info: app requested whitelist probes refresh → testHost=\(WhitelistProbePreferences.testHost) whitelistHost=\(WhitelistProbePreferences.whitelistHost)")
            whitelistDetector?.applyConfig()
            completionHandler?("whitelistProbesRefreshed".data(using: .utf8))
        case "status":
            // IPA-Z (D21 update): main-screen lamp polls this every 500 ms.
            // Snapshot is built from in-process Socksstub*() getters which
            // read tamizdat.Client + ping-prober atomic state — no locks,
            // no I/O. Field names must stay in sync with
            // TamizdatStatusSnapshot in TamizdatStatusStore.swift.
            //
            // D21: rttBulk/rttLite/liteAlive/lockedFlows kept in the JSON
            // (no harm) but no longer read on the Swift side — the lamp
            // now uses the ping snapshot fields. Old fields will be
            // dropped in a future cleanup commit once the v0.2.D21 IPA is
            // rolled out and no skewed clients remain in the wild.
            let pingSnap = SocksstubPingProbeSnapshot()
            // IPA-D22: include hev cumulative byte counters + uptime so
            // the main-app Data + Uptime stat tiles can render without
            // any extra RPC. `hev_socks5_tunnel_stats` semantics on the
            // iOS side: tx = packets/bytes from utun (app→remote), rx
            // = packets/bytes back. We expose both as "rxBytes" and
            // "txBytes"; the main app sums them for the Data tile and
            // diffs them for the rate readout.
            var tx_pkts = 0, tx_bytes = 0, rx_pkts = 0, rx_bytes = 0
            hev_socks5_tunnel_stats(&tx_pkts, &tx_bytes, &rx_pkts, &rx_bytes)
            let uptime: Int64
            if let started = self.tunnelStartedAt {
                uptime = Int64(Date().timeIntervalSince(started))
            } else {
                uptime = 0
            }
            let payload: [String: Any] = [
                "realShape":   SocksstubRealShapeMode(),
                "lockedFlows": Int(SocksstubLockedRealtimeFlows()),
                "liteAlive":   Int(SocksstubLiteAlive()),
                "rttLiteMs":   Int(SocksstubRTTLiteP50Ms()),
                "rttBulkMs":   Int(SocksstubRTTBulkP50Ms()),
                // IPA-D21 ping-prober fields.
                "pingMs":      Int(pingSnap?.lastMs ?? -1),
                "pingOK":      pingSnap?.ok ?? false,
                "pingFailed":  pingSnap?.failed ?? false,
                "pingURL":     pingSnap?.url ?? "",
                // IPA-D22 stat-tile + reconnecting fields.
                "rxBytes":     Int64(rx_bytes),
                "txBytes":     Int64(tx_bytes),
                "uptimeSec":   uptime,
                "isRewiring":  self.isRewiring ? 1 : 0,
                // VK TURN relay credential status. IPA-D65b: the main
                // app now acquires creds itself via WKWebView captcha
                // solving and writes them to App Group UserDefaults
                // (`TURNCredsStore`). The extension only READS the
                // cache here — no VK API touch from inside the NE.
                // The legacy `SocksstubTURNCredsSnapshot()` is kept on
                // the Go side as a no-op fallback for now but is no
                // longer the source of truth.
                "hasTURNCreds": TURNCredsStore.shared.isFresh,
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
        // IPA-A7: revert A4's hev YAML caps. The 2nd analyst's review
        // identified A4's `tcp-buffer-size: 16 KiB` as the smoking gun
        // for Go heap explosion in the A4 log: lwIP outbound buffer
        // (16 KiB) was too small relative to Go h2 stream window
        // (64 KiB), producing backpressure pile-up that pinned 200
        // streams × ~100 KB = 20+ MiB of "released-but-stuck" Go state.
        // A5 added pcs eviction but kept the YAML, so heap explosions
        // continued under load.
        //
        // Back to defaults — let lwIP run with its standard 64 KiB
        // tcp-buffer matched against Go's 64 KiB stream window. The
        // pcs-map leak (the original A3 9-min YouTube cause) is still
        // bounded by Phase A in IPA-A5.
        //
        // Only retained: task-stack-size 24 KiB (default 84 KiB,
        // historic iOS budget choice — out of scope to revisit).
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
  # IPA-D19: bump hev per-socket read/write idle from 60s to 5min.
  # 60s killed AnyDesk after ~1 minute when the user paused typing on the
  # HID side of its multi-TCP relay (only the video channel kept hev's read
  # loop fed; HID went silent and tripped the deadline). 5 min matches sing-
  # box's industry-standard UDPTimeout/TCPKeepAliveInitial constants
  # (sing-box/constant/timeout.go:6,12). See diagnosis at
  # /c/var-tmp/anydesk-diagnosis.md.
  read-write-timeout: 300000
"""
        appendExtLog("info: hev config built (\(yaml.utf8.count) bytes)")

        // IPA-A1: direct utun fd handoff to hev. Same pattern as
        // Tun2SocksKit, Shadowrocket, sing-box-with-hev configs etc.
        // KVO `socket.fileDescriptor` is the well-known private API
        // every shipping iOS proxy app uses — wireguard-apple,
        // sing-box-for-apple, Tun2SocksKit. Apple has not deprecated it.
        // Fallback fd-scanner kept as diagnostic for the rare case KVO
        // returns nil (typically when iCloud Private Relay's utun
        // shadows ours).
        let kvoFD = (self.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32) ?? -1
        let scanFD = Self.findTunnelFileDescriptor(log: { line in self.appendExtLog(line) }) ?? -1
        appendExtLog("info: utun fd kvo=\(kvoFD) scan=\(scanFD)")
        let fd: Int32
        if kvoFD >= 0 {
            fd = kvoFD
        } else if scanFD >= 0 {
            appendExtLog("warn: KVO fd unavailable, falling back to scan")
            fd = scanFD
        } else {
            appendExtLog("error: could not locate utun fd (KVO + scan both failed)")
            completionHandler(makeError("utun fd not found"))
            return
        }
        appendExtLog("info: utun fd selected = \(fd)")

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
        startBurstProtection()  // IPA-D2
        startPathMonitor()
        startWhitelistDetectorIfNeeded()
        isRunning = true
        // IPA-D22: anchor uptime for the main-app Uptime stat tile.
        tunnelStartedAt = Date()

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

    /// IPA-D23: turn a user-entered probe target ("8.8.8.8" or "google.com")
    /// into an IPv4 literal suitable for an NEIPv4Route /32 exclusion.
    /// IP literals pass through unchanged. Hostnames are resolved via the
    /// system resolver with a 2 s budget; failure returns nil and the
    /// caller skips the route (the detector will then surface that probe
    /// as a failure until the tunnel reconnects). IPv6 literals also
    /// return nil — we don't currently expose IPv6 excludedRoutes (the
    /// tunnel is v4-only by Phase 2.5 design).
    private static func resolveProbeTargetIPv4(_ target: String, log: (String) -> Void) -> String? {
        let trimmed = target.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return nil }
        // Already an IPv4 literal?
        var v4 = in_addr()
        if inet_pton(AF_INET, trimmed, &v4) == 1 {
            return trimmed
        }
        // IPv6 literal — explicitly skip (v4-only tunnel, no v6 routes).
        var v6 = in6_addr()
        if inet_pton(AF_INET6, trimmed, &v6) == 1 {
            log("info: probe target \(trimmed) is IPv6 literal — skipping v4 exclusion")
            return nil
        }
        // Hostname — synchronous resolve with 2 s budget.
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        let sem = DispatchSemaphore(value: 0)
        var found: String?
        DispatchQueue.global(qos: .utility).async {
            var res: UnsafeMutablePointer<addrinfo>?
            defer { if let res = res { freeaddrinfo(res) } }
            if getaddrinfo(trimmed, nil, &hints, &res) != 0 {
                sem.signal(); return
            }
            if let head = res {
                var addr = head.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                    found = String(cString: buf)
                }
            }
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + 2.0)
        return found
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
        var excluded: [NEIPv4Route] = (ipv4.excludedRoutes ?? []) + [
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
        ]
        // IPA-D23: dynamic WhitelistDetector probe-target exclusions.
        // Pull the two configured hosts (testHost + whitelistHost) from
        // App Group UserDefaults. If a value is an IPv4 literal, add it
        // as /32. If it's a hostname, resolve once now (synchronous, 2 s
        // budget). On resolution failure, skip — the detector will
        // simply report fail on that probe until the user reconnects
        // with a working value.
        let probeTargets = [
            WhitelistProbePreferences.testHost,
            WhitelistProbePreferences.whitelistHost,
        ]
        var addedProbeIPs = Set<String>()
        for target in probeTargets {
            guard let ip = Self.resolveProbeTargetIPv4(target, log: appendExtLog) else {
                appendExtLog("warn: probe target \(target) — could not resolve to IPv4, route skipped")
                continue
            }
            if addedProbeIPs.contains(ip) {
                appendExtLog("info: probe target \(target) → \(ip) already excluded (deduped)")
                continue
            }
            addedProbeIPs.insert(ip)
            appendExtLog("info: probe target \(target) → excludedRoute \(ip)/32")
            excluded.append(NEIPv4Route(destinationAddress: ip, subnetMask: "255.255.255.255"))
        }
        ipv4.excludedRoutes = excluded
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
        // SocksStub opens a samizdat UDP tunnel to the configured
        // resolver, and the response comes back the same way.
        //
        // IPA-D22 fix3 (DNS leak): the resolver IPs were 1.1.1.1 + 8.8.8.8
        // — the SAME IPs we exclude above for WhitelistDetector canary.
        // Result: iOS sent DNS queries to 1.1.1.1, routing matched
        // excludedRoutes, packets went OUT VIA PHYSICAL Wi-Fi/cellular
        // (RU ISP), Cloudflare anycast saw RU client and returned
        // RU-close CDN edges. App then opened TCP to that RU-close IP
        // via tunnel → exit Finland → server saw Finland IP for an
        // RU-edge destination → mismatch → ChatGPT/CDN refusals.
        //
        // Use Cloudflare/Google SECONDARY IPs (1.0.0.1, 8.8.4.4) for
        // DNS-via-tunnel. They are anycast and unrelated to canary IPs
        // in excludedRoutes, so they resolve cleanly through the tunnel
        // and the upstream-server (Finland exit) is the query source.
        // GeoDNS therefore returns Finland-close edges; subsequent TCP
        // is consistent with the tunnel exit IP.
        //
        // IPA-DNS-LEAK-FIX (2026-05-11): the previous fix3 set
        // `matchDomains = [""]` but did NOT set `matchDomainsNoSearch =
        // true`. On iOS 17/18 with split-DNS semantics this is the
        // documented difference between "every query goes to our DNS"
        // vs "iOS still consults the system resolver in parallel /
        // first for FQDNs". Production iOS proxy clients (sing-box-
        // for-apple ExtensionProvider.swift, Hiddify, Streisand) all
        // set BOTH flags together — empty matchDomain alone is not a
        // reliable catch-all on iOS. The leak manifested as ChatGPT
        // and Roblox refusing the iPhone: app got a Russia-biased CDN
        // IP from the leaked system DNS query (RU ISP resolver
        // returning RU-edge), then opened TCP to that RU-edge IP via
        // tunnel → exit IP Finland but destination is RU-edge of CDN
        // → CDN sees geo-mismatch → block. Setting
        // matchDomainsNoSearch=true forces ALL DNS through the tunnel
        // so the IPs the app receives are Finland-edge from the start.
        //
        // Refs:
        //   https://sing-box.sagernet.org/configuration/dns/  (catch-all pattern)
        //   sing-box-for-apple/ExtensionProvider/include/ExtensionProvider.swift
        //   Apple NEDNSSettings docs:
        //     matchDomainsNoSearch=true means "treat matchDomains as a
        //     pure resolver-selection filter, do NOT also add them to
        //     the system search list" — which is exactly what we want
        //     for [""] catch-all (otherwise iOS treats "" as a search
        //     suffix and bypass FQDNs).
        let dns = NEDNSSettings(servers: ["1.0.0.1", "8.8.4.4"])
        dns.matchDomains = [""]
        dns.matchDomainsNoSearch = true
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

    private func startBurstProtection() {
        // IPA-D7: nuclear close pattern from sing-box-for-apple.
        // IPA-D9: dump heap profile right before nuclear close — captures
        // the heap state at the exact moment iOS says we're critical,
        // which is the most informative snapshot for diagnosing leaks.
        let q = DispatchQueue(label: "com.anarki.samizdat-test.burst", qos: .userInitiated)
        let src = DispatchSource.makeMemoryPressureSource(eventMask: [.critical], queue: q)
        src.setEventHandler { [weak self] in
            self?.dumpProfileBeforeNuclear(reason: "kernel-critical")
            let closed = SocksstubCloseAllFlows()
            self?.appendExtLog("warn: kernel memorypressure CRITICAL — nuclear close (\(closed) flows)")
        }
        src.activate()
        self.memPressureSrc = src
    }

    private func dumpProfileBeforeNuclear(reason: String) {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: Self.appGroupID
        ) else {
            appendExtLog("warn: heap-dump: appGroup container not available")
            return
        }
        let stamp = Int(Date().timeIntervalSince1970)
        let heapURL = containerURL.appendingPathComponent("heap-\(reason)-\(stamp).pb.gz")
        let heapErr = SocksstubWriteHeapProfile(heapURL.path)
        if heapErr.isEmpty {
            appendExtLog("info: heap-dump → \(heapURL.lastPathComponent)")
        } else {
            appendExtLog("warn: heap-dump failed: \(heapErr)")
        }
    }

    private func stopBurstProtection() {
        self.memPressureSrc?.cancel()
        self.memPressureSrc = nil
    }

    private func startSwiftHeartbeat() {
        let queue = DispatchQueue(label: "com.anarki.samizdat-test.swift-hb", qos: .userInitiated)
        let timer = DispatchSource.makeTimerSource(queue: queue)
        // IPA-D18: 1 s → 30 s. The 1 Hz cadence kept the extension CPU
        // pinned awake and ran runtime.GC() 3600x/hour — both major
        // battery leaks per gpt-5.5 analyst. Memory leak from D12 is
        // fixed; we no longer need fast crash-correlation. Pressure
        // detection still fires via DispatchSource.makeMemoryPressure
        // Source(.critical) which kernel-pushes (zero-cost when idle).
        // sing-box-for-apple has no comparable extension heartbeat at
        // all — we keep one for diagnostics but at human cadence.
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(30))
        timer.setEventHandler { [weak self] in
            guard let self, self.isRunning else { return }
            // iOS's apple-supplied "available before jetsam" gauge.
            let availKB = os_proc_available_memory() / 1024

            // IPA-D7/D9: per-process memory backstop with heap dump.
            let availBytes = os_proc_available_memory()
            var nuclearFired = false
            if availBytes > 0 && availBytes < 8 * 1024 * 1024 {
                self.dumpProfileBeforeNuclear(reason: "avail8mib")
                let closed = SocksstubCloseAllFlows()
                self.appendExtLog("warn: avail<8MiB heartbeat — nuclear close (\(closed) flows)")
                nuclearFired = true
            }

            // Go heap detail — disambiguates "Go is bloating" from
            // "non-Go is bloating" on a crash.
            //   inUse: working set of allocated objects RIGHT NOW.
            //   sys: heap committed from OS (>= inUse).
            //   released: returned to OS via madvise.
            //   numGC: cycles completed since process start (rate)
            let goInUseKB = SocksstubMemHeapInUseKB()
            let goSysKB   = SocksstubMemHeapSysKB()
            let goRelKB   = SocksstubMemHeapReleasedKB()
            let numGC     = SocksstubMemNumGC()

            // IPA-D18: only force GC when actually approaching the
            // jetsam ceiling. The unconditional 1 Hz call was running
            // runtime.GC() 3600 times/hour, pinning CPU and burning
            // battery. Go's pacer + GOGC handles the normal case;
            // we only step in when avail-memory is genuinely tight
            // (< 12 MiB headroom before iOS reaps us).
            if availBytes > 0 && availBytes < 12 * 1024 * 1024 {
                SocksstubFreeOSMemory()
            }

            // IPA-A1: pps comes from hev's own tunnel-stats counters
            // (it now owns the data path again — no bridge counters
            // to consult). Compute delta since last heartbeat.
            var tx_pkts = 0, tx_bytes = 0, rx_pkts = 0, rx_bytes = 0
            hev_socks5_tunnel_stats(&tx_pkts, &tx_bytes, &rx_pkts, &rx_bytes)
            let inboundPPS  = Int64(tx_pkts) - self.lastHevTxPkts
            let outboundPPS = Int64(rx_pkts) - self.lastHevRxPkts
            self.lastHevTxPkts = Int64(tx_pkts)
            self.lastHevRxPkts = Int64(rx_pkts)

            // IPA-D18: log only every 5 ticks (~150 s) for periodic
            // health snapshot, OR immediately when nuclear close
            // fired. Drops appendExtLog() rate from 3600/hour to
            // ~24/hour, removing the per-tick file-write that pulled
            // iOS out of idle state.
            self.hbTick += 1
            if nuclearFired || (self.hbTick % 5) == 0 {
                self.appendExtLog(String(
                    format: "info: hb avail=%dKB go.inuse=%lldKB go.sys=%lldKB go.rel=%lldKB gc=%lld pps in=%lld out=%lld",
                    availKB,
                    goInUseKB, goSysKB, goRelKB,
                    numGC,
                    inboundPPS, outboundPPS
                ))
            }
        }
        timer.resume()
        swiftHeartbeatTimer = timer
    }

    // IPA-A1 bookkeeping for pps delta in heartbeat (from hev's own counters).
    private var lastHevTxPkts: Int64 = 0
    private var lastHevRxPkts: Int64 = 0

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

/// IPA-D26: gomobile-bound bridge for the ping prober's auto-rewire
/// signal. Go calls `requestRewire()` when it has detected 2+
/// consecutive HTTP HEAD failures through the tunnel — likely the
/// upstream is unreachable on the current path (wifi dying without
/// NWPath having flipped yet, or upstream node blip). We respond by
/// rebuilding the samizdat client over the current default route.
/// Throttled in Go to once per 15 s.
final class AutoRewireBridge: NSObject, SocksstubRewireRequesterProtocol {
    private let onRequest: () -> Void

    init(onRequest: @escaping () -> Void) {
        self.onRequest = onRequest
        super.init()
    }

    /// Called from a Go goroutine — bounce off Go's stack before
    /// touching extension state.
    func requestRewire() {
        DispatchQueue.global(qos: .userInitiated).async { [onRequest] in
            onRequest()
        }
    }
}

import Foundation
import NetworkExtension
import OSLog
import SamizdatClient

final class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = Logger(subsystem: "com.anarki.samizdat-test.tunnel", category: "extension")
    private let pumpQueue = DispatchQueue(label: "com.anarki.samizdat-test.packet-writer")
    /// Dedicated queue for the iOS metrics timer. Cannot share pumpQueue:
    /// the packet-writer pumps a tight loop most of the time and would
    /// starve our 1 Hz timer events queued behind it.
    private let metricsQueue = DispatchQueue(label: "com.anarki.samizdat-test.ios-metrics", qos: .utility)
    private var isRunning = false
    private var iosMetricsTimer: DispatchSourceTimer?

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let configBlob = proto.providerConfiguration?["configBlob"] as? String else {
            completionHandler(makeError("missing samizdat config"))
            return
        }

        SamizdatAddLog("info: PacketTunnelProvider startTunnel")
        let engineConfigBlob = proto.providerConfiguration?["engineConfigBlob"] as? String ?? configBlob
        let serverIP = proto.providerConfiguration?["serverIP"] as? String
        if serverIP != nil {
            SamizdatAddLog("info: using pre-resolved server IPv4")
        } else {
            SamizdatAddLog("warn: no pre-resolved server IPv4 in provider configuration")
        }

        let settings = makeNetworkSettings(configBlob: configBlob, serverIP: serverIP)
        SamizdatAddLog("info: applying packet tunnel network settings")
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                SamizdatAddLog("error: setTunnelNetworkSettings: \(error.localizedDescription)")
                completionHandler(error)
                return
            }

            var nsError: NSError?
            SamizdatTunnelStart(engineConfigBlob, &nsError)
            if let nsError {
                SamizdatAddLog("error: SamizdatTunnelStart: \(nsError.localizedDescription)")
                completionHandler(nsError)
                return
            }

            self.isRunning = true
            self.startPacketReadLoop()
            self.startPacketWriteLoop()
            self.startIOSMetricsLoop()
            self.log.info("packet tunnel started")
            SamizdatAddLog("info: packet tunnel started")
            completionHandler(nil)
        }
    }

    /// Polls iOS-reported available memory + thermal state every second.
    /// `os_proc_available_memory()` returns the byte budget BEFORE the
    /// process is reaped, which is the metric jetsam actually uses. If
    /// this number drops to a few MB while our Go-side `sys` is still
    /// modest, we know the kill is coming from jetsam (not our heap).
    /// Also captures iOS sleep/wake transitions: if the extension is
    /// suspended (`sleep` callback fires) and never wakes back, we know
    /// the kill was a suspend-then-reap rather than memory pressure.
    private func startIOSMetricsLoop() {
        let timer = DispatchSource.makeTimerSource(queue: metricsQueue)
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timer.setEventHandler { [weak self] in
            guard let self, self.isRunning else { return }
            let avail = os_proc_available_memory()
            let thermal = ProcessInfo.processInfo.thermalState.rawValue
            let lowPower = ProcessInfo.processInfo.isLowPowerModeEnabled ? 1 : 0
            SamizdatAddLog(String(
                format: "info: ios avail=%dKB thermal=%d lowpwr=%d",
                avail / 1024,
                thermal,
                lowPower
            ))
        }
        timer.resume()
        iosMetricsTimer = timer
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        SamizdatAddLog("warn: PacketTunnelProvider sleep() — iOS suspending extension")
        completionHandler()
    }

    override func wake() {
        SamizdatAddLog("info: PacketTunnelProvider wake() — iOS resumed extension")
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue, privacy: .public)")
        isRunning = false
        iosMetricsTimer?.cancel()
        iosMetricsTimer = nil
        SamizdatAddLog("info: PacketTunnelProvider stopTunnel reason=\(reason.rawValue)")
        SamizdatTunnelStop()
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        let command = String(data: messageData, encoding: .utf8) ?? "logs"
        switch command {
        case "clearLogs":
            SamizdatClearLogs()
            completionHandler?(Data())
        case "status":
            let payload = [
                "status=\(SamizdatStatus())",
                "lastError=\(SamizdatLastError())",
                SamizdatLogs(0)
            ].filter { !$0.isEmpty }.joined(separator: "\n")
            completionHandler?(payload.data(using: .utf8))
        default:
            completionHandler?(SamizdatLogs(0).data(using: .utf8))
        }
    }

    private func makeNetworkSettings(configBlob: String, serverIP: String?) -> NEPacketTunnelNetworkSettings {
        let remoteAddress = serverIP ?? "127.0.0.1"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        settings.mtu = 1500

        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        if let serverIP {
            ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: serverIP, subnetMask: "255.255.255.255")]
        }
        settings.ipv4Settings = ipv4

        let ipv6 = NEIPv6Settings(addresses: ["fd00:7361:6d69::1"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6

        let dns = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        return settings
    }

    private func startPacketReadLoop() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, self.isRunning else { return }

            for packet in packets {
                var nsError: NSError?
                SamizdatTunnelInjectPacket(packet, &nsError)
                if let nsError {
                    self.log.error("inject packet failed: \(nsError.localizedDescription, privacy: .public)")
                }
            }
            self.startPacketReadLoop()
        }
    }

    private func startPacketWriteLoop() {
        pumpQueue.async { [weak self] in
            guard let self else { return }
            while self.isRunning {
                guard let packet = SamizdatTunnelReadPacket(), !packet.isEmpty else {
                    // Empty packet means the Go side returned (ctx done /
                    // stack closed). Don't spin — yield briefly so we
                    // don't pin the CPU if Go is in shutdown.
                    Thread.sleep(forTimeInterval: 0.05)
                    continue
                }
                self.packetFlow.writePackets([packet], withProtocols: [NSNumber(value: self.protocolFamily(for: packet))])
            }
        }
    }

    private func protocolFamily(for packet: Data) -> Int32 {
        guard let first = packet.first else { return AF_INET }
        return (first >> 4) == 6 ? AF_INET6 : AF_INET
    }

    private func makeError(_ message: String) -> NSError {
        NSError(
            domain: "com.anarki.samizdat-test.tunnel",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}

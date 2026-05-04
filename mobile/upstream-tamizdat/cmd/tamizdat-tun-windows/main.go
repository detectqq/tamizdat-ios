// Command samizdat-tun-windows exposes a Windows Wintun TUN interface and
// forwards IPv4 TCP flows through the existing Samizdat Client API.
package main

import (
	"context"
	_ "expvar" // registers /debug/vars on http.DefaultServeMux when --debug-listen is set
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/detectqq/tamizdat"
	"github.com/detectqq/tamizdat/internal/configurl"
)

type tunOptions struct {
	Name                     string
	MTU                      int
	Debug                    bool
	TCPModerateReceiveBuffer bool
	TCPSendBufferSize        int
	TCPReceiveBufferSize     int
	TunIP                    string
	TunPrefix                int
	AutoRoute                bool
	PostTunUp                func() error // optional callback fired once TUN device is open
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("samizdat-tun-windows", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configURL := fs.String("config", "", "tamizdat:// URL with server, sni, pubkey, shortid and fp")
	tunName := fs.String("tun-name", "Samizdat", "Windows TUN interface name")
	mtu := fs.Int("mtu", 1500, "TUN MTU")
	debug := fs.Bool("debug", false, "Enable verbose flow logs")
	tcpFrag := fs.Bool("tcpfrag", true, "Enable Samizdat TCP ClientHello fragmentation")
	poolVariant := fs.String("pool-variant", "v1", "Transport pool variant: v1 (single H2, default), v2 (split bulk/realtime), or empty (foundation V3-shaped, MinTransports=2)")
	strictSingleH2 := fs.Bool("strict-single-h2", false, "STRICT mode: never spawn lite transport, always 1 TCP/443. Realtime classifier flips bulk shape between full/lite. Trade-off: HoL on shared TCP. Default false = current V1 behaviour (lite-transport spawned on demand).")
	debugListen := fs.String("debug-listen", "", "Listen addr (e.g. 127.0.0.1:16062) for /debug/vars expvar HTTP. Empty = off.")
	tcpModerateReceiveBuffer := fs.Bool("tcp-moderate-receive-buffer", true, "Enable gVisor TCP receive-buffer auto-tuning")
	tcpSendBufferSize := fs.Int("tcp-send-buffer-size", 0, "Optional gVisor TCP send buffer size in bytes (0 = default)")
	tcpReceiveBufferSize := fs.Int("tcp-receive-buffer-size", 0, "Optional gVisor TCP receive buffer size in bytes (0 = default)")
	tunIP := fs.String("tun-ip", "10.255.0.2", "IPv4 address to assign to the TUN interface")
	tunPrefix := fs.Int("tun-prefix", 24, "IPv4 prefix length for the TUN interface")
	autoRoute := fs.Bool("auto-route", true, "Automatically configure host-route to server + default-route via TUN; cleaned up on exit")
	selectiveRoutes := fs.String("selective-routes", "", "Comma-separated host names or IPv4 literals. When set: TUN comes up but default route is NOT installed; instead /32 host-routes for each resolved IP point into the TUN. Use this to route only specific test sites through samizdat alongside an existing default-route owner (e.g. another VPN).")
	bypassRoutes := fs.String("bypass-routes", "", "Comma-separated host names or IPv4 literals that MUST go through the physical gateway (bypass the tunnel). Default route still goes via TUN. Use this for AI provider APIs / control plane that must remain reachable when the tunnel is congested or geo-blocked from the exit point.")
	selectiveRefresh := fs.Duration("selective-refresh", 5*time.Minute, "How often to re-resolve --selective-routes / --bypass-routes hostnames and update host-routes. 0 = disable.")
	routeHelp := fs.Bool("route-help", false, "Print manual Windows route setup notes and exit")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s --config 'tamizdat://host:port/?sni=...&pubkey=...&shortid=...&fp=chrome' [flags]\n\n", fs.Name())
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *routeHelp {
		printRouteHelp(stdout, *tunName, *configURL)
		return 0
	}
	if strings.TrimSpace(*configURL) == "" {
		fs.Usage()
		return 2
	}

	// Parse --selective-routes into a slice.
	var selectiveHosts []string
	for _, h := range strings.Split(*selectiveRoutes, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			selectiveHosts = append(selectiveHosts, h)
		}
	}
	if len(selectiveHosts) > 0 && !*autoRoute {
		log.Printf("--selective-routes requires --auto-route=true (it controls how routes are installed)")
		return 2
	}
	// Parse --bypass-routes into a slice.
	var bypassHosts []string
	for _, h := range strings.Split(*bypassRoutes, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			bypassHosts = append(bypassHosts, h)
		}
	}
	if len(bypassHosts) > 0 && !*autoRoute {
		log.Printf("--bypass-routes requires --auto-route=true")
		return 2
	}
	if len(bypassHosts) > 0 && len(selectiveHosts) > 0 {
		log.Printf("--bypass-routes and --selective-routes are mutually exclusive (bypass needs default-via-TUN, selective leaves default alone)")
		return 2
	}

	parsed, err := configurl.Parse(*configURL)
	if err != nil {
		log.Printf("config URL: %v", err)
		return 2
	}

	client, err := tamizdat.NewClient(tamizdat.ClientConfig{
		ServerAddr:       parsed.ServerAddr,
		ServerName:       parsed.ServerName,
		ServerNames:      parsed.ServerNames,
		PublicKey:        parsed.PublicKey,
		MasterShortID:    parsed.MasterShortID,
		Fingerprint:      parsed.Fingerprint,
		TCPFragmentation: *tcpFrag,
		PoolVariant:      *poolVariant,
		StrictSingleH2:   *strictSingleH2,
	})
	if err != nil {
		log.Printf("client init: %v", err)
		return 1
	}
	defer client.Close()

	if addr := strings.TrimSpace(*debugListen); addr != "" {
		ln, lerr := net.Listen("tcp", addr)
		if lerr != nil {
			log.Printf("debug-listen: %v", lerr)
			return 1
		}
		log.Printf("expvar /debug/vars listening on %s", ln.Addr())
		go func() {
			// expvar registers itself on http.DefaultServeMux at init time
			// (via the blank import above). Use a fresh server so we control
			// shutdown semantics if needed later.
			srv := &http.Server{Handler: http.DefaultServeMux}
			_ = srv.Serve(ln)
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := tunOptions{
		Name:                     *tunName,
		MTU:                      *mtu,
		Debug:                    *debug,
		TCPModerateReceiveBuffer: *tcpModerateReceiveBuffer,
		TCPSendBufferSize:        *tcpSendBufferSize,
		TCPReceiveBufferSize:     *tcpReceiveBufferSize,
	}

	log.Printf("tamizdat TUN starting: server=%s sni=%s fp=%s pool=%q tun=%s mtu=%d", parsed.ServerAddr, parsed.ServerName, parsed.Fingerprint, *poolVariant, opts.Name, opts.MTU)

	// Auto-routing: snapshot original gateway, pin host-route to server, install
	// default route via TUN OR /32 selective routes via TUN. Cleanup on shutdown.
	var routingCleanup func()
	opts.TunIP = *tunIP
	opts.TunPrefix = *tunPrefix
	opts.AutoRoute = *autoRoute
	if *autoRoute {
		defer func() {
			if routingCleanup != nil {
				routingCleanup()
			}
		}()
		opts.PostTunUp = func() error {
			cleanup, e := configureAutoRouting(ctx, parsed.ServerAddr, opts.Name, *tunIP, *tunPrefix, selectiveHosts, bypassHosts, *selectiveRefresh)
			if e != nil {
				return e
			}
			routingCleanup = cleanup
			return nil
		}
	}

	if err := runTUN(ctx, opts, client); err != nil && ctx.Err() == nil {
		log.Printf("tun: %v", err)
		return 1
	}
	log.Printf("shutdown complete")
	return 0
}

func printRouteHelp(w io.Writer, tunName, rawConfig string) {
	server := "<samizdat-server-ip>"
	if cfg, err := configurl.Parse(rawConfig); err == nil {
		if host, _, splitErr := net.SplitHostPort(cfg.ServerAddr); splitErr == nil {
			server = host
		}
	}

	fmt.Fprintf(w, `Manual Windows routing notes (run PowerShell as Administrator; this program never changes routes automatically):

1. Start the client first:
   .\samizdat-tun-windows.exe --config "tamizdat://..."

2. Find the TUN interface index:
   Get-NetIPInterface -InterfaceAlias %q

3. Assign an IPv4 address to the TUN if Windows did not assign one:
   New-NetIPAddress -InterfaceAlias %q -IPAddress 10.255.0.2 -PrefixLength 24

4. Add a host route for the Samizdat server (%s) via your normal physical gateway BEFORE default-routing traffic into the TUN. This prevents Samizdat outer dials from recursively entering the TUN.

5. Add the default IPv4 route only when ready to test:
   New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias %q -NextHop "0.0.0.0" -RouteMetric 1

6. Remove test route when done:
   Remove-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias %q -Confirm:$false

UDP is intentionally not relayed by Samizdat v1; UDP flows are dropped so applications can retry over TCP.
`, tunName, tunName, server, tunName, tunName)
}

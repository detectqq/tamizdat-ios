// Command samizdat-server runs a standalone Samizdat protocol server.
//
// Usage:
//
//	samizdat-server -listen :8443 -domain ok.ru -cert cert.pem -key key.pem -privkey-file server.key -shortid-file shortid.hex
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/detectqq/tamizdat"
)

func main() {
	var (
		listenAddr       = flag.String("listen", ":8443", "Listen address")
		masqueradeDomain = flag.String("domain", "", "Masquerade domain (e.g. ok.ru)")
		masqueradeAddr   = flag.String("domain-addr", "", "Masquerade domain IP:port override")
		masqPool         = flag.String("masq-pool", "", "Cover-SNI rotation pool (comma-separated sni=origin pairs, e.g. ok.ru=ok.ru,vk.com=vk.com,mail.ru=mail.ru). Empty = use --domain only.")
		certFile         = flag.String("cert", "", "TLS certificate PEM file")
		keyFile          = flag.String("key", "", "TLS key PEM file")
		privKeyHex       = flag.String("privkey", "", "Server X25519 private key (hex; deprecated, visible in process list)")
		privKeyFile      = flag.String("privkey-file", "", "Path to file containing server X25519 private key hex")
		shortIDHex       = flag.String("shortid", "", "Master short ID (hex, 16 chars; deprecated, visible in process list)")
		shortIDFile      = flag.String("shortid-file", "", "Path to file containing master short ID hex")
		coverConfig      = flag.String("cover-config", "", "Path to server-pushed cover config bundle JSON")
		coverConfigPrev  = flag.String("cover-config-previous", "", "Path to previous cover config bundle JSON for epoch grace")
		epochGraceWindow = flag.Int("epoch-grace-window", 2, "Number of previous epoch pools to accept")
		genKeys          = flag.Bool("genkeys", false, "Generate new server keypair and short ID")
		debug            = flag.Bool("debug", false, "Enable debug logs and localhost expvar /debug/vars")
		debugListen      = flag.String("debug-listen", "127.0.0.1:6060", "Debug expvar listen addr (Debug=true only)")
	)
	flag.Parse()

	if *genKeys {
		generateKeys()
		return
	}

	if *certFile == "" || *keyFile == "" {
		log.Fatal("--cert and --key are required")
	}
	privKey, err := readHexFlagOrFile("privkey", *privKeyHex, "privkey-file", *privKeyFile, 32, "use --genkeys to generate")
	if err != nil {
		log.Fatal(err)
	}
	shortIDBytes, err := readHexFlagOrFile("shortid", *shortIDHex, "shortid-file", *shortIDFile, 8, "use --genkeys to generate")
	if err != nil {
		log.Fatal(err)
	}

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		log.Fatalf("reading cert: %v", err)
	}
	keyPEM, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatalf("reading key: %v", err)
	}

	var masterShortID [8]byte
	copy(masterShortID[:], shortIDBytes)

	config := tamizdat.ServerConfig{
		ListenAddr:              *listenAddr,
		PrivateKey:              privKey,
		MasterShortID:           masterShortID,
		CoverConfigPath:         *coverConfig,
		CoverConfigPreviousPath: *coverConfigPrev,
		EpochGraceWindow:        *epochGraceWindow,
		CertPEM:                 certPEM,
		KeyPEM:                  keyPEM,
		MasqueradeDomain:        *masqueradeDomain,
		MasqueradePool:          parseMasqPool(*masqPool),
		MasqueradeAddr:          *masqueradeAddr,
		Debug:                   *debug,
		DebugListenAddr:         *debugListen,
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			proxyHandler(ctx, conn, destination, *debug)
		},
	}

	server, err := tamizdat.NewServer(config)
	if err != nil {
		log.Fatalf("creating server: %v", err)
	}

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		server.Close()
	}()

	log.Printf("Samizdat server listening on %s (masquerade: %s)", *listenAddr, *masqueradeDomain)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func readHexFlagOrFile(flagName, flagValue, fileFlagName, filePath string, wantBytes int, missingHint string) ([]byte, error) {
	flagValue = strings.TrimSpace(flagValue)
	filePath = strings.TrimSpace(filePath)
	if flagValue != "" && filePath != "" {
		return nil, fmt.Errorf("use one of -%s or -%s, not both", flagName, fileFlagName)
	}

	var hexValue string
	switch {
	case filePath != "":
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("reading -%s: %w", fileFlagName, err)
		}
		hexValue = strings.TrimSpace(string(data))
	case flagValue != "":
		log.Printf("DEPRECATED: -%s on cmdline is visible in /proc/<pid>/cmdline; use -%s", flagName, fileFlagName)
		hexValue = flagValue
	default:
		return nil, fmt.Errorf("--%s is required (%s)", flagName, missingHint)
	}

	decoded, err := hex.DecodeString(hexValue)
	if err != nil || len(decoded) != wantBytes {
		return nil, fmt.Errorf("--%s must be %d hex characters (%d bytes)", flagName, wantBytes*2, wantBytes)
	}
	return decoded, nil
}

func generateKeys() {
	privKey, pubKey, err := tamizdat.GenerateKeyPair()
	if err != nil {
		log.Fatalf("generating keypair: %v", err)
	}
	shortID, err := tamizdat.GenerateShortID()
	if err != nil {
		log.Fatalf("generating short ID: %v", err)
	}

	fmt.Printf("Private key: %s\n", hex.EncodeToString(privKey))
	fmt.Printf("Public key:  %s\n", hex.EncodeToString(pubKey))
	fmt.Printf("Short ID:    %s\n", hex.EncodeToString(shortID[:]))
}

// proxyHandler is the default handler that dials the destination and proxies
// data bidirectionally.
func proxyHandler(ctx context.Context, conn net.Conn, destination string, debug bool) {
	defer conn.Close()

	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		host = destination
		port = "443"
	}

	// CRIT-0: validate destination + dial resolved IP (defeats SSRF and
	// DNS-rebinding TOCTOU). CRIT-4: log destination only behind debug gate.
	target, err := tamizdat.ResolveAndValidateDestination(ctx, host, port)
	if err != nil {
		if debug {
			log.Printf("rejected destination %s: %v", destination, err)
		}
		return
	}

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		if debug {
			log.Printf("Failed to dial %s: %v", destination, err)
		}
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, conn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, targetConn)
		// HIGH-6: when target sends EOF, propagate write-close to the H2
		// stream so the client's blocking Read(s) wake up cleanly.
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	wg.Wait()
}

// parseMasqPool turns "sni1=origin1,sni2=origin2" into a map for ServerConfig.
// Empty input returns nil (no pool, default-only behaviour).
func parseMasqPool(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq < 1 {
			log.Fatalf("--masq-pool: bad pair %q (want sni=origin)", pair)
		}
		sni := strings.TrimSpace(pair[:eq])
		origin := strings.TrimSpace(pair[eq+1:])
		if sni == "" || origin == "" {
			log.Fatalf("--masq-pool: empty sni or origin in %q", pair)
		}
		out[sni] = origin
	}
	return out
}

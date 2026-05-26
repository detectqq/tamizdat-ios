package socksstub

import (
	"strings"
	"testing"

	"github.com/detectqq/tamizdat/wgturnclient"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestShouldUseUDPIgnoresTurnsEndpoints(t *testing.T) {
	creds := &wgturnclient.Credentials{
		TurnServers: []wgturnclient.TurnServer{
			{Host: "secure.example", Port: 5349, Scheme: "turns", Transport: "udp"},
		},
	}
	if shouldUseUDP(creds) {
		t.Fatal("shouldUseUDP returned true for turns endpoint; TURNS must use TLS/TCP in this client")
	}
}

func TestStopVKTurnUpstreamClearsStaleNetstackWhenNotRunning(t *testing.T) {
	vkturnMu.Lock()
	vkturnRunner = nil
	vkturnCancel = nil
	vkturnAttachStop = nil
	vkturnRunning.Store(false)
	staleNet := &netstack.Net{}
	vkturnNet.Store(staleNet)
	staleConfig := "stale-wg-config"
	staleStats := `{"active":1,"running":false}`
	staleErr := "stale-error"
	vkturnWGConfig.Store(&staleConfig)
	vkturnStats.Store(&staleStats)
	vkturnErr.Store(&staleErr)
	vkturnMu.Unlock()

	StopVKTurnUpstream()

	if got := vkturnNet.Load(); got != nil {
		t.Fatalf("vkturnNet after StopVKTurnUpstream = %p, want nil", got)
	}
	if got := vkturnWGConfig.Load(); got != nil {
		t.Fatalf("vkturnWGConfig after StopVKTurnUpstream = %q, want nil", *got)
	}
	if got := vkturnStats.Load(); got != nil {
		t.Fatalf("vkturnStats after StopVKTurnUpstream = %q, want nil", *got)
	}
	if got := vkturnErr.Load(); got != nil {
		t.Fatalf("vkturnErr after StopVKTurnUpstream = %q, want nil", *got)
	}
	if vkturnRunning.Load() {
		t.Fatal("vkturnRunning after StopVKTurnUpstream = true, want false")
	}
}

func TestCurrentSamizdatShortIDHexUsesActiveProfile(t *testing.T) {
	rt.mu.Lock()
	oldBlob := rt.samizdatBlob
	rt.samizdatBlob = "samizdat://AABBCCDDEEFF0011@ru.example:443?pbk=" + strings.Repeat("1", 64) + "&sni=ya.ru&fp=chrome"
	rt.mu.Unlock()
	defer func() {
		rt.mu.Lock()
		rt.samizdatBlob = oldBlob
		rt.mu.Unlock()
	}()

	if got, want := currentSamizdatShortIDHex(), "aabbccddeeff0011"; got != want {
		t.Fatalf("currentSamizdatShortIDHex = %q, want %q", got, want)
	}
}

func TestParseVKTurnCredsJSONNormalizesV2SchemeAndTransport(t *testing.T) {
	creds, err := parseVKTurnCredsJSON(`{
		"username":"user",
		"password":"pass",
		"turn_servers_v2":[
			{"host":"udp.example","port":3478,"scheme":"TURN","transport":"UDP"},
			{"host":"secure.example","port":5349,"scheme":"TURNS","transport":"UDP"}
		],
		"lifetime_sec":600
	}`)
	if err != nil {
		t.Fatalf("parseVKTurnCredsJSON: %v", err)
	}
	if len(creds.TurnServers) != 2 {
		t.Fatalf("TurnServers len = %d", len(creds.TurnServers))
	}
	if creds.TurnServers[0].Scheme != "turn" || creds.TurnServers[0].Transport != "udp" {
		t.Fatalf("first server = %+v, want turn/udp", creds.TurnServers[0])
	}
	if creds.TurnServers[1].Scheme != "turns" || creds.TurnServers[1].Transport != "tcp" {
		t.Fatalf("second server = %+v, want turns/tcp", creds.TurnServers[1])
	}
	if strings.Contains(creds.TurnURLs[0], "turn:") || strings.Contains(creds.TurnURLs[1], "turns:") {
		t.Fatalf("TurnURLs should remain legacy host:port values, got %#v", creds.TurnURLs)
	}
}

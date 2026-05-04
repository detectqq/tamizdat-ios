# Tamizdat

A private censorship-resistant transport.  HTTP/2 CONNECT tunnel over a single TLS layer; outer TLS handshake masquerades as a real RU website (ok.ru by default).  Reality-style PSK authentication (no on-the-wire X.509 verification, auth happens after the handshake).

This is a personal project.  Public repo would be welcome upstream contributions; this one is private — the protocol identifiers, deploy scripts, and operator tooling are kept off the open web on purpose.

## Status

**Working.** As of 2026-05-01 there are two live deploys (server-A primary, server-B secondary, both behind ok.ru SNI).  Wire protocol is stable for now; HKDF auth label is `TAMIZDAT v1`.

## Layout

```
tamizdat/
├── auth.go              ECDH PSK derivation + sessionID v1 build/verify
├── client.go            samizdat.Client — owns transport pool, picks shortIDs/SNIs
├── server.go            serveH2 magic CONNECT branch + ConnHandler dispatch
├── h2transport.go       single-tunnel H2 transport (drains, soft-cap rotation)
├── connpool.go          MinTransports pool with byte-cap-driven retire
├── auth_extension.go    standard TLS key_share carries client ephemeral pubkey
├── replay_guard.go      time-windowed sessionID replay cache
├── cover_traffic.go     periodic cover-CONNECTs to legitimate RU targets
├── cover_config.go      operator-pushed bundle JSON (epoch_key, sni_pool, cover_targets)
├── shortid_derive.go    HKDF-SHA256 pool derivation: master + epoch_key -> [N][8]byte
├── shortid_pool.go      server-side pool + grace-window for old epochs
├── geneva.go            Geneva-style fragmentation + Thompson Sampling bandit
├── sni_pool.go          weighted Russian-cover-SNI pool
├── sni_parse.go         ClientHello SNI extraction
├── cert_padding.go      ~4 KB cert chain padding to defeat aparecium fingerprints
├── masquerade.go        proxy unauth traffic to the cover origin
├── masquerade_ratelimit.go  per-IP token bucket
├── ssrf_guard.go        DNS-resolve-and-validate before masquerade dial
├── telemetry.go         expvar metrics
├── fragmenter.go        TCP record-level fragmentation
├── fingerprint.go       uTLS fingerprint refresh
├── udp_packetconn.go    UDP-over-CONNECT
├── udp_server.go        server side of UDP tunnelling
├── streamconn.go        small adapter for io.ReadWriter framing
├── shaper.go            traffic-shape padding/jitter (mostly retired post-NDSS-2025)
├── samizdat.go          ClientConfig / ServerConfig
│
├── cmd/tamizdat-server/         standalone server binary
├── cmd/tamizdat-client/         standalone SOCKS5 client binary
├── cmd/tamizdat-genpool/        master + epoch_key generator CLI
├── cmd/tamizdat-node/           node-mode dispatcher entry-point
├── cmd/tamizdat-tun-windows/    Windows TUN-mode client (gVisor + wintun)
│
├── node/                inbound/outbound dispatcher (xray-style routing)
├── internal/configurl/  URI parser used by node config
└── ...
```

## Build

```
go build ./...
```

Cross-build the Windows client:

```
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o tamizdat-client.exe ./cmd/tamizdat-client
```

## URI format

```
tamizdat://<master_hex>@<host>:<port>?pbk=<server_pubkey_hex>&sni=<cover_sni>[&cpool=<csv>]#<label>
```

- `<master_hex>` — 16 hex chars (8-byte master shortID).  Generate via `tamizdat-genpool master`.
- `pbk` — server X25519 public key, hex.
- `sni` — primary cover SNI (must be in server's `--masq-pool`).
- `cpool` — optional comma-separated `host:port` cover-traffic overrides (max 32 entries, ASCII, single occurrence).
- Fragment label is preserved but ignored by the parser.

## Server cmdline

```
tamizdat-server \
  -listen :777 \
  -shortid <master_hex> \
  -privkey <server_x25519_priv_hex> \
  -cert cert.pem \
  -key key.pem \
  -domain ok.ru \
  -masq-pool "ok.ru=ok.ru,vk.com=vk.com,mail.ru=mail.ru,yandex.ru=yandex.ru" \
  -cover-config cover-config.json \
  [-epoch-grace-window 2] \
  [-debug]
```

Bind on ports < 1024 requires `cap_net_bind_service`:

```
sudo setcap cap_net_bind_service=+ep tamizdat-server
```

Cover-config bundle JSON shape:

```json
{
  "version": 1,
  "epoch_key": "ep-2026-05-01-rotated-XXXXXXXX",
  "shortid_pool_size": 100,
  "sni_pool": [
    {"sni": "yandex.ru", "weight": 100},
    {"sni": "vk.com",    "weight": 90},
    {"sni": "mail.ru",   "weight": 75}
  ],
  "cover_targets": [
    "mc.yandex.ru:443", "an.yandex.ru:443", "yastatic.net:443",
    "top-fwz1.mail.ru:443", "clck.yandex.ru:443"
  ],
  "cover_gap_min_ms": 30000,
  "cover_gap_max_ms": 90000
}
```

Operator rotates without rebuilding the client by editing this file and `systemctl restart`.

## Client cmdline

```
tamizdat-client \
  -server llm2.example.com:777 \
  -servername ok.ru \
  -pubkey <server_x25519_pub_hex> \
  -shortid <master_hex> \
  -listen 127.0.0.1:1080 \
  [-debug]
```

Exposes a SOCKS5 proxy on `127.0.0.1:1080`.  Plug a browser into it.

## Lineage / NOTICE

Derivative work.  See [NOTICE.md](NOTICE.md) for the full attribution + the reason we treat upstream as effectively abandoned.  Wire-format identifiers were renamed from `SAMIZDAT v1` to `TAMIZDAT v1` etc., so this build is not interoperable with upstream binaries.

## Tests

```
go test ./... -race -count=1 -timeout 600s
```

`TestBanditPerServerIsolation` is a known statistical flake (~10 % rate; Beta-sample over Thompson sampling); re-run if it trips.  Everything else is deterministic.

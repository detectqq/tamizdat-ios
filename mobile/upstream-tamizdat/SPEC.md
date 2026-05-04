# Tamizdat Protocol Specification

**Version**: P0.3 + compass v1/v2/v3 + pool feature (Option F) + tamizdat rename (2026-05-01)

**Wire-protocol break notice**: As of 2026-05-01, all wire identifiers were renamed (`SAMIZDAT v1` -> `TAMIZDAT v1`, `samizdat-config.invalid` -> `tamizdat-config.invalid`, `Samizdat-Protocol` -> `Tamizdat-Protocol`). Old upstream `getlantern/samizdat` clients are intentionally not interoperable with this build. See [NOTICE.md](NOTICE.md) for the lineage and license-grey-area disclosure
**Wire format**: TLS 1.3 + HTTP/2 CONNECT, single layer
**Threat model target**: Russian TSPU 2025-2026
**Reference implementation**: this repo (Go, branch `phase-b-bbcr-removal`)

---

## 1. Wire layout

```
Client                                                     Server (samizdat)        Origin (cover, e.g. ok.ru)
  │                                                                │                              │
  │── TCP SYN ───────────────────────────────────────────────────▶│                              │
  │                                                                │                              │
  │── TLS ClientHello (uTLS Chrome_Auto, fragmented per Geneva) ──▶│ parse SessionID + key_share  │
  │                                                                │ verify HMAC; auth pass?      │
  │                                                                │                              │
  │              [auth FAIL — masquerade path]                                                    │
  │                                                                │── ClientHello bytes ─────────▶│
  │ ◀──────────────────────────── ServerHello + cert + Finished ──────────────────────── (real)──┤
  │ … bidirectional TCP forward, no TLS termination by samizdat …                                  │
  │                                                                                                │
  │              [auth OK — authenticated path]                                                   │
  │ ◀── ServerHello (samizdat self-signed cert + padded chain ~4.4KB) + Finished + 1 NST ─────────┤
  │── HTTP/2 connection preface ─────────────────────────────────▶│                              │
  │── H2 CONNECT host=destination [Samizdat-Protocol: tcp/1|udp/1]▶│ resolve+SSRF-check destination│
  │                                                                │── TCP/UDP to destination ───▶│
  │ ◀── 200 OK ───────────────────────────────────────────────────┤                              │
  │ … bidirectional H2 stream, multiplexed with other streams …                                   │
```

---

## 2. Authentication

### 2.1 SessionID structure (32 bytes, TLS legacy_session_id)

```
| 0..7    | 8..15      | 16..31           |
|---------|------------|------------------|
| shortID | nonce(rand)| HMAC-SHA256(...) |
```

- **shortID**: 8 bytes, pre-shared between client and server. Server may accept a pool (rotation); client picks random per fresh transport.
- **nonce**: 8 random bytes, fresh per ClientHello (replay protection).
- **HMAC tag**: 16 bytes, truncated `HMAC-SHA256(PSK, version || shortID || nonce || eph_pub)[:16]` where `version=0x01`.

### 2.2 PSK derivation

```
shared_secret = X25519(eph_priv, server_static_pub)
PSK = HKDF-SHA256(salt=shortID, IKM=shared_secret, info="TAMIZDAT v1")[:32]
```

Where `eph_priv` is the X25519 private key the client's TLS-1.3 stack already generated for the standard `key_share` extension (group 0x001D). Reality-style: piggy-back on the same keypair; no private extension.

### 2.3 Server-side verification

1. Read ClientHello SessionID and `key_share` extension.
2. Locate standalone X25519 entry (group 0x001D). Reject if absent.
3. Extract `shortID` from SessionID[0:8]; reject if not in allowed pool.
4. `PSK = HKDF-SHA256(salt=shortID, IKM=X25519(server_static_priv, eph_pub), info="TAMIZDAT v1")`.
5. Recompute `HMAC-SHA256(PSK, 0x01 || shortID || nonce || eph_pub)[:16]`; compare constant-time to SessionID[16:32].
6. Replay check: `replay_key = SHA-256(SessionID || eph_pub)[:16]`; reject if seen within sliding window (default 2 min in `ServerConfig.applyDefaults`, hard cap 65536 entries, LRU eviction; `replay_guard.go` constant supports up to 5 min if explicitly configured).

### 2.4 Constant-time guarantee

`hmac.Equal` for tag comparison.

**Known regression as of 2026-05-01**: `server.go:349-356` returns to the masquerade path before deriving PSK when the candidate shortID is rejected by `shortIDPool.Accept`; `auth.go:199-204` (`VerifySessionIDv1WithServerKey`) has the same early-return shape. This contradicts the original "PSK derivation runs unconditionally" guarantee and **enables a timing side-channel that distinguishes valid vs invalid shortIDs**. Flagged for code fix; spec retains the original guarantee as the target invariant.

---

## 3. Cover handshake (auth-fail path)

When auth fails (HMAC mismatch, replay, unknown shortID, missing key_share, etc.) the server enters **masquerade mode**:

1. The original ClientHello bytes (already buffered) are forwarded byte-for-byte to the configured masquerade origin (default: `ok.ru:443`).
2. Server splices: client TCP ↔ origin TCP, no TLS termination by samizdat.
3. Origin completes the TLS handshake, sends its real cert chain, NewSessionTicket, etc. **All wire-level cryptographic responses are produced by the real origin**, not by samizdat.
4. SNI-aware origin selection: `MasqueradePool` map allows different SNIs to forward to different origins (e.g. `ok.ru` → `ok.ru:443`, `vk.com` → `vk.com:443`).
5. Per-IP rate-limit: 30 forwards/min per source IP, burst 10 (DoS protection).

### Why this is stronger than Reality

Reality's "spider" mode: the Reality server DOES terminate the TLS handshake itself, then forwards subsequent application data to the target. This means Reality's wire-level handshake is produced by Reality's TLS stack, not the target's. ShadowTLS v3 is similar (and the Aparecium PoC exploits this). Samizdat doesn't terminate TLS in masquerade mode — wire-level == real origin == perfectly indistinguishable.

---

## 4. Authenticated handshake (auth-OK path)

Once auth verifies, the samizdat server terminates TLS itself:

- **TLS version**: 1.3 only (`MinVersion = tls.VersionTLS13`).
- **Certificate**: self-signed, padded to ~4.4 KB chain via `cert_padding.go` so encrypted Certificate flight matches ok.ru's GlobalSign chain (~4.1 KB DER).
- **NewSessionTicket**: 1 NST (`SessionTicketsDisabled = false` — Go default). Empirically matches what real ok.ru sends to a real Chrome ClientHello (~40 byte encrypted record post-handshake).
- **ALPN**: `h2` only.

### 4.1 Cert model — explicit choice

> **Why NOT Reality-style cert stealing?**
>
> Reality MITMs a live target handshake on each auth-OK to obtain the target's actual cert chain and reply to the client with that chain. This requires:
> - An additional outbound TCP+TLS to target on every auth-OK.
> - Race-condition handling between the client's ClientHello and the spider TLS state.
> - Trust the target server hasn't blocked our spider IP.
>
> Samizdat trades wire-level cert mimicry (Reality has it; we don't) for operational simplicity:
> - Zero per-connection outbound to target (only on auth-FAIL).
> - Self-signed + chain padding makes encrypted-Cert SIZE indistinguishable on the wire (TLS 1.3 encrypts cert content).
> - Active probes hit the masquerade path → see real origin cert. Same as Reality.
>
> The trade-off: an attacker who decrypts our TLS (impossible without keys) sees self-signed + dummy CAs instead of real ok.ru chain. Passive observers cannot decrypt. Active probers cannot trigger our authenticated path without the PSK. Net: equivalent to Reality for realistic threat models, simpler to operate.

---

## 5. Tunnel

After TLS handshake completes, samizdat speaks HTTP/2:

- **TCP CONNECT**: client opens H2 stream `CONNECT example.com:443` (no Samizdat-Protocol header). Server validates destination via `ResolveAndValidateDestination` (SSRF guard: blocks RFC1918, loopback, link-local, multicast, CGNAT, IPv6 ULA), dials TCP, splices.
- **UDP CONNECT**: client opens H2 stream with header `Samizdat-Protocol: udp/1`. Server bridges H2 stream ↔ `net.UDPConn` with uint16-BE length-prefixed datagram framing.

### 5.1 Connection pool

- **MinTransports**: pre-warm N parallel TLS+H2 transports up-front. Default 1; ops set 2-4 to ride out the #490 curtain (15-20KB shaping).
- **BytesPerTransportSoftCap**: drain the transport when cumulative outbound bytes >= cap. Default 0 (disabled). Set to ~12000 to drain BEFORE TSPU detector #490 fires.
- **Round-robin distribution**: streams spread across alive transports (compass P1.2).
- **Reaper**: 5-second tick replaces drained/closed transports up to MinTransports.

---

## 6. Geneva-style ClientHello fragmentation

- **5 strategies registered**: `sni_split` (split at SNI extension boundary), `first_byte` (1+rest), `midpoint`, `two_thirds`, `hdr_then_body`.
- **Multi-armed bandit selection**: per-server (host:port) Thompson Sampling. Each strategy maintains Beta(wins+1, losses+1) posterior; `argmax` of one sample per strategy. Robust against adversarial-bandit attack where censor selectively blocks a winning arm.
- **Outcome feedback**: client.createTransport reports success/failure to the bandit after TLS handshake completes.

---

## 7. Stealth measures

- **uTLS Chrome fingerprint pool**: configurable via `ClientConfig.Fingerprint`. Modes:
  - `chrome` (current default): random pick from `Chrome_120`, `Chrome_115_PQ`, `Chrome_106_Shuffle`, `Chrome_100`, `Chrome_Auto` (= Chrome 133 with X25519MLKEM768). **Known drift**: includes pre-2024 Chrome variants that the `mix` mode explicitly drops as "stale browser signature"; recommended fix is to switch the default to `mix`.
  - `mix` / `auto` / `rotate`: curated rotation that prefers `Chrome_Auto` and excludes stale variants.
  - `firefox` / `safari` / `edge`: corresponding uTLS profiles.
- **shortID rotation**: client picks uniformly from `{master} ∪ derivedPool` per `pickShortID` call (after a bundle is applied; before bundle, master only). Closes the "fixed prefix per server IP" entropy signal in steady state. See §10 for HKDF derivation.
- **SNI rotation**: client picks random SNI from `ClientConfig.ServerNames` per fresh transport. Server `MasqueradePool` matches SNI to forward target so probes on any pool SNI see correct cover. Optional Zipf-weighted pool of 39 RU sites in `sni_pool.go` (was 38 in earlier docs; one extra entry was added in compass v3).
- **Cover/decoy traffic**: `ClientConfig.CoverTrafficEnabled=true` spawns background goroutine that opens periodic CONNECT streams to RU cover targets every 30-90s. Mixes "browser-like" side streams on the same H2 session.
- **TCP fragmentation**: ClientHello split into 2+ TCP segments on the SNI extension boundary (Geneva style). Default enabled.
- **TCP_QUICKACK=0** on accept'ed server-side TCP (Linux). Compresses RTTdiff per NDSS 2025 §I recommendation.
- **No per-record jitter**: NDSS 2025 paper §I shows random jitter INFLATES RTTdiff (anti-pattern). Samizdat does not jitter.
- **Replay guard**: 2-min sliding window default (configurable via `ServerConfig.ReplayWindow`, hard cap 5 min in `replay_guard.go`), 65536-entry hard cap, LRU eviction. `tamizdat.replay.{hits,window_size,evictions}` expvars (post wire-rename).
- **No production logs**: all data-plane logs gated behind `ServerConfig.Debug=true` + `s.logf`.
- **SSRF defense**: `ResolveAndValidateDestination` blocks all reserved IP ranges (TCP and UDP).
- **HIGH-1/HIGH-2**: `SetDeadline` on `udpFramedPacketConn` and `serverStreamConn` honors `os.ErrDeadlineExceeded` contract via atomic deadline + AfterFunc-driven close.
- **HIGH-4**: `connPool.reserveStreamSlot` atomic CAS prevents oversubscription race.

---

## 8. Threat model coverage

| Threat | Defense | Status |
|---|---|---|
| TSPU #490 (15-20KB shaping on single TCP) | MinTransports=2 default + `BytesPerTransportSoftCap=13312` drain (well below the 15-20 KB threshold) | ✅ Built-in. **Trade-off note**: aggressive byte-cap rotation produces high new-handshake-rate which is itself a detection axis (see #546 row); current rotation rate is calibrated to stay below browser baselines |
| TSPU #546 (TLS conn-count policing) | H2 multiplexing within a small connection pool. **Implementation**: `MinTransports=2`, `MaxStreamsPerConn=100`, no explicit `MaxTransports` cap (default behavior keeps simultaneous count well below browser norms) | ✅ Acceptable per analyst review. **Observed threshold** per [net4people/bbs#546 comment 3568225757](https://github.com/net4people/bbs/issues/546#issuecomment-3568225757): ~12 simultaneous TLS sessions in short window triggered shaping on MTS Novosibirsk. Tamizdat default of 2 is well below. **Trade-off note**: row 1 (#490 — rotate often) and this row (#546 — keep count low) are in tension; the chosen compromise is "low simultaneous count + moderate rotation cadence". `connpool.go:181-186` documents this in code |
| TSPU active probing | Transparent TCP forward to real origin on auth-FAIL via `doMasquerade` (full HTTP forward proxy with SSRF guard, NOT TCP-splice) | ✅ Stronger than Reality (Reality TCP-splices; we proxy at L7 with `ssrf_guard.go` + `masquerade_ratelimit.go`) |
| Aparecium-class post-handshake fingerprint | 1 NST emitted (matches Chrome→ok.ru); cert chain padded to ~5.2 KB total via `padCertChain(target=4200, count=3)` in `server.go:113-122` | ✅ Closed (numeric overshoot vs earlier "~4.4 KB" doc; reality is ~5.2 KB) |
| TLS-in-TLS (USENIX Sec 2024) | Single TLS layer, inner TLS forwarded as opaque H2 DATA, fragmented across H2 DATA frames via `RecordFragmenter` | ✅ Architectural |
| JA4 fingerprinting | uTLS Chrome rotation pool; ZERO private extensions on wire (post-compass v2 §5.1 migration). **Drift**: default `chrome` pool includes pre-2024 Chrome variants — recommend switching default to `mix` (see §7) | ⚠️ Partial — code regression on default fingerprint pool |
| Cross-layer RTT (NDSS 2025 dMAP) | `TCP_QUICKACK=0` on accepted server-side TCP + H2 multiplexing; no per-record jitter (jitter was retired in P0.4 after NDSS 2025 showed jitter INFLATES RTTdiff) | ⚠️ Partial — full mitigation requires Markov flow shaping (research-grade) |
| SNI-prefix correlation | Per-transport SNI rotation, optional Zipf-weighted pool of 39 entries | ✅ Closed |
| shortID-prefix correlation | Per-transport shortID rotation from `{master} ∪ derivedPool` (HKDF-derived, see §10) | ✅ Closed |
| ECH (cloudflare-ech.com block) | Not used | ⚠️ Deferred (compass v3 P1) |
| Post-quantum (harvest-now-decrypt-later) | TLS-level X25519MLKEM768 hybrid via Chrome_Auto fingerprint when picked from rotation pool. **Note**: with the current default `chrome` pool, only `Chrome_Auto` provides PQ; the four pre-2024 variants do NOT. Auth PSK is X25519-only (HMAC tag, no data encryption — compromise leaks identity, not data) | ⚠️ Partial when default fingerprint pool is `chrome` (some variants non-PQ). Closed when `mix` mode is used |
| Active probing rate amplification | Per-IP rate-limit on masquerade forward (30/min, burst 10) | ✅ Closed |
| Cert flight size mismatch | Padded chain ~5.2 KB matches CDN-edge profile | ✅ Closed |
| Replay attack | 2-min sliding window guard (default), 65536 entries, LRU eviction | ✅ Closed (window narrowed from 5 min for performance; `replay_guard.go` still supports up to 5 min if `ServerConfig.ReplayWindow` is set explicitly) |
| TSPU #516 (mobile whitelist by SNI) | SNI rotation through RKN-whitelisted RU cover sites | ✅ Partial (cover-IP must also whitelist) |
| **Per-shortID compromise / blocklist accumulation** (NEW row, post-pool-feature 2026-05-01) | HKDF-derived per-epoch shortID pool: master + derived pool valid concurrently; operator rotates `epoch_key` in cover-config bundle; old derived pool retained `--epoch-grace-window` (default 2) rotations for in-flight clients. See §10 | ✅ Closed (unique among RU-deployed protocols; REALITY's static shortID list does not have this) |
| **Operational rotation of cover targets / SNI pool / pool size without client rebuild** (NEW row) | Server-pushed config bundle delivered via magic CONNECT to `tamizdat-config.invalid:443` (see §9). Operator edits `cover-config.json` and `systemctl restart` server; clients pick up bundle on next fresh transport | ✅ Closed |
| **Auth-OK timing distinguishability** (NEW row) | Auth-OK path performs a shadow dial to the masquerade origin via `addShadowDial` (`server.go:414-445`) before TLS handshake completes, so authenticated and unauthenticated paths absorb similar outbound dial RTT | ✅ Closed |

---

## 9. Comparison summary

| Property | Samizdat | Reality+Vision | NaiveProxy | ShadowTLS v3 | AmneziaWG |
|---|---|---|---|---|---|
| Transport | TLS+H2 / TCP | TLS / TCP | TLS+H2 / TCP | TLS / TCP | UDP+WG |
| Auth | ECDH-PSK in SessionID + key_share | ECDH-PSK in SessionID + key_share | HTTP basic | HMAC PSK | WG noise |
| TLS terminator on auth-OK | Self with padded self-signed cert | Self with target-stolen cert | Caddy with real LE cert | Front-server with HMAC | N/A |
| Auth-fail behavior | Transparent TCP forward to origin | Spider TLS to target | Caddy fallback to web | Tag-modified TLS records | N/A |
| Multi-conn against #490 | ✅ Built-in | ❌ Manual | ❌ Manual | ❌ | N/A |
| H2 mux against #546 | ✅ | Optional | ✅ | ❌ | N/A |
| PQ encryption | ✅ TLS-level X25519MLKEM768 | ✅ ML-KEM-768 + ML-DSA-65 | ✅ Chrome PQ | ❌ | ❌ |
| 0xFE0C/private extensions on wire | ✅ None (post compass v2) | ✅ None | ✅ None | +4 byte HMAC tag (Aparecium-vulnerable) | N/A |
| Adversarial-robust strategy selection | ✅ Thompson Sampling | ❌ Static | ❌ Static | ❌ | Periodic manual updates |
| Mature ecosystem | ❌ Lantern only | ✅ Xray/sing-box/3X-UI/Hiddify | Moderate | Moderate | Excellent (Amnezia) |
| Audit | This SPEC + 4-LLM cross-review | OSS community + multiple audits | OSS Cronet + Caddy | OSS community | RKS Global, NCC |

---

## 10. Limitations and known gaps

- **No 0-RTT TLS 1.3**: each new transport pays a 1-RTT handshake. Architectural conflict with PSK auth (PSK is in SessionID, processed before Finished).
- **No CDN fronting**: samizdat does not natively support routing through Cloudflare/Fastly. Lantern has separate `mirage` transport for that.
- **No multi-path / connection migration**: single TLS+H2 path per transport; relies on multi-transport pool for resilience.
- **Cert is self-signed not stolen**: documented architectural choice (§4.1). Encrypted-flight size matches via padding; content does not (impossible without target private key).
- **uTLS pool requires periodic refresh**: when Chrome moves to 134+/135+, Chrome_Auto in installed utls falls behind. `go get -u github.com/refraction-networking/utls` periodically.
- **Mobile whitelist (TSPU #516)**: when ISP whitelists by SNI+CIDR, samizdat passes only if cover SNI is in whitelist AND cover IP-CIDR is in whitelist. Real ok.ru CIDR usually is; our server CIDR (Hetzner/etc) usually isn't. Gap shared with all proxy protocols.
- **Application-layer RTT distribution** (compass v3 §5.10): we add TCP_QUICKACK=0 (transport-layer mitigation) and per-CONNECT cover traffic, but don't model realistic Chrome→ok.ru page-load latency distribution. Markov flow shaping is research-grade work, not implemented.

---

## 11. References

- net4people/bbs#490 (15-20KB curtain), #546 (TLS-conn policing), #516 (mobile whitelist), #417 (ECH block).
- USENIX Sec 2024 — Xue, Kallitsis, Houmansadr, Ensafi, "Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes".
- NDSS 2025 — Xue, Stanley, Kumar, Ensafi, "The Discriminative Power of Cross-layer RTTs in Fingerprinting Proxy Traffic".
- Aparecium PoC (ban6cat6) — REALITY/ShadowTLS v3 detector via NewSessionTicket absence.
- XTLS REALITY spec, NaiveProxy README, AmneziaWG protocol description.
- Lantern `tlsmasq` (precursor of the transparent-forward fail-mode), `mirage` (CDN transport).

---

## 12. Implementation status

Branch `phase-b-bbcr-removal` HEAD `66b2440` (post compass v3 cleanup) on llm2.

Diff vs upstream `phase3-T1-off` baseline: **89 files, +3540 / -14305 LOC**. ~75% net code reduction (BBCR removal -13.5K + new features +3.5K - cleanup -0.5K).

Production endpoints:
- `llm2.detectqq.dpdns.org:777` (privileged port via setcap)
- `odikee.dpdns.org:778` (systemd unit)

Both serve the same auth keys (single shortID + pubkey) so client config works with either endpoint as failover.

---

## 9. Config bundle (v1)

Pool-feature addendum (Option F): after a fresh TLS+HTTP/2 transport is ready, the client asynchronously opens a normal HTTP/2 CONNECT stream to the reserved authority `tamizdat-config.invalid:443` with `Tamizdat-Protocol: config/1`. **Server validation note**: `server.go:520` matches against the host only (`r.Host == configAuthority`) and ignores the protocol header; the header is preserved for forward-compat / observability. The server handles this inside the `serveH2` handler before normal destination dispatch and returns a JSON bundle. If no operator bundle is configured, the server returns `{"version":1}`.

Bundle schema:

```json
{
  "version": 1,
  "epoch_key": "ep-2026-05-01-rotated",
  "shortid_pool_size": 100,
  "sni_pool": [
    {"sni": "yandex.ru", "weight": 100},
    {"sni": "vk.com", "weight": 90}
  ],
  "cover_targets": ["mc.yandex.ru:443", "an.yandex.ru:443"],
  "cover_gap_min_ms": 30000,
  "cover_gap_max_ms": 90000
}
```

Client handling is best-effort: non-200, empty body, timeout, parse failure, or a body over 4096 bytes leaves URI/default settings in effect. Overrides are applied atomically for subsequent operations only: derived shortIDs, cover targets/gaps, and additive weighted SNI pool.

Server flags:

- `--shortid <master_hex>`: exactly one 16-hex master shortID.
- `--cover-config <path>`: optional JSON bundle path, read and validated at startup.
- `--cover-config-previous <path>`: optional previous bundle used to pre-populate grace-window auth.
- `--epoch-grace-window <N>`: number of previous derived pools accepted in memory (default 2).

Validation fails startup if `version != 1`, `shortid_pool_size` is outside `[0,1000]`, `epoch_key` is non-ASCII or longer than 64 bytes, `sni_pool` entries are absent from the configured masquerade pool, cover targets are not valid `host:port`, or cover gaps are outside `[1,600000]` ms / min exceeds max.

## 10. ShortID pool derivation

The URI carries exactly one master shortID. Client and server independently derive a pool for the current epoch using HKDF-SHA256 (RFC 5869):

```text
PRK_epoch = HKDF-Extract(salt = []byte(epoch_key), IKM = master_shortid_8_bytes_raw)
for i in [0, shortid_pool_size):
    info_i = uint32(i) encoded big-endian
    pool[i] = HKDF-Expand(PRK_epoch, info_i, 8 bytes)
```

Pinned vectors used by tests:

| master_hex | epoch_key | i | output_hex |
|---|---:|---:|---|
| `0001020304050607` | `ep-2026-05-01-rotated` | 0 | `a20a3598400b2c6d` |
| `0001020304050607` | `ep-2026-05-01-rotated` | 1 | `1b567f05a87cdd50` |
| `d1b122782219759f` | `ep-2026-05-01-rotated-a1b2c3d4` | 42 | `46a1a2b7b66bb3a7` |

The server accepts the master, current derived pool, and previous derived pools within the configured grace window. The client picks uniformly from `{master} ∪ derivedPool`; before a bundle is fetched or when the bundle has no derivation fields, it uses the master only.

## 11. Security considerations

URI master shortID compromise yields full pool derivation by an attacker who also has the server pubkey (which is in the URI). This is acceptable in our threat model because realistic URI leakage scenarios (screenshot, chat share, cloud backup) leak the entire URI atomically — the attacker has both master AND pubkey in the same leak. Per-shortID compromise (e.g., operator log accidentally captures one entry without leaking the URI) is mitigated only by epoch rotation: operator publishes a new bundle with a new `epoch_key`, server's grace-window flushes the old derived pool after `N` rotations.



---

## Variant 1 full pool strategy

Variant 1 (`PoolVariant="v1"`) is the strict single-transport posture for operators who prefer a stable wire signature over throughput-oriented pool expansion.

### State machine

- `BulkOnlyFull`: one bulk TLS+HTTP/2 transport, record fragmentation enabled, cover traffic enabled, delayed-ACK posture. This is the default steady state.
- `BulkOnlyLite`: the same single bulk transport flips to `ShapeLite` when the realtime controller sees the first realtime flow. Existing and new streams read the transport shape atomically on every write, so the next write bypasses record fragmentation. TCP_QUICKACK is toggled on the live TCP socket when reachable.
- `BulkLiteHystToFull`: after the last realtime flow closes, the controller keeps Lite mode for the existing 30-60s hysteresis window. Cover traffic remains suppressed and streams continue to bypass fragmentation until the timer returns to Full.
- `BulkRotatingFull` / `BulkRotatingLite`: reachable only when `BytesPerTransportSoftCap > 0`. V1 permits one transient replacement transport (`RotationOverlapAllowance=1`) while the old bulk transport drains, so the simultaneous TCP count is bounded by two. The default byte cap is 0, so rotation is off unless explicitly enabled.

### Realtime transitions

`RealtimeController.Open(TrafficRealtime)` and `Promote` flip the controller to Lite and invoke the client-side pool callback. In V1 (`MaxTransports==1`) that callback flips all live bulk transports to Lite instead of opening a separate realtime transport. `returnToFull` fires `onModeReturnToFull` after hysteresis and flips live bulk transports back to Full.

### Cover traffic and rotation defaults

The cover loop polls `Controller.Mode()` after each scheduled gap and skips `coverOnce` while Lite. No pause/resume channel is used. This means a cover request already in flight may finish, but no new cover CONNECT is emitted during the Lite window.

`BytesPerTransportSoftCap` defaults to 0. When an operator enables the cap for V1, the rotation overlap allowance allows one fresh bulk replacement while the draining transport closes. Long realtime streams can still be cut off by `DrainTimeout`; operators who enable byte-cap rotation for VoIP-heavy use should raise `DrainTimeout` or leave rotation disabled.

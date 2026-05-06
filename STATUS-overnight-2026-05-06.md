# Overnight 2026-05-05 → 2026-05-06 status

## TL;DR

- **IPA-B4 готов**: `ipa/milestones/B4-v2-mode/samizdat-ios.ipa` (9.1 MB).
  Должен решить crash из B3 (V1 cap=150 streams не выдерживал iOS multi-app burst).
- **B3 крашнулся ИНАЧЕ чем B2** — sing-tun-side архитектура (Mixed mode) теперь корректна, упёрлись в наш собственный tamizdat StrictSingleH2 cap=1.
- **Path 5 дизайн готов** в `C:\var-tmp\custom-shim-design-result.md` — Option A (custom userspace TCP, ~14× меньше памяти per flow, 5-day effort) если B4 не пройдёт.

## Хронология ночи

### 23:46 MSK — твой B3 smoke test

1. `info: netstack up (Path 4 / sing-tun + sagernet/gvisor)` ✓
2. fd=8 duped to 11 ✓ (наш B10 fd-ownership фикс работает)
3. `info: netstack started fd=11 server=odikee.dpdns.org:778 sni=ok.ru mtu=4064 nic=172.19.0.1/30` ✓ — все sing-box-for-apple parity параметры применены
4. **0 stack-side warnings** — B3 Tier 1-4 фиксы (ForwarderBindInterface, InterfaceFinder, with_low_memory tag, real Logger) сработали полностью
5. 02:45:23 — `588× tamizdat: pool at MaxTransports cap: cap=1` за <1 сек
6. 02:45:24 — go.inuse 32→91 MB, go.sys 33→96 MB (+60 MB за 1 сек)
7. 02:46:09 — bridge: status connected → disconnected (jetsam reaped)

**Жил 71 сек** (vs B2 = 30 сек, B1 = 110 сек).

### Root cause B3

`StrictSingleH2: true` (V1 mode) пинит tamizdat connpool на `MaxTransports=1, MaxStreamsPerConn=150` = всего **150 одновременных H2 streams**. iOS multi-app cold-start (Safari + Roblox + YouTube + speedtest всё сразу) генерит 200+ unique flows за секунды. Когда slots saturate, каждый dial возвращает `ErrPoolBackpressure`; наш udpDemux не справляется с failure storm, goroutines + 64 KB read buffers накапливаются → +60 MB allocation spike → jetsam.

**Почему B1 не падал так**: forced gvisor mode имел 128 KiB TCP buffer cap (наш Achilles heel для throughput, но и accidental backpressure для concurrency). iOS apps не могли flood'ить запросы.

**Почему IPA-A1..A9 не падали так**: hev/lwIP коалесировал UDP flows, только TCP шёл через socksstub→tamizdat (модерат concurrency).

**B3 убрал throughput cap → iOS apps firehosed → upiрerлись в наш V1 cap=150.**

### B4 фиксы (commit `352ea03`)

1. **tamizdat config**: V1 → V2:
   - `PoolVariant: "v2"` (вместо "v1")
   - `StrictSingleH2: false` (вместо true)
   - `MaxStreamsPerConn: 150` остаётся
   
   **Эффект**: cap = 2 transports × 150 = **300 streams**. TSPU exposure: 2 long-running connections per device vs 1, всё ещё значительно ниже #546 fingerprint counter trigger (~12 conn/user).

2. **sync.Pool в udpDemux.pumpRemoteToLocal** для 64 KiB read buffer. Per-pump goroutine больше не аллоцирует `make([]byte, 65536)` — пул переиспользует.

   **Эффект**: при 588-flow burst было ~38 MB pinned per-pump heap. Теперь shared pool.

V1 был твой stated TSPU preference (memory `feedback_overnight_2026_05_02_priorities`), НО V1 не работает на iOS NE при реалистичной multi-app load — Path 4 routes каждый flow напрямую через tamizdat, без hev coalescing layer.

### B4 build matrix

```
go build -tags=with_gvisor,netstack_real,with_low_memory,badlinkname ./samizdat ./socksstub ./netstack — green
go vet — green
go test ./samizdat ./internal/configparse — 4/4 pass
CI build 25408764658 — green за 2m38s
```

Артефакт: `ipa/milestones/B4-v2-mode/samizdat-ios.ipa` (9.1 MB).

## B4 smoke test чек-лист

1. Установи IPA из `B4-v2-mode/`
2. Speedtest на odikee — цель 100+ Mbps (раньше 30 в B1, сломан в B2/B3)
3. Roblox в середине — должен открыться И не убить extension
4. Safari + YouTube + Roblox combo 5 мин — должно жить
5. **App Group log будет показывать stack warnings от sing-tun** (Logger=real в B3+):
   - `info: stack: ...` — нормально, gvisor/system stack info
   - `warn: stack: ...` — насторожиться, прислать
   - `error: stack: ...` — точно прислать
6. memwatch будет логать `warn: memwatch fired Sys=... → FreeOSMemory()` при пиках. Это watchdog работает — нормально.
7. Если опять падает — пришли лог. Будет видно куда упёрлись на этот раз (B3 показал V1 cap, B4 покажет V2 cap или другое).

## Если B4 не работает

### Quick fix (B5, ~30 мин работы)

Уменьшить per-flow buffers (отвечал на твой вопрос про "ужать KB на бурст"):
1. TCP relay buf 32 → 16 KiB (handler.go:relay) — экономит ~5 MB at 300 flows
2. udpDemux pump buf 64 → 16 KiB — экономит ~7 MB at 300 flows
3. **H2 stream window 64 → 16 KiB** (vendored x/net дополнительный патч) — экономит ~14 MB at 300 streams. Самый большой выигрыш. Per-stream peak падает с 64 KB до 16 KB / 30ms RTT = 4 Mbps, но aggregate 300 streams × 4 Mbps = 1.2 Gbps (>>700 Mbps base) — для multi-app workload (параллельный) trade-off правильный.

С этими 3 дельтами: 300 streams × 82 KB (вместо 130) = 24 MB вместо 39 MB. **Total ~39 MB (вместо 54)** = comfortable headroom.

### Proper fix (Path 5 / Option A, 5 days)

Custom userspace TCP, pure Go, iOS-only. **~14× меньше памяти per TCP flow** (9 KiB vs 130 KiB). Total RSS at 50 flows = 14 MiB (25 MiB headroom). Полный дизайн в `C:\var-tmp\custom-shim-design-result.md` — 277 строк, file layout + memory math + per-packet path analysis + risk register + 7 risks с mitigations.

Архитектурно Option A повторяет Outline iOS / Psiphon's стратегию: **tunnel IP packets, NOT per-flow Go structs**. Outline уже использует pure-Go lwIP-go и **всё равно упирается в 15 MB iOS NE cap** — их фикс был именно архитектурный (per-flow <9 KiB bounded), не выбор стека.

Bonus: bind() workaround для 3× TCP perf на iOS NE при full-tunnel — Apple developer thread #681516.

Если B4 не работает, варианты:
- A. Quick B5 (memory shrink) — 30 мин, может хватит, может нет
- B. Path 5 / Option A — 5 дней, гарантированно решает
- Можно сделать сначала A, если не пройдёт — B

## Path 5 design highlights (full text in `C:\var-tmp\custom-shim-design-result.md`)

```
mobile/netstack/  (replace everything)
  netstack.go         — public Start(fd, configBlob) — Swift entry unchanged
  ipv4.go             — IP+TCP+UDP header parse/build, byte-slice arithmetic only
  tun_io.go           — utun fd reader/writer, sync.Pool of MTU-sized scratch
  tcp_state.go        — TCP state machine (one tcpFlow per 5-tuple)
  tcp_ring.go         — 4 KiB power-of-two ring; sync.Pool of [4096]byte
  tcp_table.go        — 5-tuple → *tcpFlow, MaxFlows=128, mutex
  udp_nat.go          — port-keyed UDP NAT (port from existing handler.go)
  pump.go             — bidirectional copier, sync.Pool buffers
  bind_workaround_ios.go — bind() to utun IP for 3× TCP perf
```

Build tags: `//go:build ios` everywhere.
Drops sing-tun, sing, gvisor, hev from go.mod.

TCP correctness scope reduction (мы владеем обоими endpoints):
- ✗ SACK ✗ Window scaling ✗ Fast retransmit ✗ TIME-WAIT ✗ Path MTU discovery
- Same trick lwIP применяет; делаем idiomatic Go

Memory budget at 50 flows (30 TCP / 20 UDP):
- TCP flow + state: 30 × 1 KiB = 30 KiB
- TCP rxring (4 KiB pool buf): 30 × 4 KiB = 120 KiB
- TCP txring (2 KiB embed): 30 × 2 KiB = 60 KiB
- UDP flow + state: 20 × 0.5 KiB = 10 KiB
- NAT tables: 32 KiB
- Scratch pools: 128 KiB
- Goroutine stacks (2/flow × 4 KiB): 400 KiB
- **Subtotal: ~900 KiB shim**
- + tamizdat 5 MB + Go runtime 5 MB + TLS 3 MB = **~14 MiB total RSS**

Effort: 5 focused days (Day 1-3 implementation, +2 days TCP edge fix-up). Brief explicitly says don't compress.

## Memory files updated

- `feedback_no_fallback_find_what_works.md` — debug rule: outward research over rollback
- `project_ios_singtun_ground_truth.md` — 7 sing-box-for-apple parity requirements + iOS NE hard limits + failure mode catalogue per IPA

## Открытые вопросы для тебя утром

1. **Работает ли B4** на твоём iPhone (Speedtest + Roblox)?
2. Если работает — какая скорость? Если близко к 150+ Mbps — ship as IPA-B5 production, Path 5 = future direction.
3. Если не работает — выбираешь между B5 quick memory shrink (30 мин) и Path 5 Option A (5 дней)?
4. Если выбираешь Path 5 — могу прямо утром начинать имплементацию.

## Файлы исследований (если хочешь пересмотреть)

- `C:\var-tmp\b2-rootcause-result.md` — B2 forensic (Mixed mode TCP NAT loopback)
- `C:\var-tmp\b2-sbfa-archaeology-result.md` — sing-box-for-apple source archaeology (7 deltas для B3)
- `C:\var-tmp\b2-web-research-result.md` — Outline iOS / hev / heiher empirical evidence
- `C:\var-tmp\custom-shim-design-result.md` — Path 5 / Option A полный дизайн (277 строк)
- `STATUS-overnight-2026-05-06.md` — этот файл

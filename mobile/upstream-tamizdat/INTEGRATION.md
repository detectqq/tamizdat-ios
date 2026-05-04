# Samizdat integration notes

## Bundle handling on iOS

Network Extension wrappers continue to construct `samizdat.Client` from the URI-derived config. No UI change is required for the pool feature: the URI still carries one master shortID, one server pubkey, and one primary SNI.

When a fresh TLS+HTTP/2 transport is created, the Go client asynchronously fetches the config bundle via `CONNECT samizdat-config.invalid:443` with `Samizdat-Protocol: config/1`. The fetch is best-effort and does not block first user traffic. If the server is old, the bundle is absent, the body is empty/oversized, or parsing fails, the client silently keeps URI/default behavior.

After a valid bundle is applied, subsequent operations use the atomically swapped values:

- shortID picks use `{master} ∪ HKDF(master, epoch_key, i)`;
- cover CONNECT destinations use `cover_targets` when present;
- cover traffic jitter uses `cover_gap_min_ms` / `cover_gap_max_ms` when present;
- outer TLS SNI selection uses primary URI SNI plus weighted bundle `sni_pool` entries.

The bundle is not persisted to disk. A new transport fetches again, so app restart or tunnel reconnect naturally picks up server-side operator rotations.


## Variant 1 client settings

Use `PoolVariant: "v1"` (or `tamizdat-client -pool-variant=v1`) for the strict single-transport strategy. Defaults are:

- `MinTransports=1`, `MaxTransports=1`;
- `BytesPerTransportSoftCap=0` (rotation disabled by default);
- `RotationOverlapAllowance=1` for the optional byte-cap rotation path;
- realtime flows stay on the bulk transport and flip the whole transport to Lite for the realtime hysteresis window;
- cover traffic is suppressed while the realtime controller is Lite and resumes naturally after the 30-60s return-to-Full hysteresis.

For debug/experiments, `tamizdat-client -rotation-overlap=N` sets the transient overlap allowance used when byte-cap rotation is enabled. Production V1 deployments should normally keep the byte cap at 0 to preserve exactly one TCP connection to the server.

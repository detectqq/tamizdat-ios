# Samizdat URI scheme (F-shape)

Canonical form:

```text
tamizdat://<master_hex>@<host>:<port>?pbk=<server_pubkey_hex>&sni=<primary_sni>[&cpool=<csv>]#<label>
```

Fields:

- `master_hex`: exactly 16 lowercase/uppercase hex characters (8 raw bytes). This is the single master shortID. Derived shortID pools are never listed in the URI.
- `host:port`: server address. `port` must be in `[1,65535]`.
- `pbk`: server X25519 public key as 64 hex characters.
- `sni`: primary outer TLS ServerName. Server-pushed `sni_pool` entries are additive to this primary SNI.
- `cpool`: optional comma-separated cover target override. Values are URL-decoded before splitting; each entry must be ASCII `host:port`; max 32 entries; duplicate entries are preserved; duplicate `cpool` parameters are rejected.
- `label`: optional fragment, parsed as display metadata only.

Examples:

```text
tamizdat://d1b122782219759f@llm2.detectqq.dpdns.org:8443?pbk=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&sni=ok.ru#llm2
tamizdat://d1b122782219759f@llm2.detectqq.dpdns.org:8443?pbk=1ecb6d89948bda812bcbd56eff43bd63f94d2a2a32c3d52ebfee0010e4634363&sni=ok.ru&cpool=mc.yandex.ru%3A443%2Can.yandex.ru%3A443#with-cover-pool
```

The URI is deliberately single-master to keep its visible size/shape similar to other proxy URIs while preserving many-valid-shortIDs operational behavior through HKDF derivation from server-pushed epochs.

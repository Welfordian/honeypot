# Safety Model

This project is a decoy and telemetry system, not a malware sandbox.

## Hard boundaries

- No attacker input is executed.
- No payload is written with execute permissions.
- No attacker traffic is proxied to another host.
- No scanning back, exploitation, or retaliation is implemented.
- Public sensors do not have Cloudflare credentials.
- Public sensors only know the local ingest gateway URL and HMAC ingestion secret.
- The VPS has no Cloudflare R2 access keys; the Cloudflare Worker writes to R2 through a binding.
- Raw R2 objects remain private; the public dashboard reads only sanitized D1 metadata.
- Full PCAP chunks remain private under the `private-pcap/` R2 prefix and are never exposed by public Pages/Functions routes.

## VPS posture

The VPS is single-purpose for this honeypot. It can safely dedicate public service ports to decoys and use broad firewall rules.

Sensor services should run with:

- `cap_drop: [ALL]`
- `security_opt: no-new-privileges:true`
- `read_only: true`
- `tmpfs` mounted with `noexec,nosuid,nodev`
- no Docker socket mount
- no database credentials
- no Cloudflare credentials

Only `r2-writer` is allowed egress to the Cloudflare ingest Worker. Sensors sit on an internal Docker network for collector traffic and a separate public Docker network for published decoy ports; host `DOCKER-USER` rules deny new outbound egress from both sensor networks.

The host network capture service runs outside Docker so it can observe `enp1s0` before Docker/UFW handling. It must always exclude `203.0.113.10` at the BPF filter, raw-table metadata rule, local app, and Cloudflare ingest layers. Admin SSH on `22222` must never be redirected to the generic banner sink. Host metadata is sent to the loopback-only `r2-writer` listener to avoid high-rate direct Cloudflare egress from the capture process; the sender has bounded concurrency and queue limits.

## Public dashboard posture

The public dashboard (e.g. `https://dashboard.example.com`) should expose only:

- source IP
- protocol/trap/event type
- timestamps
- severity
- sensor id
- target path/port
- redacted credential flags
- payload hash, size, and short redacted preview
- packet/byte counts, TCP flags, aggregate markers, PCAP SHA-256, and PCAP availability

It must not expose raw headers, cookies, authorization tokens, passwords, full payload bodies, raw PCAP bytes, signed URLs, or R2 object URLs.

## Cowrie

Cowrie is optional and isolated behind the `cowrie` Compose profile. The provided config disables proxy/high-interaction behavior and enables JSON logging for ingestion by `cowrie-shipper`.

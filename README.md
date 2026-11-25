# Exordos Link

Exordos Link is a Linux proxy for private service-to-service endpoints. It
uses TLS 1.3 and X.509-SVIDs from a PEM file to authenticate both
ends. Each listener has an exact allowlist of peer SPIFFE IDs. An outbound
proxy selects a reachable replica and retries another replica when TCP connect
or the client-side TLS handshake fails. Once the client handshake returns, the
connection is pinned to that replica. A later TLS alert or relay failure
closes the connection.

## Why Link for this data path

Link has a single Tokio I/O worker, a fixed copy buffer per direction, and
a direct TCP forwarding path. It reads JSON policy and reloads the PEM
credentials on SIGHUP. This fits direct private links where
another component already owns service discovery and policy distribution.

In our direct-veth comparison, both products ran as an outbound/inbound pair
with one worker per proxy on an AMD EPYC 7742. Both used TLS 1.3 with SPIRE
and session resumption disabled. Throughput, latency and keep-alive PSS used
three 30-second runs with five seconds of warmup. The 2,000-connection PSS
row comes from a separate idle-connection test. Envoy was **1.40.2** with a
TCP proxy filter.

| Workload | Link | Envoy |
| --- | ---: | ---: |
| 1 KiB responses, 32 connections | **53.4k req/s** | 46.7k req/s |
| 4,000 keep-alive req/s, p99 | **0.34 ms** | 0.38 ms |
| 4,000 keep-alive req/s, two-proxy PSS | **3.42 MiB** | 38.02 MiB |
| 500 new connections/s, p99 | **2.12 ms** | 4.74 ms |
| 4 MiB responses, four streams, Link at 16 KiB buffers | 10.74 Gbit/s | **10.98 Gbit/s** |
| 4 MiB responses, four streams, Link at 64 KiB buffers | **12.62 Gbit/s** | 10.98 Gbit/s |
| 2,000 open connections, two-proxy PSS | 173 MiB | **167 MiB** |

Link used 16 KiB buffers except where indicated. PSS covers the proxy
processes. The SPIRE agents are shared infrastructure and were measured
separately. This comparison predates Link's access log. In a separate
comparison of batched logging to tmpfs and logging disabled, Link handled
3,044 versus 3,161 new connections/s at saturation. At 500 new connections/s
both p99s were about 0.9 ms on that stand. These numbers describe a
same-host private route and the tested workloads.

## Install and run

Download the `.deb` or `.tar.gz` for Linux amd64 or arm64 and the
`SHA256SUMS` file from [GitHub Releases](https://github.com/exordos/exordos_link/releases).
Release binaries are built on Ubuntu 24.04. The `.deb` declares its required
versions of the C runtime libraries.

```sh
sha256sum --ignore-missing --check SHA256SUMS
sudo apt install ./exordos-link_*_"$(dpkg --print-architecture)".deb
exordos-link --version
```

Provision one PEM file containing the workload certificate, public CA bundle and
private key, with the workload certificate first. Link reads
`/var/lib/exordos/link/identity.pem` by default. Use
`EXORDOS_LINK_CREDENTIALS` to specify a different path. Replace the complete
file atomically and send `SIGHUP` to refresh credentials on live listeners.

```sh
EXORDOS_LINK_CREDENTIALS=/path/to/identity.pem exordos-link examples/outbound.json
```

Restrict access to outbound loopback listeners to trusted local processes.
The receiving peer sees the Link workload identity for every local caller.

Outbound listeners probe TCP reachability of each remote Link at startup and
wait 60 seconds between probe rounds by default. Set `health_interval_ms` on
the outbound listener to change the interval. Link tries reachable replicas
first and falls back to replicas that failed a probe if needed. A deployment
that publishes only ready application replicas must supply its own membership, for
example the current writable database leader. Open streams stay on the replica
where they were established.

## Configuration and operations

Link can run multiple listeners in one process. Set the optional connection
limit on the process and list the listeners in `listeners`.

```json
{
  "max_connections": 4096,
  "listeners": [
    {
      "role": "outbound",
      "listen": "127.0.0.1:20000",
      "targets": [{"address": "10.42.0.7:20000", "source": "10.42.0.4"}],
      "peer_ids": ["spiffe://example.test/catalog"]
    }
  ]
}
```

The TLS ALPN `exordos-endpoint/1` identifies the wire protocol. Once authenticated, the
receiving proxy dials the application and sends a readiness byte inside
TLS. If setup fails, the outbound proxy can try the next replica before
forwarding application bytes. A scoped target binds the outgoing socket to
the supplied source address. Guest routing needs to support that address.

Set `protocol` on each inbound listener. `tcp` relays bytes. `http` handles
HTTP/1.x and HTTP/2 with a cleartext HTTP/2 preface, including gRPC. The
receiving proxy replaces `X-Forwarded-Client-Cert` on each request with the
authenticated caller's URI SAN and certificate fingerprint. Bind the
application to a dedicated loopback port and restrict local access to the
trusted proxy. WebSocket upgrades carry the header on the opening request.

Publish a complete replacement JSON file with an atomic rename and send
`SIGHUP`. Link logs `configuration applied` on success. An invalid update
leaves the last applied configuration in use. An empty `peer_ids` list
denies all peer IDs. An empty outbound `targets` list makes the route
unavailable. These updates apply to new connections. Existing connections
run until they close. Switching an application port to HTTP closes earlier
TCP sessions to that address. Link adds and removes listeners on reload
and retries unavailable bind addresses. Changes to the process connection
limit require a restart.

The inbound access log records verified peer IDs and reports duration and
byte counts when a session ends. A bounded queue and a dedicated writer
batch output to stderr. A full queue makes affected sessions wait
asynchronously and may drop listener diagnostics. `SIGTERM` and `SIGINT`
stop the proxy and drain queued records. Set the process file descriptor
limit to at least `2 × max_connections + 64` plus one descriptor per listener
to make the full configured capacity available.

## Build and test

Build on Linux with the pinned Rust toolchain, a C compiler, CMake, and Make.

```sh
cargo build --locked --release
python3 tests/integration.py target/release/exordos-link
python3 tests/integration_grpc.py target/release/exordos-link
bash packaging/build.sh target/release/exordos-link dist
```

The integration test issues certificates with a disposable CA and exercises authentication, replica failover, live revocation,
access logging, and HTTP header forwarding. The gRPC test requires `grpcio`.
Packaging uses `dpkg-deb` and `dpkg-shlibdeps` from the
Debian tools. GitHub Actions run the checks and package builds on both Linux
architectures and publish artifacts when the tag matches the binary version.

[Apache License 2.0](LICENSE).

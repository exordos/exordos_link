# Exordos Link

Exordos Link is a Linux TCP proxy for private service-to-service links. It
uses TLS 1.3 and X.509-SVIDs from the SPIFFE Workload API to authenticate both
ends. Each listener has an exact allowlist of peer SPIFFE IDs. An outbound
proxy selects a reachable replica and retries another replica when TCP connect
or the client-side TLS handshake fails. Once the client handshake returns, the
connection is pinned to that replica. A later TLS alert or relay failure
closes the connection.

## Why Link for this data path

Link has a single Tokio I/O worker, a fixed copy buffer per direction, and
a TCP-only forwarding path. It reads static JSON and obtains rotated
credentials from the Workload API. This fits direct private links where
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
sudo apt install ./exordos-link_0.0.1_amd64.deb
exordos-link --version
```

On each machine, register the proxy with a local SPIRE Agent. For example,
issue `spiffe://example.test/api` to the outbound proxy and issue
`spiffe://example.test/db` to the inbound proxy on each database replica.
Restrict access to the local outbound listener to processes that may act
with that proxy's identity. TCP loopback is shared by processes in the same
network namespace.

On each destination, run Link with [the inbound config](examples/inbound.json).
It listens on a private interface and sends traffic to one local application
listener. On the client, use [the outbound config](examples/outbound.json).
It listens on loopback and selects one of the private replica addresses.
Replace the example addresses and SPIFFE IDs with values from your deployment.

```sh
SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent.sock exordos-link examples/outbound.json
```

The periodic TCP probe measures reachability of the remote proxy. A deployment
that publishes only ready application replicas must supply its own endpoint
membership, for example the current writable database leader. Open streams
stay on the replica where they were established.

## Configuration and operations

Publish a complete replacement JSON file with an atomic rename and send
`SIGHUP`. Link logs `configuration applied` on success. An invalid update
leaves the last applied configuration in use. An empty `peer_ids` list
denies all peer IDs. An empty outbound `targets` list makes the route
unavailable. These updates apply to new connections. Existing connections
run until they close. Changes to `listen`, `role`, or `max_connections`
require a restart.

The inbound access log records verified peer IDs and reports duration and
byte counts when a session ends. A bounded queue and a dedicated writer
batch output to stderr. A full queue makes affected sessions wait
asynchronously and may drop listener diagnostics. `SIGTERM` and `SIGINT`
stop the proxy and drain queued records. Set the process file descriptor
limit to at least `2 × max_connections + 64` to make the full configured
capacity available.

## Build and test

Build on Linux with the pinned Rust toolchain, a C compiler, CMake, and Make.

```sh
cargo build --locked --release
python3 tests/integration.py target/release/exordos-link /path/to/spire/bin
bash packaging/build.sh target/release/exordos-link dist
```

The integration test starts an isolated SPIRE Server and three agents on
loopback. It exercises authentication, replica failover, live revocation,
and access logging. Packaging uses `dpkg-deb` and `dpkg-shlibdeps` from the
Debian tools. GitHub Actions run the checks and package builds on both Linux
architectures and publish artifacts when the tag matches the binary version.

[Apache License 2.0](LICENSE).

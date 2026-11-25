#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the production binary with a disposable SPIRE server and agents."""

from contextlib import ExitStack, closing
import errno
import fcntl
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
from threading import Thread
import time


DOMAIN = "link.test"
CLIENT = f"spiffe://{DOMAIN}/client"
BACKEND = f"spiffe://{DOMAIN}/backend"


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def spawn(stack, log, *args, env=None):
    with log.open("wb") as output:
        process = subprocess.Popen(args, stdout=output, stderr=output, env=env)
    stack.callback(stop, process)
    return process


def wait_for(description, predicate, process=None):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if predicate():
            return
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"Process exited while waiting for {description}")
        time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for {description}")


def cli(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=5)
    if result.returncode:
        raise RuntimeError(f"SPIRE {args[1]} failed: {result.stderr}")
    return result.stdout


def address():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()


def endpoint(address):
    return f"{address[0]}:{address[1]}"


def start_spire(stack, work, bin_dir):
    server = bin_dir / "spire-server"
    agent = bin_dir / "spire-agent"
    server_sock = work / "server.sock"
    server_dir = work / "server"
    server_dir.mkdir()
    _, port = address()
    server_config = work / "server.conf"
    server_config.write_text(f'''
server {{
    bind_address = "127.0.0.1"
    bind_port = "{port}"
    socket_path = "{server_sock}"
    trust_domain = "{DOMAIN}"
    data_dir = "{server_dir}"
    log_level = "WARN"
}}
plugins {{
    DataStore "sql" {{ plugin_data {{
        database_type = "sqlite3"
        connection_string = "{server_dir}/store.sqlite3"
    }} }}
    NodeAttestor "join_token" {{ plugin_data {{}} }}
    KeyManager "memory" {{ plugin_data {{}} }}
}}
''')
    process = spawn(stack, work / "server.log", server, "run", "-config", server_config)
    wait_for("server socket", server_sock.exists, process)
    bundle = work / "bundle.pem"
    bundle.write_text(cli(server, "bundle", "show", "-socketPath", server_sock, "-format", "pem"))
    sockets = {}
    for name, identity in (("client", CLIENT), ("first", BACKEND), ("second", BACKEND)):
        agent_dir = work / name
        agent_dir.mkdir()
        agent_sock = work / f"{name}.sock"
        token = cli(server, "token", "generate", "-socketPath", server_sock).split()[1]
        parent = f"spiffe://{DOMAIN}/spire/agent/join_token/{token}"
        cli(server, "entry", "create", "-socketPath", server_sock, "-parentID", parent,
            "-spiffeID", identity, "-selector", f"unix:uid:{os.getuid()}")
        config = work / f"{name}.conf"
        config.write_text(f'''
agent {{
    trust_domain = "{DOMAIN}"
    data_dir = "{agent_dir}"
    socket_path = "{agent_sock}"
    server_address = "127.0.0.1"
    server_port = "{port}"
    trust_bundle_path = "{bundle}"
    log_level = "WARN"
}}
plugins {{
    NodeAttestor "join_token" {{ plugin_data {{}} }}
    KeyManager "memory" {{ plugin_data {{}} }}
    WorkloadAttestor "unix" {{ plugin_data {{}} }}
}}
''')
        process = spawn(stack, work / f"{name}-agent.log", agent, "run", "-config", config,
                        "-joinToken", token)
        wait_for(f"{name} workload socket", agent_sock.exists, process)
        sockets[name] = agent_sock
    return sockets


class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            if line == b"ping\n":
                self.wfile.write(self.server.reply)


def echo_server(stack, reply):
    server = stack.enter_context(socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo))
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    server.reply = reply
    thread.start()
    stack.callback(thread.join)
    stack.callback(server.shutdown)
    return server.server_address


def write_config(path, config):
    pending = path.with_suffix(".new")
    pending.write_text(json.dumps(config))
    pending.replace(path)


def start_proxy(stack, directory, binary, name, workload_socket, config):
    path = directory / f"{name}.json"
    log = directory / f"{name}.log"
    write_config(path, config)
    process = spawn(stack, log, binary, path,
                    env={**os.environ, "SPIFFE_ENDPOINT_SOCKET": f"unix://{workload_socket}"})
    addresses = [c["listen"] for c in config["listeners"]]
    wait_for(f"{name} listeners", lambda: all(f" {addr}\n" in log.read_text()
                                             for addr in addresses), process)
    return process, path, log


def reload_proxy(proxy, config):
    process, path, log = proxy
    applied = log.read_text().count("configuration applied")
    write_config(path, config)
    process.send_signal(signal.SIGHUP)
    wait_for("applied configuration", lambda: log.read_text().count("configuration applied") > applied, process)


def request(address):
    with socket.create_connection(address, timeout=2) as client:
        try:
            client.sendall(b"ping\n")
            client.shutdown(socket.SHUT_WR)
            with client.makefile("rb") as response:
                return response.read()
        except OSError as error:
            if error.errno not in (errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN):
                raise
            return b""


def check_reload_with_full_stderr(directory, binary, sock, listen, outbound, config, settings, new_targets):
    settings = {**settings, "listen": endpoint(address())}
    path = directory / "full-stderr.json"
    write_config(path, {"listeners": [settings]})
    read_fd, write_fd = os.pipe()
    with os.fdopen(read_fd, "rb", buffering=0) as reader, os.fdopen(write_fd, "wb", buffering=0) as writer:
        capacity = fcntl.fcntl(writer, fcntl.F_SETPIPE_SZ, 4096)
        process = subprocess.Popen(
            (binary, path), stderr=writer,
            env={**os.environ, "SPIFFE_ENDPOINT_SOCKET": f"unix://{sock}"},
        )
        try:
            assert select.select([reader], [], [], 15)[0] and reader.readline().startswith(b"ready ")
            assert writer.write(b"\n" * capacity) == capacity
            reload_proxy(outbound, {"listeners": [{**config, "targets": [settings["listen"]]}]})
            assert request(listen) == b"one\n"
            assert request(listen) == b"one\n"
            write_config(path, {"listeners": [{**settings, "targets": new_targets}]})
            process.send_signal(signal.SIGHUP)
            wait_for("config reload with blocked stderr", lambda: request(listen) == b"two\n", process)
        finally:
            writer.close()
            drainer = Thread(target=reader.read, daemon=True)
            drainer.start()
            stop(process)
            drainer.join(timeout=3)
    print("PASS: reload and forwarding with a full stderr pipe")


def check_managed_listeners(stack, directory, binary, sockets):
    replicas = []
    for index, name in enumerate(("first", "second")):
        listeners = []
        for port in range(2):
            app = stack.enter_context(ExitStack())
            target = echo_server(app, f"{index}:{port}\n".encode())
            listeners.append((app, {
                "role": "inbound",
                "protocol": "tcp",
                "listen": endpoint(address()),
                "targets": [endpoint(target)],
                "peer_ids": [CLIENT],
                "connect_timeout_ms": 1000,
            }))
        config = {"listeners": [item for _, item in listeners]}
        process = start_proxy(stack, directory, binary, f"managed-{name}", sockets[name], config)
        replicas.append((process, listeners, config))

    addresses = [address(), address()]
    routes = [
        {
            "role": "outbound",
            "listen": endpoint(public),
            "targets": [
                {"address": listeners[port][1]["listen"], "source": "127.0.0.1"}
                for _, listeners, _ in replicas
            ],
            "peer_ids": [BACKEND],
            "connect_timeout_ms": 1000,
        }
        for port, public in enumerate(addresses)
    ]
    client = start_proxy(
        stack, directory, binary, "managed-client", sockets["client"], {"listeners": routes}
    )
    for port, public in enumerate(addresses):
        assert {request(public) for _ in range(4)} == {
            f"0:{port}\n".encode(), f"1:{port}\n".encode()
        }

    replicas[0][1][0][0].close()
    assert {request(addresses[0]) for _ in range(4)} == {b"1:0\n"}
    assert {request(addresses[1]) for _ in range(4)} == {b"0:1\n", b"1:1\n"}
    assert all(proxy[0].poll() is None for proxy, _, _ in replicas)

    for proxy, listeners, _ in replicas:
        reload_proxy(proxy, {"listeners": [listeners[1][1]]})
    assert request(addresses[0]) == b""
    assert {request(addresses[1]) for _ in range(4)} == {b"0:1\n", b"1:1\n"}
    reload_proxy(client, {"listeners": [routes[1]]})
    reload_proxy(client, {"listeners": routes})
    assert request(addresses[0]) == b""

    process, path, log = client
    with socket.socket() as blocked:
        blocked.bind(("127.0.0.1", 0))
        blocked.listen()
        pending = {**routes[1], "listen": endpoint(blocked.getsockname())}
        applied = log.read_text().count("configuration applied")
        write_config(path, {"listeners": [*routes, pending]})
        process.send_signal(signal.SIGHUP)
        wait_for("partial reload", lambda: "retrying unavailable listeners" in log.read_text(), process)
        assert log.read_text().count("configuration applied") == applied
        assert request(addresses[1]) in (b"0:1\n", b"1:1\n")
        later_address = blocked.getsockname()
    wait_for("automatic bind retry", lambda: log.read_text().count("configuration applied") > applied, process)
    assert request(later_address) in (b"0:1\n", b"1:1\n")
    print("PASS: managed listeners, per-endpoint failover, and revocation")


def check_http(stack, directory, binary, sockets):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.headers.get("Upgrade") == "websocket":
                self.send_response(101)
                self.send_header("Connection", "Upgrade")
                self.send_header("Upgrade", "websocket")
                self.end_headers()
                self.wfile.write(self.rfile.read(4))
                self.close_connection = True
                return
            if self.path == "/chunked":
                assert self.headers.get("Transfer-Encoding") == "chunked"
                content = bytearray()
                while size := int(self.rfile.readline(), 16):
                    content.extend(self.rfile.read(size))
                    assert self.rfile.readline() == b"\r\n"
                assert self.rfile.readline() == b"\r\n"
                body = bytes(content)
            else:
                values = self.headers.get_all("x-forwarded-client-cert") or []
                values += self.headers.get_all("x_forwarded_client_cert") or []
                body = json.dumps(values).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    app = stack.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), Handler))
    thread = Thread(target=app.serve_forever, daemon=True)
    thread.start()
    stack.callback(thread.join)
    stack.callback(app.shutdown)
    inbound = {
        "role": "inbound",
        "protocol": "tcp",
        "listen": endpoint(address()),
        "targets": [endpoint(app.server_address)],
        "peer_ids": [CLIENT],
        "connect_timeout_ms": 1000,
    }
    receiver = start_proxy(
        stack, directory, binary, "http-inbound", sockets["first"], {"listeners": [inbound]}
    )
    client = address()
    start_proxy(stack, directory, binary, "http-outbound", sockets["client"], {"listeners": [{
        "role": "outbound",
        "listen": endpoint(client),
        "targets": [inbound["listen"]],
        "peer_ids": [BACKEND],
        "connect_timeout_ms": 1000,
    }]})
    connection = http.client.HTTPConnection(*client, timeout=4)
    stack.callback(connection.close)
    connection.request("GET", "/")
    assert json.loads(connection.getresponse().read()) == []
    reload_proxy(receiver, {"listeners": []})
    connection.request("GET", "/")
    assert json.loads(connection.getresponse().read()) == []
    reload_proxy(receiver, {"listeners": [{**inbound, "protocol": "http"}]})
    try:
        connection.request("GET", "/")
        connection.getresponse().read()
    except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError):
        pass
    else:
        raise AssertionError("Old TCP stream survived a switch to HTTP")
    connection.close()

    def available():
        with closing(http.client.HTTPConnection(*client, timeout=2)) as probe:
            try:
                probe.request("GET", "/")
                response = probe.getresponse()
                return response.status == 200 and b"URI=" in response.read()
            except (OSError, http.client.HTTPException):
                return False

    wait_for("healthy HTTP route", available)

    for index in range(2):
        connection.putrequest("GET", "/")
        connection.putheader("X-Forwarded-Client-Cert", "untrusted")
        connection.putheader("X-Forwarded-Client-Cert", "duplicate")
        connection.putheader("X_Forwarded_Client_Cert", "alternate")
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 200
        values = json.loads(response.read())
        assert len(values) == 1
        assert re.fullmatch(rf"By={BACKEND};Hash=[a-f0-9]{{64}};URI={CLIENT}", values[0])
        if index == 0:
            socket_before = connection.sock
        else:
            assert connection.sock is socket_before

    connection.request("GET", "/chunked", (b"chunked-", b"get"),
                       headers={"Transfer-Encoding": "chunked"}, encode_chunked=True)
    assert connection.getresponse().read() == b"chunked-get"

    connection.request("GET", "/", headers={"Connection": "Upgrade", "Upgrade": "h2c"})
    rejected = connection.getresponse()
    assert rejected.status == 400
    rejected.read()

    with socket.create_connection(client, timeout=4) as upgraded:
        upgraded.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n"
                         b"Upgrade: websocket\r\n\r\n")
        with upgraded.makefile("rb") as stream:
            assert stream.readline().split()[1] == b"101"
            for header in iter(stream.readline, b"\r\n"):
                assert header
            upgraded.sendall(b"ping")
            assert stream.read(4) == b"ping"
    print("PASS: HTTP/1.1 XFCC, keepalive, upgrades and TCP-to-HTTP cutover")


def run(stack, directory, binary, spire_bin):
    sockets = start_spire(stack, directory, spire_bin)
    check_managed_listeners(stack, directory, binary, sockets)
    check_http(stack, directory, binary, sockets)
    inbound = []
    for name, reply in (("first", b"one\n"), ("second", b"two\n")):
        config = {
            "role": "inbound",
            "protocol": "tcp",
            "listen": endpoint(address()),
            "targets": [endpoint(echo_server(stack, reply))],
            "peer_ids": [CLIENT],
            "connect_timeout_ms": 1000,
        }
        proxy = start_proxy(stack, directory, binary, name, sockets[name], {"listeners": [config]})
        inbound.append((proxy, config))

    listen = address()
    config = {
        "role": "outbound",
        "listen": endpoint(listen),
        "targets": [settings["listen"] for _, settings in inbound],
        "peer_ids": [BACKEND],
        "connect_timeout_ms": 1000,
    }
    outbound = start_proxy(stack, directory, binary, "outbound", sockets["client"], {"listeners": [config]})
    assert {request(listen) for _ in range(4)} == {b"one\n", b"two\n"}
    print("PASS: SPIFFE-authenticated mTLS and replica selection")

    reload_proxy(outbound, {"listeners": [{**config, "peer_ids": [f"spiffe://{DOMAIN}/unexpected"]}]})
    assert request(listen) == b""
    reload_proxy(outbound, {"listeners": [{**config, "targets": []}]})
    assert request(listen) == b""
    reload_proxy(outbound, {"listeners": [config]})

    for proxy, settings in inbound:
        reload_proxy(proxy, {"listeners": [{**settings, "peer_ids": []}]})
    assert request(listen) == b""
    for proxy, settings in inbound:
        reload_proxy(proxy, {"listeners": [settings]})
    assert {request(listen) for _ in range(4)} == {b"one\n", b"two\n"}
    print("PASS: wrong identity, zero replicas, and revocation of the last grant")

    stop(inbound[0][0][0])
    assert {request(listen) for _ in range(4)} == {b"two\n"}
    log = inbound[1][0][2]
    wait_for("session access log", lambda: any(
        line.startswith(f"RESP: {CLIENT} ") and " received=5 sent=4 " in line
        for line in log.read_text().splitlines()
    ))
    print("PASS: replica failover, TCP half-close, and access logging")
    check_reload_with_full_stderr(directory, binary, sockets["first"], listen, outbound,
                                  config, inbound[0][1], inbound[1][1]["targets"])


if __name__ == "__main__":
    binary, spire_bin = (Path(arg).resolve(strict=True) for arg in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="exordos-link-", dir="/tmp") as name:
        directory = Path(name)
        try:
            with ExitStack() as stack:
                run(stack, directory, binary, spire_bin)
        except Exception:
            for log in sorted(directory.glob("*.log")):
                print(f"--- {log.name} ---\n{log.read_text()}", file=sys.stderr)
            raise

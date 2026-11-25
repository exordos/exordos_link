#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise gRPC metadata, multiplexing and trailers with the released proxy."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
import re
import sys
import tempfile
from threading import Event

import grpc

from integration import BACKEND, CLIENT, address, endpoint, start_proxy, start_spire


def check_metadata(context):
    headers = [value for key, value in context.invocation_metadata()
               if key == "x-forwarded-client-cert"]
    assert len(headers) == 1
    assert re.fullmatch(rf"By={BACKEND};Hash=[a-f0-9]{{64}};URI={CLIENT}", headers[0])
    assert ("x-request-id", "mesh-test") in context.invocation_metadata()
    context.set_trailing_metadata((("x-mesh-test", "complete"),))


def run(stack, directory, binary, spire_bin):
    sockets = start_spire(stack, directory, spire_bin)
    server = grpc.server(stack.enter_context(ThreadPoolExecutor(max_workers=4)))

    def unary(payload, context):
        check_metadata(context)
        if payload == b"error":
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "test status")
        return payload

    def stream(payloads, context):
        check_metadata(context)
        yield from payloads

    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(
        "test.Mesh", {
            "Unary": grpc.unary_unary_rpc_method_handler(unary),
            "Stream": grpc.stream_stream_rpc_method_handler(stream),
        }),))
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    stack.callback(lambda: server.stop(0).wait())
    transport = endpoint(address())
    start_proxy(stack, directory, binary, "receiver", sockets["first"], {"listeners": [{
        "role": "inbound",
        "listen": transport,
        "targets": [f"127.0.0.1:{port}"],
        "peer_ids": [CLIENT],
        "protocol": "http",
        "connect_timeout_ms": 1000,
    }]})
    local = endpoint(address())
    start_proxy(stack, directory, binary, "sender", sockets["client"], {"listeners": [{
        "role": "outbound",
        "listen": local,
        "targets": [transport],
        "peer_ids": [BACKEND],
        "connect_timeout_ms": 1000,
    }]})
    metadata = (("x-forwarded-client-cert", "untrusted"), ("x-request-id", "mesh-test"))
    ready = Event()

    def messages():
        yield b"first"
        assert ready.wait(8)
        yield b"second"

    with grpc.insecure_channel(local) as channel:
        call = channel.unary_unary("/test.Mesh/Unary")
        streaming = channel.stream_stream("/test.Mesh/Stream")(
            messages(), metadata=metadata, timeout=10
        )
        try:
            assert next(streaming) == b"first"
            payload, rpc = call.with_call(b"unary", metadata=metadata, timeout=5)
            assert payload == b"unary"
            assert dict(rpc.trailing_metadata()) == {"x-mesh-test": "complete"}
        finally:
            ready.set()
        assert list(streaming) == [b"second"]
        assert dict(streaming.trailing_metadata()) == {"x-mesh-test": "complete"}
        try:
            call(b"error", metadata=metadata, timeout=5)
        except grpc.RpcError as error:
            assert error.code() == grpc.StatusCode.FAILED_PRECONDITION
            assert error.details() == "test status"
        else:
            raise AssertionError("Expected gRPC error status")
    print("PASS: gRPC XFCC, concurrent unary and bidirectional RPCs, trailers and status")


if __name__ == "__main__":
    binary, spire_bin = (Path(arg).resolve(strict=True) for arg in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="exordos-link-grpc-", dir="/tmp") as name:
        directory = Path(name)
        try:
            with ExitStack() as stack:
                run(stack, directory, binary, spire_bin)
        except Exception:
            for log in sorted(directory.glob("*.log")):
                print(f"--- {log.name} ---\n{log.read_text()}", file=sys.stderr)
            raise

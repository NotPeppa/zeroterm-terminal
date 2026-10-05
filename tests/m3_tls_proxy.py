#!/usr/bin/env python3
"""Loopback-only TLS tunnel for isolated M3/native HTTPS acceptance, not deployment.

No credentials, certificate bypass, or third-party dependencies. Optional fixture
proxy headers use one HTTP request per TLS connection (or a WebSocket upgrade).
Use an explicitly trusted fixture CA and a SAN certificate; native clients must
still validate TLS. Each direction holds at most one 32 KiB application chunk.
"""
import argparse
import asyncio
import contextlib
import ipaddress
import ssl

CHUNK_BYTES = 32 * 1024
STALL_SECONDS = 30
MAX_SECONDS = 8 * 60 * 60


async def pump(reader, writer):
    while True:
        data = await reader.read(CHUNK_BYTES)
        if not data:
            return
        writer.write(data)
        await asyncio.wait_for(writer.drain(), STALL_SECONDS)


async def proxy_headers(reader, writer, peer):
    header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
    if len(header) > CHUNK_BYTES:
        raise ValueError("fixture header too large")
    lines = header[:-4].split(b"\r\n")
    request = lines[0].split(b" ")
    if len(request) != 3 or not request[1].startswith(b"/") or request[2] != b"HTTP/1.1":
        raise ValueError("fixture accepts only origin-form HTTP/1.1")
    fields = []
    websocket = False
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator or not name or line[:1] in (b" ", b"\t"):
            raise ValueError("invalid fixture header")
        name = name.lower()
        if name == b"upgrade":
            websocket = value.strip().lower() == b"websocket"
        if name not in (b"forwarded", b"x-forwarded-for", b"x-forwarded-proto", b"connection", b"proxy-connection"):
            fields.append(line)
    fields.extend([b"X-Forwarded-For: " + str(ipaddress.ip_address(peer)).encode("ascii"),
                   b"X-Forwarded-Proto: https", b"Connection: " + (b"Upgrade" if websocket else b"close")])
    writer.write(b"\r\n".join([lines[0], *fields]) + b"\r\n\r\n")
    await asyncio.wait_for(writer.drain(), STALL_SECONDS)


async def bridge(reader, writer, upstream_port, trusted_proxy_headers=False):
    upstream_writer = None
    tasks = []
    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", upstream_port, limit=CHUNK_BYTES), 5
        )
        # StreamReader and each transport's output buffer have explicit bounds.
        for stream in (writer, upstream_writer):
            stream.transport.set_write_buffer_limits(high=CHUNK_BYTES, low=CHUNK_BYTES // 2)
        if trusted_proxy_headers:
            await proxy_headers(reader, upstream_writer, writer.get_extra_info("peername")[0])
        tasks = [
            asyncio.create_task(pump(reader, upstream_writer)),
            asyncio.create_task(pump(upstream_reader, writer)),
        ]
        done, _ = await asyncio.wait(tasks, timeout=MAX_SECONDS, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        # Never print request bytes, headers, URL, Cookie, tokens, or certificates.
        pass
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for stream in (upstream_writer, writer):
            if stream is not None:
                stream.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError, ssl.SSLError):
                    await asyncio.wait_for(stream.wait_closed(), 2)


async def serve(args):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.certificate, args.key)
    clients = set()

    async def accepted(reader, writer):
        task = asyncio.current_task()
        clients.add(task)
        try:
            await bridge(reader, writer, args.upstream_port, args.trusted_proxy_headers)
        finally:
            clients.discard(task)

    server = await asyncio.start_server(
        accepted, args.listen, args.port, ssl=context, limit=CHUNK_BYTES,
        ssl_handshake_timeout=5, ssl_shutdown_timeout=2,
    )
    try:
        async with server:
            await server.serve_forever()
    finally:
        for task in list(clients):
            task.cancel()
        if clients:
            await asyncio.gather(*list(clients), return_exceptions=True)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--trusted-proxy-headers", action="store_true",
                        help="overwrite forwarding headers; close each non-WebSocket HTTP request")
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    try:
        address = ipaddress.ip_address(args.listen)
    except ValueError:
        parser.error("listen must be an explicit loopback IP address")
    if not address.is_loopback:
        parser.error("this acceptance fixture cannot listen publicly")
    if not all(1 <= value <= 65535 for value in (args.port, args.upstream_port)):
        parser.error("port must be in 1..65535")
    if args.port == args.upstream_port:
        parser.error("TLS and upstream ports must differ")
    return args


if __name__ == "__main__":
    try:
        asyncio.run(serve(parse_args()))
    except KeyboardInterrupt:
        pass

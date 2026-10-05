"""Bounds and teardown tests for the isolated HTTPS/native acceptance fixture."""
import asyncio
import unittest
from m3_tls_proxy import CHUNK_BYTES, bridge, pump, proxy_headers


class Reader:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.sizes = []

    async def read(self, size):
        self.sizes.append(size)
        return next(self.chunks, b"")


class Writer:
    def __init__(self):
        self.chunks = []
        self.drains = 0

    def write(self, data):
        self.chunks.append(data)

    async def drain(self):
        self.drains += 1


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def test_raw_chunks_and_backpressure(self):
        chunks = [b"\x00\xff\xc3", b"\xa9\r\n", b"x" * CHUNK_BYTES]
        reader = Reader(chunks)
        writer = Writer()
        await pump(reader, writer)
        self.assertEqual(writer.chunks, chunks)
        self.assertEqual(writer.drains, len(chunks))
        self.assertEqual(reader.sizes, [CHUNK_BYTES] * (len(chunks) + 1))

    async def test_proxy_headers_overwrite_identity_and_close_http(self):
        reader = asyncio.StreamReader(limit=CHUNK_BYTES)
        reader.feed_data(b"GET /api/v1/info HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.9\r\nX-Forwarded-Proto: http\r\nForwarded: forged\r\nConnection: keep-alive\r\n\r\n")
        writer = Writer()
        await proxy_headers(reader, writer, "127.0.0.1")
        result = b"".join(writer.chunks)
        self.assertNotIn(b"203.0.113.9", result)
        self.assertNotIn(b"forged", result)
        self.assertIn(b"X-Forwarded-For: 127.0.0.1\r\n", result)
        self.assertIn(b"X-Forwarded-Proto: https\r\n", result)
        self.assertIn(b"Connection: close\r\n", result)

    async def test_proxy_headers_preserve_websocket_upgrade(self):
        reader = asyncio.StreamReader(limit=CHUNK_BYTES)
        reader.feed_data(b"GET /api/v1/sessions/id/stream HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: bastion.v1\r\n\r\n")
        writer = Writer()
        await proxy_headers(reader, writer, "::1")
        result = b"".join(writer.chunks)
        self.assertIn(b"Upgrade: websocket", result)
        self.assertIn(b"Connection: Upgrade", result)
        self.assertIn(b"X-Forwarded-For: ::1", result)

    async def test_bridge_drains_upstream_response_and_joins(self):
        async def echo(reader, writer):
            try:
                while data := await reader.read(CHUNK_BYTES):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        upstream_port = upstream.sockets[0].getsockname()[1]
        proxy = await asyncio.start_server(
            lambda r, w: bridge(r, w, upstream_port), "127.0.0.1", 0
        )
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", proxy.sockets[0].getsockname()[1]
            )
            data = b"raw\x00\xff" * 10_000
            writer.write(data)
            await writer.drain()
            result = await asyncio.wait_for(reader.readexactly(len(data)), 3)
            self.assertEqual(result, data)
            writer.close()
            await writer.wait_closed()
        finally:
            proxy.close()
            upstream.close()
            await proxy.wait_closed()
            await upstream.wait_closed()


if __name__ == "__main__":
    unittest.main()

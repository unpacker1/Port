#!/usr/bin/env python3
"""Tests for upstream v2.2.16's retired ws2tcp bridge.

Tests an actual local WebSocket -> TCP byte echo, not a Metin2 GAME login.
No external network, no game engine, no ports published beyond 127.0.0.1.
"""
import argparse
from contextlib import contextmanager
from io import BytesIO
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import sys
import threading
from unittest import TestCase, TestLoader, TextTestRunner, mock

BRIDGE = None


def client_frame(payload, opcode=2, fin=True, masked=True):
    """Make RFC 6455 client frame with fixed test masking key."""
    key = b"test"
    n = len(payload)
    head = bytes([(0x80 if fin else 0) | opcode,
                  (0x80 if masked else 0) | (n if n < 126 else (126 if n < 65536 else 127))])
    if n >= 65536:
        head += struct.pack("!Q", n)
    elif n >= 126:
        head += struct.pack("!H", n)
    if masked:
        payload = bytes(c ^ key[i % 4] for i, c in enumerate(payload))
        head += key
    return head + payload


@contextmanager
def local_http(handler):
    server = BRIDGE.Server(("127.0.0.1", 0), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=5)


class BridgeContractTests(TestCase):
    def test_client_frame_masked_payload_survives(self):
        for length in (0, 1, 125, 126, 1024, 65536):
            raw = b"\x00\xfeA" * (length // 3) + b"B" * (length % 3)
            result = BRIDGE.read_frame(BytesIO(client_frame(raw)))
            self.assertEqual(result, (True, 2, raw))

    def test_rejects_unmasked_and_forbidden_control_frames(self):
        with self.assertRaises(BRIDGE.ProtocolError):
            BRIDGE.read_frame(BytesIO(client_frame(b"abc", masked=False)))
        with self.assertRaises(BRIDGE.ProtocolError):
            BRIDGE.read_frame(BytesIO(client_frame(b"abc", opcode=9, fin=False)))
        with mock.patch.object(BRIDGE, "MAX_FRAME", 2):
            with self.assertRaises(BRIDGE.ProtocolError):
                BRIDGE.read_frame(BytesIO(client_frame(b"abc")))

    def test_forbidden_ports_override_cannot_expose_db(self):
        with mock.patch.dict(os.environ, {"M2_BRIDGE_PORTS":
                                          "11000,13000,12000,14000,14009,15000,99999"}):
            self.assertEqual(BRIDGE.computed_ports(), {11000, 13000})
        self.assertTrue({12000, 15000, 14000, 14009}.issubset(BRIDGE.FORBIDDEN_PORTS))

    def test_url_must_be_valid_and_port_allowlisted(self):
        with mock.patch.object(BRIDGE, "ALLOWED_PORTS", {11000, 13000}):
            for invalid in ("/to/example.test:15000", "/to/example.test:12000",
                            "/to/example.test:0", "/to/example.test:99999",
                            "/to/example.test", "/to/invalid/path:11000",
                            "/to/evil%2fsite:11000", "/to/a:bad", "/any"):
                self.assertIsNone(BRIDGE.Handler.resolve_target(None, invalid)[1], invalid)
            self.assertEqual(
                BRIDGE.Handler.resolve_target(None, "/to/example.test%3A11000"),
                ("example.test", 11000))

    def test_ping_ports_health_without_real_game(self):
        from urllib.request import urlopen
        from urllib.error import HTTPError
        with local_http(BRIDGE.Handler) as server:
            base = "http://127.0.0.1:%d" % server.server_address[1]
            with urlopen(base + "/ping", timeout=5) as r:
                self.assertTrue(r.read().startswith(b"m2-ws2tcp"))
                self.assertEqual(r.getheader("Access-Control-Allow-Origin"), "*")
            with urlopen(base + "/ports", timeout=5) as r:
                info = json.loads(r.read())
                self.assertIn("ports", info)
                self.assertNotIn(15000, info["ports"])
            with urlopen(base + "/health", timeout=5) as r:
                self.assertEqual(r.read(), b"ok\n")
            with self.assertRaises(HTTPError) as err:
                urlopen(base + "/private", timeout=5)
            self.assertEqual(err.exception.code, 404)

    def test_actual_ws_to_tcp_echo_with_fake_backend(self):
        """Real WS upgrade, masked binary frame, TCP socket, binary response."""
        target = socket.socket()
        target.bind(("127.0.0.1", 0))
        target.listen(1)
        target.settimeout(8)
        port = target.getsockname()[1]
        errors = []

        def echo():
            try:
                conn, _ = target.accept()
                with conn:
                    conn.settimeout(8)
                    received = conn.recv(8192)
                    if received:
                        conn.sendall(received)
            except Exception as e:
                errors.append(str(e))
            finally:
                target.close()

        worker = threading.Thread(target=echo, daemon=True)
        worker.start()
        with mock.patch.object(BRIDGE, "TARGET_HOST", "127.0.0.1"), \
             mock.patch.object(BRIDGE, "ALLOWED_PORTS", {port}):
            with local_http(BRIDGE.Handler) as server:
                sock = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=6)
                sock.settimeout(6)
                try:
                    request = (
                        "GET /to/does-not-exist.invalid:%d HTTP/1.1\r\n"
                        "Host: 127.0.0.1\r\n"
                        "Connection: Upgrade\r\n"
                        "Upgrade: websocket\r\n"
                        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                        "Sec-WebSocket-Version: 13\r\n"
                        "\r\n"
                    ) % port
                    sock.sendall(request.encode("ascii"))
                    stream = sock.makefile("rb")
                    self.assertIn(b"101 Switching Protocols", stream.readline())
                    while stream.readline().strip():
                        pass
                    payload = b"metin2-bridge-bytes\x00\xff"
                    sock.sendall(client_frame(payload))
                    start = stream.read(2)
                    self.assertEqual(len(start), 2)
                    length = start[1] & 0x7F
                    self.assertEqual(start[0] & 0x0F, 2)
                    self.assertFalse(start[1] & 0x80)
                    if length == 126:
                        length = struct.unpack("!H", stream.read(2))[0]
                    self.assertEqual(stream.read(length), payload)
                finally:
                    sock.close()
        worker.join(timeout=8)
        self.assertFalse(worker.is_alive(), "fake backend thread did not finish")
        self.assertEqual(errors, [])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--report-dir", default=Path("reports"), type=Path)
    args = parser.parse_args()
    src = args.upstream.resolve() / "linux-port/docker/wsbridge/bin/ws2tcp.py"
    if not src.is_file():
        parser.error("upstream v2.2.16 bridge was not found: " + str(src))
    spec = importlib.util.spec_from_file_location("m2_legacy_ws2tcp", src)
    global BRIDGE
    BRIDGE = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(BRIDGE)
    suite = TestLoader().loadTestsFromTestCase(BridgeContractTests)
    result = TextTestRunner(verbosity=2).run(suite)
    args.report_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "source": "TieruYT/metin2-playerbots v2.2.16, linux-port/docker/wsbridge/bin/ws2tcp.py",
        "scope": "local loopback with simulated TCP game server only; NO real Metin2 protocol",
        "ran": result.testsRun, "successful": result.wasSuccessful(),
        "failures": [name.id() for name, _ in result.failures],
        "errors": [name.id() for name, _ in result.errors]
    }
    (args.report_dir / "wsbridge-loopback-tests.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())

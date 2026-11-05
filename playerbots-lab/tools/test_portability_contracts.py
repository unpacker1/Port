#!/usr/bin/env python3
"""Pinned-source regression checks. No game engine, network or SQL required."""
import argparse
from pathlib import Path
import unittest

ROOT = None

class PortabilityContracts(unittest.TestCase):
    def test_i386_image_cannot_be_called_arm64(self):
        source = (ROOT / "linux-port-mt2009/docker/game/Dockerfile").read_text()
        for marker in ("Linux/i386", "gcc -m32", "/usr/lib/i386-linux-gnu/libssl.a",
                       "ELF 32-bit LSB .* Intel 80386", 'CXX="g++ -m32"'):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

    def test_websocket_fixed_target_and_denied_ports(self):
        source = (ROOT / "linux-port/docker/wsbridge/bin/ws2tcp.py").read_text()
        for marker in ('TARGET_HOST = env("M2_BRIDGE_TARGET_HOST", "game")',
                       'socket.create_connection((TARGET_HOST, port)',
                       'FORBIDDEN_PORTS = {12000, 15000} | set(range(14000, 14010))',
                       'return {p for p in wanted if 1 <= p <= 65535} - FORBIDDEN_PORTS'):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

    def test_wasm_host_patch_requires_existing_shim(self):
        source = (ROOT / "wasm-port/scripts/fix_ws_proxy_host.py").read_text()
        for marker in ("serverHost=", "serverTLS=1", "already patched",
                       "the TLS block was not found unchanged", "scheme + HOST"):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path, required=True)
    args = parser.parse_args()
    ROOT = args.upstream.resolve()
    if not (ROOT / "artifacts.json").is_file():
        parser.error("pinned upstream submodule missing")
    unittest.main(argv=["portability-contracts"], verbosity=2)

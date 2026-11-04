#!/usr/bin/env python3
"""Reproducible read-only compatibility inventory for Playerbots.

Separate observation (facts) from inference (portability is unproven).
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

def has(root, suffix):
    return (root / suffix).is_file()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--current-manifest", type=Path, default=None)
    parser.add_argument("--report-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()
    root = args.upstream.resolve()
    report = args.report_dir.resolve()
    report.mkdir(parents=True, exist_ok=True)
    if not (root / "artifacts.json").is_file():
        print("Missing pinned upstream source/submodule: artifacts.json", file=sys.stderr)
        return 2
    artifacts = json.loads((root / "artifacts.json").read_text(encoding="utf-8"))
    docker = (root / "linux-port-mt2009/docker/game/Dockerfile").read_text(encoding="utf-8")
    bridge_path = "linux-port/docker/wsbridge/bin/ws2tcp.py"
    bridge = (root / bridge_path).read_text(encoding="utf-8") if has(root, bridge_path) else ""
    files = [p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]
    tests = sorted(p.name for p in (root / "tests").glob("playerbot_*_test.cpp"))
    headers = list((root / "linux-port/overlays/playerbot/src/game/src").glob("playerbot_*.h"))
    facts = {
        "cpp_bot_manager_present": has(root, "linux-port/overlays/playerbot/src/game/src/playerbot_manager.cpp"),
        "cpp_standalone_tests_at_least_14": len(tests) >= 14,
        "mt2009_dockerfile_targets_i386_m32": "Linux/i386" in docker and "-m32" in docker,
        "legacy_webclient_not_supported": "does not distribute, fetch, update, or support the browser client" in artifacts.get("_engine", ""),
        "legacy_webclient_url_absent": not artifacts.get("engine_url"),
        "server_baseline_is_not_vendored": not has(root, "linux-port-mt2009/docker/game/src/server/game/src/main.cpp"),
        "baseline_url_unset": not artifacts.get("src_server_url"),
        "legacy_websocket_to_tcp_bridge_source_present": has(root, bridge_path),
        "legacy_bridge_fixed_game_target": "socket.create_connection((TARGET_HOST, port)" in bridge,
        "legacy_bridge_db_p2p_ports_forbidden": "FORBIDDEN_PORTS = {12000, 15000}" in bridge,
        "legacy_webclient_package_tool_present": has(root, "linux-port/package-web-client.sh"),
    }
    latest = {}
    if args.current_manifest is not None and args.current_manifest.is_file():
        latest = json.loads(args.current_manifest.read_text(encoding="utf-8"))
        facts["current_client_windows_x64"] = (
            latest.get("client", {}).get("architecture") == "x64"
            and latest.get("client", {}).get("requiresClientExe") is True
        )
    try:
        revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        revision = "unknown"
    payload = {
        "project": "TieruYT/metin2-playerbots",
        "source_tag": "v2.2.16",
        "source_commit": revision,
        "current_server_version": latest.get("server", {}).get("version"),
        "current_client_version": latest.get("client", {}).get("version"),
        "inventory": {"files": len(files), "policy_cpp_test_targets": len(tests),
                      "playerbot_headers": len(headers), "selected_cpp_tests": tests},
        "source_evidence": facts,
        "build_status": "NOT_TESTED_full_GAME_or_DB_or_AUTH",
        "browser_status": "LOOPBACK_WS_TO_FAKE_TCP_ONLY; NOT_TESTED_live_WebClient",
        "termux_status": "NOT_TESTED_local_Android",
        "interpretation": "Isolated ARM64 unit tests do not prove complete engine ARM64 support."
    }
    (report / "compatibility-audit.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                                                       encoding="utf-8")
    lines = [
        "# Playerbots source / platform audit",
        "",
        "Source: TieruYT/metin2-playerbots `v2.2.16`",
        "",
        "| Source fact | Observed |",
        "|---|---|",
    ]
    lines += ["| " + key + " | " + ("YES" if value else "NO") + " |"
              for key, value in facts.items()]
    lines += ["", "**Limit:** This is static analysis; no full GAME build, Termux runtime or WebClient login.",
              "", "Unit tests in other CI jobs provide separate proof.", ""]
    (report / "compatibility-audit.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if all(facts.values()) else 1

if __name__ == "__main__":
    sys.exit(main())

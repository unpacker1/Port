#!/usr/bin/env python3
"""Compile and execute upstream's 14 self-contained C++ policy tests.

Only standalone unit tests. Does not build or run Metin2 GAME.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

TEST_NAMES = (
    "channel_rules", "empire_rules", "event_rules", "lure_order_rules",
    "offline_policy", "offline_scan", "persona_rules", "progression_needs",
    "shop_name_rules", "stall_rules", "truce_rules", "world_rules",
    "arrange_rules", "conversation",
)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()
    root = args.upstream.resolve()
    out = args.report_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    include = root / "linux-port/overlays/playerbot/src/game/src"
    with tempfile.TemporaryDirectory(prefix="playerbots-tests-") as td:
        for name in TEST_NAMES:
            src = root / "tests" / ("playerbot_" + name + "_test.cpp")
            exe = Path(td) / name
            commands = [
                ["g++", "-std=c++17", "-O0", "-Wall", "-Wextra", "-I", str(include),
                 str(src), "-o", str(exe)],
                [str(exe)],
            ]
            result = {"name": name, "architecture": platform.machine(),
                      "compile": "not_run", "run": "not_run", "details": ""}
            for index, command in enumerate(commands):
                phase = "compile" if index == 0 else "run"
                try:
                    p = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, timeout=120, check=False)
                    result[phase] = "pass" if p.returncode == 0 else "fail"
                    result["details"] += p.stdout[-8000:]
                    if p.returncode != 0:
                        break
                except (OSError, subprocess.TimeoutExpired) as error:
                    result[phase] = "fail"
                    result["details"] += str(error)
                    break
            rows.append(result)
            print(("PASS" if result["run"] == "pass" else "FAIL") + " " + name, flush=True)
            if result["run"] != "pass":
                print(result["details"][-2000:], flush=True)
    passed = sum(x["run"] == "pass" for x in rows)
    result = {"source": "TieruYT/metin2-playerbots v2.2.16",
              "scope": "isolated C++ unit tests, not full GAME build",
              "architecture": platform.machine(), "passed": passed,
              "failed": len(rows) - passed, "total": len(rows), "tests": rows}
    dest = out / ("cpp-tests-" + platform.machine() + ".json")
    dest.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("RESULT", passed, "/", len(rows), "report:", dest, flush=True)
    return 0 if passed == len(rows) else 1

if __name__ == "__main__":
    sys.exit(main())

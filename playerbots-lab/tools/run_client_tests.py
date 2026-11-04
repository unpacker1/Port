#!/usr/bin/env python3
"""Run upstream's Python 3 client mock tests and shell migrator unit test.

Does not run the native Windows client, MariaDB or game server.
"""
import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys

PYTHON_TESTS = (
    "playerbot_status_tail_test.py",
    "uiautohunt_test.py",
    "autologin_test.py",
    "coop_serverinfo_test.py",
    "client_taskbar_test.py",
)
SHELL_TESTS = ("playerbot_migrate_rates_test.sh",)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()
    root = args.upstream.resolve()
    report = args.report_dir.resolve()
    report.mkdir(parents=True, exist_ok=True)
    rows = []
    for name in PYTHON_TESTS + SHELL_TESTS:
        command = ([sys.executable] if name.endswith(".py") else ["sh"]) + [str(root / "tests" / name)]
        try:
            p = subprocess.run(command, cwd=root, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, timeout=120)
            status = "pass" if p.returncode == 0 else "fail"
            output = p.stdout[-12000:]
        except (OSError, subprocess.TimeoutExpired) as error:
            status, output = "fail", str(error)
        rows.append({"test": name, "status": status, "output": output})
        print(status.upper(), name, flush=True)
        if status == "fail":
            print(output[-2400:], flush=True)
    successes = sum(x["status"] == "pass" for x in rows)
    data = {"source": "TieruYT/metin2-playerbots v2.2.16",
            "scope": "Python client mock tests and shell migrator mock only",
            "host": platform.platform(), "passed": successes,
            "failed": len(rows) - successes, "tests": rows}
    (report / "client-mock-tests.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0 if successes == len(rows) else 1

if __name__ == "__main__":
    sys.exit(main())

"""Scan real, published MCP servers with the installed ``mcpguard`` command.

Needs Node.js (``npx``) and network access the first time each package is fetched.

    python benchmarks/real_servers.py                 # print the table
    python benchmarks/real_servers.py --json out.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

PACKAGES = {
    "server-everything": "@modelcontextprotocol/server-everything",
    "server-memory": "@modelcontextprotocol/server-memory",
    "server-sequential-thinking": "@modelcontextprotocol/server-sequential-thinking",
    "server-filesystem": "@modelcontextprotocol/server-filesystem {tmp}",
}


def scan(command: str) -> dict[str, Any]:
    started = time.perf_counter()
    done = subprocess.run(
        ["mcpguard", "scan", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
    )
    seconds = round(time.perf_counter() - started, 1)
    report = json.loads(done.stdout[done.stdout.index("{") :])
    checks = report["checks"]
    rules = [c for c in checks if ":" in c["name"]]
    return {
        "server": report["server"]["name"],
        "protocol_version": report["protocol_version"],
        "exit_code": done.returncode,
        "passed": report["passed"],
        "seconds": seconds,
        "errors": [c["message"] for c in rules if not c["passed"]],
        "dangerous_names": sorted(
            c["message"].split(":")[0] for c in rules if "MCP05" in c["name"]
        ),
        "unbounded_schemas": sum(1 for c in rules if "unbounded-input" in c["name"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    rows = {}
    with tempfile.TemporaryDirectory() as tmp:
        for label, package in PACKAGES.items():
            rows[label] = scan(f"npx -y {package.format(tmp=tmp)}")
    print("| Server | Passed | Scan time | Tools flagged as risky by name | Errors |")
    print("|---|:-:|---:|---|---|")
    for label, row in rows.items():
        risky = ", ".join(f"`{n}`" for n in row["dangerous_names"]) or "none"
        errors = "; ".join(row["errors"]) or "none"
        mark = "yes" if row["passed"] else "no"
        print(f"| {label} | {mark} | {row['seconds']} s | {risky} | {errors} |")
    if args.json:
        args.json.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

"""Run reproducible black-box comparisons without invoking a shell."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--config", type=Path, default=Path("benchmarks/tools.json"))
    parser.add_argument("--output", type=Path, default=Path("benchmark-results.json"))
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    config: dict[str, Any] = json.loads(args.config.read_text(encoding="utf-8"))
    results = []
    for tool in config["tools"]:
        command = [
            str(part).replace("{target}", args.target) for part in tool["command"]
        ]
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=args.timeout,
                check=False,
            )
            results.append(
                {
                    "name": tool["name"],
                    "command": command,
                    "exit_code": completed.returncode,
                    "duration_seconds": round(time.perf_counter() - started, 3),
                    "stdout_bytes": len(completed.stdout.encode()),
                    "stderr_bytes": len(completed.stderr.encode()),
                }
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            results.append(
                {
                    "name": tool["name"],
                    "command": command,
                    "error": type(exc).__name__,
                    "duration_seconds": round(time.perf_counter() - started, 3),
                }
            )
    args.output.write_text(json.dumps({"results": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()

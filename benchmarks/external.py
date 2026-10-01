"""Evaluate the static rules on data MCPGuard's author did not write.

Poisoned side: MCPTox (Wang et al., AAAI 2026), poisoned tool descriptions
written for 45 real MCP servers. Clone https://github.com/zhiqiangwang4/MCPTox-Benchmark
and pass its ``pure_tool.json``. The data has no license, so it is not copied here.

Benign side: real tool definitions collected with ``collect_tools.py``.

The rules were written while looking only at the "dev" half of the servers (every
other server in sorted order). The "held-out" half was run once, after the rules
were frozen, and is the number to quote.

    python benchmarks/external.py pure_tool.json real_tools.json --json out.json
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from mcpguard.security import SecurityFinding, scan_tool_definitions

STRICT = {"type": "object", "properties": {}, "additionalProperties": False}
NOISE = {"unbounded-input", "dangerous-tool-name"}


def _verdict(findings: list[SecurityFinding]) -> tuple[bool, bool]:
    """(blocked, flagged): an error finding, or any finding about the description."""
    blocked = any(f.severity == "error" for f in findings)
    flagged = blocked or any(f.rule not in NOISE for f in findings)
    return blocked, flagged


def _split(servers: set[str]) -> tuple[set[str], set[str]]:
    ordered = sorted(servers)
    dev = set(ordered[::2])
    return dev, set(ordered) - dev


def _summary(hits: list[tuple[bool, bool]]) -> dict[str, Any]:
    total = len(hits)
    blocked = sum(b for b, _ in hits)
    flagged = sum(f for _, f in hits)
    return {
        "cases": total,
        "blocked": blocked,
        "blocked_rate": round(blocked / total, 3) if total else 0.0,
        "flagged": flagged,
        "flagged_rate": round(flagged / total, 3) if total else 0.0,
    }


def evaluate_poisoned(path: Path) -> dict[str, Any]:
    cases: dict[str, Any] = {}
    for part in json.loads(path.read_text(encoding="utf-8")):
        cases.update(part)
    dev, held_out = _split({c["server_name"] for c in cases.values()})
    groups: dict[str, list[tuple[bool, bool]]] = defaultdict(list)
    by_risk: dict[str, list[tuple[bool, bool]]] = defaultdict(list)
    for case in cases.values():
        tool = SimpleNamespace(
            name=case["tool_name"], description=case["tool_content"], inputSchema=STRICT
        )
        verdict = _verdict(scan_tool_definitions([tool]))
        side = "dev" if case["server_name"] in dev else "held_out"
        groups[side].append(verdict)
        groups["all"].append(verdict)
        if side == "held_out":
            by_risk[case["security risk"]].append(verdict)
    return {
        **{side: _summary(hits) for side, hits in groups.items()},
        "held_out_by_risk": {k: _summary(v) for k, v in sorted(by_risk.items())},
    }


def evaluate_benign(path: Path) -> dict[str, Any]:
    tools = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []
    warnings: list[str] = []
    for tool in tools:
        findings = scan_tool_definitions(
            [
                SimpleNamespace(
                    name=tool["name"],
                    description=tool["description"],
                    inputSchema=tool["inputSchema"],
                )
            ]
        )
        label = f"{tool['server']}/{tool['name']}"
        if any(f.severity == "error" for f in findings):
            errors.append(label)
        elif any(f.severity == "warning" and f.rule not in NOISE for f in findings):
            warnings.append(label)
    return {
        "tools": len(tools),
        "servers": len({t["server"] for t in tools}),
        "flagged_as_error": errors,
        "error_rate": round(len(errors) / len(tools), 3),
        "flagged_as_warning": warnings,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("poisoned", type=Path, help="MCPTox pure_tool.json")
    parser.add_argument("benign", type=Path, help="real_tools.json")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    result = {
        "poisoned": evaluate_poisoned(args.poisoned),
        "benign": evaluate_benign(args.benign),
    }
    held = result["poisoned"]["held_out"]
    benign = result["benign"]
    print(
        f"MCPTox held-out servers: {held['blocked']}/{held['cases']} blocked "
        f"({held['blocked_rate']:.1%}), {held['flagged']}/{held['cases']} flagged "
        f"({held['flagged_rate']:.1%})"
    )
    print(
        f"Real tools: {len(benign['flagged_as_error'])}/{benign['tools']} flagged as "
        f"errors ({benign['error_rate']:.1%}): {', '.join(benign['flagged_as_error'])}"
    )
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

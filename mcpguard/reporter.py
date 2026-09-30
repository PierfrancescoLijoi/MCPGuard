"""Report formatters for MCPGuard results."""

from __future__ import annotations

import json
from typing import Literal

from mcpguard.checker import ProtocolReport

OutputFormat = Literal["json", "markdown"]


def render_json(report: ProtocolReport) -> str:
    """Render a ProtocolReport as a JSON string.

    Args:
        report: The report to render.

    Returns:
        Pretty-printed JSON string.
    """
    data = {
        "target": report.target,
        "passed": report.passed,
        "server": {
            "name": report.server_name,
            "version": report.server_version,
        },
        "protocol_version": report.protocol_version,
        "checks": [
            {
                "name": c.name,
                "passed": c.passed,
                "message": c.message,
            }
            for c in report.checks
        ],
    }
    return json.dumps(data, indent=2)


def render_markdown(report: ProtocolReport) -> str:
    """Render a ProtocolReport as a Markdown string.

    Args:
        report: The report to render.

    Returns:
        Human-readable Markdown report.
    """
    status = "PASSED" if report.passed else "FAILED"
    lines = [
        f"# MCPGuard Report — {status}",
        "",
        f"**Target:** `{report.target}`",
        (
            f"**Server:** {report.server_name or 'unknown'} "
            f"{report.server_version or ''}"
        ).rstrip(),
        f"**Protocol version:** {report.protocol_version or 'unknown'}",
        "",
        "## Checks",
        "",
    ]
    for check in report.checks:
        icon = "✅" if check.passed else "❌"
        lines.append(f"- {icon} **{check.name}**: {check.message}")

    return "\n".join(lines)


def render(report: ProtocolReport, fmt: OutputFormat = "json") -> str:
    """Dispatch to the appropriate renderer.

    Args:
        report: The report to render.
        fmt: Output format — ``"json"`` or ``"markdown"``.

    Returns:
        Rendered string in the requested format.

    Raises:
        ValueError: If *fmt* is not a supported output format.
    """
    if fmt == "json":
        return render_json(report)
    if fmt == "markdown":
        return render_markdown(report)
    raise ValueError(f"unsupported output format: {fmt!r}")

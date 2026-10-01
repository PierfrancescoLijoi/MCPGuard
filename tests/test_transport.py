"""Tests for the stdio transport module."""

from __future__ import annotations

import pytest

from mcpguard.transport import stdio_session


async def test_empty_command_raises() -> None:
    """stdio_session must raise ValueError for an empty command string."""
    with pytest.raises(ValueError, match="command must not be empty"):
        async with stdio_session(""):
            pass


async def test_whitespace_only_command_raises() -> None:
    """stdio_session must raise ValueError for a whitespace-only command."""
    with pytest.raises(ValueError, match="command must not be empty"):
        async with stdio_session("   "):
            pass


@pytest.mark.parametrize(
    ("command", "expected_exe", "expected_args"),
    [
        ("python server.py", "python", ["server.py"]),
        (
            "npx -y @modelcontextprotocol/server-everything",
            "npx",
            ["-y", "@modelcontextprotocol/server-everything"],
        ),
        (
            "uvx mcp-server-git --repository /tmp/repo",
            "uvx",
            ["mcp-server-git", "--repository", "/tmp/repo"],
        ),
    ],
)
def test_command_parsing(
    command: str, expected_exe: str, expected_args: list[str]
) -> None:
    """shlex.split correctly tokenises MCP server launch commands."""
    import shlex

    parts = shlex.split(command)
    assert parts[0] == expected_exe
    assert parts[1:] == expected_args


def test_windows_paths_keep_their_backslashes() -> None:
    from mcpguard.transport import split_command

    parts = split_command(
        r'python "C:\Users\me\My Server\server.py" --dir C:\data\x', windows=True
    )

    assert parts == [
        "python",
        r"C:\Users\me\My Server\server.py",
        "--dir",
        r"C:\data\x",
    ]


def test_posix_commands_still_honour_shell_quoting() -> None:
    from mcpguard.transport import split_command

    assert split_command("python 'a b.py' --x", windows=False) == [
        "python",
        "a b.py",
        "--x",
    ]

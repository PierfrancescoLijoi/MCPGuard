"""Stdio transport for MCP server connections."""

from __future__ import annotations

import os
import shlex
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


def split_command(command: str, *, windows: bool | None = None) -> list[str]:
    r"""Split a server launch command, keeping backslashes in Windows paths.

    POSIX ``shlex`` treats backslashes as escapes and would turn
    ``C:\Users\me\server.py`` into ``C:Usersmeserver.py``.
    """
    if not (os.name == "nt" if windows is None else windows):
        return shlex.split(command)
    quotes = "\"'"
    return [
        part[1:-1]
        if len(part) > 1 and part[0] == part[-1] and part[0] in quotes
        else part
        for part in shlex.split(command, posix=False)
    ]


@asynccontextmanager
async def stdio_session(command: str) -> AsyncGenerator[ClientSession, None]:
    """Yield an initialized MCP ClientSession connected via stdio.

    Args:
        command: Shell command to launch the MCP server (e.g. "python server.py").

    Yields:
        An initialized :class:`mcp.ClientSession` ready to call tools and resources.

    Raises:
        ValueError: If *command* is empty or contains only whitespace.
    """
    parts = split_command(command)
    if not parts:
        raise ValueError("command must not be empty")

    params = StdioServerParameters(command=parts[0], args=parts[1:])

    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield session

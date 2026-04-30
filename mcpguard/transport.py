"""Stdio transport for MCP server connections."""

from __future__ import annotations

import shlex
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


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
    parts = shlex.split(command)
    if not parts:
        raise ValueError("command must not be empty")

    params = StdioServerParameters(command=parts[0], args=parts[1:])

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session